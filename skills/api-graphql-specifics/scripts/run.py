#!/usr/bin/env python3
"""
run.py -- api-graphql-specifics entry point.

Tests REST and GraphQL APIs for introspection leaks (+ schema dump), mass
assignment (over-posting privileged fields), batch-query abuse (rate-limit
bypass), and ID enumeration.

SAFETY MODEL
------------
* Read-only tests by default. Introspection is a benign query; batching sends a
  small, capped batch of harmless aliased queries to *detect* that batching is
  processed (a rate-limit-bypass vector) -- it is NOT used to brute-force. ID
  enumeration is bounded (small range) and GET-only.
* Mass assignment MUTATES (it writes privileged fields), so it runs only when
  config.authorize_mutations is true (an explicit mutation budget) and every
  write is recorded in a cleanup ledger (meta.mutations).
* Scope-gated. GraphQL schemas and responses are offloaded to the spill store.

CONTRACT
--------
* Input  : {"api_endpoints": [{"url","method","body"}], "graphql_endpoints": ["..."],
            "scope_policy_spill_id": "...",
            "config": {"authorize_mutations": false, "batch_size": 10,
                       "id_enum_count": 20}}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

try:
    import httpx  # type: ignore
except ImportError:  # pragma: no cover
    httpx = None

try:
    from spill_store import read_spill, write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import read_spill, write_spill  # type: ignore

HTTP_TIMEOUT = float(os.environ.get("API_HTTP_TIMEOUT", "20"))
DEFAULT_BATCH = int(os.environ.get("API_BATCH_SIZE", "10"))
BATCH_MAX = int(os.environ.get("API_BATCH_MAX", "25"))
DEFAULT_ID_ENUM = int(os.environ.get("API_ID_ENUM", "20"))
ID_ENUM_MAX = int(os.environ.get("API_ID_ENUM_MAX", "50"))
_MA_FIELDS = os.environ.get(
    "API_MASS_FIELDS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets", "mass-assignment-fields.txt"))

INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { queryType { name } mutationType { name } "
    "types { name kind fields { name } } } }")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _coerce(v: str) -> Any:
    v = v.strip()
    if v.lower() in ("true", "false"):
        return v.lower() == "true"
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    if (v.startswith("[") and v.endswith("]")) or (v.startswith("{") and v.endswith("}")):
        try:
            return json.loads(v)
        except Exception:  # noqa: BLE001
            return v
    return v


class ScopePolicy:
    def __init__(self, policy: Optional[dict], hosts: List[str]):
        self.raw = policy or {}
        self.have_policy = policy is not None
        self.in_scope = [self._c(p) for p in self.raw.get("in_scope", [])]
        self.out_scope = [self._c(p) for p in self.raw.get("out_of_scope", [])]
        if not self.in_scope:
            for h in hosts:
                if h:
                    self.in_scope += [self._c(h), self._c(f"*.{h}")]

    @staticmethod
    def _c(pattern: str) -> re.Pattern:
        p = pattern.strip().lower().rstrip(".")
        if p.startswith("*."):
            return re.compile(rf"^([a-z0-9_-]+\.)*{re.escape(p[2:])}$")
        return re.compile(rf"^{re.escape(p)}$")

    def allowed(self, host: str) -> bool:
        h = (host or "").strip().lower()
        if not h:
            return False
        if any(rx.match(h) for rx in self.out_scope):
            return False
        return any(rx.match(h) for rx in self.in_scope)


class APITester:
    def __init__(self, api_endpoints: List[dict], graphql_endpoints: List[str],
                 scope_policy_spill_id: Optional[str] = None, config: Optional[dict] = None):
        self.api = api_endpoints or []
        self.gql = [g if isinstance(g, str) else g.get("url", "") for g in (graphql_endpoints or [])]
        self.config = config or {}
        self.authorized = bool(self.config.get("authorize_mutations", False))
        self.batch_size = min(int(self.config.get("batch_size", DEFAULT_BATCH)), BATCH_MAX)
        self.id_enum_count = min(int(self.config.get("id_enum_count", DEFAULT_ID_ENUM)), ID_ENUM_MAX)
        self.errors: List[Dict[str, str]] = []
        self.mutations: List[dict] = []
        hosts = [_host_of(e.get("url", "")) for e in self.api] + [_host_of(g) for g in self.gql]
        policy = None
        if scope_policy_spill_id:
            try:
                policy = read_spill(scope_policy_spill_id)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "scope_load", "error": str(exc)})
        self.scope = ScopePolicy(policy, [h for h in hosts if h])
        self.ma_fields = self._load_fields()

    def _load_fields(self) -> List[Tuple[str, Any]]:
        out = []
        try:
            with open(_MA_FIELDS, "r", encoding="utf-8") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if not ln or ln.startswith("#") or "=" not in ln:
                        continue
                    k, v = ln.split("=", 1)
                    out.append((k.strip(), _coerce(v)))
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "ma_fields", "error": str(exc)})
        return out

    # -- GraphQL introspection -------------------------------------------------
    async def test_graphql_introspection(self, client, url: str) -> List[dict]:
        if not self.scope.allowed(_host_of(url)):
            return []
        findings = []
        try:
            r = await client.post(url, json={"query": INTROSPECTION_QUERY})
            data = r.json()
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "introspection", "error": f"{url}: {exc}"})
            return []
        schema = (data or {}).get("data", {}).get("__schema")
        if schema:
            types = schema.get("types", [])
            schema_spill = write_spill({"kind": "graphql_schema", "endpoint": url,
                                        "schema": schema, "captured_at": _now_iso()})
            findings.append({
                "vuln_class": "graphql_introspection", "endpoint": url,
                "schema_spill_id": schema_spill,
                "detail": {"types": len(types),
                           "type_names": [t.get("name") for t in types[:40] if t.get("name")]},
                "evidence_spill_id": write_spill({"kind": "introspection_response",
                                                  "endpoint": url, "response": json.dumps(data)[:8000],
                                                  "captured_at": _now_iso()}),
            })
            # batching abuse (read-only, capped) on the same GraphQL endpoint
            findings += await self.test_batching(client, url)
        return findings

    # -- batching abuse (capped, benign aliased queries) -----------------------
    async def test_batching(self, client, url: str) -> List[dict]:
        # array-batch form
        batch = [{"query": "{ __typename }"} for _ in range(self.batch_size)]
        processed = 0
        try:
            r = await client.post(url, json=batch)
            data = r.json()
            if isinstance(data, list):
                processed = sum(1 for x in data if isinstance(x, dict) and
                                (x.get("data") or x.get("errors")))
        except Exception:  # noqa: BLE001
            data = None
        # aliased-batch form (single query, N aliases)
        aliased = "{ " + " ".join(f"a{i}: __typename" for i in range(self.batch_size)) + " }"
        aliases_ok = 0
        try:
            r2 = await client.post(url, json={"query": aliased})
            d2 = r2.json()
            aliases_ok = len((d2 or {}).get("data", {}) or {})
        except Exception:  # noqa: BLE001
            pass
        if processed >= max(2, self.batch_size) or aliases_ok >= max(2, self.batch_size):
            return [{
                "vuln_class": "batching_abuse", "endpoint": url,
                "schema_spill_id": None,
                "detail": {"array_batch_processed": processed, "aliases_processed": aliases_ok,
                           "batch_size": self.batch_size,
                           "note": "server processes batched/aliased queries in one request -> rate-limit bypass vector"},
                "evidence_spill_id": write_spill({"kind": "batching", "endpoint": url,
                                                  "array_processed": processed, "aliases_ok": aliases_ok,
                                                  "captured_at": _now_iso()}),
            }]
        return []

    # -- mass assignment (mutating -> gated) -----------------------------------
    async def test_mass_assignment(self, client, ep: dict) -> List[dict]:
        url = ep.get("url", "")
        method = (ep.get("method") or "POST").upper()
        if not self.scope.allowed(_host_of(url)):
            return []
        base_body = dict(ep.get("body") or {})
        # baseline (no injected fields) for comparison
        try:
            rb = await client.request(method, url, json=base_body)
            base_text = rb.text
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "mass_assign_base", "error": f"{url}: {exc}"})
            return []
        findings = []
        for field, value in self.ma_fields:
            body = dict(base_body)
            body[field] = value
            self.mutations.append({"action": "mass_assignment_probe", "endpoint": url,
                                   "method": method, "injected_field": field, "value": value,
                                   "at": _now_iso(), "note": "over-post probe; may create/modify a record"})
            try:
                r = await client.request(method, url, json=body)
                text = r.text
            except Exception:  # noqa: BLE001
                continue
            # accepted if the elevated field is reflected back with our value and
            # it was NOT present in the baseline response
            reflected = self._field_reflected(text, field, value)
            base_reflected = self._field_reflected(base_text, field, value)
            if 200 <= r.status_code < 300 and reflected and not base_reflected:
                findings.append({
                    "vuln_class": "mass_assignment", "endpoint": url,
                    "confidence": "confirmed",  # normalized for DualMethodVerifier
                    "schema_spill_id": None,
                    "detail": {"field": field, "value": value, "method": method},
                    "evidence_spill_id": write_spill({"kind": "mass_assignment", "endpoint": url,
                                                      "field": field, "value": value,
                                                      "response": text[:6000], "captured_at": _now_iso()}),
                })
        return findings

    @staticmethod
    def _field_reflected(text: str, field: str, value: Any) -> bool:
        try:
            obj = json.loads(text)
        except Exception:  # noqa: BLE001
            return False

        def walk(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k == field and v == value:
                        return True
                    if walk(v):
                        return True
            elif isinstance(o, list):
                return any(walk(x) for x in o)
            return False
        return walk(obj)

    # -- ID enumeration (bounded, GET-only) ------------------------------------
    async def test_id_enumeration(self, client, ep: dict) -> List[dict]:
        url = ep.get("url", "")
        if not self.scope.allowed(_host_of(url)):
            return []
        # find a numeric id in the path or query to iterate
        parts = urlsplit(url)
        m = re.search(r"/(\d+)(?=/|$)", parts.path)
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        id_param = next((k for k, v in q.items() if re.fullmatch(r"\d+", v)), None)
        if not m and not id_param:
            return []
        base_id = int(m.group(1)) if m else int(q[id_param])
        distinct: Dict[str, int] = {}
        hits = 0
        sem = asyncio.Semaphore(8)

        async def fetch(i: int):
            nonlocal hits
            if m:
                path = parts.path[:m.start()] + f"/{i}" + parts.path[m.end():]
                u = urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))
            else:
                q2 = dict(q); q2[id_param] = str(i)
                u = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q2), ""))
            async with sem:
                try:
                    r = await client.get(u)
                except Exception:  # noqa: BLE001
                    return
            if 200 <= r.status_code < 300 and len(r.text.strip()) > 0:
                hits += 1
                distinct[str(i)] = len(r.text)

        # bounded sweep around the observed id
        ids = list(range(max(1, base_id - self.id_enum_count // 2),
                          base_id + self.id_enum_count // 2 + 1))[:self.id_enum_count]
        await asyncio.gather(*(fetch(i) for i in ids))
        # enumeration is meaningful if many sequential ids return distinct objects
        distinct_sizes = len(set(distinct.values()))
        if hits >= max(3, self.id_enum_count // 2) and distinct_sizes > 1:
            return [{
                "vuln_class": "id_enumeration", "endpoint": url, "schema_spill_id": None,
                "detail": {"ids_probed": len(ids), "accessible": hits,
                           "sample_ids": sorted(distinct.keys())[:10]},
                "evidence_spill_id": write_spill({"kind": "id_enumeration", "endpoint": url,
                                                  "accessible_ids": distinct, "captured_at": _now_iso()}),
            }]
        return []

    # -- orchestration ---------------------------------------------------------
    async def run(self) -> dict:
        started = time.time()
        if httpx is None:
            self.errors.append({"stage": "http", "error": "httpx not installed"})
            return self._artifact([], started, fatal=True)
        if not self.api and not self.gql:
            self.errors.append({"stage": "input", "error": "no api_endpoints or graphql_endpoints"})
            return self._artifact([], started, fatal=True)
        mass_gated = bool(self.api) and not self.authorized
        if mass_gated:
            self.errors.append({"stage": "authorization", "error":
                                "mass-assignment writes to the target; set config.authorize_mutations=true "
                                "to run it. Proceeding with read-only tests (introspection/batching/id-enum)."})
        findings: List[dict] = []
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
                for g in self.gql:
                    findings += await self.test_graphql_introspection(client, g)
                for ep in self.api:
                    findings += await self.test_id_enumeration(client, ep)
                    if self.authorized:
                        findings += await self.test_mass_assignment(client, ep)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "run", "error": repr(exc)})
        return self._artifact(findings, started, gated=mass_gated)

    def _artifact(self, findings, started, fatal=False, gated=False) -> dict:
        by = {}
        for f in findings:
            by[f["vuln_class"]] = by.get(f["vuln_class"], 0) + 1
        return {
            "findings": findings,
            "meta": {
                "skill": "api-graphql-specifics", "version": "1.0", "phase": "5",
                "status": "error" if fatal else "ok",
                "mass_assignment_authorization_required": gated,
                "generated_at": _now_iso(),
                "duration_seconds": round(time.time() - started, 2),
                "counts": by,
                "safety": {"mass_assignment_authorized": self.authorized,
                           "batch_capped_at": self.batch_size, "id_enum_capped_at": self.id_enum_count,
                           "read_only_except_mass_assignment": True},
                "mutations": self.mutations,
            },
            "scope_summary": {"policy_present": self.scope.have_policy},
            "errors": self.errors,
        }


# --- entry point -------------------------------------------------------------
def _load_input(argv: List[str]) -> dict:
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError("no input: expected JSON {\"api_endpoints\":[...],\"graphql_endpoints\":[...]}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str) -> dict:
    return {
        "findings": [],
        "meta": {"skill": "api-graphql-specifics", "version": "1.0", "phase": "5",
                 "status": "error", "generated_at": _now_iso()},
        "errors": [{"stage": "init", "error": message}],
    }


async def _amain(argv: List[str]) -> int:
    try:
        payload = _load_input(argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    api = payload.get("api_endpoints") or []
    gql = payload.get("graphql_endpoints") or []
    if not api and not gql:
        print(json.dumps(_error_artifact("need 'api_endpoints' and/or 'graphql_endpoints'")))
        return 2
    tester = APITester(api, gql, scope_policy_spill_id=payload.get("scope_policy_spill_id"),
                       config=payload.get("config"))
    artifact = await tester.run()
    print(json.dumps(artifact, ensure_ascii=False))
    return 0


def main() -> int:
    return asyncio.run(_amain(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())
