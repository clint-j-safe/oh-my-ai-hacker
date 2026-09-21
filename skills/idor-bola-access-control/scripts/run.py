#!/usr/bin/env python3
"""
run.py -- idor-bola-access-control entry point.

Executes differential access-control testing using the Phase 3 privilege matrix
and session pool. Confirms Broken Object Level Authorization (BOLA/IDOR) by
requesting one identity's protected object with another identity's session and
comparing normalized response hashes, and re-verifies vertical denials.

SAFETY MODEL
------------
* Read-only by default. Cross-session access tests use GET/HEAD/OPTIONS only.
  Mutating IDOR (PUT/PATCH/DELETE on another user's object) runs ONLY when
  config.allow_mutating is true (an explicit mutation budget).
* Real-vuln discriminator. A horizontal BOLA is confirmed only when the endpoint
  is actually access-controlled -- the matrix's `unauthenticated` baseline was
  `denied` -- so genuinely public objects do not produce false positives.
* Scope-gated on endpoint hosts. Response bodies (which may hold another test
  identity's data) are offloaded to the spill store, never inlined.

CONTRACT
--------
* Input  : {"privilege_matrix_spill_id": "...", "session_pool_spill_id": "...",
            "scope_policy_spill_id": "...", "config": {...}}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, parse_qsl

try:
    import httpx  # type: ignore
except ImportError:  # pragma: no cover
    httpx = None

try:
    from spill_store import read_spill, write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import read_spill, write_spill  # type: ignore

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
REQ_TIMEOUT = float(os.environ.get("IDOR_TIMEOUT", "20"))
CONCURRENCY = int(os.environ.get("IDOR_CONCURRENCY", "10"))
UNAUTH = "unauthenticated"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _normalize(text: str) -> str:
    if not text:
        return ""
    t = text
    t = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?", "<TS>", t)
    t = re.sub(r"(?i)(csrf|xsrf|authenticity)[-_]?token[\"'\s:=>]{1,6}[\w.\-+/=]+", r"\1=<CSRF>", t)
    t = re.sub(r"\bnonce[\"'\s:=>]{1,6}[\w.\-+/=]+", "nonce=<N>", t, flags=re.I)
    return t


def _hash(text: str) -> str:
    return hashlib.sha256(_normalize(text).encode("utf-8", "replace")).hexdigest()[:16]


def _extract_ids(url: str) -> List[str]:
    ids: List[str] = []
    parts = urlsplit(url)
    for seg in parts.path.split("/"):
        if re.fullmatch(r"\d+", seg) or re.fullmatch(r"[0-9a-fA-F]{24}", seg) \
                or re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", seg):
            ids.append(seg)
    for k, v in parse_qsl(parts.query):
        if k.lower() in ("id", "user_id", "uid", "account", "account_id", "order",
                         "order_id", "doc", "oid", "pid", "file", "num") or re.fullmatch(r"\d+", v):
            ids.append(v)
    return ids


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


class IDORTester:
    def __init__(self, privilege_matrix_spill_id: str, session_pool_spill_id: str,
                 scope_policy_spill_id: Optional[str] = None, config: Optional[dict] = None):
        self.matrix_id = privilege_matrix_spill_id
        self.sessions_id = session_pool_spill_id
        self.config = config or {}
        self.allow_mutating = bool(self.config.get("allow_mutating", False))
        self.errors: List[Dict[str, str]] = []
        self.rows: List[dict] = []
        self.sessions: Dict[str, Dict[str, str]] = {}   # role -> headers
        self.load_matrix()
        self.load_sessions()
        hosts = list({_host_of(r.get("endpoint", "")) for r in self.rows})
        policy = None
        if scope_policy_spill_id:
            try:
                policy = read_spill(scope_policy_spill_id)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "scope_load", "error": str(exc)})
        self.scope = ScopePolicy(policy, hosts)

    def load_matrix(self) -> None:
        try:
            data = read_spill(self.matrix_id)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "load_matrix", "error": str(exc)})
            return
        # accept: list of rows | {matrix_inline|matrix_spill_id} | full artifact
        if isinstance(data, dict):
            if data.get("matrix_inline"):
                self.rows = data["matrix_inline"]
            elif data.get("matrix_spill_id"):
                try:
                    self.rows = read_spill(data["matrix_spill_id"])
                except Exception as exc:  # noqa: BLE001
                    self.errors.append({"stage": "matrix_inner", "error": str(exc)})
            elif isinstance(data.get("matrix"), list):
                self.rows = data["matrix"]
        elif isinstance(data, list):
            self.rows = data

    def load_sessions(self) -> None:
        try:
            data = read_spill(self.sessions_id)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "load_sessions", "error": str(exc)})
            return
        pool = data.get("session_pool", data) if isinstance(data, dict) else data
        for sdef in (pool or []):
            role = sdef.get("role")
            if not role:
                continue
            cookies = sdef.get("cookies", [])
            hdr = {"User-Agent": "idor-bola-access-control/1.0"}
            ck = "; ".join(f"{c.get('name')}={c.get('value')}" for c in cookies if c.get("name"))
            if ck:
                hdr["cookie"] = ck
            hdr.update({k: v for k, v in (sdef.get("auth_headers") or {}).items()})
            self.sessions[role] = hdr

    # -- request ---------------------------------------------------------------
    async def _fetch(self, client, role: str, url: str, method: str = "GET") -> Tuple[int, str]:
        headers = self.sessions.get(role, {"User-Agent": "idor-bola-access-control/1.0"})
        try:
            r = await client.request(method, url, headers=headers)
            return r.status_code, r.text
        except Exception as exc:  # noqa: BLE001
            return 0, f"__ERROR__:{exc}"

    # -- horizontal BOLA -------------------------------------------------------
    async def test_horizontal(self, client) -> List[dict]:
        findings: List[dict] = []
        sem = asyncio.Semaphore(CONCURRENCY)

        for row in self.rows:
            url = row.get("endpoint", "")
            method = (row.get("method") or "GET").upper()
            if method not in SAFE_METHODS and not self.allow_mutating:
                continue
            if not self.scope.allowed(_host_of(url)):
                continue
            ids = _extract_ids(url)
            if not ids:
                continue  # BOLA needs an object identifier in the URL
            amap = row.get("access_map", {})
            # discriminator: the resource must actually be access-controlled
            if amap.get(UNAUTH, {}).get("verdict") != "denied":
                continue
            owners = [r for r, v in amap.items()
                      if r != UNAUTH and 200 <= int(v.get("status", 0)) < 300 and r in self.sessions]
            if not owners:
                continue

            async def check(owner: str, attacker: str, url=url, ids=ids, method=method):
                async with sem:
                    ost, obody = await self._fetch(client, owner, url, method)
                    if not (200 <= ost < 300):
                        return
                    ast, abody = await self._fetch(client, attacker, url, method)
                if 200 <= ast < 300 and _hash(abody) == _hash(obody) and not abody.startswith("__ERROR__"):
                    findings.append({
                        "endpoint": url, "resource_id": ",".join(ids),
                        "attacker_role": attacker, "victim_role": owner,
                        "access_type": "horizontal", "method": method,
                        "attacker_status": ast, "confidence": "confirmed",
                        "evidence_spill_id": write_spill({
                            "kind": "horizontal_bola", "endpoint": url, "resource_id": ids,
                            "attacker_role": attacker, "victim_role": owner,
                            "attacker_status": ast, "owner_hash": _hash(obody),
                            "attacker_body": abody[:12000], "captured_at": _now_iso()}),
                    })

            tasks = []
            roles = [r for r in self.sessions if r != UNAUTH]
            for owner in owners:
                for attacker in roles:
                    if attacker != owner:
                        tasks.append(check(owner, attacker))
            await asyncio.gather(*tasks)
        # dedup symmetric duplicates: one finding per (endpoint, role-pair)
        uniq: Dict[tuple, dict] = {}
        for f in findings:
            k = (f["endpoint"], frozenset((f["attacker_role"], f["victim_role"])))
            uniq.setdefault(k, f)
        return list(uniq.values())

    # -- vertical (privilege escalation re-verification) -----------------------
    async def test_vertical(self, client) -> List[dict]:
        findings: List[dict] = []
        sem = asyncio.Semaphore(CONCURRENCY)

        async def check(url, method, drole, victim):
            if not self.scope.allowed(_host_of(url)):
                return
            async with sem:
                st, body = await self._fetch(client, drole, url, method)
            if 200 <= st < 300 and not body.startswith("__ERROR__"):
                findings.append({
                    "endpoint": url, "resource_id": ",".join(_extract_ids(url)) or "-",
                    "attacker_role": drole, "victim_role": victim,
                    "access_type": "vertical", "method": method,
                    "attacker_status": st, "confidence": "confirmed",
                    "evidence_spill_id": write_spill({
                        "kind": "vertical_break", "endpoint": url, "denied_role": drole,
                        "privileged_role": victim, "status": st, "body": body[:12000],
                        "captured_at": _now_iso()}),
                })

        tasks = []
        for row in self.rows:
            url = row.get("endpoint", "")
            method = (row.get("method") or "GET").upper()
            if method not in SAFE_METHODS and not self.allow_mutating:
                continue
            amap = row.get("access_map", {})
            allowed = [r for r, v in amap.items()
                       if r != UNAUTH and 200 <= int(v.get("status", 0)) < 300]
            denied = [r for r, v in amap.items()
                      if r != UNAUTH and v.get("verdict") == "denied" and r in self.sessions]
            if allowed and denied:
                for drole in denied:
                    tasks.append(check(url, method, drole, allowed[0]))
        await asyncio.gather(*tasks)
        return findings

    async def run(self) -> dict:
        started = time.time()
        if httpx is None:
            self.errors.append({"stage": "http", "error": "httpx not installed"})
            return self._artifact([], started, fatal=True)
        if not self.rows:
            self.errors.append({"stage": "matrix", "error": "empty privilege matrix"})
            return self._artifact([], started, fatal=True)
        if len([r for r in self.sessions if r != UNAUTH]) < 1:
            self.errors.append({"stage": "sessions", "error": "no role sessions to test with"})
            return self._artifact([], started, fatal=True)
        findings: List[dict] = []
        try:
            async with httpx.AsyncClient(timeout=REQ_TIMEOUT, follow_redirects=False) as client:
                findings += await self.test_horizontal(client)
                findings += await self.test_vertical(client)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "run", "error": repr(exc)})
        return self._artifact(findings, started)

    def _artifact(self, findings: List[dict], started: float, fatal: bool = False) -> dict:
        h = sum(1 for f in findings if f.get("access_type") == "horizontal")
        v = sum(1 for f in findings if f.get("access_type") == "vertical")
        return {
            "findings": findings,
            "meta": {
                "skill": "idor-bola-access-control", "version": "1.0", "phase": "5",
                "status": "error" if fatal else "ok",
                "generated_at": _now_iso(),
                "duration_seconds": round(time.time() - started, 2),
                "matrix_rows": len(self.rows),
                "roles_available": [r for r in self.sessions if r != UNAUTH],
                "horizontal_findings": h, "vertical_findings": v,
                "safety": {"read_only": not self.allow_mutating, "mutating_allowed": self.allow_mutating,
                           "protected_resource_discriminator": True},
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
        raise ValueError("no input: expected JSON {\"privilege_matrix_spill_id\":...,\"session_pool_spill_id\":...}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str) -> dict:
    return {
        "findings": [],
        "meta": {"skill": "idor-bola-access-control", "version": "1.0", "phase": "5",
                 "status": "error", "generated_at": _now_iso()},
        "errors": [{"stage": "init", "error": message}],
    }


async def _amain(argv: List[str]) -> int:
    try:
        payload = _load_input(argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    mid = payload.get("privilege_matrix_spill_id")
    pid = payload.get("session_pool_spill_id")
    if not mid or not pid:
        print(json.dumps(_error_artifact("need 'privilege_matrix_spill_id' and 'session_pool_spill_id'")))
        return 2
    tester = IDORTester(mid, pid,
                        scope_policy_spill_id=payload.get("scope_policy_spill_id"),
                        config=payload.get("config"))
    artifact = await tester.run()
    print(json.dumps(artifact, ensure_ascii=False))
    return 0


def main() -> int:
    return asyncio.run(_amain(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())
