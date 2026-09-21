#!/usr/bin/env python3
"""
run.py -- privilege-matrix-mapping entry point.

Builds a strict Role x Resource x Verb authorization matrix by replaying the
Phase 2 sitemap endpoints with each Phase 3 role session (plus an
unauthenticated baseline) and comparing the differential responses. This matrix
is the required substrate for the Phase 5 IDOR/BOLA skill.

CONTRACT
--------
* Input  : JSON on argv[1] or stdin:
    { "sitemap_spill_id": "phase2_sitemap_hash",
      "session_pool_spill_id": "phase3_sessions_hash",
      "config": {"allow_mutating": false, "concurrency": 20,
                 "api_only": true, "idor_size_delta": 0.25} }
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
           No prose. On fatal error, a schema-valid artifact with
           meta.status == "error".

SAFETY (blast-radius discipline)
--------------------------------
Read-only by default. Only SAFE, idempotent verbs (GET/HEAD/OPTIONS) are
replayed. Mutating verbs (POST/PUT/PATCH/DELETE) are recorded with verdict
`skipped` and NOT sent, unless `config.allow_mutating` is explicitly true (an
opt-in mutation budget). Concurrency is capped (default 20) to avoid tripping
WAF/rate limits. The unauthenticated baseline is what proves broken access
control, not an assumption.
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
DEFAULT_CONCURRENCY = int(os.environ.get("PM_CONCURRENCY", "20"))
REQ_TIMEOUT = float(os.environ.get("PM_TIMEOUT", "20"))
INLINE_CAP = int(os.environ.get("PM_INLINE_CAP", "100"))
IDOR_SIZE_DELTA = float(os.environ.get("PM_IDOR_DELTA", "0.25"))
UNAUTH = "unauthenticated"

_API_RE = re.compile(r"/(api|v[0-9]+|graphql|rest)(/|$|\?)", re.I)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_body(text: str) -> str:
    """Strip dynamic noise so equal payloads hash equal, while preserving the
    record-level differences IDOR detection needs (record ids/values stay)."""
    if not text:
        return ""
    t = text
    t = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?", "<TS>", t)
    t = re.sub(r"(?i)(csrf[-_]?token|xsrf[-_]?token|authenticity_token)[\"'\s:=>]{1,6}[\w.\-+/=]+", r"\1=<CSRF>", t)
    t = re.sub(r"\bnonce[\"'\s:=>]{1,6}[\w.\-+/=]+", "nonce=<N>", t, flags=re.I)
    t = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "<UUID>", t)
    t = re.sub(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "<JWT>", t)
    t = re.sub(r"\b[A-Fa-f0-9]{32,}\b", "<HEX>", t)  # long hex blobs / signatures
    return t


def _body_hash(text: str) -> str:
    return hashlib.sha256(_normalize_body(text).encode("utf-8", "replace")).hexdigest()[:16]


class PrivilegeMapper:
    def __init__(self, sitemap_spill_id: str, session_pool_spill_id: str,
                 config: Optional[dict] = None):
        self.sitemap_id = sitemap_spill_id
        self.sessions_id = session_pool_spill_id
        self.config = config or {}
        self.allow_mutating = bool(self.config.get("allow_mutating", False))
        self.api_only = bool(self.config.get("api_only", True))
        self.concurrency = int(self.config.get("concurrency", DEFAULT_CONCURRENCY))
        self.idor_delta = float(self.config.get("idor_size_delta", IDOR_SIZE_DELTA))
        self.errors: List[Dict[str, str]] = []
        self.endpoints: List[dict] = []
        self.sessions: List[dict] = []

    # -- loaders ---------------------------------------------------------------
    def load_sitemap(self) -> None:
        try:
            data = read_spill(self.sitemap_id)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "load_sitemap", "error": str(exc)})
            return
        rows = data.get("sitemap", data) if isinstance(data, dict) else data
        seen = set()
        for it in (rows or []):
            if not isinstance(it, dict):
                continue
            url = it.get("url", "")
            method = (it.get("method") or "GET").upper()
            if not url:
                continue
            is_api = bool(_API_RE.search(url)) or \
                it.get("discovered_by") in ("xhr", "fetch", "form_action") or \
                "json" in (it.get("content_type") or "")
            if self.api_only and not is_api:
                continue
            key = (method, url)
            if key in seen:
                continue
            seen.add(key)
            self.endpoints.append({
                "url": url, "method": method,
                "template_spill_id": it.get("captured_request_spill_id"),
                "content_type": it.get("content_type", ""), "is_api": is_api,
            })

    def load_sessions(self) -> None:
        try:
            data = read_spill(self.sessions_id)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "load_sessions", "error": str(exc)})
            return
        pool = data.get("session_pool", data) if isinstance(data, dict) else data
        for s in (pool or []):
            if not isinstance(s, dict):
                continue
            cookies = s.get("cookies", [])
            cookie_hdr = "; ".join(f"{c.get('name')}={c.get('value')}"
                                   for c in cookies if c.get("name"))
            self.sessions.append({
                "role": s.get("role", "role"),
                "cookie_header": cookie_hdr,
                "auth_headers": {k: v for k, v in (s.get("auth_headers") or {}).items()},
            })

    def _roles(self) -> List[str]:
        return [s["role"] for s in self.sessions] + [UNAUTH]

    # -- template body ---------------------------------------------------------
    def _load_body(self, ep: dict) -> Tuple[Optional[str], Optional[str]]:
        tid = ep.get("template_spill_id")
        if not tid:
            return None, None
        try:
            tpl = read_spill(tid)
        except Exception:  # noqa: BLE001
            return None, None
        return tpl.get("post_data"), (tpl.get("headers", {}) or {}).get("content-type")

    # -- replay ----------------------------------------------------------------
    async def replay_endpoint(self, client, ep: dict, role_headers: Dict[str, Dict[str, str]],
                              sem: asyncio.Semaphore) -> Tuple[str, str, dict]:
        method = ep["method"]
        url = ep["url"]
        access_map: Dict[str, dict] = {}

        if method not in SAFE_METHODS and not self.allow_mutating:
            for role in self._roles():
                access_map[role] = {"status": 0, "verdict": "skipped", "response_hash": ""}
            return method, url, access_map

        body, ctype = self._load_body(ep)

        async def one(role: str, headers: Dict[str, str]):
            hdrs = dict(headers)
            if body and ctype:
                hdrs.setdefault("content-type", ctype)
            async with sem:
                try:
                    resp = await client.request(
                        method, url, headers=hdrs,
                        content=(body.encode() if isinstance(body, str) else body)
                        if (body and method not in SAFE_METHODS) else None)
                    text = resp.text
                    access_map[role] = {
                        "status": resp.status_code,
                        "verdict": self._verdict_for(resp.status_code),
                        "response_hash": _body_hash(text),
                        "_size": len(text),
                    }
                except Exception as exc:  # noqa: BLE001
                    access_map[role] = {"status": 0, "verdict": "error",
                                        "response_hash": "", "_size": 0,
                                        "_err": str(exc)[:120]}

        await asyncio.gather(*(one(role, hdrs) for role, hdrs in role_headers.items()))
        self.analyze_differential_response(access_map)
        return method, url, access_map

    @staticmethod
    def _verdict_for(status: int) -> str:
        if 200 <= status < 300:
            return "allowed"
        if status in (401, 403, 404) or 300 <= status < 400:
            return "denied"       # 3xx here = redirect to login; 404 = hidden/absent
        return "error"            # 5xx, 429, network

    def analyze_differential_response(self, amap: Dict[str, dict]) -> None:
        allowed = [r for r, v in amap.items() if v["verdict"] == "allowed"]
        if len(allowed) >= 2:
            hashes = {amap[r]["response_hash"] for r in allowed}
            sizes = [amap[r].get("_size", 0) for r in allowed]
            hi, lo = max(sizes), min(sizes)
            size_delta = (hi - lo) / hi if hi else 0.0
            # Same URL returns DIFFERENT data (normalized hash differs) or a
            # drastically different size to ≥2 identities that all got in ->
            # candidate horizontal-authz / IDOR. Verdict "idorsuspect" is a
            # lead for the Phase 5 IDOR/BOLA skill to verify, not a finding.
            if len(hashes) > 1 or size_delta >= self.idor_delta:
                for r in allowed:
                    amap[r]["verdict"] = "idorsuspect"

    # -- assembly --------------------------------------------------------------
    def offload_matrix(self, matrix: List[dict], started: float) -> dict:
        roles = self._roles()
        idor = sum(1 for m in matrix
                   if any(c["verdict"] == "idorsuspect" for c in m["access_map"].values()))
        unauth_open = sum(1 for m in matrix
                          if m["access_map"].get(UNAUTH, {}).get("verdict") in ("allowed", "idorsuspect"))
        summary = {
            "total_endpoints_tested": len(matrix),
            "roles_tested": roles,
            "idor_suspects_count": idor,
            "unauthorized_access_count": unauth_open,
        }
        # strip internal keys from inline copy
        clean = [{"endpoint": m["endpoint"], "method": m["method"],
                  "access_map": {r: {"status": c["status"], "verdict": c["verdict"],
                                     "response_hash": c["response_hash"]}
                                 for r, c in m["access_map"].items()}} for m in matrix]

        if len(clean) > INLINE_CAP:
            matrix_spill_id = write_spill(clean)
            matrix_inline = None
        else:
            matrix_spill_id = None
            matrix_inline = clean

        return {
            "matrix_inline": matrix_inline,
            "matrix_spill_id": matrix_spill_id,
            "summary": summary,
            "meta": {
                "skill": "privilege-matrix-mapping", "version": "1.0", "phase": "3",
                "status": "ok" if matrix else "error",
                "generated_at": _now_iso(),
                "duration_seconds": round(time.time() - started, 2),
                "endpoints_loaded": len(self.endpoints),
                "mutating_allowed": self.allow_mutating,
                "api_only": self.api_only,
                "concurrency": self.concurrency,
            },
            "errors": self.errors,
        }

    async def run(self) -> dict:
        started = time.time()
        self.load_sitemap()
        self.load_sessions()
        if httpx is None:
            self.errors.append({"stage": "http", "error": "httpx not installed"})
            return self.offload_matrix([], started)
        if not self.endpoints:
            self.errors.append({"stage": "sitemap", "error": "no endpoints to test"})
            return self.offload_matrix([], started)

        # precompute per-role header sets (unauth = empty)
        base_ua = {"User-Agent": "privilege-matrix-mapping/1.0"}
        role_headers: Dict[str, Dict[str, str]] = {}
        for s in self.sessions:
            h = dict(base_ua)
            if s["cookie_header"]:
                h["cookie"] = s["cookie_header"]
            h.update(s["auth_headers"])
            role_headers[s["role"]] = h
        role_headers[UNAUTH] = dict(base_ua)

        sem = asyncio.Semaphore(self.concurrency)
        matrix: List[dict] = []
        try:
            async with httpx.AsyncClient(timeout=REQ_TIMEOUT, follow_redirects=False) as client:
                results = await asyncio.gather(*(
                    self.replay_endpoint(client, ep, role_headers, sem)
                    for ep in self.endpoints))
            for method, url, amap in results:
                matrix.append({"endpoint": url, "method": method, "access_map": amap})
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "replay", "error": repr(exc)})
        return self.offload_matrix(matrix, started)


# --- entry point -------------------------------------------------------------
def _load_input(argv: List[str]) -> dict:
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError("no input: expected JSON {\"sitemap_spill_id\":...,\"session_pool_spill_id\":...}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str) -> dict:
    return {
        "matrix_inline": None, "matrix_spill_id": None,
        "summary": {"total_endpoints_tested": 0, "roles_tested": [],
                    "idor_suspects_count": 0, "unauthorized_access_count": 0},
        "meta": {"skill": "privilege-matrix-mapping", "version": "1.0", "phase": "3",
                 "status": "error", "generated_at": _now_iso()},
        "errors": [{"stage": "init", "error": message}],
    }


async def _amain(argv: List[str]) -> int:
    try:
        payload = _load_input(argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    sid = payload.get("sitemap_spill_id")
    pid = payload.get("session_pool_spill_id")
    if not sid or not pid:
        print(json.dumps(_error_artifact("need 'sitemap_spill_id' and 'session_pool_spill_id'")))
        return 2
    mapper = PrivilegeMapper(sid, pid, config=payload.get("config"))
    artifact = await mapper.run()
    print(json.dumps(artifact, ensure_ascii=False))
    return 0


def main() -> int:
    return asyncio.run(_amain(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())
