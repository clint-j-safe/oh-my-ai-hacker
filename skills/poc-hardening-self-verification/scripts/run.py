#!/usr/bin/env python3
"""
run.py -- poc-hardening-self-verification entry point.

A pre-flight check before the Oracle. Re-runs a generated PoC twice in a
hardened sandbox and diffs the results (ignoring dynamic fields) to rule out
flakiness / transient-state dependence, and compares against the PoC's
expected_output_hash. Flags unstable PoCs so the Oracle doesn't waste budget.

SAFETY MODEL
------------
* Never run an unvetted script. Before execution the loaded PoC source is
  RE-VALIDATED with the same ast import-allow-list + destructive-token scan as
  the generator -- this skill independently vets upstream output rather than
  trusting it. A failure => verdict "error", nothing runs.
* Hardened sandbox. Subprocess with POSIX rlimits (CPU, address space, file
  size, open files), a scrubbed environment (only SESSION_JSON + a minimal
  PATH), and a hard timeout. Docker (--memory/--pids-limit, --network=none when
  no target is needed) is the preferred production isolation and used when
  available.
* Deterministic diff. Outputs are compared after stripping well-known dynamic
  fields (timestamps, csrf/xsrf tokens, nonces, uuids), so transient churn is
  not mistaken for flakiness.

CONTRACT
--------
* Input  : {"poc_script_spill_id": "...", "expected_output_hash": "...",
            "config": {"timeout_s": 30, "session_json": {...} | "session_spill_id": "...",
                       "use_docker": false, "network_none": false,
                       "mem_mb": 256, "cpu_s": 20, "fsize_mb": 100}}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from spill_store import read_spill, write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import read_spill, write_spill  # type: ignore

try:
    import resource  # POSIX only
except ImportError:  # pragma: no cover
    resource = None

ALLOWED_IMPORTS = {"json", "os", "re", "sys", "hashlib", "base64", "urllib",
                   "httpx", "asyncio", "html", "playwright"}
DESTRUCTIVE = re.compile(
    r"\bsubprocess\b|\bos\.system\b|\bos\.popen\b|\beval\b|\bexec\b|__import__|"
    r"\bsocket\b|\bctypes\b|\bshutil\b|open\([^)]*['\"][wax]\b|\bpty\b", re.I)
JS_DESTRUCTIVE = re.compile(
    r"child_process|execSync|\bexec\b|require\(['\"]fs['\"]\)|process\.binding|eval\(", re.I)

_ISO = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
DYNAMIC_KEYS = {"timestamp", "time", "date", "ts", "generated_at", "csrf_token",
                "csrf", "xsrf", "nonce", "uuid", "requestid", "trace_id"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class UnsafeToRun(Exception):
    pass


# --- vetting ------------------------------------------------------------------
def vet_python(source: str) -> None:
    if DESTRUCTIVE.search(source):
        raise UnsafeToRun("destructive token in PoC source")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise UnsafeToRun(f"syntax error in PoC: {exc}")
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in ALLOWED_IMPORTS:
                    raise UnsafeToRun(f"disallowed import: {a.name}")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root and root not in ALLOWED_IMPORTS:
                raise UnsafeToRun(f"disallowed import: {node.module}")


def vet_javascript(source: str) -> None:
    if JS_DESTRUCTIVE.search(source):
        raise UnsafeToRun("destructive token in JS PoC source")


# --- dynamic-field stripping + hashing ---------------------------------------
def _strip(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _strip(v) for k, v in obj.items()
                if k.lower().replace("-", "").replace("_", "") not in
                {d.replace("_", "") for d in DYNAMIC_KEYS}}
    if isinstance(obj, list):
        return [_strip(x) for x in obj]
    if isinstance(obj, str):
        s = _ISO.sub("<TS>", obj)
        s = _UUID.sub("<UUID>", s)
        return s
    return obj


def canonicalize(text: str) -> str:
    text = text.strip()
    try:
        obj = json.loads(text)
        return json.dumps(_strip(obj), sort_keys=True, separators=(",", ":"))
    except Exception:  # noqa: BLE001
        t = _ISO.sub("<TS>", text)
        t = _UUID.sub("<UUID>", t)
        return t


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


class PoCHardener:
    def __init__(self, poc_script_spill_id: str, expected_output_hash: str = "",
                 config: Optional[dict] = None):
        self.spill_id = poc_script_spill_id
        self.expected = (expected_output_hash or "").strip()
        self.config = config or {}
        self.timeout_s = int(self.config.get("timeout_s", 30))
        self.mem_mb = int(self.config.get("mem_mb", 256))
        self.cpu_s = int(self.config.get("cpu_s", 20))
        self.fsize_mb = int(self.config.get("fsize_mb", 100))
        self.use_docker = bool(self.config.get("use_docker", False))
        self.network_none = bool(self.config.get("network_none", False))
        self.errors: List[Dict[str, str]] = []
        self.source = ""
        self.language = "python"
        self._load()

    def _load(self) -> None:
        try:
            rec = read_spill(self.spill_id)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "load", "error": str(exc)})
            return
        self.source = rec.get("source", "") if isinstance(rec, dict) else str(rec)
        self.language = (rec.get("language", "python") if isinstance(rec, dict) else "python").lower()

    def _session_json(self) -> str:
        sj = self.config.get("session_json")
        if sj is not None:
            return json.dumps(sj) if not isinstance(sj, str) else sj
        sid = self.config.get("session_spill_id")
        if sid:
            try:
                data = read_spill(sid)
                pool = data.get("session_pool", data) if isinstance(data, dict) else data
                entry = pool[0] if isinstance(pool, list) and pool else (pool if isinstance(pool, dict) else {})
                return json.dumps(entry)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "session", "error": str(exc)})
        return "{}"

    # -- sandboxed execution ---------------------------------------------------
    def _rlimits(self):
        if resource is None:
            return None

        def apply():
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (self.cpu_s, self.cpu_s + 2))
                mem = self.mem_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
                fs = self.fsize_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_FSIZE, (fs, fs))
                resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
                try:
                    resource.setrlimit(resource.RLIMIT_NPROC, (128, 128))
                except (ValueError, OSError):
                    pass
            except Exception:  # noqa: BLE001
                pass
        return apply

    def run_in_sandbox(self, session_json: str) -> Tuple[int, str, str]:
        if self.use_docker and shutil.which("docker"):
            return self._run_docker(session_json)
        return self._run_subprocess(session_json)

    def _scrubbed_env(self, session_json: str) -> Dict[str, str]:
        env = {"SESSION_JSON": session_json, "PATH": "/usr/bin:/bin",
               "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1",
               "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}
        # preserve the proxy/CA vars the environment needs for outbound TLS
        for k in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "REQUESTS_CA_BUNDLE",
                  "SSL_CERT_FILE", "PLAYWRIGHT_BROWSERS_PATH", "HOME"):
            if k in os.environ:
                env[k] = os.environ[k]
        return env

    def _run_subprocess(self, session_json: str) -> Tuple[int, str, str]:
        suffix = ".py" if self.language == "python" else ".js"
        interp = [sys.executable] if self.language == "python" else ["node"]
        if self.language != "python" and shutil.which("node") is None:
            return (127, "", "node not available")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, f"poc{suffix}")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.source)
            try:
                p = subprocess.run(interp + [path], capture_output=True, text=True,
                                   env=self._scrubbed_env(session_json),
                                   cwd=d, timeout=self.timeout_s,
                                   preexec_fn=self._rlimits() if resource else None)
                return (p.returncode, p.stdout, p.stderr)
            except subprocess.TimeoutExpired:
                return (124, "", f"timeout after {self.timeout_s}s")
            except Exception as exc:  # noqa: BLE001
                return (1, "", str(exc))

    def _run_docker(self, session_json: str) -> Tuple[int, str, str]:
        img = self.config.get("docker_image",
                              "python:3.11-slim" if self.language == "python" else "node:18-slim")
        suffix = ".py" if self.language == "python" else ".js"
        cmd_in = "python" if self.language == "python" else "node"
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, f"poc{suffix}")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.source)
            argv = ["docker", "run", "--rm", "--read-only",
                    f"--memory={self.mem_mb}m", "--cpus=1", "--pids-limit=64",
                    "--cap-drop=ALL", "-e", f"SESSION_JSON={session_json}",
                    f"--network={'none' if self.network_none else 'bridge'}",
                    "-v", f"{path}:/poc{suffix}:ro", img, cmd_in, f"/poc{suffix}"]
            try:
                p = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout_s + 20)
                return (p.returncode, p.stdout, p.stderr)
            except subprocess.TimeoutExpired:
                return (124, "", "docker timeout")
            except Exception as exc:  # noqa: BLE001
                return (1, "", str(exc))

    # -- diff ------------------------------------------------------------------
    @staticmethod
    def diff_outputs(a: str, b: str) -> str:
        ca, cb = canonicalize(a), canonicalize(b)
        if ca == cb:
            return "identical after stripping dynamic fields"
        # brief character-level summary
        return f"outputs differ (stripped): run1={ca[:120]!r} vs run2={cb[:120]!r}"

    # -- orchestration ---------------------------------------------------------
    def run(self) -> dict:
        started = datetime.now(timezone.utc)
        if not self.source:
            return self._artifact("error", "", "", "PoC source unavailable", None, started)
        # re-vet before running anything
        try:
            if self.language == "python":
                vet_python(self.source)
            else:
                vet_javascript(self.source)
        except UnsafeToRun as exc:
            return self._artifact("error", "", "", f"refused to run: {exc}", None, started)

        session_json = self._session_json()
        rc1, out1, err1 = self.run_in_sandbox(session_json)
        rc2, out2, err2 = self.run_in_sandbox(session_json)

        logs_spill = write_spill({"run1": {"rc": rc1, "stdout": out1[:8000], "stderr": err1[:2000]},
                                  "run2": {"rc": rc2, "stdout": out2[:8000], "stderr": err2[:2000]},
                                  "captured_at": _now_iso()})

        if not out1.strip() and not out2.strip():
            return self._artifact("error", "", "", "PoC produced no output in either run",
                                  logs_spill, started, {"rc1": rc1, "rc2": rc2})

        c1, c2 = canonicalize(out1), canonicalize(out2)
        run1_hash, run2_hash = _hash(c1), _hash(c2)
        diff = self.diff_outputs(out1, out2)

        if c1 != c2:
            verdict = "flaky"
        elif self.expected and run1_hash != self.expected:
            verdict = "regressed"   # stable, but no longer matches the recorded proof
        else:
            verdict = "reproduced"
        return self._artifact(verdict, run1_hash, run2_hash, diff, logs_spill, started,
                              {"expected_output_hash": self.expected,
                               "matches_expected": bool(self.expected) and run1_hash == self.expected,
                               "stable": c1 == c2})

    def _artifact(self, verdict, run1_hash, run2_hash, diff, logs_spill, started, extra=None) -> dict:
        art = {
            "verdict": verdict,
            "run1_hash": run1_hash,
            "run2_hash": run2_hash,
            "diff_summary": diff,
            "logs_spill_id": logs_spill or "",
            "meta": {
                "skill": "poc-hardening-self-verification", "version": "1.0", "phase": "6",
                "status": "ok" if verdict != "error" else "error",
                "generated_at": _now_iso(),
                "language": self.language,
                "expected_output_hash": self.expected,
                "sandbox": "docker" if (self.use_docker and shutil.which("docker")) else "subprocess+rlimits",
                "safety": {"revetted_before_run": True,
                           "rlimits_applied": resource is not None,
                           "env_scrubbed": True, "network_none": self.network_none},
            },
            "errors": self.errors,
        }
        if extra:
            art["meta"].update(extra)
        return art


# --- entry point -------------------------------------------------------------
def _load_input(argv: List[str]) -> dict:
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError("no input: expected JSON {\"poc_script_spill_id\":\"...\"}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str) -> dict:
    return {"verdict": "error", "run1_hash": "", "run2_hash": "", "diff_summary": message,
            "logs_spill_id": "",
            "meta": {"skill": "poc-hardening-self-verification", "version": "1.0", "phase": "6",
                     "status": "error", "generated_at": _now_iso()},
            "errors": [{"stage": "init", "error": message}]}


def main() -> int:
    try:
        payload = _load_input(sys.argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    if not payload.get("poc_script_spill_id"):
        print(json.dumps(_error_artifact("need 'poc_script_spill_id'")))
        return 2
    h = PoCHardener(payload["poc_script_spill_id"],
                    payload.get("expected_output_hash", ""), config=payload.get("config"))
    print(json.dumps(h.run(), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
