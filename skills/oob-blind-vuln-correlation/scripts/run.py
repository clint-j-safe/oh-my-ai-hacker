#!/usr/bin/env python3
"""
run.py -- oob-blind-vuln-correlation entry point.

The Observer's OOB handler. It collects Interactsh/OAST callbacks and proves,
by exact canary match, which specific request triggered a blind vulnerability --
then computes the request->callback latency. It waits (with a timeout) rather
than assuming failure.

CORRECTNESS / SAFETY
--------------------
* No target traffic, no mutations -- this skill only listens to the OOB channel
  and correlates. It is an observer.
* Attribution is exact. A callback is bound to a request ONLY when that request's
  unique canary appears in the callback. Callbacks that match no pending canary
  are reported under `meta.uncorrelated_interactions`, never attributed. Canaries
  that never call back appear in `meta.timed_out` -- absence is reported, not
  guessed as success or failure.

CONTRACT
--------
* Input  : {"oob_domain": "abc.oast.pro",
            "pending_tests": [{"request_id": "...", "canary": "s1a2b3", "sent_at_ms": 1730000000000}],
            "config": {"timeout_s": 30, "poll_interval_s": 3, "poll_url": "...",
                       "interactions_inline": [ ... ]}}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).

Interaction sources (priority): config.poll_url (polled) > interactions_inline
(single pass, e.g. supplied by a shared Interactsh session) > interactsh-client CLI.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import httpx  # type: ignore
except ImportError:  # pragma: no cover
    httpx = None

try:
    from spill_store import write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import write_spill  # type: ignore

DEFAULT_TIMEOUT = int(os.environ.get("OOB_TIMEOUT_S", "30"))
DEFAULT_POLL = int(os.environ.get("OOB_POLL_INTERVAL_S", "3"))
_ISO = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_ms() -> int:
    return int(time.time() * 1000)


def _ts_to_ms(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        # seconds vs milliseconds heuristic
        return int(v if v > 1e12 else v * 1000)
    s = str(v)
    m = _ISO.search(s)
    if m:
        try:
            iso = m.group(0).replace(" ", "T")
            return int(datetime.fromisoformat(iso).replace(tzinfo=timezone.utc).timestamp() * 1000)
        except Exception:  # noqa: BLE001
            return None
    if s.isdigit():
        return _ts_to_ms(int(s))
    return None


class OOBCorrelator:
    def __init__(self, oob_domain: str, pending_tests: List[dict], config: Optional[dict] = None):
        self.oob_domain = (oob_domain or "").strip()
        self.config = config or {}
        self.timeout_s = int(self.config.get("timeout_s", DEFAULT_TIMEOUT))
        self.poll_interval_s = max(1, int(self.config.get("poll_interval_s", DEFAULT_POLL)))
        self.errors: List[Dict[str, str]] = []
        # canary -> pending test (lowercased canary key for matching)
        self.pending: Dict[str, dict] = {}
        for t in (pending_tests or []):
            c = str(t.get("canary", "")).strip()
            if c:
                self.pending[c.lower()] = {"request_id": str(t.get("request_id", "")),
                                           "canary": c,
                                           "sent_at_ms": _ts_to_ms(t.get("sent_at_ms"))}
        self.started_ms = _now_ms()

    # -- interaction sources ---------------------------------------------------
    @staticmethod
    def _normalize(item: Any) -> dict:
        """-> {protocol, ident, ts_ms, raw}. `ident` is the text a canary is
        searched in (subdomain / path / raw request)."""
        if isinstance(item, dict):
            proto = str(item.get("protocol") or item.get("proto") or "dns").lower()
            ident_fields = [item.get(k, "") for k in
                            ("full-id", "unique-id", "fqdn", "host", "hostname",
                             "path", "url", "raw-request", "raw", "q", "smtp-from")]
            ident = " ".join(str(x) for x in ident_fields if x)
            if not ident:
                ident = json.dumps(item)
            ts = _ts_to_ms(item.get("timestamp") or item.get("time") or item.get("ts"))
            return {"protocol": proto if proto in ("dns", "http", "smtp") else "dns",
                    "ident": ident, "ts_ms": ts, "raw": item}
        s = str(item)
        proto = "http" if ("http" in s.lower() or s.startswith("/")) else "dns"
        return {"protocol": proto, "ident": s, "ts_ms": None, "raw": s}

    async def _fetch_poll(self) -> List[Any]:
        poll = self.config.get("poll_url")
        if not poll or httpx is None:
            return []
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(poll)
            data = r.json()
            return data.get("interactions", data) if isinstance(data, dict) else (data or [])
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "poll", "error": str(exc)})
            return []

    def _fetch_cli_once(self) -> List[Any]:
        # best-effort: interactsh-client writing JSON lines to a file we tail
        out_file = self.config.get("interactsh_json_file")
        if not out_file or not os.path.exists(out_file):
            if shutil.which("interactsh-client") and not out_file:
                self.errors.append({"stage": "cli", "error":
                                    "interactsh-client present but no interactsh_json_file configured to read"})
            return []
        items = []
        try:
            with open(out_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            items.append(json.loads(line))
                        except json.JSONDecodeError:
                            items.append(line)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "cli", "error": str(exc)})
        return items

    # -- correlation -----------------------------------------------------------
    def extract_canary(self, ident: str) -> Optional[str]:
        low = ident.lower()
        for canary_key in self.pending:
            if canary_key in low:
                return canary_key
        return None

    async def run(self) -> dict:
        correlated: Dict[str, dict] = {}          # canary_key -> callback record
        callback_counts: Dict[str, int] = {}
        uncorrelated: List[dict] = []
        seen_raw: set = set()
        inline = self.config.get("interactions_inline")
        deadline = time.time() + self.timeout_s

        async def ingest(items: List[Any]):
            for item in items:
                norm = self._normalize(item)
                key = json.dumps(norm["raw"], sort_keys=True, default=str)
                if key in seen_raw:
                    continue
                seen_raw.add(key)
                canary_key = self.extract_canary(norm["ident"])
                if not canary_key:
                    uncorrelated.append({"protocol": norm["protocol"],
                                         "ident": norm["ident"][:200]})
                    continue
                callback_counts[canary_key] = callback_counts.get(canary_key, 0) + 1
                if canary_key in correlated:
                    continue   # first callback per canary is the correlated one
                pend = self.pending[canary_key]
                cb_ms = norm["ts_ms"] or _now_ms()
                sent = pend["sent_at_ms"] or self.started_ms
                latency = max(0, cb_ms - sent)
                correlated[canary_key] = {
                    "request_id": pend["request_id"], "canary": pend["canary"],
                    "protocol": norm["protocol"], "latency_ms": int(latency),
                    "raw_log_spill_id": write_spill({"kind": "oob_interaction",
                                                     "canary": pend["canary"],
                                                     "request_id": pend["request_id"],
                                                     "protocol": norm["protocol"],
                                                     "interaction": norm["raw"],
                                                     "captured_at": _now_iso()}),
                }

        # single pass for inline; poll loop otherwise
        if inline is not None:
            await ingest(inline)
        else:
            while True:
                await ingest(await self._fetch_poll())
                if not self.config.get("poll_url"):
                    await ingest(self._fetch_cli_once())
                if len(correlated) >= len(self.pending) or time.time() >= deadline:
                    break
                await asyncio.sleep(self.poll_interval_s)

        timed_out = [self.pending[k]["request_id"] for k in self.pending if k not in correlated]
        results = sorted(correlated.values(), key=lambda c: c["latency_ms"])
        return self._artifact(results, callback_counts, uncorrelated, timed_out)

    def _artifact(self, correlated, counts, uncorrelated, timed_out) -> dict:
        return {
            "correlated_callbacks": correlated,
            "meta": {
                "skill": "oob-blind-vuln-correlation", "version": "1.0", "phase": "6",
                "status": "ok",
                "generated_at": _now_iso(),
                "oob_domain": self.oob_domain,
                "pending_count": len(self.pending),
                "correlated_count": len(correlated),
                "timed_out": timed_out,
                "uncorrelated_interactions": uncorrelated,
                "callback_counts": counts,
                "observer_only": True, "sends_target_traffic": False, "mutates": False,
            },
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
        raise ValueError("no input: expected JSON {\"pending_tests\":[...]}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str) -> dict:
    return {"correlated_callbacks": [],
            "meta": {"skill": "oob-blind-vuln-correlation", "version": "1.0", "phase": "6",
                     "status": "error", "generated_at": _now_iso()},
            "errors": [{"stage": "init", "error": message}]}


async def _amain(argv: List[str]) -> int:
    try:
        payload = _load_input(argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    pending = payload.get("pending_tests") or []
    if not isinstance(pending, list) or not pending:
        print(json.dumps(_error_artifact("need non-empty 'pending_tests' list")))
        return 2
    corr = OOBCorrelator(payload.get("oob_domain", ""), pending, config=payload.get("config"))
    artifact = await corr.run()
    print(json.dumps(artifact, ensure_ascii=False))
    return 0


def main() -> int:
    return asyncio.run(_amain(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())
