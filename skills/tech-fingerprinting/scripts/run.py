#!/usr/bin/env python3
"""
run.py -- tech-fingerprinting entry point.

Identifies the server, framework, language runtime, libraries, and WAF behind a
target from captured HTTP responses (headers, cookies, HTML/JS signatures),
cross-references component versions against the OSV.dev CVE database, and emits
a stack profile (`stack` + `waf` + `meta.signals`). The LLM Threat Model and
Skill Planner read this stack/WAF to decide what to test (M14 removed the old
deterministic `recommended_skills` class table).

CONTRACT
--------
* Input  : JSON on argv[1] or stdin:
    { "target": "https://app.example.com",
      "captured_responses_spill_id": "abc123",   # preferred (no re-probe)
      "sitemap_spill_id": "def456" }             # optional seed for probing
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
           No prose. On fatal error, a schema-valid artifact with
           meta.status == "error".
* Laws   : Offload Law (raw OSV payloads + oversized CVE lists -> spill_store),
           Artifact Contract (strict JSON), "load, don't re-probe" (if captured
           responses exist, they are used verbatim -- lightweight probing is a
           fallback only, and stays on the target host).
"""
from __future__ import annotations

import asyncio
import json
import math
import os
import re
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
    from spill_store import read_spill, should_offload, write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import read_spill, should_offload, write_spill  # type: ignore

OSV_URL = os.environ.get("OSV_URL", "https://api.osv.dev/v1/query")
OSV_TIMEOUT = float(os.environ.get("TF_OSV_TIMEOUT", "30"))
PROBE_TIMEOUT = float(os.environ.get("TF_PROBE_TIMEOUT", "20"))
PROBE_MAX = int(os.environ.get("TF_PROBE_MAX", "8"))
CVE_INLINE_CAP = int(os.environ.get("TF_CVE_INLINE_CAP", "15"))
_FP_PATH = os.environ.get(
    "TF_FINGERPRINTS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets", "fingerprints.json"))

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


# --- CVSS v3.1 base-score calculator (vector -> qualitative severity) ---------
def cvss3_base_score(vector: str) -> Optional[float]:
    try:
        parts = dict(kv.split(":") for kv in vector.split("/") if ":" in kv)
    except ValueError:
        return None
    AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(parts.get("AV"))
    AC = {"L": 0.77, "H": 0.44}.get(parts.get("AC"))
    UI = {"N": 0.85, "R": 0.62}.get(parts.get("UI"))
    scope_changed = parts.get("S") == "C"
    pr_map = {"N": 0.85, "L": 0.68 if scope_changed else 0.62,
              "H": 0.5 if scope_changed else 0.27}
    PR = pr_map.get(parts.get("PR"))
    cia = {"H": 0.56, "L": 0.22, "N": 0.0}
    C, I, A = cia.get(parts.get("C")), cia.get(parts.get("I")), cia.get(parts.get("A"))
    if None in (AV, AC, UI, PR, C, I, A):
        return None
    iss = 1 - (1 - C) * (1 - I) * (1 - A)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    expl = 8.22 * AV * AC * PR * UI
    raw = min((1.08 if scope_changed else 1.0) * (impact + expl), 10)
    return math.ceil(raw * 10) / 10.0


def score_to_severity(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "low"


def _normalize_db_severity(s: str) -> Optional[str]:
    s = (s or "").strip().lower()
    return {"critical": "critical", "high": "high", "moderate": "medium",
            "medium": "medium", "low": "low"}.get(s)


class TechFingerprinter:
    def __init__(self, target: str, captured_responses_spill_id: Optional[str] = None,
                 sitemap_spill_id: Optional[str] = None, config: Optional[dict] = None):
        self.target = (target or "").strip()
        self.target_host = _host_of(self.target)
        self.responses_id = captured_responses_spill_id
        self.sitemap_id = sitemap_spill_id
        self.config = config or {}
        self.errors: List[Dict[str, str]] = []
        try:
            with open(_FP_PATH, "r", encoding="utf-8") as fh:
                self.fp = json.load(fh)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "fingerprints", "error": str(exc)})
            self.fp = {}
        self.responses: List[dict] = []
        # component key -> detection record
        self._stack: Dict[str, dict] = {}
        self._waf = {"detected": False, "product": None, "evidence": ""}
        #: Edge and hosting providers found in front of the application. Reported
        #: separately from the stack because they describe who serves the response rather
        #: than what built it, and because an edge in the path changes how every later
        #: result must be read: a block may be the provider's, not the application's.
        self._edge: List[dict] = []
        self._raw_osv: Dict[str, Any] = {}
        self._probed = False

    # -- response loading ("load, don't re-probe") -----------------------------
    async def load_captured_responses(self) -> None:
        if self.responses_id:
            try:
                data = read_spill(self.responses_id)
                self.responses = self._normalize_responses(data)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "load_responses", "error": str(exc)})
        if self.responses:
            return
        # Fallback: lightweight probe (target root + a few sitemap URLs, on-host).
        await self._probe()

    @staticmethod
    def _normalize_responses(data: Any) -> List[dict]:
        rows = []
        if isinstance(data, dict) and "responses" in data:
            data = data["responses"]
        if isinstance(data, dict) and "log" in data:  # HAR shape
            entries = data.get("log", {}).get("entries", [])
            for e in entries:
                resp = e.get("response", {})
                rows.append({
                    "url": e.get("request", {}).get("url", ""),
                    "status": resp.get("status"),
                    "headers": {h.get("name", "").lower(): h.get("value", "")
                                for h in resp.get("headers", [])},
                    "body": (resp.get("content", {}) or {}).get("text", ""),
                })
            return rows
        if isinstance(data, list):
            for r in data:
                if not isinstance(r, dict):
                    continue
                rows.append({
                    "url": r.get("url", ""),
                    "status": r.get("status"),
                    "headers": {k.lower(): v for k, v in (r.get("headers") or {}).items()},
                    "body": r.get("body", "") or r.get("content", "") or "",
                })
        return rows

    async def _probe(self) -> None:
        if httpx is None:
            self.errors.append({"stage": "probe", "error": "httpx not installed"})
            return
        urls = [self.target]
        if self.sitemap_id:
            try:
                sm = read_spill(self.sitemap_id)
                for item in (sm if isinstance(sm, list) else []):
                    u = item.get("url") if isinstance(item, dict) else None
                    if u and _host_of(u) == self.target_host and u not in urls:
                        urls.append(u)
                    if len(urls) >= PROBE_MAX:
                        break
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "sitemap", "error": str(exc)})
        self._probed = True
        for u in urls[:PROBE_MAX]:
            if _host_of(u) != self.target_host:
                continue  # stay on target host for probing
            try:
                async with httpx.AsyncClient(timeout=PROBE_TIMEOUT, follow_redirects=True) as c:
                    r = await c.get(u, headers={"User-Agent": "tech-fingerprinting/1.0"})
                self.responses.append({
                    "url": u, "status": r.status_code,
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                    "body": r.text[:200000],
                })
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "probe", "error": f"{u}: {exc}"})

    # -- detectors -------------------------------------------------------------
    def _add(self, component: str, category: str, version: Optional[str],
             confidence: str, evidence: str, osv: Optional[str]) -> None:
        key = component.lower()
        rec = self._stack.get(key)
        if rec is None:
            self._stack[key] = {"component": component, "category": category,
                                "version": version, "confidence": confidence,
                                "evidence": evidence, "osv": osv, "known_cves": []}
            return
        if version and not rec["version"]:
            rec["version"] = version
        if _SEV_RANK.get(confidence, 0) and \
                {"high": 3, "medium": 2, "low": 1}[confidence] > {"high": 3, "medium": 2, "low": 1}[rec["confidence"]]:
            rec["confidence"] = confidence
        if osv and not rec.get("osv"):
            rec["osv"] = osv

    @staticmethod
    def _extract(regex: Optional[str], text: str) -> Optional[str]:
        if not regex:
            return None
        try:
            m = re.search(regex, text)
            if m and m.groups():
                return m.group(1)
        except re.error:
            return None
        return None

    def analyze_headers(self) -> None:
        for resp in self.responses:
            headers = resp.get("headers", {})
            for rule in self.fp.get("headers", []):
                val = headers.get(rule["header"], "")
                if val and re.search(rule["match"], val):
                    version = self._extract(rule.get("version"), val)
                    self._add(rule["component"], rule["category"], version,
                              "high", f"header {rule['header']}: {val[:80]}", rule.get("osv"))
            # cookies from Set-Cookie
            setck = headers.get("set-cookie", "")
            for rule in self.fp.get("cookies", []):
                if re.search(rf"\b{re.escape(rule['name'])}=", setck):
                    self._add(rule["component"], rule["category"], None, "high",
                              f"cookie {rule['name']}", rule.get("osv"))

    def analyze_html_signatures(self) -> None:
        for resp in self.responses:
            body = resp.get("body", "") or ""
            if not body:
                continue
            for rule in self.fp.get("html", []):
                try:
                    m = re.search(rule["pattern"], body)
                except re.error:
                    continue
                if not m:
                    continue
                version = self._extract(rule.get("version"), body)
                component = rule["component"]
                category = rule["category"]
                if component == "__META_GENERATOR__":
                    gen = m.group(1) if m.groups() else ""
                    component = gen.split(" ")[0] or "generator"
                    version = self._extract(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", gen)
                conf = "high" if version else "medium"
                self._add(component, category, version, conf,
                          f"html: {rule['pattern'][:40]}", rule.get("osv"))

    def detect_waf(self) -> None:
        for rule in self.fp.get("waf", []):
            for resp in self.responses:
                headers = resp.get("headers", {})
                body = resp.get("body", "") or ""
                setck = headers.get("set-cookie", "")
                # header signatures
                for hname, hpat in (rule.get("headers") or {}).items():
                    v = headers.get(hname, "")
                    if v and re.search(hpat, v):
                        self._flag_waf(rule["product"], f"header {hname}: {v[:60]}")
                        return
                # cookie signatures
                for ck in rule.get("cookies") or []:
                    if re.search(ck, setck):
                        self._flag_waf(rule["product"], f"cookie {ck}")
                        return
                # body signatures
                for bpat in rule.get("body") or []:
                    if re.search(bpat, body):
                        self._flag_waf(rule["product"], f"body match: {bpat[:40]}")
                        return

    def detect_edge(self) -> None:
        """Identify CDN and cloud providers in front of the application.

        Providers announce themselves in response headers — a request id, a cache status,
        a branded ``Server`` value — because their own tooling needs to. Matching is by
        vendor signature only; nothing is inferred from an address or a name, so a target
        served directly shows an empty list rather than a guess.

        Every matching provider is reported, not just the first. A site can sit behind a
        CDN that is itself in front of a cloud host, and collapsing that to one name loses
        the part an operator needs: which layer a given response actually came from.
        """
        for rule in self.fp.get("cdn", []):
            hit = None
            for resp in self.responses:
                headers = resp.get("headers", {})
                setck = headers.get("set-cookie", "")
                for hname, hpat in (rule.get("headers") or {}).items():
                    value = headers.get(hname, "")
                    if value and re.search(hpat, value):
                        hit = f"header {hname}: {value[:60]}"
                        break
                if hit is None:
                    for ck in rule.get("cookies") or []:
                        if setck and re.search(ck, setck):
                            hit = f"cookie {ck}"
                            break
                if hit:
                    break
            if hit:
                self._edge.append({
                    "product": rule["product"],
                    "kind": rule.get("kind", "cdn"),
                    "evidence": hit,
                })

    def _flag_waf(self, product: str, evidence: str) -> None:
        self._waf = {"detected": True, "product": product, "evidence": evidence}

    # -- CVE lookup (OSV.dev) --------------------------------------------------
    async def query_osv_cves(self) -> None:
        if httpx is None:
            self.errors.append({"stage": "osv", "error": "httpx not installed"})
            return
        eco_map = self.fp.get("osv_ecosystem", {})
        targets = [(k, rec) for k, rec in self._stack.items()
                   if rec.get("osv") and rec.get("version")]
        if not targets:
            return

        async def one(key: str, rec: dict):
            name = rec["osv"]
            eco = eco_map.get(name)
            if not eco:
                return
            body = {"package": {"name": name, "ecosystem": eco}, "version": rec["version"]}
            try:
                async with httpx.AsyncClient(timeout=OSV_TIMEOUT) as c:
                    r = await c.post(OSV_URL, json=body)
                if r.status_code != 200:
                    self.errors.append({"stage": "osv", "error": f"{name}: HTTP {r.status_code}"})
                    return
                data = r.json()
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "osv", "error": f"{name}: {exc}"})
                return
            self._raw_osv[f"{name}@{rec['version']}"] = data
            rec["known_cves"] = self._parse_osv(data)

        await asyncio.gather(*(one(k, r) for k, r in targets))

    @staticmethod
    def _parse_osv(data: dict) -> List[dict]:
        out = []
        for vuln in (data.get("vulns") or []):
            # prefer a CVE alias as the id
            vid = vuln.get("id", "")
            for alias in vuln.get("aliases", []) or []:
                if alias.startswith("CVE-"):
                    vid = alias
                    break
            # severity: CVSS vector -> score -> qualitative, else DB severity
            severity = None
            for sev in vuln.get("severity", []) or []:
                if str(sev.get("type", "")).startswith("CVSS"):
                    severity = score_to_severity(cvss3_base_score(sev.get("score", "")))
                    if severity:
                        break
            if not severity:
                dbs = (vuln.get("database_specific") or {}).get("severity", "")
                severity = _normalize_db_severity(dbs) or "medium"
            summary = vuln.get("summary") or (vuln.get("details", "")[:200])
            out.append({"id": vid, "severity": severity, "summary": summary})
        out.sort(key=lambda c: _SEV_RANK.get(c["severity"], 0), reverse=True)
        return out

    # -- skill recommendation (drives Phase 5) ---------------------------------
    def _signals(self) -> List[str]:
        sig = set()
        for rec in self._stack.values():
            name = rec["component"].lower()
            cat = rec["category"]
            if "java" in name or "servlet" in name or "spring" in name:
                sig.add("lang:java")
            if "spring" in name:
                sig.add("framework:spring")
            if ".net" in name or "asp.net" in name or "iis" in name:
                sig.add("lang:dotnet")
            if name == "php" or "php" in name:
                sig.add("lang:php")
            if "express" in name or "node" in name or name == "next.js" or name == "nuxt.js":
                sig.add("lang:node")
            if "django" in name or "werkzeug" in name or "gunicorn" in name or "flask" in name:
                sig.add("lang:python")
            if "rails" in name or "ruby" in name:
                sig.add("lang:ruby")
            if "wordpress" in name:
                sig.add("framework:wordpress")
            if name in ("react", "vue.js", "angular", "next.js", "nuxt.js", "svelte") or cat == "library":
                sig.add("spa")
        # graphql from sitemap/probed urls
        if any("/graphql" in (r.get("url", "") or "") for r in self.responses):
            sig.add("graphql")
        if self._waf["detected"]:
            sig.add("waf")
        return sorted(sig)

    # -- assembly --------------------------------------------------------------
    def build_stack_profile(self) -> List[dict]:
        stack = []
        for rec in self._stack.values():
            cves = rec.get("known_cves", [])
            item = {"component": rec["component"], "version": rec.get("version"),
                    "category": rec["category"], "confidence": rec["confidence"],
                    "evidence": rec["evidence"]}
            # Offload Law: cap large CVE lists inline, spill the full set.
            if len(cves) > CVE_INLINE_CAP or should_offload(cves):
                item["cves_overflow_spill_id"] = write_spill(cves)
                item["known_cves"] = cves[:CVE_INLINE_CAP]
                item["known_cves_total"] = len(cves)
            else:
                item["known_cves"] = cves
            stack.append(item)
        stack.sort(key=lambda s: (s["category"], s["component"]))
        return stack

    def return_artifact(self, started: float) -> dict:
        stack = self.build_stack_profile()
        raw_osv_spill_id = write_spill(self._raw_osv) if self._raw_osv else None
        total_cves = sum(len(r.get("known_cves", [])) for r in self._stack.values())
        status = "ok"
        if not self.responses:
            status = "error"
        return {
            "stack": stack,
            # "WAF or no WAF" is a finding either way, so the absence is stated rather than
            # left as a missing key. An operator reading "no WAF detected" against a set of
            # responses knows something; an empty field only says nobody looked.
            "waf": {
                **self._waf,
                "checked": True,
                "responses_examined": len(self.responses),
            },
            "edge": self._edge,
            # ---- additive fields ----
            "meta": {
                "skill": "tech-fingerprinting", "version": "1.0", "phase": "2",
                "target": self.target, "status": status,
                "generated_at": _now_iso(),
                "duration_seconds": round(time.time() - started, 2),
                "responses_analyzed": len(self.responses),
                "data_source": "spill" if (self.responses_id and not self._probed) else "probe",
                "components_detected": len(stack),
                "edge_providers": [e["product"] for e in self._edge],
                "waf_detected": bool(self._waf.get("detected")),
                "cve_total": total_cves,
                "signals": self._signals(),
                "raw_osv_spill_id": raw_osv_spill_id,
            },
            "errors": self.errors,
        }

    async def run(self) -> dict:
        started = time.time()
        await self.load_captured_responses()
        self.analyze_headers()
        self.analyze_html_signatures()
        self.detect_waf()
        self.detect_edge()
        await self.query_osv_cves()
        return self.return_artifact(started)


# --- input handling & entry point --------------------------------------------
def _load_input(argv: List[str]) -> dict:
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError("no input: expected JSON {\"target\":\"https://...\"}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str, target: str = "") -> dict:
    return {
        "stack": [],
        "waf": {"detected": False, "product": None, "evidence": ""},
        "meta": {"skill": "tech-fingerprinting", "version": "1.0", "phase": "2",
                 "target": target, "status": "error", "generated_at": _now_iso()},
        "errors": [{"stage": "init", "error": message}],
    }


async def _amain(argv: List[str]) -> int:
    try:
        payload = _load_input(argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    target = str(payload.get("target", "")).strip()
    if not target and not payload.get("captured_responses_spill_id"):
        print(json.dumps(_error_artifact("need 'target' or 'captured_responses_spill_id'")))
        return 2
    fp = TechFingerprinter(
        target=target,
        captured_responses_spill_id=payload.get("captured_responses_spill_id"),
        sitemap_spill_id=payload.get("sitemap_spill_id"),
        config=payload.get("config"),
    )
    artifact = await fp.run()
    print(json.dumps(artifact, ensure_ascii=False))
    return 0


def main() -> int:
    return asyncio.run(_amain(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())
