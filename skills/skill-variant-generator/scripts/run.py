#!/usr/bin/env python3
"""
run.py -- skill-variant-generator entry point.

Takes an existing SKILL.md and generates a VARIANT adapted for a new context the
base skill does not cover (SQLi via WebSocket, XSS via GraphQL, SSRF via file
upload, ...). It rewrites the delivery / detection / evidence / tools guidance for
the new transport, PRESERVES the base skill's artifact contract byte-for-byte (so
the Oracle verifies the variant with the identical schema), writes the variant
folder, and registers it in the Dynamic Skill Registry.

WHAT IT PRESERVES (non-negotiable)
----------------------------------
The variant's `references/ARTIFACT_SCHEMA.md` and `references/artifact.schema.json`
are copied UNCHANGED from the base and hash-verified equal. `preserve_contract`
sets `artifact_contract_preserved` only when that equality holds. Same input/output
contract in, same contract out — only the transport changes.

This is a code-GENERATOR. It reads/writes skill files and sends no target traffic.

CONTRACT
--------
* Input  : {"base_skill":"sqli-database-injection", "new_context":"websocket",
            "observed_behavior":"...", "constraints":["..."],
            "config":{"skills_dir":"skills"}}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# per-context adaptation: delivery/detection/evidence/tools + body substitutions
CONTEXTS: Dict[str, Dict[str, Any]] = {
    "websocket": {
        "delivery": "HTTP query/body params → WebSocket JSON frames",
        "detection": "HTTP status codes → inbound-frame diffing / close codes",
        "evidence": "HTTP response body → inbound WS frame log",
        "client_lib": "websockets",
        "subs": [("HTTP requests", "WebSocket frames"), ("HTTP request", "WebSocket frame"),
                 ("query parameter", "WS message field"), ("query string", "WS JSON payload"),
                 ("status code", "WS message-diff / close-code"), ("response body", "inbound WS frame"),
                 ("httpx", "websockets"), ("requests library", "websockets library")],
    },
    "graphql": {
        "delivery": "HTTP query/body params → GraphQL query variables",
        "detection": "HTTP status codes → presence of GraphQL errors[]",
        "evidence": "HTTP response body → GraphQL data/errors JSON",
        "client_lib": "gql",
        "subs": [("query parameter", "GraphQL variable"), ("HTTP request", "GraphQL operation"),
                 ("status code", "GraphQL errors[] presence"), ("response body", "GraphQL data/errors JSON"),
                 ("httpx", "gql (over httpx)")],
    },
    "file_upload": {
        "delivery": "HTTP query/body params → multipart form fields / filename",
        "detection": "HTTP status codes → upload/parse error message",
        "evidence": "HTTP response body → stored file content / processing log",
        "client_lib": "httpx (multipart)",
        "subs": [("query parameter", "multipart form field / filename"),
                 ("status code", "upload/parse error message"),
                 ("response body", "stored file content / processing log"),
                 ("httpx", "httpx multipart")],
    },
    "grpc": {
        "delivery": "HTTP query/body params → gRPC protobuf message fields",
        "detection": "HTTP status codes → gRPC status codes",
        "evidence": "HTTP response body → protobuf response message",
        "client_lib": "grpc",
        "subs": [("HTTP request", "gRPC call"), ("query parameter", "protobuf field"),
                 ("status code", "gRPC status code"), ("response body", "protobuf message"),
                 ("httpx", "grpcio")],
    },
    "xml_soap": {
        "delivery": "HTTP query/body params → SOAP body elements",
        "detection": "HTTP status codes → SOAP Fault presence",
        "evidence": "HTTP response body → SOAP envelope",
        "client_lib": "zeep",
        "subs": [("query parameter", "SOAP body element"), ("status code", "SOAP Fault presence"),
                 ("response body", "SOAP envelope"), ("httpx", "zeep (over httpx)")],
    },
    "http_header": {
        "delivery": "HTTP query/body params → request headers",
        "detection": "HTTP status codes → header-reflected / behavioral diff",
        "evidence": "HTTP response body → response headers + body",
        "client_lib": "httpx",
        "subs": [("query parameter", "request header"), ("query string", "header value")],
    },
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "").strip().lower()).strip("-")


def _sha(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except Exception:  # noqa: BLE001
        return ""


class SkillSpec:
    def __init__(self, name: str, frontmatter: str, body: str, base_dir: str):
        self.name = name
        self.frontmatter = frontmatter  # raw text between the --- fences
        self.body = body
        self.base_dir = base_dir


class SkillVariantGenerator:
    def __init__(self, payload: dict):
        self.payload = payload or {}
        self.config = self.payload.get("config", {}) or {}
        self.base_skill = str(self.payload.get("base_skill", "") or "")
        self.context = str(self.payload.get("new_context", "") or "")
        self.observed = str(self.payload.get("observed_behavior", "") or "")
        self.constraints = list(self.payload.get("constraints", []) or [])
        self.skills_dir = str(self.config.get("skills_dir")
                              or os.environ.get("SKILLS_DIR") or "skills")
        self.changes: List[str] = []
        self.errors: List[Dict[str, str]] = []

    # -- load ---------------------------------------------------------------
    def load_base_skill(self) -> Optional[SkillSpec]:
        base_dir = os.path.join(self.skills_dir, self.base_skill)
        md = os.path.join(base_dir, "SKILL.md")
        if not os.path.isfile(md):
            self.errors.append({"stage": "load", "error": f"base SKILL.md not found at {md}"})
            return None
        with open(md, "r", encoding="utf-8") as fh:
            text = fh.read()
        m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", text, re.S)
        if not m:
            self.errors.append({"stage": "load", "error": "base SKILL.md has no YAML frontmatter"})
            return None
        return SkillSpec(self.base_skill, m.group(1), m.group(2), base_dir)

    # -- adapt --------------------------------------------------------------
    def _ctx(self) -> Dict[str, Any]:
        return CONTEXTS.get(_slug(self.context).replace("-", "_"),
                            {"delivery": f"HTTP → {self.context}", "detection": f"→ {self.context} signal",
                             "evidence": f"→ {self.context} evidence", "client_lib": "context-specific",
                             "subs": []})

    def adapt_delivery(self, body: str) -> str:
        for a, b in self._ctx()["subs"]:
            if a in body:
                body = body.replace(a, b)
                self.changes.append(f"delivery/tooling: '{a}' → '{b}'")
        return body

    def adapt_detection(self, body: str) -> str:
        # detection/evidence substitutions already included in the context sub list;
        # this records the conceptual mapping in changes for auditability.
        ctx = self._ctx()
        self.changes.append(f"detection: {ctx['detection']}")
        self.changes.append(f"evidence: {ctx['evidence']}")
        return body

    def _adaptation_section(self) -> str:
        ctx = self._ctx()
        cons = "\n".join(f"- {c}" for c in self.constraints) or "- (none supplied)"
        return (
            f"\n\n## Context adaptation — {self.context}\n\n"
            f"This is a variant of **{self.base_skill}** adapted for the `{self.context}` "
            f"context. The artifact contract is unchanged — the Oracle verifies this variant "
            f"with the base skill's schema.\n\n"
            f"- **Delivery:** {ctx['delivery']}\n"
            f"- **Detection:** {ctx['detection']}\n"
            f"- **Evidence:** {ctx['evidence']}\n"
            f"- **Client library:** `{ctx['client_lib']}` (see `scripts/delivery_adapter.py`)\n\n"
            f"**Observed behavior:** {self.observed or '(not supplied)'}\n\n"
            f"**Constraints:**\n{cons}\n\n"
            f"`scripts/delivery_adapter.py` provides `wrap_payload()` / `detect()` for this "
            f"transport; the base engine's detection/evidence logic and artifact schema are "
            f"reused unchanged.\n"
        )

    def _rewrite_frontmatter(self, fm: str, variant_name: str) -> str:
        # rename; keep everything else. Add variant metadata markers.
        fm = re.sub(r"(?m)^name:\s*.*$", f"name: {variant_name}", fm, count=1)
        markers = (f"  base-skill: \"{self.base_skill}\"\n"
                   f"  adapted-context: \"{self.context}\"\n"
                   f"  artifact-contract: \"preserved\"\n")
        if re.search(r"(?m)^metadata:\s*$", fm):
            fm = re.sub(r"(?m)^(metadata:\s*\n)", r"\1" + markers, fm, count=1)
        else:
            fm = fm.rstrip() + "\nmetadata:\n" + markers
        return fm

    # -- contract preservation ---------------------------------------------
    def preserve_contract(self, base_dir: str, variant_dir: str) -> bool:
        ok = True
        found_any = False
        os.makedirs(os.path.join(variant_dir, "references"), exist_ok=True)
        for fname in ("ARTIFACT_SCHEMA.md", "artifact.schema.json"):
            src = os.path.join(base_dir, "references", fname)
            if not os.path.isfile(src):
                continue
            found_any = True
            dst = os.path.join(variant_dir, "references", fname)
            shutil.copyfile(src, dst)
            if _sha(src) != _sha(dst) or not _sha(src):
                ok = False
            else:
                self.changes.append(f"preserved contract file references/{fname} (sha256 verified equal)")
        if not found_any:
            self.errors.append({"stage": "contract", "error": "base skill has no references/ contract files"})
            return False
        return ok

    # -- delivery adapter (generated, complete) -----------------------------
    def _delivery_adapter_src(self) -> str:
        ctx = self._ctx()
        c = _slug(self.context).replace("-", "_")
        return f'''#!/usr/bin/env python3
"""Delivery adapter for the '{self.context}' variant of {self.base_skill}.

Wraps a probe payload into the {self.context} transport envelope and provides a
context-appropriate detection helper. The base engine's artifact schema is reused
unchanged; only delivery/detection differ. Pure transformation — no traffic sent
here unless the caller supplies a client.
"""
from __future__ import annotations
import json

CONTEXT = "{self.context}"
CLIENT_LIB = "{ctx['client_lib']}"


def wrap_payload(payload: str, endpoint: str = "") -> dict:
    """Return a {self.context}-shaped request envelope carrying `payload`."""
    ctx = CONTEXT
    if ctx == "websocket":
        return {{"transport": "websocket", "url": endpoint,
                "frame": json.dumps({{"type": "message", "data": payload}})}}
    if ctx == "graphql":
        return {{"transport": "graphql", "url": endpoint,
                "body": {{"query": "query($q:String!){{ search(q:$q){{ id }} }}",
                         "variables": {{"q": payload}}}}}}
    if ctx == "file_upload":
        return {{"transport": "multipart", "url": endpoint,
                "files": {{"file": ("probe.txt", payload, "text/plain")}}}}
    if ctx == "grpc":
        return {{"transport": "grpc", "target": endpoint, "message": {{"field": payload}}}}
    if ctx == "xml_soap":
        env = ("<soap:Envelope xmlns:soap=\\"http://schemas.xmlsoap.org/soap/envelope/\\">"
               "<soap:Body><q>%s</q></soap:Body></soap:Envelope>" % payload)
        return {{"transport": "soap", "url": endpoint, "body": env}}
    if ctx == "http_header":
        return {{"transport": "http", "url": endpoint, "headers": {{"X-Probe": payload}}}}
    return {{"transport": ctx, "url": endpoint, "payload": payload}}


def detect(before: str, after: str) -> bool:
    """Context detection: a meaningful difference between baseline and probe response."""
    ctx = CONTEXT
    if ctx == "graphql":
        return ('"errors"' in (after or "")) != ('"errors"' in (before or ""))
    return (before or "").strip() != (after or "").strip()


if __name__ == "__main__":
    import sys
    payload = sys.argv[1] if len(sys.argv) > 1 else "PROBE"
    endpoint = sys.argv[2] if len(sys.argv) > 2 else ""
    print(json.dumps(wrap_payload(payload, endpoint)))
'''

    # -- save ---------------------------------------------------------------
    def save_variant(self, spec: SkillSpec, variant_name: str) -> str:
        variant_dir = os.path.join(self.skills_dir, variant_name)
        os.makedirs(os.path.join(variant_dir, "scripts"), exist_ok=True)

        body = self.adapt_delivery(spec.body)
        body = self.adapt_detection(body)
        body = body.rstrip() + self._adaptation_section()
        fm = self._rewrite_frontmatter(spec.frontmatter, variant_name)
        with open(os.path.join(variant_dir, "SKILL.md"), "w", encoding="utf-8") as fh:
            fh.write("---\n" + fm.rstrip() + "\n---\n\n" + body.lstrip())
        self.changes.append("wrote SKILL.md (adapted delivery/detection/evidence + adaptation section)")

        # copy base engine + spill store unchanged (contract-identical behavior)
        for rel in ("scripts/run.py", "scripts/spill_store.py"):
            src = os.path.join(spec.base_dir, rel)
            if os.path.isfile(src):
                shutil.copyfile(src, os.path.join(variant_dir, rel))
                self.changes.append(f"copied {rel} from base (engine + schema unchanged)")
        # write the generated delivery adapter
        with open(os.path.join(variant_dir, "scripts", "delivery_adapter.py"), "w", encoding="utf-8") as fh:
            fh.write(self._delivery_adapter_src())
        self.changes.append("wrote scripts/delivery_adapter.py (wrap_payload/detect for the context)")

        contract_ok = self.preserve_contract(spec.base_dir, variant_dir)
        self._contract_ok = contract_ok
        return variant_dir

    # -- register -----------------------------------------------------------
    def register_variant(self, variant_name: str, variant_dir: str) -> bool:
        reg_path = os.path.join(self.skills_dir, ".variant_registry.json")
        try:
            reg = []
            if os.path.isfile(reg_path):
                with open(reg_path, "r", encoding="utf-8") as fh:
                    reg = json.load(fh)
                if not isinstance(reg, list):
                    reg = []
            reg = [r for r in reg if r.get("variant_name") != variant_name]
            reg.append({"variant_name": variant_name, "base_skill": self.base_skill,
                        "context": self.context, "path": variant_dir, "registered_at": _now_iso()})
            with open(reg_path, "w", encoding="utf-8") as fh:
                json.dump(reg, fh, indent=2, sort_keys=True)
            self.changes.append("registered in Dynamic Skill Registry (.variant_registry.json)")
            return True
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "register", "error": str(exc)})
            return False

    # -- orchestration ------------------------------------------------------
    def return_artifact(self) -> dict:
        if not self.base_skill or not self.context:
            return self._err("need base_skill and new_context")
        spec = self.load_base_skill()
        if spec is None:
            return self._err("could not load base skill")
        variant_name = f"{self.base_skill}-via-{_slug(self.context)}"
        variant_dir = self.save_variant(spec, variant_name)
        registered = self.register_variant(variant_name, variant_dir)
        return {
            "variant_name": variant_name,
            "variant_path": os.path.join(variant_dir, "SKILL.md"),
            "base_skill": self.base_skill,
            "context": self.context,
            "artifact_contract_preserved": bool(getattr(self, "_contract_ok", False)),
            "registered": registered,
            "changes_made": self.changes,
            "meta": {
                "skill": "skill-variant-generator", "version": "1.0", "phase": "5-6",
                "loop_component": "34-skill-variant-generator", "status": "ok",
                "generated_at": _now_iso(), "skills_dir": self.skills_dir,
                "client_lib": self._ctx()["client_lib"], "sends_traffic": False,
            },
            "errors": self.errors,
        }

    def _err(self, msg: str) -> dict:
        return {"variant_name": "", "variant_path": "", "base_skill": self.base_skill,
                "context": self.context, "artifact_contract_preserved": False,
                "registered": False, "changes_made": self.changes,
                "meta": {"skill": "skill-variant-generator", "version": "1.0", "phase": "5-6",
                         "loop_component": "34-skill-variant-generator", "status": "error",
                         "generated_at": _now_iso(), "sends_traffic": False},
                "errors": self.errors + [{"stage": "run", "error": msg}]}


# --- entry point -------------------------------------------------------------
def _load_input(argv: List[str]) -> dict:
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError('no input: expected JSON {"base_skill": "...", "new_context": "..."}')
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(msg: str) -> dict:
    return {"variant_name": "", "variant_path": "", "base_skill": "", "context": "",
            "artifact_contract_preserved": False, "registered": False, "changes_made": [],
            "meta": {"skill": "skill-variant-generator", "version": "1.0", "phase": "5-6",
                     "status": "error", "generated_at": _now_iso(), "sends_traffic": False},
            "errors": [{"stage": "init", "error": msg}]}


def main() -> int:
    try:
        payload = _load_input(sys.argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    art = SkillVariantGenerator(payload).return_artifact()
    print(json.dumps(art, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
