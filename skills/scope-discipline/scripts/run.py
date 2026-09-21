#!/usr/bin/env python3
"""
run.py -- scope-discipline entry point.

The Proposer's self-audit. BEFORE a proposed action reaches the deterministic
Safety Gate, this skill parses the action's URL, evaluates it against the Phase 0
Scope Policy (exact domains, subdomain wildcards, explicit deny-lists) and the
Phase 2 redirect map, and returns an ADVISORY verdict: proceed / modify / abort.
Its purpose is to save tokens and avoid deterministic gate denials by catching
out-of-scope actions early. It is advisory only -- the Gate still decides.

DESIGN PRINCIPLES
-----------------
* Default deny. A host that matches no in-scope rule is `abort`, never a guess.
* Deny wins. An explicit deny / out-of-scope match beats any allow, including a
  wildcard.
* Boundary-safe matching. Suffix checks are label-anchored so
  `example.com.evil.com`, `notexample.com`, and `example.com@evil.com` never pass
  as `example.com`.
* Internal/metadata guard. Loopback, RFC1918, and link-local (incl.
  169.254.169.254) IP targets are `abort` unless the policy explicitly allows the
  address -- scope discipline will not let an SSRF pivot slip through as "in
  scope by default".
* No traffic. This skill parses and reasons; it never sends a request.

CONTRACT
--------
* Input  : {"proposed_action": {"url","method","payload"},
            "scope_policy_spill_id": "...", "scope_policy": {...(inline)},
            "config": {"allowed_schemes": ["https"]}}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from spill_store import read_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import read_spill  # type: ignore

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm_host(host: str) -> str:
    """Lowercase, strip trailing dot, IDNA-normalize to punycode ascii."""
    if not host:
        return ""
    h = host.strip().rstrip(".").lower()
    if not h:
        return ""
    try:
        # Convert any unicode/IDN to ascii punycode for stable comparison.
        h = h.encode("idna").decode("ascii")
    except Exception:  # noqa: BLE001
        # non-encodable => leave as-is; matching will simply fail -> default deny
        try:
            h = h.encode("ascii", "ignore").decode("ascii")
        except Exception:  # noqa: BLE001
            return h
    return h


def _rule_host(rule: str) -> str:
    r = (rule or "").strip().lower().rstrip(".")
    if r.startswith("*."):
        return "*." + _norm_host(r[2:])
    return _norm_host(r)


def _host_matches(host: str, rule: str) -> Optional[str]:
    """Return the match kind ('exact'|'wildcard') if host matches rule, else None."""
    if not host or not rule:
        return None
    rule = _rule_host(rule)
    if rule.startswith("*."):
        suffix = rule[1:]  # ".example.com"
        base = rule[2:]    # "example.com"
        if host == base:
            return None            # wildcard does not cover the apex
        if host.endswith(suffix):  # label-anchored proper subdomain
            return "wildcard"
        return None
    return "exact" if host == rule else None


class ScopeAuditor:
    def __init__(self, action: dict, policy: Optional[dict], config: Optional[dict] = None):
        self.action = action or {}
        self.policy = policy or {}
        self.config = config or {}
        self.url = str(self.action.get("url", "") or "")
        self.method = str(self.action.get("method", "GET") or "GET").upper()
        self.in_scope = [_rule_host(r) for r in self.policy.get("in_scope", [])]
        deny = list(self.policy.get("out_of_scope", [])) + list(self.policy.get("deny", []))
        self.deny = [_rule_host(r) for r in deny]
        self.allow_ips = set(str(x).strip() for x in self.policy.get("allow_ips", []))
        self.allowed_schemes = [s.lower() for s in
                                (self.policy.get("allowed_schemes")
                                 or self.config.get("allowed_schemes")
                                 or ["http", "https"])]
        self.redirect_map = self.policy.get("redirect_map", {}) or {}
        self.notes: List[str] = []

    # -- parsing ------------------------------------------------------------
    def parse_url(self) -> Dict[str, Any]:
        try:
            parts = urllib.parse.urlsplit(self.url)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"unparseable: {exc}"}
        scheme = (parts.scheme or "").lower()
        # urlsplit correctly puts the userinfo before '@' and host after it,
        # so example.com@evil.com -> hostname 'evil.com' (the real destination).
        userinfo = None
        if parts.netloc and "@" in parts.netloc:
            userinfo = parts.netloc.rsplit("@", 1)[0]
        try:
            raw_host = parts.hostname or ""
        except Exception:  # noqa: BLE001
            raw_host = ""
        host = _norm_host(raw_host)
        port = None
        try:
            port = parts.port
        except Exception:  # noqa: BLE001
            self.notes.append("invalid_port")
        return {"ok": bool(host), "scheme": scheme, "host": host, "port": port,
                "userinfo": userinfo, "path": parts.path, "raw_host": raw_host,
                "error": "" if host else "no_host"}

    # -- ip guard -----------------------------------------------------------
    def _ip_guard(self, host: str) -> Optional[Tuple[str, str]]:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return None  # not an IP literal
        if host in self.allow_ips or any(_host_matches(host, r) for r in self.in_scope):
            return None  # explicitly allowed
        if ip.is_loopback:
            return ("internal_loopback", f"loopback IP {host} not in explicit scope")
        if ip.is_link_local:
            return ("internal_link_local", f"link-local/metadata IP {host} not in explicit scope")
        if ip.is_private:
            return ("internal_private", f"RFC1918 IP {host} not in explicit scope")
        if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return ("internal_reserved", f"reserved IP {host} not in explicit scope")
        return None  # public IP -> fall through to normal scope rules

    # -- deny / allow -------------------------------------------------------
    def check_denylist(self, host: str) -> Optional[str]:
        for r in self.deny:
            if _host_matches(host, r):
                return r
        return None

    def _in_scope_rule(self, host: str) -> Optional[str]:
        # prefer the most specific (longest) matching rule
        best = None
        for r in self.in_scope:
            if _host_matches(host, r):
                cand = r[2:] if r.startswith("*.") else r
                if best is None or len(cand) > len(best[1]):
                    best = (r, cand)
        return best[0] if best else None

    # -- redirects ----------------------------------------------------------
    def check_redirects(self, host: str) -> Optional[Tuple[str, str]]:
        """If this URL historically redirects out of scope, return (dest, dest_host)."""
        dest = self.redirect_map.get(self.url)
        if not dest:
            # try path-normalized key (drop query/fragment)
            p = urllib.parse.urlsplit(self.url)
            base = urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, "", ""))
            dest = self.redirect_map.get(base)
        if not dest:
            return None
        dh = _norm_host(urllib.parse.urlsplit(dest).hostname or "")
        if not dh:
            return None
        if self.check_denylist(dh) or not self._in_scope_rule(dh):
            return (dest, dh)
        return None

    # -- orchestration ------------------------------------------------------
    def return_verdict(self) -> dict:
        if not self.url:
            return self._art("abort", "no url in proposed_action", None, "none")
        if not self.in_scope and not self.deny:
            return self._art("abort", "no scope policy loaded; refusing under default-deny",
                             None, "none")

        p = self.parse_url()
        if not p["ok"]:
            return self._art("abort", f"URL rejected: {p.get('error')}", None, "unparseable")
        host, scheme = p["host"], p["scheme"]

        if p.get("userinfo"):
            return self._art("abort",
                             f"userinfo present in URL ('{p['userinfo']}@'); real host is "
                             f"'{host}' -- classic scope-spoof, refusing", None, "userinfo_spoof")

        ipg = self._ip_guard(host)
        if ipg:
            return self._art("abort", ipg[1], None, ipg[0])

        denied = self.check_denylist(host)
        if denied:
            return self._art("abort", f"host '{host}' matches deny rule '{denied}'",
                             None, f"deny:{denied}")

        scope_rule = self._in_scope_rule(host)
        if not scope_rule:
            return self._art("abort",
                             f"host '{host}' matches no in-scope rule (default-deny)",
                             None, "default_deny")

        # in scope so far -- scheme check
        if scheme and scheme not in self.allowed_schemes:
            if scheme in ("http", "https") and ("http" in self.allowed_schemes or
                                                 "https" in self.allowed_schemes):
                target = "https" if "https" in self.allowed_schemes else "http"
                newurl = urllib.parse.urlunsplit(
                    (target,) + urllib.parse.urlsplit(self.url)[1:])
                return self._art("modify",
                                 f"scheme '{scheme}' not allowed; use '{target}'",
                                 {"url": newurl, "method": self.method}, f"scheme:{scheme}")
            return self._art("abort", f"scheme '{scheme}' not permitted by policy",
                             None, f"scheme:{scheme}")

        # in scope -- redirect check
        redir = self.check_redirects(host)
        if redir:
            return self._art("modify",
                             f"URL is in scope but historically 3xx-redirects to out-of-scope "
                             f"'{redir[1]}'; proceed only with redirect-following disabled",
                             {"url": self.url, "method": self.method, "follow_redirects": False},
                             f"redirect_out_of_scope:{redir[1]}")

        return self._art("proceed", f"host '{host}' is in scope via rule '{scope_rule}'",
                         None, scope_rule)

    def _art(self, verdict: str, reason: str, modified: Optional[dict], rule: str) -> dict:
        return {
            "verdict": verdict,
            "reason": reason,
            "modified_action": modified,
            "scope_rule_matched": rule,
            "meta": {
                "skill": "scope-discipline", "version": "1.0", "phase": "5",
                "loop_component": "2-proposer", "advisory_only": True,
                "status": "ok", "generated_at": _now_iso(),
                "audited_url": self.url, "method": self.method,
                "in_scope_rules": self.in_scope, "deny_rules": self.deny,
                "sends_traffic": False, "notes": self.notes,
                "final_authority": "deterministic-safety-gate",
            },
            "errors": [],
        }


# --- policy loading ----------------------------------------------------------
def load_policy(payload: dict) -> Tuple[Optional[dict], Optional[str]]:
    if isinstance(payload.get("scope_policy"), dict):
        return payload["scope_policy"], None
    sid = payload.get("scope_policy_spill_id")
    if sid:
        try:
            data = read_spill(sid)
        except Exception as exc:  # noqa: BLE001
            return None, f"could not load scope policy spill '{sid}': {exc}"
        if isinstance(data, dict):
            return data.get("scope_policy", data), None
        return None, "scope policy spill is not an object"
    return None, "no scope_policy or scope_policy_spill_id provided"


def _error_artifact(msg: str) -> dict:
    return {"verdict": "abort", "reason": msg, "modified_action": None,
            "scope_rule_matched": "error",
            "meta": {"skill": "scope-discipline", "version": "1.0", "phase": "5",
                     "loop_component": "2-proposer", "advisory_only": True,
                     "status": "error", "generated_at": _now_iso(), "sends_traffic": False,
                     "final_authority": "deterministic-safety-gate"},
            "errors": [{"stage": "init", "error": msg}]}


def _load_input(argv: List[str]) -> dict:
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError('no input: expected JSON {"proposed_action": {...}}')
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def main() -> int:
    try:
        payload = _load_input(sys.argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    action = payload.get("proposed_action")
    if not isinstance(action, dict) or not action.get("url"):
        print(json.dumps(_error_artifact("need proposed_action.url")))
        return 2
    policy, perr = load_policy(payload)
    if perr and policy is None:
        # still emit an advisory abort (default-deny) rather than crashing
        art = _error_artifact(f"scope policy unavailable: {perr}")
        print(json.dumps(art))
        return 0
    auditor = ScopeAuditor(action, policy, config=payload.get("config"))
    print(json.dumps(auditor.return_verdict(), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
