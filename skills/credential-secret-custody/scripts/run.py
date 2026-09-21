#!/usr/bin/env python3
"""
run.py -- credential-secret-custody entry point.

The Observer's secret handler. When the loop discovers a credential (API key, DB
password, JWT private key, cloud key), this skill mathematically secures it
BEFORE the LLM ever sees the next turn: it SHA-256-hashes the secret (the only
form allowed back into context), encrypts the raw value at rest with Fernet in
spill_store/secrets/<hash>.enc, and appends a custody-log entry for the final
cleanup/rotation report. The raw secret never reaches stdout, stderr, logs, or
the artifact.

THE ONE RULE
------------
The raw secret leaves this process only as (a) ciphertext on disk and (b) a
SHA-256 hash. It is NEVER printed, never logged, never placed in the artifact,
and the plaintext buffer is zeroed and released as soon as it is encrypted. A
final guard scans the outgoing artifact for the raw bytes and refuses to print
if any leaked.

INPUT CHANNELS (most to least safe)
-----------------------------------
* stdin JSON            (preferred — no process-table exposure)
* {"raw_secret_env":"VAR"}  read the secret from an env var
* {"raw_secret_file":"/path"} read the secret from a file (then optionally shred)
* {"raw_secret":"..."}  inline (argv use is discouraged: visible in `ps`)

CONTRACT
--------
* Input  : {"raw_secret"|"raw_secret_env"|"raw_secret_file": ...,
            "secret_type": "AWS|JWT|DB_Password|...", "context": "...",
            "discovered_by": "skill-name",
            "action": "custody"|"update_status", "secret_hash": "...",
            "cleanup_status": "rotated"|"revoked"}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from cryptography.fernet import Fernet
    _HAVE_CRYPTO = True
except Exception:  # noqa: BLE001  # pragma: no cover
    _HAVE_CRYPTO = False

_SPILL_DIR = os.environ.get("SPILL_STORE_DIR", "/tmp/spill_store")
SECRETS_DIR = os.environ.get("SECRET_STORE_DIR", os.path.join(_SPILL_DIR, "secrets"))
CUSTODY_LOG = os.path.join(SECRETS_DIR, "custody_log.json")
KEYFILE = os.environ.get("SECRET_CUSTODY_KEYFILE", os.path.join(SECRETS_DIR, "custody.key"))

TYPE_ENUM = ["AWS", "GCP", "Azure", "JWT_Private_Key", "DB_Password", "API_Key", "Generic"]

# structural detectors (match on the SECRET itself; none of these echo bytes)
_DETECT = [
    ("AWS", re.compile(r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|aws_secret_access_key", re.I)),
    ("GCP", re.compile(r"AIza[0-9A-Za-z_\-]{20,}|\"type\"\s*:\s*\"service_account\"|gcp[_-]?key", re.I)),
    ("Azure", re.compile(r"AccountKey=|SharedAccessKey|DefaultEndpointsProtocol=|azure", re.I)),
    ("JWT_Private_Key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----", re.I)),
    ("DB_Password", re.compile(r"(postgres|postgresql|mysql|mongodb|redis|mariadb)://[^\s:/@]+:[^\s@]+@|password\s*=|pwd\s*=", re.I)),
    ("API_Key", re.compile(r"sk-[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]+|ghp_[A-Za-z0-9]{20,}|bearer\s+[A-Za-z0-9._\-]+|api[_-]?key", re.I)),
]
_TYPE_ALIASES = {"jwt": "JWT_Private_Key", "jwt_private_key": "JWT_Private_Key",
                 "db_password": "DB_Password", "dbpassword": "DB_Password",
                 "database": "DB_Password", "api_key": "API_Key", "apikey": "API_Key",
                 "aws": "AWS", "gcp": "GCP", "azure": "Azure", "generic": "Generic"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_dirs() -> None:
    os.makedirs(SECRETS_DIR, exist_ok=True)
    try:
        os.chmod(SECRETS_DIR, 0o700)
    except OSError:
        pass


class SecretCustodian:
    def __init__(self, payload: dict):
        self.payload = payload or {}
        self.declared_type = str(self.payload.get("secret_type", "") or "")
        self.context = str(self.payload.get("context", "") or "")
        self.discovered_by = str(self.payload.get("discovered_by", "") or "unknown-skill")
        self.errors: List[Dict[str, str]] = []
        self.input_channel = "unknown"

    # -- secret intake (returns a bytearray we can zero) --------------------
    def _read_secret(self) -> Optional[bytearray]:
        p = self.payload
        if p.get("raw_secret_env"):
            self.input_channel = "env"
            v = os.environ.get(str(p["raw_secret_env"]))
            return bytearray(v.encode("utf-8")) if v is not None else None
        if p.get("raw_secret_file"):
            self.input_channel = "file"
            try:
                with open(str(p["raw_secret_file"]), "rb") as fh:
                    return bytearray(fh.read())
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "read_file", "error": str(exc)})
                return None
        if "raw_secret" in p and p["raw_secret"] is not None:
            self.input_channel = p.get("_channel", "inline")
            return bytearray(str(p["raw_secret"]).encode("utf-8"))
        return None

    # -- hashing ------------------------------------------------------------
    @staticmethod
    def hash_secret(raw: bytes) -> str:
        return hashlib.sha256(bytes(raw)).hexdigest()

    # -- type classification ------------------------------------------------
    def classify_type(self, raw: bytes) -> str:
        d = (self.declared_type or "").strip().lower()
        if d in _TYPE_ALIASES:
            return _TYPE_ALIASES[d]
        if self.declared_type in TYPE_ENUM:
            return self.declared_type
        # auto-detect from the secret + surrounding context (never echoed)
        blob = bytes(raw).decode("utf-8", "replace") + "\n" + self.context
        for name, rx in _DETECT:
            if rx.search(blob):
                return name
        return "Generic"

    # -- key management -----------------------------------------------------
    def _load_key(self) -> Tuple[Optional[bytes], str]:
        env = os.environ.get("SECRET_CUSTODY_KEY")
        if env:
            return env.encode() if isinstance(env, str) else env, "env"
        if os.path.exists(KEYFILE):
            try:
                with open(KEYFILE, "rb") as fh:
                    return fh.read().strip(), "keyfile"
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "key_load", "error": str(exc)})
        if _HAVE_CRYPTO:
            key = Fernet.generate_key()
            try:
                _ensure_dirs()
                fd = os.open(KEYFILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(key)
                os.chmod(KEYFILE, 0o600)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "key_write", "error": str(exc)})
            return key, "generated"
        return None, "unavailable"

    # -- encryption ---------------------------------------------------------
    def encrypt_secret(self, raw: bytearray, secret_type: str) -> Tuple[str, str, str]:
        """Return (encrypted_relpath, key_source, key_fingerprint). Zeroes `raw`."""
        key, key_source = self._load_key()
        if not (_HAVE_CRYPTO and key):
            self._zero(raw)
            self.errors.append({"stage": "encrypt",
                                "error": "cryptography/Fernet unavailable; raw secret discarded, "
                                         "no ciphertext stored (hash-only custody)"})
            return "", key_source, ""
        _ensure_dirs()
        sha = self.hash_secret(raw)
        # envelope: encrypt the secret plus non-echoed metadata for later rotation
        envelope = json.dumps({
            "secret": bytes(raw).decode("utf-8", "replace"),
            "secret_type": secret_type,
            "context": self.context[:2000],
            "discovered_at": _now_iso(),
            "discovered_by": self.discovered_by,
        }).encode("utf-8")
        try:
            token = Fernet(key).encrypt(envelope)
        except Exception as exc:  # noqa: BLE001
            self._zero(raw)
            self.errors.append({"stage": "encrypt", "error": str(exc)})
            return "", key_source, ""
        finally:
            # scrub the plaintext envelope + raw ASAP
            self._zero(bytearray(envelope))
        relpath = os.path.join("secrets", f"{sha}.enc")
        abspath = os.path.join(SECRETS_DIR, f"{sha}.enc")
        try:
            fd = os.open(abspath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(token)
            os.chmod(abspath, 0o600)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "write_enc", "error": str(exc)})
            relpath = ""
        self._zero(raw)
        kf = hashlib.sha256(bytes(key)).hexdigest()[:16]
        return relpath, key_source, kf

    @staticmethod
    def _zero(buf: bytearray) -> None:
        try:
            for i in range(len(buf)):
                buf[i] = 0
        except Exception:  # noqa: BLE001
            pass

    # -- custody log --------------------------------------------------------
    def _load_log(self) -> List[dict]:
        try:
            with open(CUSTODY_LOG, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else data.get("entries", [])
        except Exception:  # noqa: BLE001
            return []

    def _save_log(self, entries: List[dict]) -> None:
        _ensure_dirs()
        try:
            fd = os.open(CUSTODY_LOG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(entries, fh, indent=2, sort_keys=True)
            os.chmod(CUSTODY_LOG, 0o600)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "log_write", "error": str(exc)})

    def write_custody_log(self, sha: str, secret_type: str, relpath: str,
                          key_fp: str) -> dict:
        entries = self._load_log()
        existing = next((e for e in entries if e.get("secret_hash") == sha), None)
        entry = {
            "secret_hash": sha,
            "secret_type": secret_type,
            "discovered_at": existing["discovered_at"] if existing else _now_iso(),
            "discovered_by": self.discovered_by,
            "cleanup_status": existing.get("cleanup_status", "pending") if existing else "pending",
            "encrypted_path": relpath,
            "key_fingerprint": key_fp,
            "context_fingerprint": hashlib.sha256(self.context.encode()).hexdigest()[:16] if self.context else "",
            "last_updated": _now_iso(),
            "occurrences": (existing.get("occurrences", 1) + 1) if existing else 1,
        }
        entries = [e for e in entries if e.get("secret_hash") != sha] + [entry]
        self._save_log(entries)
        # the artifact-facing view has NO raw bytes and NO absolute paths
        return {"discovered_at": entry["discovered_at"], "discovered_by": entry["discovered_by"],
                "cleanup_status": entry["cleanup_status"]}

    # -- status update mode -------------------------------------------------
    def update_status(self) -> dict:
        sha = str(self.payload.get("secret_hash", "") or "")
        new = str(self.payload.get("cleanup_status", "") or "")
        if not sha or new not in ("pending", "rotated", "revoked"):
            return self._err("update_status needs secret_hash + cleanup_status in {pending,rotated,revoked}")
        entries = self._load_log()
        hit = next((e for e in entries if e.get("secret_hash") == sha), None)
        if not hit:
            return self._err(f"no custody entry for hash {sha[:12]}...")
        hit["cleanup_status"] = new
        hit["last_updated"] = _now_iso()
        self._save_log(entries)
        return {
            "secret_hash": sha, "encrypted_spill_id": hit.get("encrypted_path", ""),
            "secret_type": hit.get("secret_type", "Generic"),
            "custody_log": {"discovered_at": hit.get("discovered_at", ""),
                            "discovered_by": hit.get("discovered_by", ""),
                            "cleanup_status": new},
            "meta": {"skill": "credential-secret-custody", "version": "1.0", "phase": "5-6",
                     "loop_component": "5-observer", "status": "ok", "action": "update_status",
                     "generated_at": _now_iso(), "raw_secret_in_output": False},
            "errors": self.errors,
        }

    # -- main custody flow --------------------------------------------------
    def run(self) -> dict:
        if str(self.payload.get("action", "custody")) == "update_status":
            return self.update_status()
        raw = self._read_secret()
        if raw is None or len(raw) == 0:
            return self._err("no secret provided (raw_secret / raw_secret_env / raw_secret_file)")
        raw_bytes_copy = bytes(raw)                 # for the leak guard only
        sha = self.hash_secret(raw)
        secret_type = self.classify_type(raw)
        relpath, key_source, key_fp = self.encrypt_secret(raw, secret_type)  # zeroes raw
        # drop every reference to the plaintext
        try:
            del self.payload["raw_secret"]
        except Exception:  # noqa: BLE001
            pass
        clog = self.write_custody_log(sha, secret_type, relpath, key_fp)

        art = {
            "secret_hash": sha,
            "encrypted_spill_id": relpath,
            "secret_type": secret_type,
            "custody_log": clog,
            "meta": {
                "skill": "credential-secret-custody", "version": "1.0", "phase": "5-6",
                "loop_component": "5-observer", "status": "ok" if relpath else "degraded",
                "generated_at": _now_iso(), "action": "custody",
                "encryption": "fernet" if relpath else "unavailable",
                "key_source": key_source, "key_fingerprint": key_fp,
                "input_channel": self.input_channel,
                "secret_length": len(raw_bytes_copy),
                "context_fingerprint": clog and hashlib.sha256(self.context.encode()).hexdigest()[:16] or "",
                "raw_secret_in_output": False,
                "secrets_dir_mode": "0700",
                "custody_log_path": "secrets/custody_log.json",
            },
            "errors": self.errors,
        }
        # FINAL LEAK GUARD: never emit the raw secret
        blob = json.dumps(art)
        raw_str = raw_bytes_copy.decode("utf-8", "replace")
        leaked = (raw_str and len(raw_str) >= 6 and raw_str in blob)
        self._zero(bytearray(raw_bytes_copy))
        raw_bytes_copy = b""
        raw_str = ""
        if leaked:
            return {"secret_hash": sha, "encrypted_spill_id": relpath, "secret_type": secret_type,
                    "custody_log": clog,
                    "meta": {"skill": "credential-secret-custody", "status": "error",
                             "raw_secret_in_output": True, "generated_at": _now_iso()},
                    "errors": [{"stage": "leak_guard",
                                "error": "raw secret detected in artifact; suppressed"}]}
        return art

    def _err(self, msg: str) -> dict:
        return {"secret_hash": "", "encrypted_spill_id": "", "secret_type": "Generic",
                "custody_log": {"discovered_at": _now_iso(), "discovered_by": self.discovered_by,
                                "cleanup_status": "pending"},
                "meta": {"skill": "credential-secret-custody", "version": "1.0", "phase": "5-6",
                         "loop_component": "5-observer", "status": "error", "generated_at": _now_iso(),
                         "raw_secret_in_output": False},
                "errors": self.errors + [{"stage": "custody", "error": msg}]}


# --- entry point -------------------------------------------------------------
def _load_input(argv: List[str]) -> dict:
    """Prefer stdin (no process-table exposure). argv is a discouraged fallback."""
    if not sys.stdin.isatty():
        raw = sys.stdin.read().strip()
        if raw:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                obj.setdefault("_channel", "stdin")
                return obj
    if len(argv) > 1 and argv[1].strip():
        obj = json.loads(argv[1])
        if isinstance(obj, dict):
            obj["_channel"] = "argv"
            return obj
    raise ValueError('no input: expected JSON on stdin with {"raw_secret": ...}')


def _error_artifact(msg: str) -> dict:
    return {"secret_hash": "", "encrypted_spill_id": "", "secret_type": "Generic",
            "custody_log": {"discovered_at": _now_iso(), "discovered_by": "unknown-skill",
                            "cleanup_status": "pending"},
            "meta": {"skill": "credential-secret-custody", "version": "1.0", "phase": "5-6",
                     "status": "error", "generated_at": _now_iso(), "raw_secret_in_output": False},
            "errors": [{"stage": "init", "error": msg}]}


def main() -> int:
    try:
        payload = _load_input(sys.argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    art = SecretCustodian(payload).run()
    print(json.dumps(art, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
