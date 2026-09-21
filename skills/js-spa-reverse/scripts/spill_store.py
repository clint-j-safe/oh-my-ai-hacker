#!/usr/bin/env python3
"""
spill_store.py -- Shared offload utility for the loop-engineered pentest framework.

THE OFFLOAD LAW (non-negotiable)
--------------------------------
Any raw output that exceeds OFFLOAD_MAX_ITEMS items OR OFFLOAD_MAX_BYTES
serialized bytes MUST be written to the content-addressed spill store. The
skill then returns ONLY a pointer (`spill_id`), a `count`, and a short
`preview`. Loops communicate through persisted state (Neo4j WorkingMemory)
and this spill store -- never by flooding the LLM's volatile context with a
5 MB scan or 10,000 URLs.

The store is content-addressed (sha256 of the canonical JSON). Identical
payloads collapse to a single file, so re-runs are idempotent and cheap, and a
`spill_id` is a stable, verifiable handle to an exact byte-for-byte payload.

This module is intentionally dependency-free (stdlib only) so every skill in
the framework can vendor or import it without pulling extra packages into the
sandboxed execution environment.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import tempfile
from typing import Any, List

# --- Thresholds (the Offload Law knobs) --------------------------------------
# Overridable via environment so the Dispatcher can tune per-engagement without
# editing skill code.
OFFLOAD_MAX_ITEMS = int(os.environ.get("SPILL_MAX_ITEMS", "500"))
OFFLOAD_MAX_BYTES = int(os.environ.get("SPILL_MAX_BYTES", str(50 * 1024)))  # 50 KB
PREVIEW_LEN = int(os.environ.get("SPILL_PREVIEW_LEN", "10"))

# Content-addressed store location. The Dispatcher sets SPILL_STORE_DIR to a
# per-engagement path; default is ./spill_store relative to the skill's CWD.
SPILL_DIR = pathlib.Path(os.environ.get("SPILL_STORE_DIR", "spill_store"))


def _digest(content: bytes) -> str:
    """Return the 16-hex-char content id used as the spill filename stem."""
    return hashlib.sha256(content).hexdigest()[:16]


def _canonical(data: Any) -> bytes:
    """Deterministic serialization so equal payloads always share an id."""
    return json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")


def write_spill(data: Any) -> str:
    """Write `data` to spill_store/<sha256[:16]>.json and return the spill_id.

    Content-addressed and atomic. If a file with the same id already exists the
    payload is identical, so the write is skipped (dedup / idempotency).
    """
    SPILL_DIR.mkdir(parents=True, exist_ok=True)
    canonical = _canonical(data)
    spill_id = _digest(canonical)
    path = SPILL_DIR / f"{spill_id}.json"
    if not path.exists():
        # Atomic publish: write to a temp file in the same dir, then os.replace.
        fd, tmp = tempfile.mkstemp(dir=str(SPILL_DIR), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    return spill_id


def read_spill(spill_id: str) -> Any:
    """Load a spilled payload by id. Raises FileNotFoundError if absent."""
    path = SPILL_DIR / f"{spill_id}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def serialized_bytes(items: Any) -> int:
    """Byte length of the JSON serialization -- the Offload Law size metric."""
    return len(json.dumps(items, ensure_ascii=False).encode("utf-8"))


def should_offload(items: List[Any]) -> bool:
    """Offload Law predicate: True when `items` MUST be spilled."""
    return len(items) > OFFLOAD_MAX_ITEMS or serialized_bytes(items) > OFFLOAD_MAX_BYTES


def _stringify(x: Any) -> str:
    return x if isinstance(x, str) else json.dumps(x, sort_keys=True, ensure_ascii=False)


def offload_list(items: List[Any], *, always: bool = False,
                 preview_len: int = PREVIEW_LEN) -> dict:
    """Return a strict pointer block ``{spill_id, count, preview}`` for a list.

    - ``always=True``: spill whenever the list is non-empty, so the *complete*
      corpus is always retrievable via ``spill_id`` even when small. Used for
      data that has no inline slot in the artifact (e.g. historical URLs).
    - ``always=False`` (default): spill only when the Offload Law trips; a small
      list returns ``spill_id=None`` with the preview carrying up to
      ``preview_len`` items.

    ``count`` is ALWAYS the true total, independent of preview truncation.
    """
    count = len(items)
    preview = [_stringify(x) for x in items[:preview_len]]
    if count == 0:
        return {"spill_id": None, "count": 0, "preview": []}
    if always or should_offload(items):
        return {"spill_id": write_spill(items), "count": count, "preview": preview}
    return {"spill_id": None, "count": count, "preview": preview}


if __name__ == "__main__":
    # Tiny self-test / CLI: `python spill_store.py read <spill_id>`
    import sys

    if len(sys.argv) == 3 and sys.argv[1] == "read":
        print(json.dumps(read_spill(sys.argv[2]), indent=2))
    else:
        demo = [f"https://example.com/path/{i}" for i in range(1200)]
        block = offload_list(demo, always=True)
        print(json.dumps(block, indent=2))
