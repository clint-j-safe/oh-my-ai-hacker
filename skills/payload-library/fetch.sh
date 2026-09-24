#!/usr/bin/env bash
# Clone PayloadsAllTheThings + SecLists at PINNED commit SHAs into raw/, then build the
# SQLite corpus index. Idempotent; safe to re-run. Pins come from the environment so the
# corpus is reproducible and never silently drifts with upstream.
set -euo pipefail
ROOT="${SAHW_PAYLOAD_LIBRARY:-/opt/payload-library}"
DB="${SAHW_PAYLOAD_DB:-$ROOT/db/payloads.db}"
PAT_SHA="${SAHW_PAYLOAD_PAT_SHA:?set SAHW_PAYLOAD_PAT_SHA to a pinned commit SHA}"
SECLISTS_SHA="${SAHW_PAYLOAD_SECLISTS_SHA:?set SAHW_PAYLOAD_SECLISTS_SHA to a pinned commit SHA}"
RAW="$ROOT/raw"
mkdir -p "$RAW" "$(dirname "$DB")"

clone_pinned() {  # $1 repo url, $2 sha, $3 dest
  local url="$1" sha="$2" dest="$3"
  if [ ! -d "$dest/.git" ]; then
    git clone --filter=blob:none --no-checkout "$url" "$dest"
  fi
  git -C "$dest" fetch --depth 1 origin "$sha"
  git -C "$dest" checkout --force "$sha"
}

clone_pinned https://github.com/swisskyrepo/PayloadsAllTheThings.git "$PAT_SHA" "$RAW/PayloadsAllTheThings"
clone_pinned https://github.com/danielmiessler/SecLists.git         "$SECLISTS_SHA" "$RAW/SecLists"

python3 "$(dirname "$0")/scripts/corpus.py" build --raw "$RAW" --db "$DB" \
  --pat-sha "$PAT_SHA" --seclists-sha "$SECLISTS_SHA"
echo "corpus built at $DB"
