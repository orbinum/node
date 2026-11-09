#!/usr/bin/env bash

# Verify a runtime WASM carries the spec name a release must have.
#
# Usage:
#   ./scripts/verify-spec-name.sh <expected-spec-name> <path/to/runtime.wasm>
#
# Local-only builds take their own spec name (`fast-runtime` → `orbinum-fast`,
# `runtime-benchmarks` → `orbinum-bench`), so `set_code` refuses them on a live chain.
# This reads the name back from the artifact's `runtime_version` custom section rather
# than trusting the feature list, so any build that is not exactly the release fails.
# Accepts the compressed WASM (8-byte magic + zstd stream) or a plain one.

set -euo pipefail

EXPECTED="${1:-}"
WASM="${2:-}"
if [ -z "$EXPECTED" ] || [ ! -f "$WASM" ]; then
  echo "usage: $0 <expected-spec-name> <path/to/runtime.wasm>" >&2
  exit 2
fi

RAW="$(mktemp)"
trap 'rm -f "$RAW"' EXIT
# `sp_maybe_compressed_blob`'s magic prefix.
if [ "$(head -c 8 "$WASM" | od -An -tx1 | tr -d ' \n')" = "52bc537646db8e05" ]; then
  # A failed decompression must fail the check, not pass it.
  tail -c +9 "$WASM" | zstd -dc > "$RAW"
else
  cp "$WASM" "$RAW"
fi

ACTUAL="$(python3 -I - "$RAW" <<'PY'
import sys

data = open(sys.argv[1], "rb").read()
if data[:4] != b"\0asm":
    sys.exit("not a WASM module")

def leb128(pos):
    value = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            return value, pos

pos = 8
while pos < len(data):
    section, pos = data[pos], pos + 1
    size, pos = leb128(pos)
    end = pos + size
    if section == 0:
        name_len, start = leb128(pos)
        if data[start:start + name_len] == b"runtime_version":
            # SCALE `RuntimeVersion`: `spec_name` first, a compact length then UTF-8.
            p = start + name_len
            mode = data[p] & 3
            if mode == 0:
                length, p = data[p] >> 2, p + 1
            elif mode == 1:
                length, p = int.from_bytes(data[p:p + 2], "little") >> 2, p + 2
            elif mode == 2:
                length, p = int.from_bytes(data[p:p + 4], "little") >> 2, p + 4
            else:
                sys.exit("spec name too long")
            print(data[p:p + length].decode())
            sys.exit(0)
    pos = end
sys.exit("no runtime_version section")
PY
)"

if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "::error::runtime WASM spec name is '$ACTUAL', expected '$EXPECTED'"
  exit 1
fi
echo "Runtime WASM spec name: $ACTUAL"
