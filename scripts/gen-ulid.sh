#!/usr/bin/env bash
# gen-ulid.sh — print a Crockford-Base32 ULID (26 chars) to stdout.
# F002 T012. Used to mint the `tenant_id` placeholder in tier-config.yaml.
#
# A ULID is:
#   - 48-bit unsigned time (ms since Unix epoch) — 10 Crockford chars
#   - 80-bit randomness                          — 16 Crockford chars
#   = 130 bits, encoded as 26 Crockford-Base32 chars (the final 2 bits are padded)
#
# Alphabet: Crockford Base32 (no I, L, O, U): 0123456789ABCDEFGHJKMNPQRSTVWXYZ

set -eu

if ! command -v python3 >/dev/null 2>&1; then
  echo "gen-ulid.sh: python3 is required but not found in PATH" >&2
  exit 1
fi

exec python3 - <<'PY'
import os
import time

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford Base32

def encode(n: int, length: int) -> str:
    out = []
    for _ in range(length):
        out.append(ALPHABET[n & 0b11111])
        n >>= 5
    return "".join(reversed(out))

ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
rand = int.from_bytes(os.urandom(10), "big")  # 80 bits

ulid = encode(ts_ms, 10) + encode(rand, 16)
assert len(ulid) == 26, f"ULID length {len(ulid)} != 26"
print(ulid)
PY
