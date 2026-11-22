# Canonical JSON against JCS

`corpus.jsonl` is 2,016 JSON values in six classes. `jcs-reference.sha256` is the SHA-256 of each value's RFC 8785 (JCS) bytes, one line per value, computed with the algorithm as the RFC defines it and matched by seven independent JCS libraries on every case in classes 1 to 4. How both were produced is in `research/2026-11-10-jcs/` in the workspace.

The test beside this holds the canonical encoder to these hashes for every value its profile admits, and checks that it refuses the rest.
