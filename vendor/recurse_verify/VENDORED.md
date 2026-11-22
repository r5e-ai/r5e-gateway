# recurse_verify, vendored

The Core verifier library: canonical JSON, the DSSE pre-authentication encoding, the Ed25519 profile and the RFC 9162 Merkle tree. Provenance records are encoded and hashed with it, so every build of this umbrella must use exactly the same code.

- Source: the r5e Core repository, directory `verifier/`, commit `fef9605`.
- Copied unmodified: `mix.exs`, `mix.lock`, the repository's `LICENSE`, and everything under `lib/` except one file.
- **One deliberate difference:** `lib/recurse_verify/canonical.ex` carries the canonical JSON change proposed in `api/core-amendments/C1-canonical-json.md` in the workspace: short escapes for backspace, tab, newline, form feed and carriage return; integers within ±(2^53 − 1); no characters above U+FFFF in object keys. It is here ahead of Core because Provenance records are hashed with this encoder and no real records exist yet. When Core adopts the change, this file goes back to being a plain copy.
- Why it is here and not a path or git dependency: the container build can only see this repository, and the build must not depend on network access to another one.

Do not edit the other files. To update, copy the same paths from a newer Core commit, change the commit above, and run the full suite: a change here can change the bytes of every record.

`R5E_CORE_VERIFIER_PATH` still overrides the location, for working against a Core checkout.
