# recurse_provenance

Provenance v2 evidence as a pure library: no process, no database, no HTTP.

It implements the October 30 contract (`api/provenance/CONTRACT.md` in the
workspace) with Amendment A1 (group-qualified kinds):

| Module | What it does |
| --- | --- |
| `Ref` | `evidence:`, `bytes:` and `event:` references |
| `Key` | key ids, Ed25519 and ES256 signing and verification |
| `Schema` | a strict JSON Schema subset: bundling and validation |
| `Definitions` | the sixteen base definitions, content-addressed at compile time |
| `Evidence` | the signed payload: assembly, validation, canonical bytes, identity |
| `Body` | constructors for call, response, policy and session bodies |
| `Envelope` | the DSSE wrapper: sign, open, verify |
| `Profile` | the capture profile and its authority bounds |
| `Epoch` | seals, manifests, Merkle roots and membership proofs |
| `Export` | the offline bundle and its layered verification |

Canonical JSON, DSSE pre-authentication encoding, key-id derivation, the
Ed25519 profile and the Merkle tree come from the Core verifier package
(`:recurse_verify`), so records are written and checked under one reading
of those rules.

```sh
MIX_ENV=test mix test
```
