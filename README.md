# r5e-gateway

r5e is a governance gateway for AI agents. Model calls and tool calls pass through it, policy written in Cedar is enforced in the response stream before the agent can act, and what happened is recorded as signed evidence that someone else can check without access to the gateway.

Evidence is recorded in the Provenance v2 format: signed records in streams, sealed in epochs, with content held by reference and each kind of record described by a published definition.

This is the gateway that started r5e's own chain, `r5e-api`. The first records of that chain are in [`genesis/`](genesis/) and can be verified with the code here.

## Verify the start of r5e's chain

You need the toolchain in `.tool-versions` (Elixir 1.19, Erlang/OTP 28, and Rust for one native dependency).

```
cd apps/recurse_provenance
MIX_ENV=test mix recurse.provenance.verify ../../genesis/block-0-r5e-api.json \
  --chain evidence:sha256:7c45caf3de9a3014b662d67c44705b6fdb180c06492abbb9e4a216828ef686c5 \
  --publisher key:es256:sha256:2685eeac8d06dd75811f6b14fb45bde55c657957e3adface2ff8b0379c31cc33=r5e.io
```

It ends with `122 held, 0 failed, 0 could not be checked`. Add `--report FILE` to write the full report; its SHA-256 is `c379ee8e555219daad6e2e0c3c7cf2ab0009a2823ea6f75eb914aaef3365d9ed`. The Python and Rust verifiers, written separately from the specification, produce the same bytes.

Nothing is trusted unless you say so. `--chain` names the chain you expect, and `--publisher` names whose definitions you accept and for which domain. Leave them out and the same file is reported as sound but not established.

| File | What it is |
|---|---|
| [`genesis/block-0-r5e-api.json`](genesis/block-0-r5e-api.json) | The first nine records of `r5e-api`, with the keys, definitions and seals needed to check them. SHA-256 `a706c2bc8e4705e57e316d4549d3d0733290d242aefca3016f80ac824cf0d55a`. |
| [`genesis/publications.json`](genesis/publications.json) | The publisher's signed statement of the base definitions. SHA-256 `b26f95e10df37756cf04217d6a739138e0e188ed3ac3c01214054e19440b13f9`. |
| [`genesis/r5e-root.pub.pem`](genesis/r5e-root.pub.pem) | The chain's root public key, `key:ed25519:sha256:aeb2f4f7d81d87ce8e9f437fa5bada43d41d7cf5badcceffdf37403ddfee53fc`. |
| [`genesis/r5e-publisher.pub.pem`](genesis/r5e-publisher.pub.pem) | The definition publisher's public key for `r5e.io`, `key:es256:sha256:2685eeac8d06dd75811f6b14fb45bde55c657957e3adface2ff8b0379c31cc33`. |

The chain's name is the reference of its `Deployment` record: `evidence:sha256:7c45caf3de9a3014b662d67c44705b6fdb180c06492abbb9e4a216828ef686c5`, recorded at 2026-11-22T04:12:28Z.

## Configuration

Settings are documented where they are read, in [`config/runtime.exs`](config/runtime.exs). The ones that shape the evidence:

- `R5E_EVIDENCE_DEPLOYMENT` names the deployment; the name appears in its stream and actor identifiers.
- `R5E_EVIDENCE_DIR` is where the local evidence log is kept. Put it on storage that survives a restart.
- `R5E_EVIDENCE_START_CHAIN=true` with `R5E_EVIDENCE_PUBLICATIONS_FILE` has a new node begin its own chain and wait to be claimed by its root key.
- `R5E_EVIDENCE_KEY_SERVICE` or `R5E_EVIDENCE_CONTENT_KEY_FILE` encrypts recorded content, so that one session's content can be erased by destroying its key. Without either, content is stored unencrypted.

`mix recurse.evidence.export` writes a bundle that the verifiers read.

## Tests

The suite needs a Postgres 17 it may create databases in. Point it there with `POSTGRES_HOST` and `POSTGRES_PORT` (default `localhost:5432`).

```
MIX_ENV=test mix test
```

## License

AGPL-3.0, see [LICENSE](LICENSE).
