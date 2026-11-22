# Verification walkthrough

For an auditor who has been handed an evidence export zip and needs a pass or fail determination on a machine with no access to the gateway that produced it.

## What you receive

| Item | From |
|---|---|
| `<run_id>.zip`, one receipt per zip | the customer's console (Export Evidence) or `bin/r5e evidence export` |
| the gateway's public signing key, PEM | the customer, through a channel other than the zip |
| `recurse-verify` and `verify-bundled-merkle` | `docs/auditor/` in this repository |

The zip contains the signed envelope, the outer container with its ledger proofs, the Cedar bundle that decided, the signer's public key, and, for receipts written with retention on, the predicate body at `predicate/<run_id>.json` and the request and response bytes under `payloads/`. What is inside is listed in `manifest.json`.

## Run

The tools are bash, `openssl`, `jq`, `unzip`, `sha256sum` or `shasum`, and `python3`. Step 4 also uses `cedar-canonical-hash` next to the script; without it the step is `NOT CHECKED` and the verdict is `FAIL`. `bin/r5e evidence verify` builds it once with `cargo`.

```
recurse-verify --zip <run_id>.zip --trust-anchor <public-key.pem>
```

```
[0] Trust anchor match
    MATCH (sha256: 9d448ab3e54659eb...)
[1] DSSE signature (Constitution Principle III)
    VALID (ES256)
[2] RFC 9162 local inclusion (session-chain epoch root)
    MATCH
[3] RFC 9162 global inclusion (ledger root)
    MATCH (computed root 64356b7aa5198cfb3bf62cc2fa89dabc27747506b5897ec818fd7e926e353e23)
[4] policy_canonical_hash
    MATCH (rule 1: Cedar-canonical JCS hash via bundled cedar-canonical-hash)
[5] payload_hash
    SKIPPED (N/A — predicate-only receipt and the export carries no predicate/<run_id>.json: ...)
[6] verification_level + tier_completeness_advisory
    INTERPRETED
[7] detached payloads (prompt_hash / response_hash)
    SKIPPED (no predicate body in the export — no prompt_hash / response_hash to check payloads against)

VERIFY: PASS (strict, anchored)
```

The output above is a receipt exported before the gateway retained predicate bodies; an export with `predicate/<run_id>.json` prints `MATCH` or `FAIL` at steps 5 and 7.

## Steps

| Step | Checks |
|---|---|
| 0 | the key you supplied is the key bundled in the zip |
| 1 | the DSSE signature over the envelope verifies against that key |
| 2 | the receipt is in the session epoch tree the envelope claims |
| 3 | the session epoch root is in the global ledger root |
| 4 | the bundled Cedar source hashes to `policy_canonical_hash` in the envelope |
| 5 | `predicate/<run_id>.json` hashes to `payload_hash` in the envelope |
| 6 | `verification_level` and `tier_completeness_advisory` are read out, not checked |
| 7 | the bytes under `payloads/` hash to `prompt_hash` and `response_hash` in the body |

Each step prints `MATCH` (`VALID` at step 1, `INTERPRETED` at step 6), `FAIL` with the two hashes that differ, or `SKIPPED` with what the export does not carry. `SKIPPED` is a statement about the export, not a failure.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | every step passed with a trust anchor supplied and matched |
| 1 | a step failed; the `FAIL` line names it and the values that differ |
| 2 | every step passed but no trust anchor was supplied; the zip's own key was used |
| 3 | bad input: zip not found or malformed, a required tool missing, or a bad flag |

Without `--trust-anchor` the last line reads `VERIFY: UNANCHORED PASS (exit 2 — NOT evidentiary-grade)`: the signature was checked against a key the zip itself supplied. Rerun with the key you received out of band.

## On a failure

Steps 0 and 1 failing means the zip was not signed by the key you hold, or its bytes changed after signing. Steps 2 and 3 failing means the envelope is not where the ledger says it is. Step 4 failing means the bundled policy is not the one this receipt was evaluated against. Steps 5 and 7 failing means the bundled bytes are not the bytes the receipt hashed. In each case request a fresh export over a different channel and, if it fails the same way, escalate to the customer's security contact with the `FAIL` line.

`--json` prints the same steps as a JSON report for filing.
