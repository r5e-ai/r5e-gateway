# What a receipt proves

For anyone who will be shown a receipt, or handed an evidence export, and asked to rely on it.

## The statement

Traffic is forwarded to the endpoint. Everything the model can do arrives as a tool call in the response. The gateway records everything it has. A recorded response with no tool call is a response with no tool call.

## Why the statement holds

The gateway holds the complete response bytes: their SHA-256 is in the receipt and the bytes themselves are in the content-addressed store. The wire format, Anthropic Messages at the version and beta flags named in the request headers, defines exactly how a tool call is encoded: a content block of type `tool_use`. A parser that recognises every event type of that format, reading the complete bytes, can state how many tool calls the response contained, including none.

The record therefore names the parser that read the bytes and the format version it is exhaustive for, and it counts the events it saw and the events it did not recognise. When that second count is zero, an empty tool-call list is a statement about the bytes. When it is not zero, the record says which event types went unrecognised and the statement is narrowed to that extent; it is not withheld.

## What a receipt contains

A receipt is two parts: an envelope the gateway signs, and the body the envelope commits to.

The envelope is a DSSE envelope signed with the gateway's key. It carries the run id, the event kind, the principal, the timestamp, the SHA-256 of the Cedar bundle in force, the ledger position, and the SHA-256 of the body. The body is retained content-addressed under that hash, and an evidence export packs it as `predicate/<run_id>.json`.

The body is a JSON document canonicalised under RFC 8785, so the same claims always produce the same bytes and the same hash. It carries:

| Field | What it is |
|---|---|
| Model and upstream host | which model was asked, and where the request was sent |
| Wire format | the API format the parser read, with its version and the betas requested |
| Request hash | SHA-256 of the request bytes as forwarded |
| Response hash | SHA-256 of the response bytes as received from the upstream |
| Token usage | the counts the upstream reported |
| Call kind and client session | agent turn, session title or side query, and the client's own session id |
| Tool calls | each extracted tool call: tool name, hash of its arguments, and the Cedar decision |
| Parser and parse counts | which parser read the bytes; events seen and events unrecognised |

A denial is a receipt of its own in the same two-part shape. Its body names the tool, the hash of its arguments, the rule that fired, the bundle hash, and the call it was extracted from.

Request and response bytes are retained under their hashes when `R5E_RETAIN_PAYLOADS` is `true`, which the compose file sets, up to `R5E_RETAIN_PAYLOADS_MAX_BYTES` per direction; over the cap nothing is kept and the export manifest records `payload_retention: truncated`.

## What offline verification checks

An evidence export is a zip: the envelope, the body, the retained request and response bytes, the signer's public key, the Merkle inclusion proofs, and the Cedar source of the bundle that decided, archived when it was activated so a later policy change does not alter it. `recurse-verify` runs on a machine with no access to the gateway and checks, in order:

| Step | Passes when |
|---|---|
| Trust anchor | the public key you supply matches the one bundled in the zip |
| Signature | the envelope verifies against that key |
| Session inclusion | the receipt is in the session epoch tree it claims |
| Global inclusion | the session epoch root is in the global ledger root |
| Policy hash | the bundled Cedar source hashes to the bundle hash in the envelope |
| Predicate body | `predicate/<run_id>.json` hashes to the body hash in the envelope |
| Detached payloads | the bundled request and response bytes hash to the request and response hashes in the body |

The verifier prints a result line under each step: `MATCH` (`VALID` for the signature), `FAIL` with the mismatch, or `SKIPPED` with what the export does not carry. It exits 0 on a pass, 1 on any `FAIL`, 2 on a pass without a trust anchor, and 3 on bad input. A `SKIPPED` line is a statement about the export, not a failure; those lines are where what was not checked is stated, and what each record kind claims and does not claim is in the Kind definitions under `specs/010-gateway-api-group/kinds/`.

The mechanics and the commands are in [the verification walkthrough](auditor/verification_walkthrough.md).
