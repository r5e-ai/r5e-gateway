# Codex and other clients

For someone who uses Codex, or a client other than Claude Code, and wants to know whether the gateway applies to it.

## Why Claude Code needs one environment variable

Claude Code documents a gateway protocol. `ANTHROPIC_BASE_URL` sends every model call to the address given, the credential travels with the request, and a plain `http://` address is accepted. The client is designed to be put behind a gateway, so the gateway needs no DNS change and no certificate on the client.

## Why Codex needs more

Codex signed in with a ChatGPT account talks to its ChatGPT-login backend, and there is no documented gateway setting for that backend. The client also does not know it is being proxied, so the gateway has to be where the client thinks the backend is, and it has to present a certificate the client trusts.

That is a man-in-the-middle, and it takes three pieces:

| Piece | What it does |
|---|---|
| Hosts override | sends the client's `chatgpt.com` to loopback, where a port bridge hands port 443 to the gateway's proxy port |
| A local certificate authority | a two-tier CA whose leaf the gateway serves for `chatgpt.com`; the client trusts it through its own certificate environment variable, because Codex carries its own root store and ignores the system keychain |
| Bypass DNS in the gateway | the gateway resolves `chatgpt.com` against public DNS so it still reaches OpenAI despite the override on the same machine |

There is a second reason Codex is harder to govern. Its internal tool-call shapes have changed three times across releases: the tool name and the argument key that carry a shell command have each moved. The gateway's parser and the shipped policy cover the shapes confirmed so far, and the parser logs any shape it does not recognise so a change is visible rather than silent.

## Status of the Codex path

The MITM runbook was last validated on Codex 0.149, in a separate workspace, before this compose stack existed. It is not part of the supported quickstart and has not been re-tested against the compose stack. It needs root for the hosts override and is written for macOS.

The runbook is [scripts/fable_demo/README-real-codex.md](../scripts/fable_demo/README-real-codex.md). Its on and off scripts add and remove the hosts entries; the on script reverts them on exit.

Unverified: the Codex 0.149 binary carries a `chatgpt_base_url` configuration key and a matching environment variable. If the client honours it for the ChatGPT-login backend, a configured base URL would replace the hosts override and the TLS interception, leaving Codex with the same one-setting shape as Claude Code. This has not been tested.

## Other clients

A client with a base-URL setting for the Anthropic Messages or OpenAI Responses formats can be pointed at the gateway the same way Claude Code is. A client that does not is in Codex's situation and needs the MITM. In both cases the receipts cover the model calls that reach the gateway, and the parser's unrecognised-event log names any shape the gateway did not extract a tool call from.
