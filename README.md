# soulstream-mcp — the remote MCP server

A URL into a Soulstream realm for clients that cannot install anything
(hosted Claude Desktop connectors, claude.ai, sandboxed clients): a
credential-free HTTP MCP server that passes each caller's bearer through
to the realm's auth callout, admitting every user as a real, signed
realm member on their own per-principal connection. The server custodies
nothing.

Extracted from the record library's nested `node/` module at
`soulstream/node v0.7.0` in the ecosystem naming re-centering
(soul-hq episode 0069, 2026-08-13); the design lives in soul-hq
(`02-DESIGN` — the remote-mcp-node extension) and the founding story in
the journey (episodes 0038 and 0047 there). Sign-in is any external
OIDC authorization server — `soulstream-idp` is the intended default —
and the tool surface is `soulstream-core`'s public embeddable
`mcpserver`.

Binaries: `soulstream-mcp` (the server), `byon-setup` and `probe`
(operator utilities for bring-your-own-NATS deployments).

Gate: `make check` — fmt, tidy, build, test, lint; all green, nothing
skipped.
