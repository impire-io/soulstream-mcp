// Package node is the remote MCP door into one realm: streamable HTTP in,
// bearer passthrough to NATS auth-callout admission, one pooled connection
// per admitted principal, the public soulstream tool surface out.
//
// The node custodies nothing. It holds no keys, no per-user secrets, and no
// durable trust state; the caller's bearer token is passed through to the
// realm's admission edge unchanged, and who a session is comes back from the
// realm after admission — never from anything the client claims. Restart is
// free.
//
// CYCLE GUARD: this module imports both the soulstream library and the
// soulstream-identity client; neither of those repositories may import the other,
// or this module. The adapter position is the point — identity delegation is
// wired here, above both.
package node
