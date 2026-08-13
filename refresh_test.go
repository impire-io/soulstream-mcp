package node_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/impire-io/soulstream-core/topic"

	node "github.com/impire-io/soulstream-mcp"
	"github.com/impire-io/soulstream-mcp/rigtest"
)

// TestUS3_SessionOutlivesTokens (T024, SC-003): a session keeps working across
// several callout TTLs. The minted JWT the pooled connection holds expires
// each TTL; nats.go reconnects, re-presents the bearer, and the callout
// re-admits — so a session outlives many token lifetimes with no user-visible
// interruption. (Prototype Bar 3, re-run through the full tool surface.)
func TestUS3_SessionOutlivesTokens(t *testing.T) {
	const ttl = 2 * time.Second
	r := rigtest.Start(t, ttl)
	url := serveNode(t, r, node.Config{})

	tok, _ := r.StaticToken(t, "long-session", "session-a")
	sess := mcpSession(t, url, tok)
	path := extractPath(t, callText(t, sess, "soulstream_start_topic", map[string]any{"name": "Long"}))

	// Post across >3 TTL windows; each round the pooled JWT has expired and
	// the connection has had to re-admit to serve the call.
	for i := 0; i < 4; i++ {
		time.Sleep(ttl + 500*time.Millisecond)
		_ = callText(t, sess, "soulstream_post_turn", map[string]any{"path": path, "body": "round"})
	}

	rc := r.ReaderRealm(t)
	kr := rigtest.DirectoryKeyring(t, r, "long-session")
	th := topic.Open(rc, path)
	th.UseKeyring(kr)
	v, err := th.Materialise(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rounds := 0
	for _, c := range v.Contributions {
		if c.Body == "round" {
			if c.Sig != topic.SigVerified {
				t.Errorf("round %d sig = %q, want verified", rounds, c.Sig)
			}
			rounds++
		}
	}
	if rounds < 4 {
		t.Errorf("only %d/4 rounds survived across TTLs", rounds)
	}
}

// TestUS3_RevocationLands (T025, SC-003): a revoked token refuses once the
// admission window (the minted JWT TTL) elapses, and a returning valid token
// re-admits — a past refusal leaves no scar on the node.
func TestUS3_RevocationLands(t *testing.T) {
	const ttl = 2 * time.Second
	r := rigtest.Start(t, ttl)
	url := serveNode(t, r, node.Config{PublicURL: "https://node.test", AuthIssuer: r.AS.Issuer()})

	tok, digest := r.StaticToken(t, "revoke-me", "revoke-me")
	sess := mcpSession(t, url, tok)
	if who := callText(t, sess, "soulstream_whoami", nil); !strings.Contains(who, "revoke-me") {
		t.Fatalf("token did not admit before revocation: %s", who)
	}

	// Revoke, then wait past the admission window: the pooled connection's
	// minted JWT expires, it reconnects, and re-admission refuses — the
	// connection closes and the entry becomes a corpse.
	r.RevokeStaticToken(t, digest)
	deadline := time.Now().Add(3 * ttl)
	refused := false
	for time.Now().Before(deadline) {
		if code, _ := rawPost(t, url, tok); code == 401 {
			refused = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !refused {
		t.Errorf("revoked token still admitted after %v (want 401 within the window)", 3*ttl)
	}

	// A different valid token admits on its next request — refusal is not
	// sticky to the node.
	good, _ := r.StaticToken(t, "still-good", "still-good")
	sess2 := mcpSession(t, url, good)
	if who := callText(t, sess2, "soulstream_whoami", nil); !strings.Contains(who, "still-good") {
		t.Errorf("valid token refused after an unrelated revocation: %s", who)
	}
}
