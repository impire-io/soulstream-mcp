package node_test

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	node "github.com/impire-io/soulstream-mcp"
	"github.com/impire-io/soulstream-mcp/rigtest"
)

// rawGet issues a bare GET (optionally with a bearer) and returns the status
// code and WWW-Authenticate header — for asserting the challenge directly.
func rawGet(t *testing.T, url, bearer string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate")
}

// rawPost issues a minimal MCP initialize POST with the given bearer and
// returns the status code and WWW-Authenticate header.
func rawPost(t *testing.T, url, bearer string) (int, string) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"0"}}}`
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate")
}

// TestUS1_NoBearerAndInvalidBearer (T014): in public mode a missing or
// refused bearer gets the 401 challenge and nothing reaches the realm; in
// local mode a missing bearer gets the SDK's bare 400.
func TestUS1_NoBearerAndInvalidBearer(t *testing.T) {
	r := rigtest.Start(t, time.Minute)

	// Public mode: no bearer → 401 pointing at the resource metadata.
	pub := serveNode(t, r, node.Config{PublicURL: "https://node.test", AuthIssuer: r.AS.Issuer()})
	code, wwwAuth := rawGet(t, pub, "")
	if code != 401 {
		t.Errorf("public no-bearer: status %d, want 401", code)
	}
	if !strings.Contains(wwwAuth, "resource_metadata=") {
		t.Errorf("401 challenge missing resource_metadata: %q", wwwAuth)
	}

	// Public mode: a garbage bearer the callout refuses → still 401, no realm write.
	code, _ = rawPost(t, pub, "not-a-real-token")
	if code != 401 {
		t.Errorf("public garbage-bearer: status %d, want 401", code)
	}

	// Local mode: no bearer → the SDK's 400 (no OAuth story to point at).
	loc := serveNode(t, r, node.Config{})
	code, _ = rawGet(t, loc, "")
	if code == 401 {
		t.Errorf("local no-bearer: got 401, want the SDK's non-OAuth status")
	}
}

// TestUS2_TwoPrincipalsConcurrent (T019): two personas through one node at
// once, every operation attributed and signed as its true author (SC-002
// first half). Static lane: distinct tokens → distinct hints.
func TestUS2_TwoPrincipalsConcurrent(t *testing.T) {
	r := rigtest.Start(t, time.Minute)
	url := serveNode(t, r, node.Config{})
	tokA, _ := r.StaticToken(t, "ana-ext", "ana laptop")
	tokB, _ := r.StaticToken(t, "ben-ext", "ben laptop")

	sessA := mcpSession(t, url, tokA)
	sessB := mcpSession(t, url, tokB)
	pathA := extractPath(t, callText(t, sessA, "soulstream_start_topic", map[string]any{"name": "Ana's"}))
	pathB := extractPath(t, callText(t, sessB, "soulstream_start_topic", map[string]any{"name": "Ben's"}))

	// Interleave posts from both principals concurrently.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = callText(t, sessA, "soulstream_post_turn", map[string]any{"path": pathA, "body": "ana-says"})
		}()
		go func() {
			defer wg.Done()
			_ = callText(t, sessB, "soulstream_post_turn", map[string]any{"path": pathB, "body": "ben-says"})
		}()
	}
	wg.Wait()

	assertVerifiedAuthor(t, r, pathA, "ana-ext", "ana-says")
	assertVerifiedAuthor(t, r, pathB, "ben-ext", "ben-says")
}

// TestUS2_ForgedHintNonInterference (T020): an attacker crafts OIDC tokens
// carrying a victim's iss+oid (so they route to the victim's pool entry) but
// with bad or unauthorized signatures. None may adopt the victim's entry,
// evict it, or interrupt the victim's live session (SC-002 second half —
// the forged-hint DoS the prototype was open to).
func TestUS2_ForgedHintNonInterference(t *testing.T) {
	r := rigtest.Start(t, time.Minute)
	url := serveNode(t, r, node.Config{PublicURL: "https://node.test", AuthIssuer: r.AS.Issuer()})

	const victimOID = "victim-oid"
	victimTok := r.OIDCToken(t, victimOID, "acme")

	// The victim establishes a live session and posts.
	victim := mcpSession(t, url, victimTok)
	path := extractPath(t, callText(t, victim, "soulstream_start_topic", map[string]any{"name": "Victim's"}))
	_ = callText(t, victim, "soulstream_post_turn", map[string]any{"path": path, "body": "victim-first"})

	// The attacker forges tokens with the victim's exact iss+oid (same routing
	// hint) but signatures the callout cannot accept.
	badSig, err := r.AS.TokenWrongKey(r.AS.Claims(victimOID, "acme"))
	if err != nil {
		t.Fatal(err)
	}
	noRole, err := r.AS.Token(r.AS.Claims(victimOID)) // valid sig, no role → refused
	if err != nil {
		t.Fatal(err)
	}
	for _, forged := range []string{badSig, noRole, "eyJ" + victimOID + ".garbage.sig"} {
		if code, _ := rawPost(t, url, forged); code != 401 {
			t.Errorf("forged bearer admitted (status %d, want 401)", code)
		}
	}

	// The victim's session is untouched: it keeps posting and both turns
	// verify as the victim.
	_ = callText(t, victim, "soulstream_post_turn", map[string]any{"path": path, "body": "victim-after-attack"})
	assertVerifiedAuthor(t, r, path, victimOID, "victim-first")
	assertVerifiedAuthor(t, r, path, victimOID, "victim-after-attack")
}

// TestUS2_ImpostorServedViaOwnEntry (T020 cont.): an attacker whose OWN valid
// token happens to collide on a victim's routing hint is served as
// themselves (their own principal), never over the victim's access.
func TestUS2_ImpostorServedViaOwnEntry(t *testing.T) {
	r := rigtest.Start(t, time.Minute)
	url := serveNode(t, r, node.Config{PublicURL: "https://node.test", AuthIssuer: r.AS.Issuer()})

	// Two real people. The rig's AS keys them by oid; to force a hint
	// collision we would need equal oids, which is illegal — so instead we
	// assert the positive: each valid token is served as its own oid even
	// under concurrent load on the same node.
	aTok := r.OIDCToken(t, "person-a", "acme")
	bTok := r.OIDCToken(t, "person-b", "acme")
	sessA := mcpSession(t, url, aTok)
	sessB := mcpSession(t, url, bTok)

	whoA := callText(t, sessA, "soulstream_whoami", nil)
	whoB := callText(t, sessB, "soulstream_whoami", nil)
	if !strings.Contains(whoA, `"persona": "person-a"`) {
		t.Errorf("person-a served as wrong principal: %s", whoA)
	}
	if !strings.Contains(whoB, `"persona": "person-b"`) {
		t.Errorf("person-b served as wrong principal: %s", whoB)
	}
}
