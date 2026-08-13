package node_test

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	node "github.com/impire-io/soulstream-mcp"
	"github.com/impire-io/soulstream-mcp/rigtest"
)

// TestUS2_CustodyNoFilesWritten (T021): after a multi-principal workload with
// HOME/XDG redirected to a temp dir, the node has written nothing — no token,
// no key, no per-user secret (SC-004 first half).
func TestUS2_CustodyNoFilesWritten(t *testing.T) {
	r := rigtest.Start(t, time.Minute)

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "xdg-data"))

	url := serveNode(t, r, node.Config{})
	tokA, _ := r.StaticToken(t, "ana-ext", "ana")
	tokB, _ := r.StaticToken(t, "ben-ext", "ben")
	for _, tok := range []string{tokA, tokB} {
		sess := mcpSession(t, url, tok)
		path := extractPath(t, callText(t, sess, "soulstream_start_topic", map[string]any{"name": "x"}))
		_ = callText(t, sess, "soulstream_post_turn", map[string]any{"path": path, "body": "hi"})
	}

	// The node's whole would-be config/data footprint must be empty.
	assertNoFilesUnder(t, home)
}

func assertNoFilesUnder(t *testing.T, dir string) {
	t.Helper()
	var found []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d != nil && !d.IsDir() {
			found = append(found, p)
		}
		return nil
	})
	if len(found) > 0 {
		t.Errorf("node wrote %d file(s) to its home dir, want zero (stateless trust): %v", len(found), found)
	}
}

// TestUS5_RestartRecovers (T033): kill the node mid-traffic, stand a fresh
// one on the same realm, and a client's next request with its current bearer
// is re-admitted — no state migration, empty durable footprint (SC-004
// second half).
func TestUS5_RestartRecovers(t *testing.T) {
	r := rigtest.Start(t, time.Minute)
	token, _ := r.StaticToken(t, "daan-ext", "daan")

	// First node: admit, post.
	n1, err := node.New(node.Config{Listen: "127.0.0.1:0", Realm: rigtest.Realm, NATSURL: r.URL, SentinelPath: r.SentinelPath})
	if err != nil {
		t.Fatal(err)
	}
	srv1 := httptest.NewServer(n1.Handler())
	sess1 := mcpSession(t, srv1.URL, token)
	path := extractPath(t, callText(t, sess1, "soulstream_start_topic", map[string]any{"name": "Durable"}))
	_ = callText(t, sess1, "soulstream_post_turn", map[string]any{"path": path, "body": "before restart"})
	_ = sess1.Close()
	srv1.Close()
	n1.Close() // the "kill"

	// Fresh node, same realm — no migration of anything.
	url2 := serveNode(t, r, node.Config{})
	sess2 := mcpSession(t, url2, token)
	_ = callText(t, sess2, "soulstream_post_turn", map[string]any{"path": path, "body": "after restart"})

	assertVerifiedAuthor(t, r, path, "daan-ext", "before restart")
	assertVerifiedAuthor(t, r, path, "daan-ext", "after restart")
}

// TestUS5_ProxyFrontedShape (T032): in public mode the node serves requests
// carrying the public Host against its loopback bind (the declared proxy
// shape); the SDK's DNS-rebinding guard yields to it (FR-012).
func TestUS5_ProxyFrontedShape(t *testing.T) {
	r := rigtest.Start(t, time.Minute)
	url := serveNode(t, r, node.Config{PublicURL: "https://node.example.com", AuthIssuer: r.AS.Issuer()})
	token, _ := r.StaticToken(t, "daan-ext", "daan")

	// A request whose Host differs from the bind address is served, not 403'd.
	sess := mcpSessionWithHost(t, url, token, "node.example.com")
	who := callText(t, sess, "soulstream_whoami", nil)
	if !strings.Contains(who, `"persona": "daan-ext"`) {
		t.Fatalf("fronted request not served as the admitted persona: %s", who)
	}
}

// TestUS2_NoTokenMaterialInLogs (T022): across an admit + refuse workload,
// no token value the rig minted appears in the node's captured logs (SC-006).
func TestUS2_NoTokenMaterialInLogs(t *testing.T) {
	logs := &syncBuf{}
	r := rigtest.Start(t, time.Minute)
	url := serveNodeLogging(t, r, node.Config{PublicURL: "https://node.test", AuthIssuer: r.AS.Issuer()}, logs)

	good := r.OIDCToken(t, "logged-person", "acme")
	sess := mcpSession(t, url, good)
	_ = callText(t, sess, "soulstream_whoami", nil)
	forged, _ := r.AS.TokenWrongKey(r.AS.Claims("logged-person", "acme"))
	_, _ = rawPost(t, url, forged)

	out := logs.String()
	for _, secret := range []string{good, forged} {
		if strings.Contains(out, secret) {
			t.Errorf("token material leaked into node logs")
		}
		// Also check the JWT payload segment specifically.
		if parts := strings.Split(secret, "."); len(parts) == 3 && strings.Contains(out, parts[1]) {
			t.Errorf("JWT payload leaked into node logs")
		}
	}
	if !strings.Contains(out, "node: admitted") || !strings.Contains(out, "node: refused") {
		t.Errorf("expected admit and refuse events in logs, got:\n%s", out)
	}
}
