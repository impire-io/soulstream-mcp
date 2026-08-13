package node_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	node "github.com/impire-io/soulstream-mcp"
	"github.com/impire-io/soulstream-mcp/rigtest"
)

// oauthClient drives the hosted-client half of the flow using ONLY what the
// node's metadata and the AS's discovery advertise — no knowledge of node or
// plane internals (SC-005). It is the "scripted conforming client".
type oauthClient struct {
	t      *testing.T
	nodeMD nodeMetadata
	asMD   asMetadata
	http   *http.Client
}

type nodeMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

type asMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
}

// discover walks 401 → node resource metadata → AS discovery, knowing only
// the node URL to begin with.
func discover(t *testing.T, nodeURL string) *oauthClient {
	t.Helper()
	c := &oauthClient{t: t, http: http.DefaultClient}

	// A cold request draws the challenge that names the metadata. (In a real
	// deployment the advertised URL IS the node's public address; in the rig
	// the node is reached at nodeURL, so the metadata is fetched there.)
	code, wwwAuth := rawGet(t, nodeURL, "")
	if code != 401 || !strings.Contains(wwwAuth, "resource_metadata=") {
		t.Fatalf("expected a 401 challenge naming resource_metadata, got %d %q", code, wwwAuth)
	}
	c.nodeMD = getJSON[nodeMetadata](t, nodeURL+"/.well-known/oauth-protected-resource")
	if len(c.nodeMD.AuthorizationServers) == 0 {
		t.Fatal("node metadata names no authorization server")
	}
	c.asMD = getJSON[asMetadata](t, c.nodeMD.AuthorizationServers[0]+"/.well-known/openid-configuration")
	return c
}

// register performs Dynamic Client Registration and returns the client id.
func (c *oauthClient) register(redirect string) string {
	c.t.Helper()
	body, _ := json.Marshal(map[string]any{"redirect_uris": []string{redirect}})
	resp, err := c.http.Post(c.asMD.RegistrationEndpoint, "application/json", strings.NewReader(string(body)))
	if err != nil {
		c.t.Fatalf("DCR: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.ClientID == "" {
		c.t.Fatal("DCR returned no client_id")
	}
	return out.ClientID
}

// signIn runs authorization-code + PKCE for a person (oid + roles) and
// returns the access token. The stand-in takes the "login" as query hints.
func (c *oauthClient) signIn(clientID, oid string, roles ...string) string {
	c.t.Helper()
	verifier := "verifier-" + oid + "-0123456789abcdef0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	redirect := "https://client.example/callback"

	// Don't follow the redirect: capture the code from the Location.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	au, _ := url.Parse(c.asMD.AuthorizationEndpoint)
	q := au.Query()
	q.Set("response_type", "code")
	q.Set("code_challenge_method", "S256")
	q.Set("code_challenge", challenge)
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirect)
	q.Set("login_hint", oid)
	if len(roles) > 0 {
		q.Set("roles_hint", strings.Join(roles, " "))
	}
	au.RawQuery = q.Encode()
	resp, err := noRedirect.Get(au.String())
	if err != nil {
		c.t.Fatalf("authorize: %v", err)
	}
	_ = resp.Body.Close()
	loc, err := resp.Location()
	if err != nil {
		c.t.Fatalf("authorize returned no redirect (status %d)", resp.StatusCode)
	}
	code := loc.Query().Get("code")
	if code == "" {
		c.t.Fatal("authorize redirect carried no code")
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirect},
		"client_id":     {clientID},
	}
	tr, err := c.http.PostForm(c.asMD.TokenEndpoint, form)
	if err != nil {
		c.t.Fatalf("token: %v", err)
	}
	defer func() { _ = tr.Body.Close() }()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(tr.Body).Decode(&tok)
	if tok.AccessToken == "" {
		c.t.Fatal("token endpoint returned no access_token")
	}
	return tok.AccessToken
}

// TestUS4_FullOIDCFlow (T029, SC-001+SC-005): a scripted client that knows
// only the node URL completes discovery → DCR → PKCE sign-in → admitted
// session, and its first post verifies as its oid persona on an independent
// reader. The client used only contract-advertised endpoints.
func TestUS4_FullOIDCFlow(t *testing.T) {
	r := rigtest.Start(t, time.Minute)
	url := serveNode(t, r, node.Config{PublicURL: "https://node.test", AuthIssuer: r.AS.Issuer()})

	c := discover(t, url)
	clientID := c.register("https://client.example/callback")
	const oid = "flow-person"
	token := c.signIn(clientID, oid, "acme")

	sess := mcpSession(t, url, token)
	who := callText(t, sess, "soulstream_whoami", nil)
	if !strings.Contains(who, `"persona": "`+oid+`"`) {
		t.Fatalf("admitted as %s, want %s", who, oid)
	}
	path := extractPath(t, callText(t, sess, "soulstream_start_topic", map[string]any{"name": "OIDC"}))
	_ = callText(t, sess, "soulstream_post_turn", map[string]any{"path": path, "body": "posted via the full oauth flow"})
	assertVerifiedAuthor(t, r, path, oid, "posted via the full oauth flow")

	// JWKS rotation mid-session: a fresh token after rotation still admits,
	// no plane restart (contract §3).
	if err := r.AS.Rotate(); err != nil {
		t.Fatal(err)
	}
	token2 := c.signIn(clientID, oid, "acme")
	sess2 := mcpSession(t, url, token2)
	if who := callText(t, sess2, "soulstream_whoami", nil); !strings.Contains(who, oid) {
		t.Fatalf("post-rotation admission failed: %s", who)
	}
}

// TestUS4_ConformanceRefusals (T030): each contract-§3 violation refuses at
// admission — nothing published, 401 at the node.
func TestUS4_ConformanceRefusals(t *testing.T) {
	r := rigtest.Start(t, time.Minute)
	url := serveNode(t, r, node.Config{PublicURL: "https://node.test", AuthIssuer: r.AS.Issuer()})

	cases := []struct {
		name  string
		token func() string
	}{
		{"illegal oid slug", func() string {
			return r.OIDCTokenRaw(t, r.AS.Claims("Not A Slug!", "acme"))
		}},
		{"missing oid", func() string {
			c := r.AS.Claims("x", "acme")
			delete(c, "oid")
			return r.OIDCTokenRaw(t, c)
		}},
		{"zero-match roles", func() string {
			return r.OIDCTokenRaw(t, r.AS.Claims("no-role-person"))
		}},
		{"ambiguous roles", func() string {
			return r.OIDCTokenRaw(t, r.AS.Claims("ambi-person", "acme", "member-alt"))
		}},
		{"wrong audience", func() string {
			c := r.AS.Claims("aud-person", "acme")
			c["aud"] = "https://someone-else"
			return r.OIDCTokenRaw(t, c)
		}},
		{"wrong issuer", func() string {
			c := r.AS.Claims("iss-person", "acme")
			c["iss"] = "https://evil.example"
			return r.OIDCTokenRaw(t, c)
		}},
		{"non-RS256 alg", func() string {
			tok, err := r.AS.TokenAlgNone(mustClaims(t, r, "alg-person"))
			if err != nil {
				t.Fatal(err)
			}
			return tok
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _ := rawPost(t, url, tc.token()); code != 401 {
				t.Errorf("%s: admitted (status %d), want 401", tc.name, code)
			}
		})
	}
}

func mustClaims(t *testing.T, r *rigtest.Rig, oid string) map[string]any {
	t.Helper()
	return r.AS.Claims(oid, "acme")
}

// --- tiny JSON/URL helpers ---

func getJSON[T any](t *testing.T, url string) T {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec // test-only, rig-local URL
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode %s: %v (body %s)", url, err, b)
	}
	return out
}

var _ = time.Minute
