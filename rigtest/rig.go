package rigtest

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	siclient "github.com/impire-io/soulstream-identity/client"
	"github.com/impire-io/soulstream-identity/embed"

	"github.com/impire-io/soulstream-core/realm"
)

// Realm is the realm name the rig provisions.
const Realm = "proof"

// Rig is an in-process operator-mode NATS deployment with the identity plane
// (embed.Run) and its auth callout — the node's admission edge, real. It is
// built on PUBLIC surfaces only (jwt/nkeys for the NATS ceremony, embed.Run
// for the plane); the node module cannot reach either repo's internals.
type Rig struct {
	URL          string
	SentinelPath string
	Account      string // the team account public key (A…)
	AS           *ASStub

	admin       *siclient.Client
	readerCreds string
	audit       *syncBuffer
}

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

// Audit returns everything the plane and issuer logged — the surface the
// token-material audit greps (SC-006).
func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// Audit exposes the identity plane's log for assertions.
func (r *Rig) Audit() string { return r.audit.String() }

// Start brings up the whole edge with callout JWT TTL = ttl. The AS stand-in
// is wired as the plane's OIDC issuer, so OIDC-lane tokens admit end to end.
func Start(t *testing.T, ttl time.Duration) *Rig {
	t.Helper()

	as, err := NewASStub("https://node.test/resource")
	if err != nil {
		t.Fatalf("as stub: %v", err)
	}
	t.Cleanup(as.Close)

	k := newKeyset(t)
	cfgPath := writeServerConfig(t, k)
	srv := startServer(t, cfgPath)

	serviceCreds := issueUser(t, k.acmeKP, "service", nil)
	adminCreds := issueUser(t, k.acmeKP, "ops", &jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{
			siclient.Segment + ".status", siclient.Segment + ".xkey",
			siclient.Segment + "." + k.acmePub + ".ops.>",
		}},
		Sub: jwt.Permission{Allow: jwt.StringList{"_INBOX.>"}},
	})
	readerCreds := issueUser(t, k.acmeKP, "reader", nil)
	issuerCreds := k.issuerCreds(t)

	// The identity plane: vault + tokens on ACME's JetStream, callout issuer
	// on AUTH with the OIDC lane against the stand-in — all via embed.Run.
	audit := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(io.MultiWriter(audit), &slog.HandlerOptions{Level: slog.LevelDebug}))

	ncService, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(serviceCreds))
	if err != nil {
		t.Fatalf("service connect: %v", err)
	}
	t.Cleanup(ncService.Close)
	ncIssuer, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(issuerCreds))
	if err != nil {
		t.Fatalf("issuer connect: %v", err)
	}
	t.Cleanup(ncIssuer.Close)

	planeCtx, cancelPlane := context.WithCancel(context.Background())
	t.Cleanup(cancelPlane)
	planeErr := make(chan error, 1)
	go func() {
		planeErr <- embed.Run(planeCtx, embed.Options{
			Conn:         ncService,
			CalloutConn:  ncIssuer,
			FirstKey:     k.firstSeed,
			SurfaceKey:   k.surfaceSeed,
			CalloutKey:   k.calloutSeed,
			AuthAccount:  k.authPub,
			AuthKeyName:  "auth/issuer",
			CalloutTTL:   ttl,
			OIDCIssuer:   as.Issuer(),
			OIDCAudience: as.Audience(),
			Logger:       logger,
		})
	}()
	t.Cleanup(func() {
		cancelPlane()
		select {
		case <-planeErr:
		case <-time.After(3 * time.Second):
		}
	})
	waitForService(t, ncService)

	// Admin provisions: the team key (→ ACME account signing key), the AUTH
	// issuer key, the sentinel. No per-person act for OIDC users (D26).
	ncAdmin, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(adminCreds))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(ncAdmin.Close)
	admin := siclient.New(ncAdmin, k.acmePub, "ops")
	mustImport(t, admin, "acme", k.acmeSKSeed, k.acmePub)
	mustImport(t, admin, "auth/issuer", k.authSKSeed, k.authPub)
	// A second declared role (bound to the AUTH account, so it does NOT make
	// ACME's token lane ambiguous) purely so an OIDC token naming both "acme"
	// and this role is genuinely ambiguous (D24) — the conformance case.
	mustImport(t, admin, "member-alt", k.authSKSeed, k.authPub)

	sentinelPath := mintSentinel(t, admin)

	// Provisioning is an operator act, not the node's: a bootstrap identity
	// creates the realm once.
	provisionRealm(t, srv.ClientURL(), readerCreds)

	return &Rig{
		URL:          srv.ClientURL(),
		SentinelPath: sentinelPath,
		Account:      k.acmePub,
		AS:           as,
		admin:        admin,
		readerCreds:  readerCreds,
		audit:        audit,
	}
}

// StaticToken mints a sit_ API token for a user in the rig's account and
// returns the token plus its digest (the revocation handle).
func (r *Rig) StaticToken(t *testing.T, user, label string) (token, digest string) {
	t.Helper()
	created, err := r.admin.CreateToken(r.Account, user, label, 0)
	if err != nil {
		t.Fatalf("create token %s: %v", user, err)
	}
	return created.Token, created.Digest
}

// RevokeStaticToken deletes a token's record by digest; the next admission
// with that token refuses.
func (r *Rig) RevokeStaticToken(t *testing.T, digest string) {
	t.Helper()
	if err := r.admin.RevokeToken(digest); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

// OIDCToken mints an access token through the AS stand-in directly (bypassing
// the browser flow) for a person identified by oid, holding the given roles.
func (r *Rig) OIDCToken(t *testing.T, oid string, roles ...string) string {
	t.Helper()
	return r.OIDCTokenRaw(t, r.AS.Claims(oid, roles...))
}

// OIDCTokenRaw mints a validly-signed token over arbitrary claims — for
// conformance-refusal tests that need to violate one claim rule at a time.
func (r *Rig) OIDCTokenRaw(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok, err := r.AS.Token(claims)
	if err != nil {
		t.Fatalf("oidc token: %v", err)
	}
	return tok
}

// ReaderRealm opens an independent bootstrap-creds realm client for
// verification — it trusts nothing the node said.
func (r *Rig) ReaderRealm(t *testing.T) *realm.Client {
	t.Helper()
	nc, err := nats.Connect(r.URL, nats.UserCredentials(r.readerCreds))
	if err != nil {
		t.Fatalf("reader connect: %v", err)
	}
	t.Cleanup(nc.Close)
	rc, err := realm.NewClient(context.Background(), nc, realm.Config{Realm: Realm})
	if err != nil {
		t.Fatalf("reader realm: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close() })
	return rc
}

func mustImport(t *testing.T, admin *siclient.Client, name, seed, account string) {
	t.Helper()
	if _, err := admin.ImportKey(name, siclient.KindNATSAccountSigningKey, seed, account, ""); err != nil {
		t.Fatalf("import key %s: %v", name, err)
	}
}

func mintSentinel(t *testing.T, admin *siclient.Client) string {
	t.Helper()
	sentinel, err := admin.MintSentinel()
	if err != nil {
		t.Fatalf("mint sentinel: %v", err)
	}
	path := filepath.Join(t.TempDir(), "sentinel.creds")
	if err := os.WriteFile(path, []byte(sentinel.Creds), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	return path
}

func provisionRealm(t *testing.T, url, creds string) {
	t.Helper()
	nc, err := nats.Connect(url, nats.UserCredentials(creds))
	if err != nil {
		t.Fatalf("provision connect: %v", err)
	}
	defer nc.Close()
	rc, err := realm.NewClient(context.Background(), nc, realm.Config{Realm: Realm})
	if err != nil {
		t.Fatalf("provision realm client: %v", err)
	}
	defer func() { _ = rc.Close() }()
	if _, err := rc.Provision(context.Background()); err != nil {
		t.Fatalf("provision: %v", err)
	}
}

func startServer(t *testing.T, cfgPath string) *natsserver.Server {
	t.Helper()
	opts, err := natsserver.ProcessConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("process config: %v", err)
	}
	opts.NoLog, opts.NoSigs = true, true
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	go srv.Start()
	t.Cleanup(srv.Shutdown)
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("server not ready")
	}
	return srv
}

// waitForService polls the sealed status surface until the plane answers.
func waitForService(t *testing.T, nc *nats.Conn) {
	t.Helper()
	c := siclient.New(nc, "", "")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := c.Status(); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("identity plane did not become ready")
}

func issueUser(t *testing.T, accKP nkeys.KeyPair, name string, perms *jwt.Permissions) string {
	t.Helper()
	ukp, _ := nkeys.CreateUser()
	uPub, _ := ukp.PublicKey()
	uc := jwt.NewUserClaims(uPub)
	uc.Name = name
	if perms != nil {
		uc.Permissions = *perms
	}
	token, err := uc.Encode(accKP)
	if err != nil {
		t.Fatalf("issue %s: %v", name, err)
	}
	seed, _ := ukp.Seed()
	creds, err := jwt.FormatUserConfig(token, seed)
	if err != nil {
		t.Fatalf("creds %s: %v", name, err)
	}
	path := filepath.Join(t.TempDir(), name+".creds")
	if err := os.WriteFile(path, creds, 0o600); err != nil {
		t.Fatalf("write creds %s: %v", name, err)
	}
	return path
}

// scopeTemplate is the represented-user scope (research R7): identity-plane
// user ops on the own prefix, the realm's subject space, and the user-info
// request the node derives the principal from.
func scopeTemplate(acmeSKPub string) *jwt.UserScope {
	scope := jwt.NewUserScope()
	scope.Key = acmeSKPub
	scope.Role = "soulstream-user"
	scope.Template = jwt.UserPermissionLimits{
		Permissions: jwt.Permissions{
			Pub: jwt.Permission{Allow: jwt.StringList{
				siclient.Segment + ".status", siclient.Segment + ".xkey",
				siclient.Segment + ".{{account-subject()}}.{{name()}}.sign.record",
				siclient.Segment + ".{{account-subject()}}.{{name()}}.keys.public",
				"SOULSTREAM.>", "$JS.API.>", "$KV.>", "$O.>",
				"$SYS.REQ.USER.INFO",
			}},
			Sub: jwt.Permission{Allow: jwt.StringList{"_INBOX.>", "SOULSTREAM.>"}},
		},
	}
	return scope
}
