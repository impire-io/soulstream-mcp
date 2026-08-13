package rigtest

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// keyset is the operator-mode NATS ceremony: an operator, a system account, an
// AUTH account declaring external authorization (the callout), and the ACME
// team account whose scoped signing key carries the represented-user template
// (research R7). One account hosts both the identity plane and the realm, so
// sign.record needs no cross-account exports.
type keyset struct {
	opKP    nkeys.KeyPair
	acmeKP  nkeys.KeyPair
	authKP  nkeys.KeyPair
	acmePub string
	authPub string

	acmeSKSeed string
	authSKSeed string

	firstSeed   string
	surfaceSeed string
	calloutSeed string

	opJWT, sysJWT, authJWT, acmeJWT string
	sysPub, authPubAcc, acmePubAcc  string

	issuerUserKP  nkeys.KeyPair
	issuerUserPub string
}

func mustSeed(kp nkeys.KeyPair) string {
	s, err := kp.Seed()
	if err != nil {
		panic(err)
	}
	return string(s)
}

func mustPub(kp nkeys.KeyPair) string {
	p, err := kp.PublicKey()
	if err != nil {
		panic(err)
	}
	return p
}

func newKeyset(t *testing.T) *keyset {
	t.Helper()
	opKP, _ := nkeys.CreateOperator()
	sysKP, _ := nkeys.CreateAccount()
	authKP, _ := nkeys.CreateAccount()
	acmeKP, _ := nkeys.CreateAccount()
	acmeSKKP, _ := nkeys.CreateAccount()
	authSKKP, _ := nkeys.CreateAccount()
	calloutKP, _ := nkeys.CreateCurveKeys()
	firstKP, _ := nkeys.CreateCurveKeys()
	surfaceKP, _ := nkeys.CreateCurveKeys()

	opPub := mustPub(opKP)
	sysPub := mustPub(sysKP)
	authPub := mustPub(authKP)
	acmePub := mustPub(acmeKP)
	acmeSKPub := mustPub(acmeSKKP)
	authSKPub := mustPub(authSKKP)
	calloutPub := mustPub(calloutKP)

	issuerUserKP, _ := nkeys.CreateUser()
	issuerUserPub := mustPub(issuerUserKP)

	oc := jwt.NewOperatorClaims(opPub)
	oc.Name = "node-rig-operator"
	opJWT, err := oc.Encode(opKP)
	if err != nil {
		t.Fatalf("operator jwt: %v", err)
	}
	sc := jwt.NewAccountClaims(sysPub)
	sc.Name = "SYS"
	sysJWT, err := sc.Encode(opKP)
	if err != nil {
		t.Fatalf("system jwt: %v", err)
	}

	authClaim := jwt.NewAccountClaims(authPub)
	authClaim.Name = "AUTH"
	authClaim.SigningKeys.Add(authSKPub)
	authClaim.EnableExternalAuthorization(issuerUserPub)
	authClaim.Authorization.AllowedAccounts.Add(acmePub)
	authClaim.Authorization.XKey = calloutPub
	authJWT, err := authClaim.Encode(opKP)
	if err != nil {
		t.Fatalf("auth jwt: %v", err)
	}

	acmeClaim := jwt.NewAccountClaims(acmePub)
	acmeClaim.Name = "ACME"
	acmeClaim.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage: -1, DiskStorage: -1, Streams: -1, Consumer: -1,
	}
	acmeClaim.SigningKeys.AddScopedSigner(scopeTemplate(acmeSKPub))
	acmeJWT, err := acmeClaim.Encode(opKP)
	if err != nil {
		t.Fatalf("acme jwt: %v", err)
	}

	return &keyset{
		opKP: opKP, acmeKP: acmeKP, authKP: authKP,
		acmePub: acmePub, authPub: authPub,
		acmeSKSeed: mustSeed(acmeSKKP), authSKSeed: mustSeed(authSKKP),
		firstSeed: mustSeed(firstKP), surfaceSeed: mustSeed(surfaceKP), calloutSeed: mustSeed(calloutKP),
		opJWT: opJWT, sysJWT: sysJWT, authJWT: authJWT, acmeJWT: acmeJWT,
		sysPub: sysPub, authPubAcc: authPub, acmePubAcc: acmePub,
		issuerUserKP: issuerUserKP, issuerUserPub: issuerUserPub,
	}
}

// issuerCreds writes the callout issuer user's creds (a user in AUTH; the
// server hands it the sealed auth requests).
func (k *keyset) issuerCreds(t *testing.T) string {
	t.Helper()
	issuerJWT, err := jwt.NewUserClaims(k.issuerUserPub).Encode(k.authKP)
	if err != nil {
		t.Fatalf("issuer user jwt: %v", err)
	}
	seed, _ := k.issuerUserKP.Seed()
	creds, err := jwt.FormatUserConfig(issuerJWT, seed)
	if err != nil {
		t.Fatalf("issuer creds: %v", err)
	}
	path := filepath.Join(t.TempDir(), "issuer.creds")
	if err := os.WriteFile(path, creds, 0o600); err != nil {
		t.Fatalf("write issuer creds: %v", err)
	}
	return path
}

func writeServerConfig(t *testing.T, k *keyset) string {
	t.Helper()
	cfg := fmt.Sprintf(`
listen: 127.0.0.1:-1
operator: %s
system_account: %s
resolver: MEMORY
resolver_preload: {
  %s: %s,
  %s: %s,
  %s: %s,
}
jetstream { store_dir: %q }
`, k.opJWT, k.sysPub, k.sysPub, k.sysJWT, k.authPubAcc, k.authJWT, k.acmePubAcc, k.acmeJWT, t.TempDir())
	cfgPath := filepath.Join(t.TempDir(), "server.conf")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}
