// Package rigtest is the node's test rig: an in-process operator-mode NATS
// server with auth callout, the identity plane via soulstream-identity's public
// embed surface, and a minimal external authorization server.
//
// The AS stand-in below is written FROM the AS-facing contract ALONE
// (specs/018-remote-mcp-node/contracts/authorization-server.md) — that
// document, not any server's internals, is the interface it proves (SC-005).
package rigtest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// ASStub is a minimal conforming authorization server per the contract:
// OIDC discovery, a JWKS publishing RS256 keys (rotatable without plane
// restarts), and JWT access tokens carrying the contract's claims with the
// deployment's FIXED audience. The sign-in endpoints (DCR, authorize+PKCE,
// token) live in flow.go — together they are the full stand-in.
type ASStub struct {
	srv      *httptest.Server
	audience string

	mu      sync.Mutex
	key     *rsa.PrivateKey
	kid     int
	clients map[string]bool     // DCR-registered client ids
	codes   map[string]authCode // issued authorization codes
}

// NewASStub serves the stand-in. audience is the deployment's fixed value
// (contract §3: stamped on every access token regardless of client).
func NewASStub(audience string) (*ASStub, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	s := &ASStub{audience: audience, key: key, kid: 1, clients: map[string]bool{}, codes: map[string]authCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("/jwks", s.jwks)
	mux.HandleFunc("/register", s.register)   // DCR (RFC 7591)
	mux.HandleFunc("/authorize", s.authorize) // authorization-code + PKCE
	mux.HandleFunc("/token", s.token)
	s.srv = httptest.NewServer(mux)
	return s, nil
}

// Close shuts the stand-in's HTTP server down.
func (s *ASStub) Close() { s.srv.Close() }

// Issuer is the exact issuer string (contract §1: matched by string
// equality — no trailing-slash slack).
func (s *ASStub) Issuer() string { return s.srv.URL }

// Audience is the fixed audience this deployment configured.
func (s *ASStub) Audience() string { return s.audience }

// Rotate replaces the signing key and bumps the kid: per contract §3 the
// validator refetches JWKS on an unknown kid, so no restart is needed.
func (s *ASStub) Rotate() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key, s.kid = key, s.kid+1
	return nil
}

// Claims is the contract-§3 claim set for a person: oid (REQUIRED, a legal
// persona slug, stable per person), roles (exactly one should name a
// declared role), preferred_username (optional display, audit only).
// Callers may delete or override entries before minting.
func (s *ASStub) Claims(oid string, roles ...string) map[string]any {
	now := time.Now()
	c := map[string]any{
		"iss":                s.srv.URL,
		"aud":                s.audience,
		"oid":                oid,
		"sub":                "pairwise-" + oid,
		"preferred_username": oid + "@stub.example",
		"iat":                now.Unix(),
		"exp":                now.Add(5 * time.Minute).Unix(),
	}
	if len(roles) > 0 {
		c["roles"] = roles
	}
	return c
}

// Token mints an RS256 access token over the given claims (contract §3:
// a JWT, RS256 only).
func (s *ASStub) Token(claims map[string]any) (string, error) {
	s.mu.Lock()
	key, kid := s.key, s.kid
	s.mu.Unlock()
	return signRS256(key, fmt.Sprintf("k%d", kid), claims)
}

// TokenWrongKey mints with a key the JWKS never published — the signature
// check must refuse it.
func (s *ASStub) TokenWrongKey(claims map[string]any) (string, error) {
	rogue, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	return signRS256(rogue, "rogue", claims)
}

// TokenAlgNone mints an unsigned (alg=none) token — the alg-downgrade the
// validator must refuse (contract §3: RS256 only).
func (s *ASStub) TokenAlgNone(claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".", nil
}

func (s *ASStub) discovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                s.srv.URL,
		"jwks_uri":                              s.srv.URL + "/jwks",
		"authorization_endpoint":                s.srv.URL + "/authorize",
		"token_endpoint":                        s.srv.URL + "/token",
		"registration_endpoint":                 s.srv.URL + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (s *ASStub) jwks(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	pub, kid := &s.key.PublicKey, s.kid
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "alg": "RS256", "use": "sig",
			"kid": fmt.Sprintf("k%d", kid),
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}
