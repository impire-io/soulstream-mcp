package rigtest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The sign-in half of the AS stand-in, per contract §2: Dynamic Client
// Registration (RFC 7591) and the authorization-code + PKCE (S256) flow with
// no client secret for public clients. There is no UI — the "person" arrives
// as login_hint (their oid) plus a space-separated roles hint, which is the
// stand-in's stand-in for a login page.

type authCode struct {
	oid       string
	roles     []string
	clientID  string
	redirect  string
	challenge string
	expires   time.Time
}

func randomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// register implements DCR: a public client posts its redirect URIs and gets
// a client id — what makes "paste a URL" sufficient for hosted dialogs.
func (s *ASStub) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.RedirectURIs) == 0 {
		http.Error(w, "redirect_uris required", http.StatusBadRequest)
		return
	}
	id := "dcr-" + randomToken()
	s.mu.Lock()
	s.clients[id] = true
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"client_id":                  id,
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": "none", // public client, PKCE carries the proof
	})
}

// authorize issues a code bound to the PKCE challenge and the "signed-in"
// person, then redirects back — the login page compressed to a query param.
func (s *ASStub) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "authorization_code + PKCE S256 only", http.StatusBadRequest)
		return
	}
	clientID, redirect, challenge := q.Get("client_id"), q.Get("redirect_uri"), q.Get("code_challenge")
	oid := q.Get("login_hint")
	if clientID == "" || redirect == "" || challenge == "" || oid == "" {
		http.Error(w, "client_id, redirect_uri, code_challenge, login_hint required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	known := s.clients[clientID]
	s.mu.Unlock()
	if !known {
		http.Error(w, "unknown client — register first", http.StatusBadRequest)
		return
	}
	code := randomToken()
	var roles []string
	if rh := q.Get("roles_hint"); rh != "" {
		roles = strings.Fields(rh)
	}
	s.mu.Lock()
	s.codes[code] = authCode{
		oid: oid, roles: roles, clientID: clientID,
		redirect: redirect, challenge: challenge,
		expires: time.Now().Add(2 * time.Minute),
	}
	s.mu.Unlock()
	u, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	qq := u.Query()
	qq.Set("code", code)
	qq.Set("state", q.Get("state"))
	u.RawQuery = qq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// token exchanges a code + PKCE verifier for the access token, stamping the
// deployment's FIXED audience no matter which client asks (contract §3).
func (s *ASStub) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		http.Error(w, "authorization_code only", http.StatusBadRequest)
		return
	}
	code, verifier := r.PostForm.Get("code"), r.PostForm.Get("code_verifier")
	s.mu.Lock()
	ac, ok := s.codes[code]
	delete(s.codes, code)
	s.mu.Unlock()
	if !ok || time.Now().After(ac.expires) {
		http.Error(w, "unknown or expired code", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != ac.challenge {
		http.Error(w, "PKCE verification failed", http.StatusBadRequest)
		return
	}
	if got := r.PostForm.Get("redirect_uri"); got != "" && got != ac.redirect {
		http.Error(w, "redirect_uri mismatch", http.StatusBadRequest)
		return
	}
	tok, err := s.Token(s.Claims(ac.oid, ac.roles...))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   300,
	})
}

// signRS256 is the stand-in's whole JWT stack: header.payload signed with
// RSASSA-PKCS1-v1_5 over SHA-256 — the one alg the contract admits.
func signRS256(key *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
