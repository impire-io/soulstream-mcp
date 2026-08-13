package node

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// wellKnownPath is the RFC 9728 protected-resource metadata location.
const wellKnownPath = "/.well-known/oauth-protected-resource"

// serveMetadata answers the discovery document that steers a hosted client
// from "I know a URL" to "I know who to sign in with". Public mode only.
func (n *Node) serveMetadata(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":                 n.cfg.PublicURL,
		"authorization_servers":    []string{n.cfg.AuthIssuer},
		"bearer_methods_supported": []string{"header"},
	})
}

// unauthorized answers 401 with the WWW-Authenticate challenge pointing at
// the resource metadata — the entry point of the OAuth flow (FR-008). The
// body stays generic: cause detail belongs in the operator log, never on
// the wire.
func (n *Node) unauthorized(w http.ResponseWriter, errCode string) {
	c := fmt.Sprintf("Bearer resource_metadata=%q", n.cfg.PublicURL+wellKnownPath)
	if errCode != "" {
		c += fmt.Sprintf(", error=%q", errCode)
	}
	w.Header().Set("WWW-Authenticate", c)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
