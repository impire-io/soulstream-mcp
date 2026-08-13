package node

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	siclient "github.com/impire-io/soulstream-identity/client"
)

// Config is everything the node durably knows — deliberately small enough to
// reason about at a glance. Nothing here is credential-shaped: the sentinel
// file routes connections to the admission edge and grants nothing by itself.
type Config struct {
	// Listen is the HTTP bind address. The binary defaults it to
	// 127.0.0.1:8080; the library requires the caller to choose.
	Listen string

	// PublicURL is the canonical fronted URL (an HTTPS terminator's public
	// name). Setting it switches on public mode: the OAuth resource metadata,
	// the 401 challenge, and the declared proxy shape. Empty is local mode —
	// static bearers only, no OAuth story.
	PublicURL string

	// AuthIssuer is the external authorization server's issuer URL, advertised
	// in the resource metadata. Required in public mode; it MUST equal the
	// issuer the admission edge validates, or clients will authenticate
	// against a server whose tokens the realm refuses.
	AuthIssuer string

	// Realm is the realm this node fronts. Required. The realm must already
	// be provisioned — the node never provisions.
	Realm string

	// NATSURL is the realm's NATS server. Required.
	NATSURL string

	// SentinelPath optionally names a deny-all credentials file that routes
	// connections to the auth callout on operator-mode deployments.
	SentinelPath string

	// Prefix is the identity plane's shared subject prefix (its D14). Empty
	// means the bare default; a mismatch with the deployment surfaces as
	// request timeouts, so the value is part of the deployment contract.
	Prefix string

	// Logger receives admission/refusal/eviction/probe events, keyed by
	// principal and hint class — never token material. Default: slog text on
	// stderr.
	Logger *slog.Logger
}

// root is the identity plane's subject root as this deployment addresses it.
func (c Config) root() string {
	if c.Prefix == "" {
		return siclient.Segment
	}
	return c.Prefix + "." + siclient.Segment
}

// validate refuses a config that cannot work, naming the field and the fix —
// pre-listen, so a misdeployment never half-serves.
func (c Config) validate() error {
	if c.Listen == "" {
		return errors.New("node: Listen is required (the HTTP bind address, e.g. 127.0.0.1:8080)")
	}
	if c.Realm == "" {
		return errors.New("node: Realm is required (the realm this node fronts)")
	}
	if c.NATSURL == "" {
		return errors.New("node: NATSURL is required (the realm's NATS server)")
	}
	if c.PublicURL != "" {
		if c.AuthIssuer == "" {
			return errors.New("node: public mode (PublicURL set) requires AuthIssuer — the resource metadata must name the authorization server hosted clients sign in against")
		}
		if strings.HasSuffix(c.PublicURL, "/") {
			return fmt.Errorf("node: PublicURL %q must not end in a slash — it is the canonical resource identifier", c.PublicURL)
		}
	}
	if c.AuthIssuer != "" && c.PublicURL == "" {
		return errors.New("node: AuthIssuer without PublicURL — the OAuth edge only exists in public mode; set PublicURL or drop AuthIssuer")
	}
	return nil
}
