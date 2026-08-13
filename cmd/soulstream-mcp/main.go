// Command soulstream-mcp serves the remote MCP door for one realm: a URL a
// hosted client connects to, bearer passthrough to the realm's admission
// edge, no credentials held. It binds plain HTTP — front it with an HTTPS
// terminator and set --public-url to the front's name.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	node "github.com/impire-io/soulstream-mcp"
)

// version is stamped by the release build (ldflags -X main.version=…).
var version = "dev"

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func main() {
	fs := flag.NewFlagSet("soulstream-mcp", flag.ExitOnError)
	listen := fs.String("listen", envOr("SOULSTREAM_NODE_LISTEN", "127.0.0.1:8080"), "HTTP bind address (front it with HTTPS; the node never terminates TLS)")
	publicURL := fs.String("public-url", envOr("SOULSTREAM_NODE_PUBLIC_URL", ""), "canonical fronted URL; enables the OAuth resource metadata and declares the proxy shape (empty = local mode)")
	issuer := fs.String("issuer", envOr("SOULSTREAM_NODE_ISSUER", ""), "external authorization server issuer URL (required with --public-url; must equal the issuer the admission edge validates)")
	realmName := fs.String("realm", envOr("SOULSTREAM_NODE_REALM", ""), "realm this node fronts (must already be provisioned)")
	natsURL := fs.String("nats-url", envOr("SOULSTREAM_NODE_NATS_URL", ""), "the realm's NATS server URL")
	sentinel := fs.String("sentinel-creds", envOr("SOULSTREAM_NODE_SENTINEL_CREDS", ""), "optional deny-all credentials file routing connections to the auth callout")
	prefix := fs.String("prefix", envOr("SOULSTREAM_NODE_PREFIX", ""), "identity plane subject prefix (must match the deployment; empty = the plane's default)")
	showVersion := fs.Bool("version", false, "print version and exit")
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Println(version)
		return
	}

	n, err := node.New(node.Config{
		Listen:       *listen,
		PublicURL:    *publicURL,
		AuthIssuer:   *issuer,
		Realm:        *realmName,
		NATSURL:      *natsURL,
		SentinelPath: *sentinel,
		Prefix:       *prefix,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer n.Close()

	mode := "local (static bearers only)"
	if *publicURL != "" {
		mode = "public (" + *publicURL + " → " + *issuer + ")"
	}
	fmt.Fprintf(os.Stderr, "soulstream-mcp %s: realm %q on %s, %s, listening on %s\n",
		version, *realmName, *natsURL, mode, *listen)

	if err := http.ListenAndServe(*listen, n.Handler()); err != nil { //nolint:gosec // timeouts are the fronting proxy's job; the node is never internet-bare
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
