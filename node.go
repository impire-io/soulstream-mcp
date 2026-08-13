package node

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// sessionHeader is the streamable-HTTP session id header (MCP spec).
const sessionHeader = "Mcp-Session-Id"

// Node is the remote MCP door: one HTTP handler, one pool, no custody.
type Node struct {
	cfg   Config
	pool  *pool
	inner http.Handler
}

// New validates cfg and returns a ready-to-serve node. It does not listen —
// the binary wraps Handler in a server; embedders mount it on their own mux.
// It also does not connect anywhere: the node holds no credentials, so the
// first realm contact happens when the first bearer arrives.
func New(cfg Config) (*Node, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	n := &Node{cfg: cfg, pool: newPool(cfg)}
	// A PublicURL means an HTTPS front (reverse proxy) is the deployment
	// shape: requests reach the bind address carrying the public Host, which
	// the SDK's DNS-rebinding guard would 403. Setting PublicURL declares the
	// front, so the guard yields to it (FR-012).
	n.inner = mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server {
			return n.pool.serverFor(bearerFrom(r.Header.Get("Authorization")))
		},
		&mcp.StreamableHTTPOptions{DisableLocalhostProtection: cfg.PublicURL != ""},
	)
	return n, nil
}

// Handler returns the node's whole HTTP surface: the MCP endpoint plus, in
// public mode, the protected-resource metadata.
func (n *Node) Handler() http.Handler { return n }

// Close drains the pool: every pooled connection and realm client. Restart
// is free — there is nothing else to keep.
func (n *Node) Close() { n.pool.close() }

// ServeHTTP is the front door: metadata route, badge extraction, admission
// (the R4 state machine), then the streamable MCP handler. The SDK handler
// never triggers admissions itself — serverFor is read-only.
func (n *Node) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	public := n.cfg.PublicURL != ""
	if public && r.URL.Path == wellKnownPath {
		n.serveMetadata(w)
		return
	}
	bearer := bearerFrom(r.Header.Get("Authorization"))
	if bearer == "" {
		if public {
			n.unauthorized(w, "")
			return
		}
		n.inner.ServeHTTP(w, r) // nil server → the SDK's bare 400 (local mode)
		return
	}
	e, err := n.pool.resolve(bearer, r.Header.Get(sessionHeader))
	if err != nil {
		if public {
			n.unauthorized(w, "invalid_token")
			return
		}
		n.inner.ServeHTTP(w, r)
		return
	}
	if r.Header.Get(sessionHeader) == "" {
		// A session is being created: capture the id the SDK mints on the
		// initialize response and bind it to the entry that admitted it.
		w = &sessionCapture{ResponseWriter: w, pool: n.pool, entry: e}
	}
	n.inner.ServeHTTP(w, r)
}

// sessionCapture binds the SDK-minted session id (on the initialize
// response) to the entry whose admission created it.
type sessionCapture struct {
	http.ResponseWriter
	pool  *pool
	entry *entry
	done  bool
}

func (s *sessionCapture) capture() {
	if s.done {
		return
	}
	s.done = true
	if sid := s.Header().Get(sessionHeader); sid != "" {
		s.pool.bindSession(sid, s.entry)
	}
}

func (s *sessionCapture) WriteHeader(code int) {
	s.capture()
	s.ResponseWriter.WriteHeader(code)
}

func (s *sessionCapture) Write(b []byte) (int, error) {
	s.capture()
	return s.ResponseWriter.Write(b)
}

// Flush keeps the SDK's SSE streaming working through the wrapper.
func (s *sessionCapture) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *sessionCapture) Unwrap() http.ResponseWriter { return s.ResponseWriter }
