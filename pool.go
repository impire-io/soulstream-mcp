package node

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nats-io/nats.go"

	siclient "github.com/impire-io/soulstream-identity/client"

	"github.com/impire-io/soulstream-core/identity"
	"github.com/impire-io/soulstream-core/mcpserver"
	"github.com/impire-io/soulstream-core/realm"
	"github.com/impire-io/soulstream-core/registry"
)

// errSessionPrincipalMismatch: a request carried an established session id
// together with a bearer that admits as a DIFFERENT principal. Serving it
// would put one principal's request on another's session — refused instead;
// the client re-initializes with its own token.
var errSessionPrincipalMismatch = errors.New("node: session and bearer belong to different principals — re-initialize the session with your own token")

// pool holds one entry per admitted principal. The trust rule (FR-005): a
// bearer may influence an entry only after it has been ADMITTED for that
// entry's principal — by building it, or by a candidate probe. Routing hints
// are unverified and route only; nothing trust-shaped ever hangs off them.
type pool struct {
	cfg Config

	mu       sync.Mutex
	entries  map[string]*entry // routing key (hint or principal alias) → entry
	byBearer map[string]*entry // admitted bearer → its entry
	sessions map[string]*entry // MCP session id → the entry that admitted it
}

// entry is one admitted principal's pooled state. latest always holds the
// freshest ADMITTED bearer; the NATS TokenHandler reads it on every
// (re)connect attempt, which is the whole re-proof mechanism.
type entry struct {
	pool *pool
	keys []string // routing keys pointing at this entry, for eviction

	latest atomic.Pointer[string]
	build  sync.Once
	err    error

	nc      *nats.Conn
	rc      *realm.Client
	server  *mcp.Server
	persona string
	account string

	// admitted is the short tail of bearers proven for this principal
	// (freshest last); an aged-out bearer simply re-probes.
	admitted []string

	// pins is the in-memory TOFU pin state backing the keyring provider —
	// per principal, never on disk (the node writes no files).
	pinsMu sync.Mutex
	pins   map[string][]string
}

func newPool(cfg Config) *pool {
	return &pool{
		cfg:      cfg,
		entries:  map[string]*entry{},
		byBearer: map[string]*entry{},
		sessions: map[string]*entry{},
	}
}

// bearerFrom extracts the one credential lane: Authorization: Bearer <token>.
func bearerFrom(rHeader string) string {
	if rest, ok := strings.CutPrefix(rHeader, "Bearer "); ok {
		return rest
	}
	return ""
}

// routeHint keys the pool WITHOUT verifying anything: for a JWT-shaped token
// the unverified issuer+subject claims, for anything else the token string
// itself. Routing only — correctness never depends on it (FR-004).
func routeHint(bearer string) string {
	if !strings.HasPrefix(bearer, "eyJ") {
		return "tok:" + bearer
	}
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return "tok:" + bearer
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "tok:" + bearer
	}
	var claims struct {
		OID string `json:"oid"`
		Sub string `json:"sub"`
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "tok:" + bearer
	}
	id := claims.OID
	if id == "" {
		id = claims.Sub
	}
	return "oidc:" + claims.Iss + ":" + id
}

// hintClass is what logs may say about a hint — its shape, never its content.
func hintClass(hint string) string {
	if strings.HasPrefix(hint, "oidc:") {
		return "oidc"
	}
	if strings.HasPrefix(hint, "pri:") {
		return "principal"
	}
	return "opaque"
}

// resolve is the R4 state machine: bearer (+ optional established session id)
// → the entry that may serve it, or a refusal. Every path that lets a bearer
// touch an entry's state runs through an admission first.
func (p *pool) resolve(bearer, sid string) (*entry, error) {
	p.mu.Lock()

	// A request on an established session must present a bearer belonging to
	// that session's principal — the session is bound to its entry for life.
	if sid != "" {
		if bound, ok := p.sessions[sid]; ok {
			if !aliveLocked(bound) {
				p.evictLocked(bound)
			} else {
				if bound.isAdmittedLocked(bearer) {
					p.mu.Unlock()
					bound.adopt(bearer) // the refresh path: bound session, admitted bearer
					return bound, nil
				}
				if other, ok := p.byBearer[bearer]; ok && other != bound {
					p.mu.Unlock()
					return nil, errSessionPrincipalMismatch
				}
				p.mu.Unlock()
				return p.candidateForBound(bearer, bound)
			}
		}
	}

	// An already-admitted bearer goes straight to its entry.
	if e, ok := p.byBearer[bearer]; ok {
		if aliveLocked(e) {
			p.bindLocked(sid, e)
			p.mu.Unlock()
			e.adopt(bearer)
			return e, nil
		}
		p.evictLocked(e)
	}

	// Route by hint. A corpse on the hint is evicted first — refusals are
	// non-sticky, and nats.go closes a connection for good after consecutive
	// authorization violations (an expired or revoked badge).
	hint := routeHint(bearer)
	e, ok := p.entries[hint]
	if ok && !aliveLocked(e) {
		p.evictLocked(e)
		ok = false
	}
	if !ok {
		// First sight of this hint: the build IS the admission probe. A
		// garbage token builds an entry only its presenter routes to; the
		// refusal is logged, the corpse evicted on next touch.
		e = p.newEntryLocked(hint, bearer)
	}
	if e.sameLatest(bearer) {
		p.mu.Unlock()
		e.build.Do(func() { e.err = e.connect() })
		if e.err != nil {
			p.mu.Lock()
			p.evictLocked(e)
			p.mu.Unlock()
			p.logRefused(hint, e.err)
			return nil, e.err
		}
		p.mu.Lock()
		e.admitLocked(bearer)
		p.bindLocked(sid, e)
		p.mu.Unlock()
		return e, nil
	}
	p.mu.Unlock()

	// A live entry and a bearer it has never admitted: the candidate probe —
	// the entry stays untouched unless the bearer proves the SAME principal.
	return p.candidate(bearer, sid, e)
}

// candidate handles an unbound request whose bearer differs from everything
// a live entry has admitted. Only an admission (the probe) may adopt it; a
// different principal is served via their OWN entry, the imitated one
// untouched (FR-005).
func (p *pool) candidate(bearer, sid string, e *entry) (*entry, error) {
	persona, account, err := p.probe(bearer)
	if err != nil {
		p.logRefused(routeHint(bearer), err)
		return nil, err
	}
	if persona == e.persona && account == e.account {
		p.mu.Lock()
		e.admitLocked(bearer)
		p.bindLocked(sid, e)
		p.mu.Unlock()
		e.adopt(bearer)
		p.logf("probe adopted fresh bearer", e)
		return e, nil
	}
	// A colliding or forged hint: the bearer's true principal gets their own
	// entry under a principal-keyed alias; the imitated entry never noticed.
	p.logf("probe diverted colliding hint", &entry{persona: persona, account: account})
	own, err := p.ensurePrincipal(bearer, persona, account)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	own.admitLocked(bearer)
	p.bindLocked(sid, own)
	p.mu.Unlock()
	own.adopt(bearer)
	return own, nil
}

// candidateForBound is the refresh probe for an established session: the new
// bearer must prove the SAME principal the session is bound to.
func (p *pool) candidateForBound(bearer string, bound *entry) (*entry, error) {
	persona, account, err := p.probe(bearer)
	if err != nil {
		p.logRefused("session-refresh", err)
		return nil, err
	}
	if persona != bound.persona || account != bound.account {
		return nil, errSessionPrincipalMismatch
	}
	p.mu.Lock()
	bound.admitLocked(bearer)
	p.mu.Unlock()
	bound.adopt(bearer)
	p.logf("probe adopted fresh bearer", bound)
	return bound, nil
}

// ensurePrincipal builds (or returns) the entry for a probe-proven principal,
// keyed by principal — the landing place for colliding hints.
func (p *pool) ensurePrincipal(bearer, persona, account string) (*entry, error) {
	key := "pri:" + account + ":" + persona
	p.mu.Lock()
	own, ok := p.entries[key]
	if ok && !aliveLocked(own) {
		p.evictLocked(own)
		ok = false
	}
	if !ok {
		own = p.newEntryLocked(key, bearer)
	}
	p.mu.Unlock()
	own.build.Do(func() { own.err = own.connect() })
	if own.err != nil {
		p.mu.Lock()
		p.evictLocked(own)
		p.mu.Unlock()
		p.logRefused(key, own.err)
		return nil, own.err
	}
	return own, nil
}

// probe dials a short-lived connection with the candidate bearer: admission
// evidence, nothing else. No reconnects, closed before returning.
func (p *pool) probe(bearer string) (persona, account string, err error) {
	opts := []nats.Option{
		nats.TokenHandler(func() string { return bearer }),
		nats.Timeout(5 * time.Second),
		nats.MaxReconnects(0),
	}
	if p.cfg.SentinelPath != "" {
		opts = append(opts, nats.UserCredentials(p.cfg.SentinelPath))
	}
	nc, err := nats.Connect(p.cfg.NATSURL, opts...)
	if err != nil {
		return "", "", fmt.Errorf("admission refused: %w", err)
	}
	defer nc.Close()
	return principalOf(nc, p.cfg.root())
}

// serverFor is the StreamableHTTPHandler hook. Read-only by design: resolve()
// in the HTTP front is the only builder, so the SDK can never trigger an
// admission on its own.
func (p *pool) serverFor(bearer string) *mcp.Server {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.byBearer[bearer]; ok && aliveLocked(e) {
		return e.server
	}
	return nil
}

// bindSession records which entry an SDK-created session belongs to (captured
// from the initialize response).
func (p *pool) bindSession(sid string, e *entry) {
	p.mu.Lock()
	p.bindLocked(sid, e)
	p.mu.Unlock()
}

// close drains everything — restart is free, so this is just tidiness.
func (p *pool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	seen := map[*entry]bool{}
	for _, e := range p.entries {
		if !seen[e] {
			seen[e] = true
			e.shutdown()
		}
	}
	p.entries = map[string]*entry{}
	p.byBearer = map[string]*entry{}
	p.sessions = map[string]*entry{}
}

// --- locked helpers (p.mu held) ---

func aliveLocked(e *entry) bool {
	return e.err == nil && (e.nc == nil || !e.nc.IsClosed())
}

func (p *pool) newEntryLocked(key, bearer string) *entry {
	e := &entry{pool: p, keys: []string{key}, pins: map[string][]string{}}
	e.latest.Store(&bearer)
	p.entries[key] = e
	return e
}

func (p *pool) bindLocked(sid string, e *entry) {
	if sid == "" {
		return
	}
	if _, taken := p.sessions[sid]; !taken {
		p.sessions[sid] = e
	}
}

func (p *pool) evictLocked(e *entry) {
	for _, k := range e.keys {
		if p.entries[k] == e {
			delete(p.entries, k)
		}
	}
	for _, b := range e.admitted {
		if p.byBearer[b] == e {
			delete(p.byBearer, b)
		}
	}
	for sid, bound := range p.sessions {
		if bound == e {
			delete(p.sessions, sid)
		}
	}
	e.shutdown()
	if e.persona != "" {
		p.cfg.Logger.Info("node: evicted", "persona", e.persona, "account", e.account)
	}
}

func (e *entry) isAdmittedLocked(bearer string) bool {
	for _, b := range e.admitted {
		if b == bearer {
			return true
		}
	}
	return false
}

// admitLocked records a proven bearer, keeping a short tail — an aged-out
// bearer is merely re-probed, never trusted from memory.
func (e *entry) admitLocked(bearer string) {
	if e.isAdmittedLocked(bearer) {
		return
	}
	e.admitted = append(e.admitted, bearer)
	e.pool.byBearer[bearer] = e
	const keep = 2
	for len(e.admitted) > keep {
		drop := e.admitted[0]
		e.admitted = e.admitted[1:]
		if e.pool.byBearer[drop] == e {
			delete(e.pool.byBearer, drop)
		}
	}
}

// --- entry (no pool lock) ---

func (e *entry) sameLatest(bearer string) bool {
	if p := e.latest.Load(); p != nil {
		return *p == bearer
	}
	return false
}

// adopt makes an ADMITTED bearer the one the TokenHandler presents next.
// Callers guarantee admission; nothing else may call this.
func (e *entry) adopt(bearer string) {
	e.latest.Store(&bearer)
}

// connect builds the entry: admit at the NATS edge, derive the principal
// server-side, wire the delegated signer, open the realm client, build the
// per-principal tool surface. Any failure marks the entry a corpse.
func (e *entry) connect() error {
	cfg := e.pool.cfg
	opts := []nats.Option{
		nats.TokenHandler(func() string {
			if p := e.latest.Load(); p != nil {
				return *p
			}
			return ""
		}),
		nats.ReconnectWait(200 * time.Millisecond),
		nats.MaxReconnects(-1),
	}
	if cfg.SentinelPath != "" {
		opts = append(opts, nats.UserCredentials(cfg.SentinelPath))
	}
	nc, err := nats.Connect(cfg.NATSURL, opts...)
	if err != nil {
		return fmt.Errorf("admission refused: %w", err)
	}
	persona, account, err := principalOf(nc, cfg.root())
	if err != nil {
		nc.Close()
		return err
	}
	// The 017 seam: signing delegated to the identity plane on the USER'S OWN
	// connection — the key materialises in the vault on first touch and the
	// node never sees it. Construction fails fast on a mis-owned persona.
	signer, err := siclient.New(nc, account, persona, siclient.WithPrefix(cfg.Prefix)).PersonaSigner(persona)
	if err != nil {
		nc.Close()
		return fmt.Errorf("persona signer for %s: %w", persona, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rc, err := realm.NewClient(ctx, nc, realm.Config{Realm: cfg.Realm, Persona: persona, Signer: signer})
	if err != nil {
		nc.Close()
		return fmt.Errorf("realm client: %w", err)
	}
	// The node never provisions (a minted user's scope may not even allow
	// it); an unprovisioned realm is the operator's to fix — say so.
	if _, err := rc.JetStream().Stream(ctx, realm.StreamName); err != nil {
		_ = rc.Close()
		return fmt.Errorf("realm %q is not provisioned on this server (stream %s: %v) — provision it once with `soulstream provision`; the node never provisions", cfg.Realm, realm.StreamName, err)
	}
	e.nc, e.rc, e.persona, e.account = nc, rc, persona, account
	e.server = mcpserver.NewServer(rc, mcpserver.WithKeyring(e.keyringFor))
	cfg.Logger.Info("node: admitted", "persona", persona, "account", account, "hint_class", hintClass(e.keys[0]))
	return nil
}

// keyringFor is the entry's reader-verification provider: the realm's
// directory plus in-memory TOFU pins — the multi-principal replacement for
// the pins file. Failures degrade to no keyring; verification never blocks
// a read.
func (e *entry) keyringFor(ctx context.Context) (*identity.Keyring, error) {
	profiles, _, err := registry.All(ctx, e.rc)
	if err != nil {
		return nil, nil //nolint:nilerr // degrade to unknown-key, per the surface contract
	}
	e.pinsMu.Lock()
	defer e.pinsMu.Unlock()
	kr, newPins := registry.BuildKeyring(profiles, e.pins)
	e.pins = newPins
	return kr, nil
}

func (e *entry) shutdown() {
	if e.rc != nil {
		_ = e.rc.Close()
	} else if e.nc != nil {
		e.nc.Close()
	}
}

// --- logging (token material never appears here) ---

func (p *pool) logRefused(context string, err error) {
	p.cfg.Logger.Info("node: refused", "route", hintClass(context), "cause", err.Error())
}

func (p *pool) logf(event string, e *entry) {
	p.cfg.Logger.Info("node: "+event, "persona", e.persona, "account", e.account)
}
