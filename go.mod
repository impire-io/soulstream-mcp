module github.com/impire-io/soulstream-mcp

go 1.26.2

// The node pins the tagged soulstream that carries its mcpserver surface —
// v0.7.0 IS the change-set this module landed with, so the original
// same-change-set concern is answered by the tag itself. No replace: the
// module is consumable by downstream compositions (soulstream is the first).
// Co-developing against an unreleased soulstream rides an untracked go.work,
// the discipline soulrealm and the e2e modules already live by.

require (
	github.com/impire-io/soulstream-core v0.8.0
	github.com/impire-io/soulstream-identity v0.2.0
	github.com/modelcontextprotocol/go-sdk v1.6.1
	github.com/nats-io/jwt/v2 v2.8.2
	github.com/nats-io/nats-server/v2 v2.14.3
	github.com/nats-io/nats.go v1.52.0
	github.com/nats-io/nkeys v0.4.16
	github.com/synadia-io/control-plane-sdk-go v0.9.0
	github.com/synadia-io/orbit.go/natscontext v0.1.3
)

require (
	github.com/antithesishq/antithesis-sdk-go v0.7.0-default-no-op // indirect
	github.com/coreos/go-oidc/v3 v3.20.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gowebpki/jcs v1.0.1 // indirect
	github.com/klauspost/compress v1.19.1 // indirect
	github.com/minio/highwayhash v1.0.4 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)
