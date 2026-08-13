package rigtest

import (
	"testing"

	"github.com/nats-io/nats.go"

	siclient "github.com/impire-io/soulstream-identity/client"

	"github.com/impire-io/soulstream-core/identity"
)

// DirectoryKeyring builds a reader keyring for personas from the IDENTITY
// PLANE's keys.public directory — NOT the soulstream profile registry. This
// is the architecture the node depends on: it publishes no soulstream
// profile; a reader verifies node-authored content from the identity plane
// (the vault is the realm's key directory). One keys.public answer per
// persona is enough.
func DirectoryKeyring(t *testing.T, r *Rig, personas ...string) *identity.Keyring {
	t.Helper()
	nc, err := nats.Connect(r.URL, nats.UserCredentials(r.readerCreds))
	if err != nil {
		t.Fatalf("directory connect: %v", err)
	}
	t.Cleanup(nc.Close)
	reader := siclient.New(nc, r.Account, "reader")
	keys := map[string][]string{}
	for _, p := range personas {
		pub, err := reader.PersonaPublicKey(p)
		if err != nil {
			t.Fatalf("keys.public %s: %v", p, err)
		}
		keys[p] = []string{pub}
	}
	return &identity.Keyring{Keys: keys}
}
