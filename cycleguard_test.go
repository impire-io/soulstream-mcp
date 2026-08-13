package node_test

import (
	"os"
	"strings"
	"testing"
)

// TestCycleGuard (T037): the dependency rule that makes the adapter position
// safe (FR-014). This module imports BOTH core repos; neither core repo
// imports the other or this one — soulstream's 017 rule. Since the
// extraction to a standalone repository (soul-hq episode 0069), the
// core-side halves of the guard are enforced structurally — a core repo
// could only import this module through a pin its own gate would surface —
// so what remains asserted here is the adapter position itself.
func TestCycleGuard(t *testing.T) {
	b, err := os.ReadFile("./go.mod")
	if err != nil {
		t.Fatalf("read ./go.mod: %v", err)
	}
	nm := string(b)
	for _, want := range []string{"impire-io/soulstream-identity", "impire-io/soulstream-core"} {
		if !strings.Contains(nm, want) {
			t.Errorf("go.mod is missing %q — this module is the consumer of both", want)
		}
	}
}
