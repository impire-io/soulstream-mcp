// Command byon-setup configures auth callout on a Synadia Cloud BYON via the
// Cloud API — scripted: the control (AUTH) account, the programmatic scoped
// signing keys (their seeds are shown exactly once — this tool is that once,
// writing them 0600 for the vault import), the callout wiring, and the issuer
// user's creds.
//
// BEST-EFFORT OPERATOR TOOLING, not a product surface of the node (spec 018
// Q2): it targets Synadia Cloud specifically and is not covered by the
// module's tests. The represented-user scope it provisions must match the
// deployment requirement in
// specs/018-remote-mcp-node/contracts/authorization-server.md §6 and
// research R7.
//
// Usage:
//
//	SYNADIA_PAT=uat_… go run ./cmd/byon-setup --system dev-impire-platform          # discover, print a plan
//	SYNADIA_PAT=uat_… go run ./cmd/byon-setup --system dev-impire-platform --apply  # do it
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/synadia-io/control-plane-sdk-go/syncp"
)

// The represented-user scope: identical to the rig's template
// (rig_test.go) — SoulIdentity user ops on the own prefix, the Soulstream
// realm's subject space, and the user-info request the node derives the
// principal from.
func userScope() *syncp.UserPermissionLimits {
	return &syncp.UserPermissionLimits{
		Permissions: syncp.Permissions{
			Pub: &syncp.Permission{Allow: []string{
				"identity.status", "identity.xkey",
				"identity.{{account-subject()}}.{{name()}}.sign.record",
				"identity.{{account-subject()}}.{{name()}}.keys.public",
				"SOULSTREAM.>", "$JS.API.>", "$KV.>", "$O.>",
				"$SYS.REQ.USER.INFO",
			}},
			Sub: &syncp.Permission{Allow: []string{"_INBOX.>", "SOULSTREAM.>"}},
		},
	}
}

func main() {
	baseURL := flag.String("base-url", "https://cloud.synadia.com", "Synadia Cloud base URL")
	systemName := flag.String("system", "", "system name (substring match, required)")
	appAccount := flag.String("app-account", "", "app/team account name (substring; defaults to the only non-system account)")
	controlName := flag.String("control-account", "AUTH", "control account name (created when missing)")
	outDir := flag.String("out", "byon-secrets", "directory for seeds and creds (created 0700)")
	apply := flag.Bool("apply", false, "perform the changes (default: discover and print the plan)")
	flag.Parse()

	pat := os.Getenv("SYNADIA_PAT")
	if pat == "" {
		log.Fatal("byon-setup: SYNADIA_PAT is required (mint one at " + *baseURL + "/profile/personal-access-tokens)")
	}
	if *systemName == "" {
		log.Fatal("byon-setup: --system is required")
	}

	client := syncp.NewAPIClient(syncp.NewConfiguration())
	ctx := context.WithValue(context.Background(), syncp.ContextServerVariables, map[string]string{"baseUrl": *baseURL})
	ctx = context.WithValue(ctx, syncp.ContextAccessToken, pat)

	// --- Discovery: team → system → accounts.
	teams, _, err := client.SessionAPI.ListTeams(ctx).Execute()
	fatal("list teams", err)
	var system *syncp.SystemViewResponse
	for _, team := range teams.Items {
		systems, _, err := client.TeamAPI.ListTeamSystems(ctx, team.Id).Execute()
		fatal("list systems for team "+team.Name, err)
		for i, s := range systems.Items {
			log.Printf("team %q: system %q (id %s)", team.Name, s.Name, s.Id)
			if strings.Contains(strings.ToLower(s.Name), strings.ToLower(*systemName)) {
				system = &systems.Items[i]
			}
		}
	}
	if system == nil {
		log.Fatalf("byon-setup: no system matching %q", *systemName)
	}
	log.Printf("using system %q (id %s)", system.Name, system.Id)

	accounts, _, err := client.SystemAPI.ListAccounts(ctx, system.Id).Execute()
	fatal("list accounts", err)
	var app, control *syncp.AccountViewResponse
	for i, a := range accounts.Items {
		pub := ""
		if a.AccountPublicKey != nil {
			pub = *a.AccountPublicKey
		}
		log.Printf("account %q (id %s, key %s, system=%v)", a.Name, a.Id, pub, a.IsSystemAccount)
		switch {
		case strings.EqualFold(a.Name, *controlName):
			control = &accounts.Items[i]
		case *appAccount != "" && strings.Contains(strings.ToLower(a.Name), strings.ToLower(*appAccount)):
			app = &accounts.Items[i]
		case *appAccount == "" && !a.IsSystemAccount && !strings.EqualFold(a.Name, *controlName) && app == nil:
			app = &accounts.Items[i]
		}
	}
	if app == nil {
		log.Fatal("byon-setup: no app account found (use --app-account)")
	}
	log.Printf("app account: %q (id %s)", app.Name, app.Id)
	if control != nil {
		log.Printf("control account: %q (id %s) — exists", control.Name, control.Id)
	} else {
		log.Printf("control account: %q — will be created", *controlName)
	}

	if !*apply {
		log.Print("plan: 1) ensure control account  2) programmatic scoped sk group on app + sk group on control (seeds → --out)  3) enable callout  4) add target account  5) issuer user + callout user + creds. Re-run with --apply.")
		return
	}

	// --- Apply.
	fatal("mkdir "+*outDir, os.MkdirAll(*outDir, 0o700))

	if control == nil {
		created, _, err := client.SystemAPI.CreateAccount(ctx, system.Id).
			AccountCreateRequest(syncp.AccountCreateRequest{Name: *controlName}).Execute()
		fatal("create control account", err)
		control = created
		log.Printf("created control account %q (id %s)", control.Name, control.Id)
	}

	appSk := ensureSkGroup(ctx, client, app.Id, "soulstream-user", userScope(), *outDir)
	ctrlSk := ensureSkGroup(ctx, client, control.Id, "soulstream-auth-issuer", nil, *outDir)

	// Enable callout for the system, naming the control account. Tolerate
	// "already enabled" — re-runs must not fail here.
	if _, err := client.SystemAPI.EnableAuthCallout(ctx, system.Id).
		AuthCalloutEnableRequest(syncp.AuthCalloutEnableRequest{ControlAccount: control.Id}).Execute(); err != nil {
		log.Printf("enable auth callout: %v (continuing — may already be enabled)", err)
	} else {
		log.Print("auth callout enabled")
	}

	// The callout object has its own id: list the system's callout configs
	// and pick the one naming our control account. XkeyPublic matters: if the
	// platform sets one, callout requests are sealed to it and OUR issuer
	// needs its seed — a blocker to surface loudly, not discover in silence.
	configs, _, err := client.SystemAPI.ListAuthCalloutConfigs(ctx, system.Id).Execute()
	fatal("list auth callout configs", err)
	calloutID := ""
	for _, c := range configs.Items {
		if c.ControlAccountId == control.Id {
			calloutID = c.Id
			if c.XkeyPublic != nil && *c.XkeyPublic != "" {
				log.Printf("NOTE: callout xkey is set by the platform (%s) — the issuer needs its seed to decrypt requests", *c.XkeyPublic)
			} else {
				log.Print("callout config has no xkey — requests arrive unsealed (signed by the server)")
			}
		}
	}
	if calloutID == "" {
		log.Fatalf("byon-setup: no callout config for control account %s after enable", control.Id)
	}
	if view, _, err := client.AuthCalloutAPI.GetAuthCallout(ctx, calloutID).Execute(); err != nil {
		log.Printf("get auth callout (%s): %v", calloutID, err)
	} else {
		log.Printf("auth callout %s: %d target account(s), %d user(s)", calloutID, len(view.TargetAccounts), len(view.Users))
	}

	if _, err := client.AuthCalloutAPI.AddAuthCalloutTargetAccount(ctx, calloutID).
		AuthCalloutAddTargetAccountRequest(syncp.AuthCalloutAddTargetAccountRequest{
			AccountId:               app.Id,
			SkGroupId:               appSk,
			ControlAccountSkGroupId: ctrlSk,
		}).Execute(); err != nil {
		log.Printf("add target account: %v (continuing — may already be configured)", err)
	} else {
		log.Printf("target account wired: app sk-group %s, control sk-group %s", appSk, ctrlSk)
	}

	// The issuer's NATS user lives in the control account; registering it as
	// a callout user puts it in auth_users (it may listen on
	// $SYS.REQ.USER.AUTH). Its creds are what soulstream-identity serve's
	// --callout-creds takes. The platform refuses users under programmatic
	// sk groups, so the issuer gets an on-demand group of its own.
	issuerSk := ensureOnDemandSkGroup(ctx, client, control.Id, "auth-users")
	issuerID := ensureNatsUser(ctx, client, control.Id, "soulstream-identity-issuer", issuerSk)
	if _, err := client.AuthCalloutAPI.AddAuthCalloutUser(ctx, calloutID).
		AuthCalloutAddUserRequest(syncp.AuthCalloutAddUserRequest{NatsUserId: issuerID}).Execute(); err != nil {
		log.Printf("add callout user: %v (continuing — may already be registered)", err)
	} else {
		log.Print("issuer registered as callout user")
	}
	creds, _, err := client.NatsUserAPI.DownloadNatsUserCreds(ctx, issuerID).Execute()
	fatal("download issuer creds", err)
	credsPath := filepath.Join(*outDir, "auth-issuer.creds")
	fatal("write issuer creds", os.WriteFile(credsPath, []byte(creds), 0o600))

	ctrlPub := ""
	if control.AccountPublicKey != nil {
		ctrlPub = *control.AccountPublicKey
	}
	appPub := ""
	if app.AccountPublicKey != nil {
		appPub = *app.AccountPublicKey
	}
	fmt.Printf(`
byon-setup: done. Next (any tailnet machine; xkey seeds via soulstream-identity keygen):

  soulstream-identity serve --context impire-dev-platform \
    --callout-creds %s --auth-account %s --callout-ttl 5m

  soulstream-identity key import --context impire-dev-platform --as %s/<your-user> \
    --name acme --kind nats-account-signing-key --seed-file %s --account %s
  soulstream-identity key import --context impire-dev-platform --as %s/<your-user> \
    --name auth/issuer --kind nats-account-signing-key --seed-file %s --account %s
  soulstream-identity token create --context impire-dev-platform --as %s/<your-user> \
    --account %s --user daan --label "claude desktop"
  soulstream-identity sentinel --context impire-dev-platform --as %s/<your-user> > sentinel.creds
`,
		credsPath, ctrlPub,
		appPub, filepath.Join(*outDir, "sk-soulstream-user.seed"), appPub,
		appPub, filepath.Join(*outDir, "sk-soulstream-auth-issuer.seed"), ctrlPub,
		appPub, appPub,
		appPub)
}

// ensureSkGroup finds a signing key group by name or creates it programmatic
// (the seed is returned exactly once — written to outDir before anything
// else can fail).
func ensureSkGroup(ctx context.Context, client *syncp.APIClient, accountID, name string, scope *syncp.UserPermissionLimits, outDir string) string {
	existing, _, err := client.AccountAPI.ListAccountSkGroup(ctx, accountID).Execute()
	fatal("list sk groups", err)
	for _, g := range existing.Items {
		if g.Name == name {
			log.Printf("sk group %q exists (id %s) — reusing; its seed was shown at creation and is NOT re-fetchable (rotate it if the seed is lost)", name, g.Id)
			return g.Id
		}
	}
	req := syncp.SigningKeyGroupCreateRequest{Name: name, Programmatic: true}
	if scope != nil {
		req.Scope = scope
	}
	created, _, err := client.AccountAPI.CreateAccountSkGroup(ctx, accountID).
		SigningKeyGroupCreateRequest(req).Execute()
	fatal("create sk group "+name, err)
	if created.Seed == nil || *created.Seed == "" {
		log.Fatalf("sk group %q created but no seed returned — cannot custody it", name)
	}
	seedPath := filepath.Join(outDir, "sk-"+name+".seed")
	fatal("write seed "+seedPath, os.WriteFile(seedPath, []byte(*created.Seed), 0o600))
	log.Printf("created sk group %q (id %s); seed → %s", name, created.Id, seedPath)
	return created.Id
}

// ensureOnDemandSkGroup finds or creates a NON-programmatic sk group — the
// kind the platform allows NATS users under (its seed stays with Synadia).
func ensureOnDemandSkGroup(ctx context.Context, client *syncp.APIClient, accountID, name string) string {
	existing, _, err := client.AccountAPI.ListAccountSkGroup(ctx, accountID).Execute()
	fatal("list sk groups", err)
	for _, g := range existing.Items {
		if g.Name == name && !g.Programmatic {
			log.Printf("on-demand sk group %q exists (id %s)", name, g.Id)
			return g.Id
		}
	}
	created, _, err := client.AccountAPI.CreateAccountSkGroup(ctx, accountID).
		SigningKeyGroupCreateRequest(syncp.SigningKeyGroupCreateRequest{Name: name, Programmatic: false}).Execute()
	fatal("create on-demand sk group "+name, err)
	log.Printf("created on-demand sk group %q (id %s)", name, created.Id)
	return created.Id
}

func ensureNatsUser(ctx context.Context, client *syncp.APIClient, accountID, name, skGroupID string) string {
	users, _, err := client.AccountAPI.ListUsers(ctx, accountID).Execute()
	fatal("list nats users", err)
	for _, u := range users.Items {
		if u.Name == name {
			log.Printf("nats user %q exists (id %s)", name, u.Id)
			return u.Id
		}
	}
	created, _, err := client.AccountAPI.CreateUser(ctx, accountID).
		NatsUserCreateRequest(syncp.NatsUserCreateRequest{Name: name, SkGroupId: skGroupID}).Execute()
	fatal("create nats user "+name, err)
	log.Printf("created nats user %q (id %s)", name, created.Id)
	return created.Id
}

func fatal(what string, err error) {
	if err != nil {
		if apiErr, ok := err.(*syncp.GenericOpenAPIError); ok {
			log.Fatalf("byon-setup: %s: %v — %s", what, err, string(apiErr.Body()))
		}
		log.Fatalf("byon-setup: %s: %v", what, err)
	}
}
