// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// bootstrap-tenant-owner is a one-time, operator-credentialed one-shot that
// creates the first/owner human identity for a tenant on a closed-registration
// self-hosted install (gibson#1103).
//
// AdminProvisionTenant (internal/server/daemon/api/gibson/tenant/v1/admin_tenant.proto)
// only enqueues Tenant-CR creation; the tenant-operator's provisioning saga
// creates the namespace, entitlements, and the tenant's per-tenant Zitadel org
// (EnsureZitadelOrg), but mints no HUMAN user and writes no ownership tuple.
// When SIGNUP_SELF_SERVE is off from first boot there is therefore no way to
// sign in as the owner without briefly reopening self-serve registration. This
// binary closes that gap without ever opening registration or requiring a
// pre-existing human session — the actor invoking it IS the operator (same
// shape as cmd/active-session-backfill).
//
// Given a tenant id (the Tenant CR name) and the owner's email, it:
//
//  1. Resolves the tenant's per-tenant Zitadel org id from the Tenant CR's
//     status.zitadelOrgID (populated by the saga's EnsureZitadelOrg step).
//  2. Calls idp.AdminClient.EnsureHumanUserNoPassword to find-or-create the
//     owner's Zitadel human user in that org, with NO password — the same
//     no-password contract the Platform owner uses (ADR-0093 decision 6/8,
//     hosted#201/#202). No password ever crosses this binary.
//  3. Checks the FGA owner tuple. If absent (first time this tenant gets its
//     Owner), calls idp.AdminClient.CreateSetupInviteCode to mint a one-time
//     setup link through Zitadel's own invite-code flow: emailed, unless
//     -offline-setup is given, in which case the raw code is turned into a
//     link and written to -setup-secret instead — the exact reuse of the
//     Platform owner's setup-link mechanism, never a second one (ADR-0027).
//     The link always names ZITADEL_EXTERNAL_DOMAIN, the public host a
//     browser can reach — never GIBSON_IDP_ADMIN_ISSUER or ZITADEL_URL,
//     which name the in-cluster Service on some profiles (gibson#254 fixed
//     the identical bug in the Platform owner's link).
//  4. Calls tenantrole.Syncer.Assign with role Owner (ADR-0093) — it writes
//     the Owner grant on the gibson Zitadel project and copies it into FGA as
//     (user:<owner-id>, owner, tenant:<tenant-id>) — the top of the tenant
//     relation hierarchy (admin/writer/member all derive "or owner" in
//     model.fga), i.e. what the dashboard and this binary's operators refer to
//     as "tenant_admin" authority.
//  5. Prints the sign-in path the owner should visit (GIBSON_PUBLIC_URL +
//     "/login") to stdout.
//
// Ordering matches the Platform owner's reconcile: the Zitadel calls
// (idempotent — safe to retry) run first, the setup link is sent or written
// BEFORE the tenant role is granted, and the grant (step 4) is fatal on
// failure — nothing else can make this tenant's Owner. Sending the link
// before the grant means a failure between the two can never strand an
// authorized Owner with no way to sign in: the FGA tuple is still absent, so
// a retry repeats both steps. Re-running for an existing owner is a no-op
// success: EnsureHumanUserNoPassword finds the existing user and the FGA
// Check finds the tuple already present, so neither the link nor the grant
// is repeated.
//
// This binary deliberately does NOT provision the tenant itself — it assumes
// AdminProvisionTenant has already run and the operator has drained the queue
// (i.e. the Tenant CR exists and status.zitadelOrgID is populated). If the org
// isn't ready yet this exits non-zero with a message telling the operator to
// wait for provisioning to converge.
//
// Environment variables:
//
//	GIBSON_IDP_ADMIN_ISSUER          — claimed OIDC issuer (a string, never dialed)
//	GIBSON_IDP_ADMIN_CLIENT_ID       — admin service account OAuth2 client id
//	GIBSON_IDP_ADMIN_CLIENT_SECRET   — admin service account OAuth2 client secret
//	GIBSON_IDP_ZITADEL_ORG_ID        — platform-level admin org id (default
//	                                    x-zitadel-orgid header; NOT the
//	                                    tenant's per-tenant org)
//	GIBSON_IDP_ZITADEL_PROJECT_ID    — the gibson Zitadel project id (ADR-0093):
//	                                    the project the Owner role is granted on
//	ZITADEL_URL                      — in-cluster Zitadel Service base URL (ADR-0092)
//	ZITADEL_EXTERNAL_DOMAIN          — claimed public host, sent as x-zitadel-instance-host
//	EXT_AUTHZ_FGA_ADDR               — HTTP endpoint of the OpenFGA server
//	EXT_AUTHZ_FGA_STORE_ID           — FGA store ID
//	EXT_AUTHZ_FGA_MODEL_ID           — FGA authorization model ID
//	GIBSON_PUBLIC_URL                — optional; base URL used to print the
//	                                    sign-in path (e.g. https://app.example.com)
//
// Flags:
//
//	-tenant                  Tenant CR name / tenant id (required)
//	-owner-email             Owner's email address (required)
//	-offline-setup           Write the one-time setup link to -setup-secret
//	                         instead of emailing it. Required on an install
//	                         with no delivering mail transport (ADR-0093).
//	-setup-secret            Secret name the offline link is written into, in
//	                         -setup-secret-namespace. Required with -offline-setup.
//	-setup-secret-key        Key within -setup-secret the link is written
//	                         under (default "setup-link").
//	-setup-secret-namespace  Namespace for -setup-secret (default "gibson").
//
// Usage:
//
//	bootstrap-tenant-owner -tenant acme -owner-email owner@acme.example
//
// Spec: first-admin-bootstrap (gibson#1103), tenant-owner-setup-link (hosted#202).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp/zitadel"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
)

// tenantsGVR is the GVR for the cluster-scoped Tenant CR.
var tenantsGVR = schema.GroupVersionResource{
	Group:    "gibson.zeroroot.ai",
	Version:  "v1alpha1",
	Resource: "tenants",
}

// ownerRelation is the FGA relation written for the founding owner — the top
// of the tenant relation hierarchy (model.fga: admin/writer/member all derive
// "or owner"). This is the relation the dashboard and operators refer to as
// "tenant_admin" authority.
const ownerRelation = "owner"

// outcome is logged as the structured "outcome" field.
type outcome string

const (
	outcomeBootstrapped outcome = "bootstrapped"
	outcomeAlreadyOwner outcome = "already_owner"
)

// BootstrapResult reports what runBootstrap did.
type BootstrapResult struct {
	Outcome     outcome
	TenantID    string
	OwnerUserID string

	// SignInPath is the URL the owner should visit to complete sign-in, or ""
	// when GIBSON_PUBLIC_URL is unset.
	SignInPath string

	// SetupLink is the offline one-time setup link, set ONLY when this run
	// established the tenant's Owner (first bootstrap) AND -offline-setup was
	// given. Empty on the emailed path and on every re-run against an
	// existing owner — a re-run must never re-invalidate a link the owner may
	// already have used (mirrors deploy#1631's "never reset a credential the
	// operator has already changed", applied to a link instead of a password).
	//
	// The caller writes it to -setup-secret. It is never logged by this
	// package, and no password is ever generated or stored anywhere
	// (ADR-0093, hosted#202).
	SetupLink string
}

// TenantGetter fetches a single Tenant CR by name. Injectable for testing.
// The subresources parameter matches dynamic.ResourceInterface.Get's
// signature exactly so *dynamic.Resource(tenantsGVR) satisfies this
// interface structurally.
type TenantGetter interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions, subresources ...string) (*unstructured.Unstructured, error)
}

// idpClient is the narrow surface of idp.AdminClient this tool needs.
// idp.AdminClient (and *zitadel.Client) satisfy this interface structurally.
type idpClient interface {
	// EnsureHumanUserNoPassword finds or creates the owner's human user in the
	// tenant's Zitadel org, with NO password (ADR-0093). Idempotent: an
	// existing user is found by email and returned, never recreated.
	EnsureHumanUserNoPassword(ctx context.Context, orgID, email, givenName, familyName string) (userID string, err error)
	// CreateSetupInviteCode mints a one-time setup-link code for userID via
	// Zitadel's own invite-code flow — the same mechanism the Platform owner
	// uses (ADR-0093, hosted#201/#202), reused here rather than a second one
	// (ADR-0027). send=true emails the link built from urlTemplate; send=false
	// returns the raw code for the caller to turn into an offline link.
	CreateSetupInviteCode(ctx context.Context, userID, urlTemplate string, send bool) (code string, err error)
	Close() error
}

// fgaClient is the narrow surface of authz.Authorizer this tool needs.
type fgaClient interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	Write(ctx context.Context, tuples []authz.Tuple) error
}

// tenantRoleAssigner is the narrow surface of tenantrole.Syncer this tool
// needs to grant the founding Owner's tenant role (ADR-0093): Assign writes
// the Zitadel grant, then copies it into FGA in the same call, so this
// binary no longer writes the FGA owner tuple directly.
type tenantRoleAssigner interface {
	Assign(ctx context.Context, t tenantrole.Tenant, userID string, r tenantrole.Role) error
}

// kubeConfigLoader loads a *rest.Config. Injectable for testing.
type kubeConfigLoader func() (*rest.Config, error)

// tenantGetterProvider builds a TenantGetter from a *rest.Config. Injectable
// so tests do not need to implement the full dynamic.Interface.
type tenantGetterProvider func(*rest.Config) (TenantGetter, error)

// idpClientBuilder builds the narrow idp client. Injectable for testing.
type idpClientBuilder func(ctx context.Context) (idpClient, error)

// fgaClientBuilder builds the narrow FGA client. Injectable for testing.
type fgaClientBuilder func(ctx context.Context) (fgaClient, error)

// tenantRoleSyncerBuilder builds the tenant role Syncer. Injectable for testing.
type tenantRoleSyncerBuilder func(ctx context.Context) (tenantRoleAssigner, error)

func main() {
	os.Exit(run())
}

// run parses flags, wires real constructors, and delegates to runWithDeps.
// Only flag parsing and the constructor calls are uncovered by tests here.
func run() int {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	flags, err := parseFlags(os.Args[1:])
	if err != nil {
		logger.Error("invalid arguments", "err", err)
		return 1
	}

	// The setup link is for a person's browser, so it names the public host
	// (gibson#254 fixed the identical bug in the Platform owner's link).
	// zitadelconn.FromEnv is the one helper that resolves ZITADEL_EXTERNAL_DOMAIN
	// — the same helper resolveIdpEnvConfig uses for the same env vars.
	endpoint, err := zitadelconn.FromEnv()
	if err != nil {
		logger.Error("zitadel endpoint", "err", err)
		return 1
	}

	ctx := context.Background()
	return runWithDeps(
		ctx,
		logger,
		os.Stdout,
		flags.TenantID,
		flags.OwnerEmail,
		os.Getenv("GIBSON_PUBLIC_URL"),
		endpoint.Host(),
		flags.OfflineSetup,
		flags.SetupSecret,
		flags.SetupSecretKey,
		flags.SetupSecretNamespace,
		loadKubeConfig,
		newTenantGetter,
		buildIdpClient,
		buildFgaClient,
		buildTenantRoleSyncer,
	)
}

// newTenantGetter builds the real TenantGetter from a *rest.Config.
// dynamic.NewForConfig only constructs a REST client object — it performs no
// network I/O — so this is safe to exercise directly in tests without a live
// cluster; only an actual Get/List call would need one.
func newTenantGetter(cfg *rest.Config) (TenantGetter, error) {
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("dynamic client: %w", err)
	}
	return dyn.Resource(tenantsGVR), nil
}

// cliFlags carries every command-line option. A struct rather than positional
// returns: the flag set crossed five values and positional returns at that
// size are exactly how a bool lands in the wrong slot silently.
type cliFlags struct {
	TenantID             string
	OwnerEmail           string
	OfflineSetup         bool
	SetupSecret          string
	SetupSecretKey       string
	SetupSecretNamespace string
}

// parseFlags parses -tenant and -owner-email, both required, and the
// setup-link flags (ADR-0093, hosted#202).
func parseFlags(args []string) (cliFlags, error) {
	fs := flag.NewFlagSet("bootstrap-tenant-owner", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "Tenant CR name / tenant id (required)")
	email := fs.String("owner-email", "", "Owner's email address (required)")
	offline := fs.Bool("offline-setup", false,
		"Write the one-time setup link to -setup-secret instead of emailing it. "+
			"Required on an install with no delivering mail transport (ADR-0093).")
	setupSecret := fs.String("setup-secret", "",
		"Secret name the offline setup link is written into, in "+
			"-setup-secret-namespace. Required when -offline-setup is set.")
	setupSecretKey := fs.String("setup-secret-key", "setup-link",
		"Key within -setup-secret the link is written under.")
	setupNS := fs.String("setup-secret-namespace", "gibson", "Namespace for -setup-secret.")
	if perr := fs.Parse(args); perr != nil {
		return cliFlags{}, fmt.Errorf("parse flags: %w", perr)
	}
	if strings.TrimSpace(*tenant) == "" {
		return cliFlags{}, errors.New("-tenant is required")
	}
	if strings.TrimSpace(*email) == "" {
		return cliFlags{}, errors.New("-owner-email is required")
	}
	if *offline && strings.TrimSpace(*setupSecret) == "" {
		return cliFlags{}, errors.New("-setup-secret is required when -offline-setup is set")
	}
	return cliFlags{
		TenantID:             *tenant,
		OwnerEmail:           *email,
		OfflineSetup:         *offline,
		SetupSecret:          *setupSecret,
		SetupSecretKey:       *setupSecretKey,
		SetupSecretNamespace: *setupNS,
	}, nil
}

// idpEnvConfig holds the Zitadel admin coordinates resolved from env vars.
type idpEnvConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	ZitadelOrgID string
	Endpoint     zitadelconn.Endpoint
}

// resolveIdpEnvConfig reads the four required GIBSON_IDP_* env vars (plus the
// optional discovery URL), matching internal/server/daemon/idp_init.go's
// initZitadelClient exactly. Pure and independently testable; the untestable
// part (the real zitadel.New network probe) is isolated in buildIdpClient.
func resolveIdpEnvConfig() (idpEnvConfig, error) {
	type reqVar struct{ name, value string }
	vars := []reqVar{
		{"GIBSON_IDP_ADMIN_ISSUER", os.Getenv("GIBSON_IDP_ADMIN_ISSUER")},
		{"GIBSON_IDP_ADMIN_CLIENT_ID", os.Getenv("GIBSON_IDP_ADMIN_CLIENT_ID")},
		{"GIBSON_IDP_ADMIN_CLIENT_SECRET", os.Getenv("GIBSON_IDP_ADMIN_CLIENT_SECRET")},
		{"GIBSON_IDP_ZITADEL_ORG_ID", os.Getenv("GIBSON_IDP_ZITADEL_ORG_ID")},
	}
	var missing []string
	for _, v := range vars {
		if v.value == "" {
			missing = append(missing, v.name)
		}
	}
	if len(missing) > 0 {
		return idpEnvConfig{}, fmt.Errorf("required env vars not set: %v", missing)
	}
	// ADR-0092: connect to the Zitadel Service, claim the public host by header.
	endpoint, err := zitadelconn.FromEnv()
	if err != nil {
		return idpEnvConfig{}, fmt.Errorf("zitadel endpoint: %w", err)
	}
	return idpEnvConfig{
		Issuer:       vars[0].value,
		ClientID:     vars[1].value,
		ClientSecret: vars[2].value,
		ZitadelOrgID: vars[3].value,
		Endpoint:     endpoint,
	}, nil
}

// buildIdpClient constructs the real Zitadel admin client. The startup probe
// inside zitadel.New requires a live Zitadel and is intentionally not
// exercised here — resolveIdpEnvConfig carries the testable logic.
func buildIdpClient(ctx context.Context) (idpClient, error) {
	cfg, err := resolveIdpEnvConfig()
	if err != nil {
		return nil, err
	}
	client, err := zitadel.New(ctx, zitadel.Config{
		Issuer:       cfg.Issuer,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		OrgID:        cfg.ZitadelOrgID,
		Endpoint:     cfg.Endpoint,
	})
	if err != nil {
		return nil, fmt.Errorf("zitadel startup probe failed (issuer=%s client_id=%s): %w",
			cfg.Issuer, cfg.ClientID, err)
	}
	return client, nil
}

// fgaEnvConfig holds the FGA coordinates resolved from env vars.
type fgaEnvConfig struct {
	Addr    string
	StoreID string
	ModelID string
}

// resolveFgaEnvConfig reads the three required EXT_AUTHZ_FGA_* env vars,
// matching cmd/active-session-backfill. Pure and independently testable.
func resolveFgaEnvConfig() (fgaEnvConfig, error) {
	addr := os.Getenv("EXT_AUTHZ_FGA_ADDR")
	storeID := os.Getenv("EXT_AUTHZ_FGA_STORE_ID")
	modelID := os.Getenv("EXT_AUTHZ_FGA_MODEL_ID")
	var missing []string
	if addr == "" {
		missing = append(missing, "EXT_AUTHZ_FGA_ADDR")
	}
	if storeID == "" {
		missing = append(missing, "EXT_AUTHZ_FGA_STORE_ID")
	}
	if modelID == "" {
		missing = append(missing, "EXT_AUTHZ_FGA_MODEL_ID")
	}
	if len(missing) > 0 {
		return fgaEnvConfig{}, fmt.Errorf("required env vars not set: %v", missing)
	}
	return fgaEnvConfig{Addr: addr, StoreID: storeID, ModelID: modelID}, nil
}

// buildFgaClient constructs the real FGA authorizer. The dial inside
// NewFgaAuthorizer requires a live FGA server and is intentionally not
// exercised here — resolveFgaEnvConfig carries the testable logic.
func buildFgaClient(ctx context.Context) (fgaClient, error) {
	cfg, err := resolveFgaEnvConfig()
	if err != nil {
		return nil, err
	}
	az, err := authz.NewFgaAuthorizer(ctx, authz.FgaConfig{
		Endpoint:  cfg.Addr,
		StoreID:   cfg.StoreID,
		ModelID:   cfg.ModelID,
		TimeoutMs: 5000,
	})
	if err != nil {
		return nil, fmt.Errorf("build FGA authorizer: %w", err)
	}
	return az, nil
}

// buildTenantRoleSyncer constructs the real tenantrole.Syncer (ADR-0093).
// It reuses the same GIBSON_IDP_* Zitadel endpoint and admin credentials as
// buildIdpClient (a client_credentials token, not the PAT-shaped clients the
// operators use) plus GIBSON_IDP_ZITADEL_PROJECT_ID, and opens its own FGA
// connection via resolveFgaEnvConfig — a second short-lived connection in a
// one-shot Job binary is an acceptable simplicity trade against sharing the
// fgaClient built above, which is deliberately narrowed to two methods.
func buildTenantRoleSyncer(ctx context.Context) (tenantRoleAssigner, error) {
	idpCfg, err := resolveIdpEnvConfig()
	if err != nil {
		return nil, err
	}
	projectID := os.Getenv("GIBSON_IDP_ZITADEL_PROJECT_ID")
	if projectID == "" {
		return nil, errors.New("required env var not set: GIBSON_IDP_ZITADEL_PROJECT_ID")
	}
	fgaCfg, err := resolveFgaEnvConfig()
	if err != nil {
		return nil, err
	}
	az, err := authz.NewFgaAuthorizer(ctx, authz.FgaConfig{
		Endpoint:  fgaCfg.Addr,
		StoreID:   fgaCfg.StoreID,
		ModelID:   fgaCfg.ModelID,
		TimeoutMs: 5000,
	})
	if err != nil {
		return nil, fmt.Errorf("build FGA authorizer for tenant role sync: %w", err)
	}
	tuples, err := tenantrole.AuthzTuples(az)
	if err != nil {
		return nil, fmt.Errorf("tenant role tuples adapter: %w", err)
	}

	base := &http.Client{Timeout: 10 * time.Second, Transport: idpCfg.Endpoint.Transport(nil)}
	ccCfg := clientcredentials.Config{
		ClientID:     idpCfg.ClientID,
		ClientSecret: idpCfg.ClientSecret,
		TokenURL:     idpCfg.Endpoint.TokenURL(),
		Scopes:       []string{"openid", "urn:zitadel:iam:org:project:id:zitadel:aud"},
	}
	baseCtx := context.WithValue(ctx, oauth2.HTTPClient, base)
	hc := oauth2.NewClient(baseCtx, ccCfg.TokenSource(baseCtx))
	grants := tenantrole.NewZitadelGrants(idpCfg.Endpoint, hc, projectID)
	return tenantrole.NewSyncer(grants, tuples, nil), nil
}

// runWithDeps resolves the Tenant CR, constructs clients via the supplied
// factory functions, and delegates to runBootstrap. All logic branches are
// exercisable by injecting fakes — only the real constructor calls in
// buildIdpClient/buildFgaClient/run's dynamic-client closure are irreducibly
// un-testable here.
func runWithDeps(
	ctx context.Context,
	logger *slog.Logger,
	stdout io.Writer,
	tenantID, ownerEmail, publicURL, externalDomain string,
	offlineSetup bool,
	setupSecret, setupSecretKey, setupSecretNamespace string,
	kubeLoader kubeConfigLoader,
	tenantProvider tenantGetterProvider,
	idpBuilder idpClientBuilder,
	fgaBuilder fgaClientBuilder,
	rolesBuilder tenantRoleSyncerBuilder,
) int {
	k8sCfg, err := kubeLoader()
	if err != nil {
		logger.Error("failed to load kubernetes config", "err", err)
		return 1
	}

	tenantGetter, err := tenantProvider(k8sCfg)
	if err != nil {
		logger.Error("failed to create tenant getter", "err", err)
		return 1
	}

	idpC, err := idpBuilder(ctx)
	if err != nil {
		logger.Error("failed to build IdP admin client", "err", err)
		return 1
	}
	defer func() {
		if cerr := idpC.Close(); cerr != nil {
			logger.Warn("failed to close IdP admin client", "err", cerr)
		}
	}()

	fgaC, err := fgaBuilder(ctx)
	if err != nil {
		logger.Error("failed to build FGA client", "err", err)
		return 1
	}

	// A failed grant is now fatal (ADR-0093): nothing else can make the
	// Owner, so an install with a Zitadel or FGA outage at this exact moment
	// must not report success and strand the operator with no way in.
	roles, err := rolesBuilder(ctx)
	if err != nil {
		logger.Error("failed to build tenant role syncer", "err", err)
		return 1
	}

	result, err := runBootstrap(ctx, tenantID, ownerEmail, publicURL, externalDomain, offlineSetup, tenantGetter, idpC, fgaC, roles)
	if err == nil && result.SetupLink != "" && setupSecret != "" {
		// Job logs are not a credential store: they are readable by anyone with
		// pod-log access and they age out. Writing a Secret gives the operator
		// something to fetch deliberately.
		//
		// CREATE-OR-UPDATE: a retry that re-ran CreateSetupInviteCode (because
		// the tenant-role grant failed after the link was sent) invalidated any
		// previously written link on the Zitadel side, so the Secret must be
		// overwritten to match — never left holding a link Zitadel no longer
		// honors.
		if serr := setupLinkWriter(ctx, k8sCfg, setupSecretNamespace, setupSecret, setupSecretKey, result.SetupLink); serr != nil {
			logger.Error("could not write the offline setup-link Secret — the link is in this Job's output and nowhere else",
				"secret", setupSecret, "err", serr)
		} else {
			logger.Info("wrote offline setup link", "secret", setupSecretNamespace+"/"+setupSecret)
		}
	}
	if err != nil {
		logger.Error("bootstrap failed", "tenant", tenantID, "err", err)
		return 1
	}

	// Pre-accept the founding-owner TenantMember, exactly what the signup
	// path writes at member creation. Without this the owner can SIGN IN (the
	// FGA owner tuple above) but every tenant-scoped RPC fails closed at the
	// session-revocation gate, because only the TenantMember reconciler's
	// Active branch seeds the active_session tuples — and it never runs for a
	// member stuck in Invited. Fatal on a real error: an owner who can log in
	// and do nothing is a broken install wearing a working login.
	outcome, paErr := foundingMemberPreAcceptor(ctx, k8sCfg, tenantID, ownerEmail, result.OwnerUserID)
	if paErr != nil {
		logger.Error("pre-accept founding member failed", "tenant", tenantID, "err", paErr)
		return 1
	}
	logger.Info("founding member pre-accept", "outcome", string(outcome), "tenant", tenantID)

	logger.Info("tenant owner bootstrap complete",
		"outcome", string(result.Outcome),
		"tenant", result.TenantID,
		"user_id", result.OwnerUserID,
	)
	var printErr error
	if result.SignInPath != "" {
		_, printErr = fmt.Fprintf(stdout, "sign-in path: %s\n", result.SignInPath)
	} else {
		_, printErr = fmt.Fprintln(stdout, "sign-in path: (GIBSON_PUBLIC_URL not set)")
	}
	if printErr == nil && result.Outcome == outcomeBootstrapped {
		if result.SetupLink != "" {
			_, printErr = fmt.Fprintf(stdout,
				"\nsetup link written to Secret %s/%s (key %q). It is one-time and expires — "+
					"give it to the owner to set a password and enroll MFA.\n",
				setupSecretNamespace, setupSecret, setupSecretKey)
		} else {
			_, printErr = fmt.Fprintln(stdout,
				"\na one-time setup link was emailed to the owner. No password crosses this binary (ADR-0093).")
		}
	}
	if printErr != nil {
		// The bootstrap itself already succeeded (user created, membership
		// granted, tuple written); a broken stdout must not turn that into a
		// failure. Log it so the operator still learns the write failed.
		logger.Warn("failed to print sign-in path", "err", printErr)
	}
	return 0
}

// runBootstrap performs the bootstrap: ensure the Zitadel human user with no
// password, send or write its one-time setup link, then ensure the tenant
// role grant (which copies the FGA owner tuple). The setup link is sent
// BEFORE the tenant role is granted, so a failure in between never leaves an
// authorized Owner unable to sign in: the FGA tuple is still absent, so a
// retry repeats both steps (see the package doc comment).
func runBootstrap(
	ctx context.Context,
	tenantID, ownerEmail, publicURL, externalDomain string,
	offlineSetup bool,
	tenants TenantGetter,
	idpC idpClient,
	fgaC fgaClient,
	roles tenantRoleAssigner,
) (BootstrapResult, error) {
	if tenantID == "" {
		return BootstrapResult{}, errors.New("tenant id required")
	}
	if ownerEmail == "" {
		return BootstrapResult{}, errors.New("owner email required")
	}

	tenantObj, err := tenants.Get(ctx, tenantID, metav1.GetOptions{})
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("get Tenant %q: %w", tenantID, err)
	}
	orgID, _, _ := nestedString(tenantObj.Object, "status", "zitadelOrgID")
	if orgID == "" {
		return BootstrapResult{}, fmt.Errorf(
			"tenant %q has no status.zitadelOrgID yet — wait for tenant provisioning (EnsureZitadelOrg) to converge and retry", tenantID)
	}

	// No password ever crosses this binary (ADR-0093 decision 8, hosted#202):
	// EnsureHumanUserNoPassword is idempotent — an existing owner is found by
	// email and returned, never recreated or touched.
	givenName, familyName := ownerProfileName(ownerEmail)
	userID, err := idpC.EnsureHumanUserNoPassword(ctx, orgID, ownerEmail, givenName, familyName)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("ensure owner Zitadel user: %w", err)
	}

	userRef := "user:" + userID
	tenantRef := "tenant:" + tenantID
	present, err := fgaC.Check(ctx, userRef, ownerRelation, tenantRef)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("fga Check %s: %w", ownerRelation, err)
	}

	result := BootstrapResult{
		TenantID:    tenantID,
		OwnerUserID: userID,
	}
	if publicURL != "" {
		result.SignInPath = strings.TrimRight(publicURL, "/") + "/login"
	}

	if present {
		result.Outcome = outcomeAlreadyOwner
		return result, nil
	}

	// First time this tenant gets its Owner: mint the one-time setup link,
	// reusing the exact mechanism the Platform owner uses (ADR-0093
	// decision 8, hosted#201/#202) — never a second one (ADR-0027).
	urlTemplate := setupLinkURLTemplate(externalDomain)
	if !offlineSetup {
		if _, ierr := idpC.CreateSetupInviteCode(ctx, userID, urlTemplate, true); ierr != nil {
			return BootstrapResult{}, fmt.Errorf("create setup invite code: %w", ierr)
		}
	} else {
		code, ierr := idpC.CreateSetupInviteCode(ctx, userID, urlTemplate, false)
		if ierr != nil {
			return BootstrapResult{}, fmt.Errorf("create setup invite code: %w", ierr)
		}
		result.SetupLink = renderSetupLink(urlTemplate, userID, orgID, code)
	}

	// Assign the Owner tenant role through the Syncer (ADR-0093): it writes
	// the Zitadel grant, then copies it into FGA in the same call. Nothing
	// else can make this tenant's Owner, so a failure here is fatal — and,
	// because it runs after the setup link, a retry (the FGA tuple is still
	// absent) safely repeats the link step too.
	if err := roles.Assign(ctx, tenantrole.Tenant{ID: tenantID, OrgID: orgID}, userID, tenantrole.Owner); err != nil {
		return BootstrapResult{}, fmt.Errorf("assign owner tenant role: %w", err)
	}
	result.Outcome = outcomeBootstrapped
	return result, nil
}

// setupLinkURLTemplate builds the Go-template URL Zitadel substitutes
// {{.UserID}}, {{.OrgID}} and {{.Code}} into (CreateInviteCode's urlTemplate
// field) — the same shape the Platform owner's setup link uses (ADR-0093,
// hosted#201), so the emitted link is identical whether Zitadel emails it or
// this binary embeds it in the offline Secret.
//
// externalDomain is the public host a browser reaches (ZITADEL_EXTERNAL_DOMAIN,
// a port included when the profile has one) — never GIBSON_IDP_ADMIN_ISSUER
// or ZITADEL_URL, both of which name the in-cluster Service on some profiles.
// gibson#254 fixed the identical bug in the Platform owner's setup link.
func setupLinkURLTemplate(externalDomain string) string {
	return "https://" + strings.TrimRight(externalDomain, "/") + "/ui/v2/login/invite?userID={{.UserID}}&code={{.Code}}&organization={{.OrgID}}"
}

// renderSetupLink substitutes the same three placeholders setupLinkURLTemplate
// declares, for the offline path where this binary builds the link itself
// instead of letting Zitadel substitute them server-side.
func renderSetupLink(urlTemplate, userID, orgID, code string) string {
	r := strings.NewReplacer("{{.UserID}}", userID, "{{.OrgID}}", orgID, "{{.Code}}", code)
	return r.Replace(urlTemplate)
}

// loadKubeConfig returns an in-cluster config if available, falling back to
// the KUBECONFIG env / default kubeconfig file.
func loadKubeConfig() (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	return cfg, nil
}

// writeOfflineSetupLinkSecret creates or updates the offline setup-link
// Secret. No password is ever written to a Secret (ADR-0093, hosted#202):
// this holds only the one-time link.
//
// CREATE-OR-UPDATE, unlike the credential Secret the password path used to
// write: CreateSetupInviteCode already invalidated any previous link on the
// Zitadel side (whether this is the first write or a retry after a
// downstream failure), so leaving a stale value in the Secret would be a
// link that looks live but no longer works.
func writeOfflineSetupLinkSecret(ctx context.Context, cs kubernetes.Interface, namespace, name, key, link string) error {
	secrets := cs.CoreV1().Secrets(namespace)
	existing, err := secrets.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		sec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "bootstrap-tenant-owner",
					"app.kubernetes.io/component":  "first-admin",
				},
				Annotations: map[string]string{
					"gibson.zeroroot.ai/ref": "hosted#202",
				},
			},
			Type:       corev1.SecretTypeOpaque,
			StringData: map[string]string{key: link},
		}
		if _, cerr := secrets.Create(ctx, sec, metav1.CreateOptions{}); cerr != nil {
			if !apierrors.IsAlreadyExists(cerr) {
				return fmt.Errorf("create setup-link Secret %s/%s: %w", namespace, name, cerr)
			}
			// Lost a create race — fall through to the update path below.
		} else {
			return nil
		}
		existing, err = secrets.Get(ctx, name, metav1.GetOptions{})
	}
	if err != nil {
		return fmt.Errorf("get setup-link Secret %s/%s: %w", namespace, name, err)
	}
	updated := existing.DeepCopy()
	if updated.StringData == nil {
		updated.StringData = map[string]string{}
	}
	updated.StringData[key] = link
	if updated.Data != nil {
		delete(updated.Data, key)
	}
	if _, uerr := secrets.Update(ctx, updated, metav1.UpdateOptions{}); uerr != nil {
		return fmt.Errorf("update setup-link Secret %s/%s: %w", namespace, name, uerr)
	}
	return nil
}

// setupLinkWriter is swapped in tests: the write path must be exercisable
// without a live API server, and a *rest.Config pointed at nothing either
// hangs or fails for reasons unrelated to what the test asserts.
var setupLinkWriter = writeOfflineSetupLinkViaConfig

// writeOfflineSetupLinkViaConfig builds the real clientset and delegates.
// Split from writeOfflineSetupLinkSecret so the create-or-update semantics
// are testable against a fake clientset without a rest.Config.
func writeOfflineSetupLinkViaConfig(ctx context.Context, cfg *rest.Config, namespace, name, key, link string) error {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("build kubernetes client: %w", err)
	}
	return writeOfflineSetupLinkSecret(ctx, cs, namespace, name, key, link)
}

// ownerProfileName derives a non-empty given/family name for the first-admin
// user from its email. Zitadel's user create requires both profile names;
// the signup path collects them from the user, but a headless bootstrap has
// only the email, so the local part becomes the given name and a fixed
// "Owner" the family name. The operator can edit both after first login.
func ownerProfileName(email string) (given, family string) {
	local := email
	if i := strings.IndexByte(email, '@'); i >= 0 {
		local = email[:i]
	}
	if local == "" {
		local = "Admin"
	}
	return local, "Owner"
}

// nestedString retrieves a string value from an unstructured map by following
// the given field path.
func nestedString(obj map[string]any, fields ...string) (value string, found bool, err error) {
	cur := any(obj)
	for _, f := range fields {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false, nil
		}
		v, exists := m[f]
		if !exists {
			return "", false, nil
		}
		cur = v
	}
	s, ok := cur.(string)
	if !ok {
		return "", false, nil
	}
	return s, true, nil
}
