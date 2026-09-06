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
// shape as cmd/active-session-backfill and cmd/tenant-owner-backfill).
//
// Given a tenant id (the Tenant CR name) and the owner's email, it:
//
//  1. Resolves the tenant's per-tenant Zitadel org id from the Tenant CR's
//     status.zitadelOrgID (populated by the saga's EnsureZitadelOrg step).
//  2. Calls idp.AdminClient.EnsureHumanUser to find-or-create the owner's
//     Zitadel human user in that org — the exact call MembershipService's
//     AcceptInvitation makes for an invited member. Zitadel emails the invitee
//     a verification/credential-setup code; no password crosses this binary.
//  3. Calls idp.AdminClient.AddTenantMember with role "owner" to grant Zitadel
//     org membership (idempotent — a 409 is treated as success upstream).
//  4. Checks and, if absent, writes the FGA tuple
//     (user:<owner-id>, owner, tenant:<tenant-id>) — the top of the tenant
//     relation hierarchy (admin/writer/member all derive "or owner" in
//     model.fga), i.e. what the dashboard and this binary's operators refer to
//     as "tenant_admin" authority.
//  5. Prints the sign-in path the owner should visit (GIBSON_PUBLIC_URL +
//     "/login") to stdout.
//
// Ordering matches AcceptInvitation / SetTenantRole: Zitadel first (both calls
// are idempotent — safe to retry), FGA second. A failure in step 2 or 3 exits
// non-zero before any FGA write is attempted, so a failed run never leaves a
// partial ownership tuple. Re-running for an existing owner is a no-op success:
// EnsureHumanUser finds the existing user, AddTenantMember's 409 is swallowed
// upstream, and the FGA Check finds the tuple already present.
//
// This binary deliberately does NOT provision the tenant itself — it assumes
// AdminProvisionTenant has already run and the operator has drained the queue
// (i.e. the Tenant CR exists and status.zitadelOrgID is populated). If the org
// isn't ready yet this exits non-zero with a message telling the operator to
// wait for provisioning to converge.
//
// Environment variables:
//
//	GIBSON_IDP_ADMIN_ISSUER          — Zitadel OIDC issuer URL
//	GIBSON_IDP_ADMIN_CLIENT_ID       — admin service account OAuth2 client id
//	GIBSON_IDP_ADMIN_CLIENT_SECRET   — admin service account OAuth2 client secret
//	GIBSON_IDP_ZITADEL_ORG_ID        — platform-level admin org id (default
//	                                    x-zitadel-orgid header; NOT the
//	                                    tenant's per-tenant org)
//	GIBSON_IDP_ADMIN_DISCOVERY_URL   — optional in-cluster OIDC discovery URL
//	EXT_AUTHZ_FGA_ADDR               — HTTP endpoint of the OpenFGA server
//	EXT_AUTHZ_FGA_STORE_ID           — FGA store ID
//	EXT_AUTHZ_FGA_MODEL_ID           — FGA authorization model ID
//	GIBSON_PUBLIC_URL                — optional; base URL used to print the
//	                                    sign-in path (e.g. https://app.example.com)
//
// Flags:
//
//	-tenant       Tenant CR name / tenant id (required)
//	-owner-email  Owner's email address (required)
//
// Usage:
//
//	bootstrap-tenant-owner -tenant acme -owner-email owner@acme.example
//
// Spec: first-admin-bootstrap (gibson#1103).
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"log/slog"
	"os"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/idp/zitadel"
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
	// MembershipWarning is set (non-empty) when granting the owner a Zitadel
	// org-member role failed. It is NON-FATAL: gibson access is authorized by
	// the FGA owner tuple written below, not by a Zitadel org-member role, so
	// the first admin can still sign in and own the tenant. The most common
	// cause is that the custom gibson.owner org-member role is not defined in
	// this deployment's Zitadel config (a separate, platform-wide gap that also
	// affects signup's founding-member grant).
	MembershipWarning string

	// SignInPath is the URL the owner should visit to complete sign-in, or ""
	// when GIBSON_PUBLIC_URL is unset.
	SignInPath string

	// InitialPassword is the generated first-admin password, set ONLY when this
	// run created the user and -generate-password was given. Empty on every
	// other path, including a re-run against an existing owner — a re-run must
	// not reset a credential the operator has already changed (deploy#1631).
	//
	// The caller surfaces it exactly once. It is never logged by this package.
	InitialPassword string
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
	// EnsureHumanUser finds or creates the owner's human user in the tenant's
	// Zitadel org. Idempotent.
	EnsureHumanUser(ctx context.Context, req idp.EnsureHumanUserRequest) (userID string, err error)
	// CreateHumanUser provisions a PASSWORD-BEARING human user. Used for the
	// self-hosted first admin, where EnsureHumanUser's emailed
	// credential-setup code is undeliverable: a vanilla install configures no
	// SMTP, so the invitation flow strands the operator with an account they
	// can never sign into (deploy#1631).
	CreateHumanUser(ctx context.Context, req idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error)
	// AddTenantMember grants the owner org membership with the given role.
	// Idempotent — an existing membership is treated as success.
	AddTenantMember(ctx context.Context, req idp.TenantMembershipRequest) error
	// FindUserIDByEmailInOrg resolves an existing user in the tenant's org, used
	// when CreateHumanUser reports the founding owner already exists (the
	// invitation flow created it) and on a re-run after the credential Secret
	// exists. The owner lives in the TENANT org, not the daemon's admin org, so
	// the resolve must be scoped to it (gibson#1560).
	FindUserIDByEmailInOrg(ctx context.Context, email, orgID string) (userID string, err error)
	// SetHumanPassword activates that already-created owner with a known
	// password. Called only on first setup (credential Secret absent).
	SetHumanPassword(ctx context.Context, req idp.SetHumanPasswordRequest) error
	// HumanPasswordChangedAt reports when Zitadel last recorded a password set
	// for the owner, or the zero time if it holds none. Read on a re-run to
	// tell a SPENT initial credential from a live one — see
	// expireSpentCredential.
	HumanPasswordChangedAt(ctx context.Context, userID string) (time.Time, error)
	Close() error
}

// fgaClient is the narrow surface of authz.Authorizer this tool needs.
type fgaClient interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	Write(ctx context.Context, tuples []authz.Tuple) error
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

	ctx := context.Background()
	return runWithDeps(
		ctx,
		logger,
		os.Stdout,
		flags.TenantID,
		flags.OwnerEmail,
		os.Getenv("GIBSON_PUBLIC_URL"),
		flags.GeneratePassword,
		flags.CredentialSecret,
		flags.CredentialNamespace,
		loadKubeConfig,
		newTenantGetter,
		buildIdpClient,
		buildFgaClient,
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
	TenantID            string
	OwnerEmail          string
	GeneratePassword    bool
	CredentialSecret    string
	CredentialNamespace string
}

// parseFlags parses -tenant and -owner-email, both required.
func parseFlags(args []string) (cliFlags, error) {
	fs := flag.NewFlagSet("bootstrap-tenant-owner", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "Tenant CR name / tenant id (required)")
	email := fs.String("owner-email", "", "Owner's email address (required)")
	credSecret := fs.String("credential-secret", "",
		"Write the generated credential into this Secret in -credential-namespace "+
			"instead of relying on Job logs. Created only if absent: a re-run must "+
			"never overwrite a credential the operator has already rotated.")
	credNS := fs.String("credential-namespace", "gibson", "Namespace for -credential-secret")
	genPw := fs.Bool("generate-password", false,
		"Create the owner with a GENERATED initial password instead of the emailed "+
			"credential-setup flow. Required on a self-hosted install, which configures "+
			"no SMTP and so cannot deliver an invitation (deploy#1631).")
	if perr := fs.Parse(args); perr != nil {
		return cliFlags{}, fmt.Errorf("parse flags: %w", perr)
	}
	if strings.TrimSpace(*tenant) == "" {
		return cliFlags{}, errors.New("-tenant is required")
	}
	if strings.TrimSpace(*email) == "" {
		return cliFlags{}, errors.New("-owner-email is required")
	}
	return cliFlags{
		TenantID:            *tenant,
		OwnerEmail:          *email,
		GeneratePassword:    *genPw,
		CredentialSecret:    *credSecret,
		CredentialNamespace: *credNS,
	}, nil
}

// idpEnvConfig holds the Zitadel admin coordinates resolved from env vars.
type idpEnvConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	ZitadelOrgID string
	DiscoveryURL string
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
	return idpEnvConfig{
		Issuer:       vars[0].value,
		ClientID:     vars[1].value,
		ClientSecret: vars[2].value,
		ZitadelOrgID: vars[3].value,
		DiscoveryURL: os.Getenv("GIBSON_IDP_ADMIN_DISCOVERY_URL"),
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
		DiscoveryURL: cfg.DiscoveryURL,
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
// matching cmd/active-session-backfill and cmd/tenant-owner-backfill. Pure
// and independently testable.
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

// runWithDeps resolves the Tenant CR, constructs clients via the supplied
// factory functions, and delegates to runBootstrap. All logic branches are
// exercisable by injecting fakes — only the real constructor calls in
// buildIdpClient/buildFgaClient/run's dynamic-client closure are irreducibly
// un-testable here.
func runWithDeps(
	ctx context.Context,
	logger *slog.Logger,
	stdout io.Writer,
	tenantID, ownerEmail, publicURL string,
	generatePassword bool,
	credentialSecret, credentialNamespace string,
	kubeLoader kubeConfigLoader,
	tenantProvider tenantGetterProvider,
	idpBuilder idpClientBuilder,
	fgaBuilder fgaClientBuilder,
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

	// Idempotence gate: if the credential Secret already exists the owner was
	// set up on a prior run (and the operator may have rotated the password), so
	// the bootstrap must resolve the owner WITHOUT resetting it. Only consulted
	// when we would otherwise write a credential.
	credentialExists := false
	if generatePassword && credentialSecret != "" {
		exists, cerr := credentialChecker(ctx, k8sCfg, credentialNamespace, credentialSecret)
		if cerr != nil {
			logger.Error("could not check the credential Secret; refusing to risk resetting a rotated password", "err", cerr)
			return 1
		}
		credentialExists = exists
	}

	result, err := runBootstrap(ctx, tenantID, ownerEmail, publicURL, generatePassword, credentialExists, tenantGetter, idpC, fgaC)
	if err == nil && result.MembershipWarning != "" {
		logger.Warn("owner is a gibson tenant owner (FGA) but the Zitadel org-member grant did not apply — sign-in still works; the Zitadel org-member role is a separate, tracked gap",
			"tenant", tenantID, "detail", result.MembershipWarning)
	}
	if err == nil && result.InitialPassword != "" && credentialSecret != "" {
		// Job logs are not a credential store: they are readable by anyone with
		// pod-log access and they age out. Writing a Secret gives the operator
		// something to fetch deliberately and delete deliberately.
		//
		// CREATE ONLY. If the Secret already exists this leaves it untouched —
		// the same rule as the re-run path, for the same reason: the operator
		// may have rotated the credential already.
		if serr := credentialWriter(ctx, k8sCfg, credentialNamespace, credentialSecret, ownerEmail, result.InitialPassword); serr != nil {
			logger.Error("could not write the credential Secret — the password is in this Job's output and nowhere else",
				"secret", credentialSecret, "err", serr)
		} else {
			logger.Info("wrote first-admin credential", "secret", credentialNamespace+"/"+credentialSecret)
		}
	}
	if err != nil {
		logger.Error("bootstrap failed", "tenant", tenantID, "err", err)
		return 1
	}

	// Complete the instruction the credential Secret carries. It says "sign in,
	// change it, then delete this Secret", and operators skip the delete, which
	// leaves a Secret that still reads as the admin password after Zitadel
	// stopped accepting it. Only on a re-run: on first setup the password and
	// the Secret were written moments ago, so there is nothing spent yet.
	//
	// Never fatal. A live owner with a stale Secret is a hygiene problem; a Job
	// that exits non-zero over it would make the install look broken when the
	// bootstrap itself succeeded.
	if credentialExists && credentialSecret != "" {
		changedAt, perr := idpC.HumanPasswordChangedAt(ctx, result.OwnerUserID)
		switch {
		case perr != nil:
			logger.Warn("could not read the owner's password-change time; leaving the credential Secret in place",
				"secret", credentialNamespace+"/"+credentialSecret, "err", perr)
		default:
			deleted, derr := credentialExpirer(ctx, k8sCfg, credentialNamespace, credentialSecret, changedAt)
			switch {
			case derr != nil:
				logger.Warn("could not expire the spent credential Secret; it still holds a password Zitadel no longer accepts",
					"secret", credentialNamespace+"/"+credentialSecret, "err", derr)
			case deleted:
				logger.Info("the owner changed their password, so the initial credential is spent — deleted it",
					"secret", credentialNamespace+"/"+credentialSecret, "password_changed", changedAt.UTC().Format(time.RFC3339))
			}
		}
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
	if printErr == nil && result.InitialPassword != "" {
		// The ONLY place this value is surfaced. It is not logged, not stored
		// by this binary, and not printed again on a re-run — a second run
		// against an existing owner deliberately reports nothing, because the
		// operator may have rotated it already (deploy#1631).
		_, printErr = fmt.Fprintf(stdout,
			"\ninitial admin password: %s\n"+
				"ROTATE THIS. It is shown once, here, and nowhere else. Sign in with\n"+
				"the owner email above, change the password, and delete any copy of\n"+
				"this output.\n", result.InitialPassword)
	}
	if printErr != nil {
		// The bootstrap itself already succeeded (user created, membership
		// granted, tuple written); a broken stdout must not turn that into a
		// failure. Log it so the operator still learns the write failed.
		logger.Warn("failed to print sign-in path", "err", printErr)
	}
	return 0
}

// runBootstrap performs the three-step bootstrap: ensure the Zitadel human
// user, ensure Zitadel org membership, ensure the FGA owner tuple. Zitadel
// calls (both idempotent) run first; the FGA write runs only after both
// succeed, so a Zitadel failure can never leave a partial FGA tuple.
func runBootstrap(
	ctx context.Context,
	tenantID, ownerEmail, publicURL string,
	generatePassword bool,
	credentialExists bool,
	tenants TenantGetter,
	idpC idpClient,
	fgaC fgaClient,
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

	var (
		userID          string
		initialPassword string
	)
	switch {
	case generatePassword && credentialExists:
		// Re-run after the credential Secret already exists. The operator holds
		// that credential (and may have rotated it), so resolve the owner
		// without touching the password and report no new credential.
		initialPassword = ""
		userID, err = idpC.FindUserIDByEmailInOrg(ctx, ownerEmail, orgID)
		if err != nil {
			return BootstrapResult{}, fmt.Errorf("resolve existing owner Zitadel user: %w", err)
		}
	case generatePassword:
		// Self-hosted first admin, first setup (no credential Secret yet).
		// EmailVerified is set true, and that is honest here in a way it would
		// not be for signup: the address was supplied by the operator performing
		// the install, on their own cluster, and there is no mail transport to
		// prove it with anyway.
		initialPassword, err = generateInitialPassword()
		if err != nil {
			return BootstrapResult{}, fmt.Errorf("generate initial password: %w", err)
		}
		givenName, familyName := ownerProfileName(ownerEmail)
		res, cerr := idpC.CreateHumanUser(ctx, idp.CreateHumanUserRequest{
			OrgID:         orgID,
			Email:         ownerEmail,
			GivenName:     givenName,
			FamilyName:    familyName,
			Password:      initialPassword,
			EmailVerified: true,
		})
		switch {
		case cerr == nil:
			userID = res.UserID
		case errors.Is(cerr, idp.ErrAlreadyExists):
			// The founding-owner user already exists — the TenantMember
			// invitation flow created it in an initial state (AcceptedByUserID
			// was empty on the operator-seeded pending row, so it invited rather
			// than pre-accepted). No credential Secret exists yet, so this IS the
			// first setup: activate that account by setting the generated
			// password on it, and keep the credential so the Secret is written.
			userID, err = idpC.FindUserIDByEmailInOrg(ctx, ownerEmail, orgID)
			if err != nil {
				return BootstrapResult{}, fmt.Errorf("resolve existing owner Zitadel user: %w", err)
			}
			if serr := idpC.SetHumanPassword(ctx, idp.SetHumanPasswordRequest{
				OrgID:    orgID,
				UserID:   userID,
				Password: initialPassword,
			}); serr != nil {
				return BootstrapResult{}, fmt.Errorf("activate existing owner with a password: %w", serr)
			}
		default:
			return BootstrapResult{}, fmt.Errorf("create owner Zitadel user: %w", cerr)
		}
	default:
		userID, err = idpC.EnsureHumanUser(ctx, idp.EnsureHumanUserRequest{OrgID: orgID, Email: ownerEmail})
		if err != nil {
			return BootstrapResult{}, fmt.Errorf("ensure owner Zitadel user: %w", err)
		}
	}

	// Non-fatal: gibson authorises tenant access via the FGA owner tuple below,
	// not via a Zitadel org-member role. If the org-member grant fails — the
	// usual cause is that the custom gibson.owner org-member role is not defined
	// in this deployment's Zitadel config — the first admin can still sign in and
	// own the tenant, so record a warning and continue rather than stranding the
	// install one grant short of a working login.
	var membershipWarning string
	if err := idpC.AddTenantMember(ctx, idp.TenantMembershipRequest{OrgID: orgID, UserID: userID, Role: ownerRelation}); err != nil {
		membershipWarning = fmt.Sprintf("add owner to tenant Zitadel org: %v", err)
	}

	userRef := "user:" + userID
	tenantRef := "tenant:" + tenantID
	present, err := fgaC.Check(ctx, userRef, ownerRelation, tenantRef)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("fga Check %s: %w", ownerRelation, err)
	}

	result := BootstrapResult{
		TenantID:          tenantID,
		OwnerUserID:       userID,
		InitialPassword:   initialPassword,
		MembershipWarning: membershipWarning,
	}
	if publicURL != "" {
		result.SignInPath = strings.TrimRight(publicURL, "/") + "/login"
	}

	if present {
		result.Outcome = outcomeAlreadyOwner
		return result, nil
	}

	tuple := authz.Tuple{User: userRef, Relation: ownerRelation, Object: tenantRef}
	if err := fgaC.Write(ctx, []authz.Tuple{tuple}); err != nil {
		return BootstrapResult{}, fmt.Errorf("fga Write %s: %w", ownerRelation, err)
	}
	result.Outcome = outcomeBootstrapped
	return result, nil
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

// writeCredentialSecret stores the generated first-admin credential.
//
// Create-only by design: an AlreadyExists is success, not an error to retry.
// Overwriting would hand back a password the operator may have already
// replaced, and would do it silently (deploy#1631).
func writeCredentialSecret(ctx context.Context, cs kubernetes.Interface, namespace, name, email, password string) error {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "bootstrap-tenant-owner",
				"app.kubernetes.io/component":  "first-admin",
			},
			Annotations: map[string]string{
				"gibson.zeroroot.ai/rotate-me": "This is the INITIAL credential. Sign in and change your password. This Secret is then deleted automatically on the next bootstrap run, and is safe to delete by hand at any time.",
				"gibson.zeroroot.ai/ref":       "deploy#1631",
			},
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"username": email,
			"password": password,
		},
	}
	_, err := cs.CoreV1().Secrets(namespace).Create(ctx, sec, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("create credential Secret %s/%s: %w", namespace, name, err)
	}
	return nil
}

// credentialWriter is swapped in tests: the write path must be exercisable
// without a live API server, and a *rest.Config pointed at nothing either
// hangs or fails for reasons unrelated to what the test asserts.
var credentialWriter = writeCredentialViaConfig

// credentialChecker reports whether the credential Secret already exists, so the
// bootstrap sets the owner's password ONCE (first install) and never resets it
// on a re-run — the operator may have rotated it. Swapped in tests.
var credentialChecker = credentialExistsViaConfig

// writeCredentialViaConfig builds the real clientset and delegates. Split from
// writeCredentialSecret so the create-only semantics are testable against a
// fake clientset without a rest.Config.
func writeCredentialViaConfig(ctx context.Context, cfg *rest.Config, namespace, name, email, password string) error {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("build kubernetes client: %w", err)
	}
	return writeCredentialSecret(ctx, cs, namespace, name, email, password)
}

// credentialExistsViaConfig reports whether the credential Secret is already
// present. A get that fails for any reason OTHER than NotFound is surfaced, so
// an API blip is never mistaken for "no credential yet" (which would reset a
// rotated password).
func credentialExistsViaConfig(ctx context.Context, cfg *rest.Config, namespace, name string) (bool, error) {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, fmt.Errorf("build kubernetes client: %w", err)
	}
	return credentialExists(ctx, cs, namespace, name)
}

// credentialExists is the testable core of credentialExistsViaConfig: a get that
// distinguishes "absent" (NotFound → false) from a real error (surfaced, so an
// API blip is never mistaken for "no credential yet").
func credentialExists(ctx context.Context, cs kubernetes.Interface, namespace, name string) (bool, error) {
	_, err := cs.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return true, nil
	}
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return false, fmt.Errorf("get credential Secret %s/%s: %w", namespace, name, err)
}

// generateInitialPassword mints the first admin's initial credential.
//
// Generated, never supplied in values: a password an operator types into a
// values file exists in that file, in shell history and in whatever copied the
// file there. This one exists only in the IdP and in the single output the
// install surfaces (deploy#1631, following the GitLab self-managed pattern).
//
// 24 bytes of crypto/rand, base64url, no padding — ~192 bits, and safe to
// paste into any terminal or form without quoting surprises.
// randRead is swapped in tests: crypto/rand cannot be made to fail on demand,
// and the error branch guards the one credential the operator gets.
var randRead = rand.Read

func generateInitialPassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := randRead(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	// Zitadel's default password policy requires an upper-case letter, a
	// lower-case letter, a digit and a symbol. base64url gives upper/lower/digit
	// but its only symbols (- _) appear by chance, so a run could omit every
	// class and Zitadel would reject the create with a bare INVALID_ARGUMENT.
	// Append one guaranteed character from each required class so a valid
	// password is produced on EVERY run, deterministically.
	return base64.RawURLEncoding.EncodeToString(buf) + "Aa1!", nil
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

// credentialSkewGuard is the margin the password-change timestamp must clear
// before the initial credential counts as spent.
//
// The two timestamps compared come from different clocks — the Kubernetes API
// server stamps the Secret, Zitadel stamps the password — so a small disagreement
// between them is normal and must not be read as a rotation. A minute is far
// more than NTP-synced hosts drift, and far less than the gap left by a real
// operator signing in and changing a password.
//
// The guard fails SAFE in one direction only: an operator who rotates within a
// minute of install keeps a stale Secret (harmless, and the annotation still
// tells them to delete it). It never deletes a live credential over skew.
const credentialSkewGuard = time.Minute

// expireSpentCredential deletes the first-admin credential Secret once Zitadel
// shows the password it holds is no longer the account's password.
//
// The Secret is written with the instruction "sign in, change it, then delete
// this Secret". Operators do the first two and skip the third, which leaves a
// Secret that still reads as the admin credential long after it stopped being
// one. That is discovered during a break-glass event, which is the worst
// possible moment to learn the recorded password is wrong.
//
// So the bootstrap completes step three itself: if the password changed AFTER
// this Secret was created, the value inside it cannot be the current password,
// and a spent credential is deleted rather than left to mislead.
//
// Three conditions must all hold before anything is deleted:
//
//  1. Zitadel reports a password-change timestamp at all (a zero time means the
//     password is still the one set at user creation — the Secret is live).
//  2. That timestamp is later than the Secret's own creation time by more than
//     credentialSkewGuard.
//  3. The Secret is one this binary wrote (managed-by label), so a Secret an
//     operator hand-placed at that name is never touched.
//
// The delete carries UID and resourceVersion preconditions: if anything rewrote
// the Secret between the read and the delete, the delete fails rather than
// destroying content this function never examined.
//
// Returns true only when a Secret was actually deleted.
func expireSpentCredential(
	ctx context.Context,
	cs kubernetes.Interface,
	namespace, name string,
	passwordChangedAt time.Time,
) (bool, error) {
	if passwordChangedAt.IsZero() {
		return false, nil
	}
	sec, err := cs.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get credential Secret %s/%s: %w", namespace, name, err)
	}
	if sec.Labels["app.kubernetes.io/managed-by"] != "bootstrap-tenant-owner" {
		return false, nil
	}
	if !passwordChangedAt.After(sec.CreationTimestamp.Add(credentialSkewGuard)) {
		return false, nil
	}
	uid, rv := sec.UID, sec.ResourceVersion
	err = cs.CoreV1().Secrets(namespace).Delete(ctx, name, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv},
	})
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		// Someone else removed or rewrote it first. Either way this function's
		// job is done and its view of the content is stale.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("delete spent credential Secret %s/%s: %w", namespace, name, err)
	}
	return true, nil
}

// expireSpentCredentialViaConfig builds the real clientset and delegates. Split
// from expireSpentCredential so the delete semantics are testable against a
// fake clientset without a rest.Config.
func expireSpentCredentialViaConfig(
	ctx context.Context,
	cfg *rest.Config,
	namespace, name string,
	passwordChangedAt time.Time,
) (bool, error) {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, fmt.Errorf("build kubernetes client: %w", err)
	}
	return expireSpentCredential(ctx, cs, namespace, name, passwordChangedAt)
}

// credentialExpirer is swapped in tests, for the same reason credentialWriter is.
var credentialExpirer = expireSpentCredentialViaConfig
