// Package daemon — idp_init.go wires the vendor-neutral IdP admin client
// into the daemon at startup. It is the only file in the daemon package that
// is allowed to import internal/idp/zitadel; all other daemon code programs
// against the idp.AdminClient interface only.
package daemon

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/zero-day-ai/gibson/internal/idp"
	"github.com/zero-day-ai/gibson/internal/idp/zitadel"
)

const (
	// IdP provider environment variables.

	// envIDPProvider selects the IdP implementation.
	// The only accepted value in this release is "zitadel".
	envIDPProvider = "GIBSON_IDP_PROVIDER"

	// Shared env vars consumed by all provider implementations.

	// envIDPAdminIssuer is the OIDC issuer URL for the IdP admin account.
	envIDPAdminIssuer = "GIBSON_IDP_ADMIN_ISSUER"

	// envIDPAdminClientID is the OAuth2 client ID of the admin service account.
	envIDPAdminClientID = "GIBSON_IDP_ADMIN_CLIENT_ID"

	// envIDPAdminClientSecret is the OAuth2 client secret. This value MUST NOT
	// appear in any log line, audit event, or error message. The constant name
	// is intentionally prefixed with "env" to flag that it is an env var name,
	// not a credential value.
	envIDPAdminClientSecret = "GIBSON_IDP_ADMIN_CLIENT_SECRET" //nolint:gosec // env var name, not a credential

	// envIDPAdminDiscoveryURL is the OPTIONAL in-cluster URL the daemon's
	// IdP admin client dials for OIDC discovery and JWKS fetches. When
	// empty (the default), discovery falls back to envIDPAdminIssuer. The
	// `iss` claim used for token validation is always envIDPAdminIssuer
	// regardless of this var; only the network path to the discovery doc
	// is moved off the externally-routable hostname.
	//
	// Spec: tier-2-host-aliases-cluster-dns. Operators with the chart
	// supply this from idp.zitadel.discoveryURL; without the chart it
	// stays empty and discovery goes through cluster DNS to the issuer.
	envIDPAdminDiscoveryURL = "GIBSON_IDP_ADMIN_DISCOVERY_URL"

	// Zitadel-specific env vars (GIBSON_IDP_ZITADEL_*).

	// envZitadelOrgID is the Zitadel organisation ID.
	envZitadelOrgID = "GIBSON_IDP_ZITADEL_ORG_ID"

	// envZitadelProjectID is the Zitadel project ID for tenant scope membership.
	envZitadelProjectID = "GIBSON_IDP_ZITADEL_PROJECT_ID"
)

// initIDPAdminClient constructs an idp.AdminClient from environment variables.
//
// Fail-closed semantics:
//   - If GIBSON_IDP_PROVIDER is empty, returns (nil, nil) — no IdP configured,
//     and TenantAdminService will not be registered.
//   - If GIBSON_IDP_PROVIDER is set but any required env var is missing, returns
//     an error. The daemon MUST refuse to start.
//   - If the startup probe fails (provider unreachable or credentials rejected),
//     returns an error. The daemon MUST refuse to start.
//
// The client_secret value MUST NOT appear in any returned error message.
func initIDPAdminClient(ctx context.Context) (idp.AdminClient, error) {
	provider := os.Getenv(envIDPProvider)
	if provider == "" {
		// No IdP configured — TenantAdminService agent-identity RPCs will not
		// be available. Operators must set GIBSON_IDP_PROVIDER to enable them.
		return nil, nil
	}

	switch provider {
	case "zitadel":
		return initZitadelClient(ctx)
	default:
		return nil, fmt.Errorf("idp: unsupported provider %q in %s; supported values: zitadel", provider, envIDPProvider)
	}
}

// initZitadelClient reads Zitadel-specific env vars and constructs the client.
func initZitadelClient(ctx context.Context) (idp.AdminClient, error) {
	type reqVar struct {
		name  string
		value string
	}
	vars := []reqVar{
		{envIDPAdminIssuer, os.Getenv(envIDPAdminIssuer)},
		{envIDPAdminClientID, os.Getenv(envIDPAdminClientID)},
		{envIDPAdminClientSecret, os.Getenv(envIDPAdminClientSecret)},
		{envZitadelOrgID, os.Getenv(envZitadelOrgID)},
		{envZitadelProjectID, os.Getenv(envZitadelProjectID)},
	}

	var missing []string
	for _, v := range vars {
		if v.value == "" {
			missing = append(missing, v.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("idp: provider \"zitadel\" requires env vars that are not set: %v", missing)
	}

	cfg := zitadel.Config{
		Issuer:       os.Getenv(envIDPAdminIssuer),
		ClientID:     os.Getenv(envIDPAdminClientID),
		ClientSecret: os.Getenv(envIDPAdminClientSecret),
		OrgID:        os.Getenv(envZitadelOrgID),
		ProjectID:    os.Getenv(envZitadelProjectID),
		HTTPTimeout:  10 * time.Second,
		// Spec tier-2-host-aliases-cluster-dns: optional in-cluster
		// discovery URL. Empty → discovery falls back to Issuer.
		DiscoveryURL: os.Getenv(envIDPAdminDiscoveryURL),
	}

	// zitadel.New performs the startup probe; if it fails the error wraps
	// idp.ErrUnreachable or idp.ErrPermission. We re-wrap to include context.
	// The ClientSecret value is NOT included in the error message.
	client, err := zitadel.New(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("idp: zitadel startup probe failed (issuer=%s client_id=%s): %w",
			cfg.Issuer, cfg.ClientID, err)
	}
	return client, nil
}
