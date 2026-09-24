// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — idp_init.go wires the vendor-neutral IdP admin client
// into the daemon at startup. It is the only file in the daemon package that
// is allowed to import internal/platform/idp/zitadel; all other daemon code programs
// against the idp.AdminClient interface only.
package daemon

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/idp/zitadel"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
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

	// Zitadel-specific env vars (GIBSON_IDP_ZITADEL_*).

	// envZitadelOrgID is the Zitadel organisation ID.
	envZitadelOrgID = "GIBSON_IDP_ZITADEL_ORG_ID"
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

	// ADR-0092: connect to the Zitadel Service and claim the public host by
	// header. Both come from the chart helper; neither is optional.
	endpoint, err := zitadelconn.FromEnv()
	if err != nil {
		return nil, fmt.Errorf("idp: provider \"zitadel\": %w", err)
	}

	cfg := zitadel.Config{
		Issuer:       os.Getenv(envIDPAdminIssuer),
		ClientID:     os.Getenv(envIDPAdminClientID),
		ClientSecret: os.Getenv(envIDPAdminClientSecret),
		OrgID:        os.Getenv(envZitadelOrgID),
		HTTPTimeout:  10 * time.Second,
		Endpoint:     endpoint,
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
