package provisioner

// bootstrap_realm.go provisions the shared "gibson" Keycloak realm that all
// tenants authenticate against in the single-realm deployment model.
//
// BootstrapGibsonRealm is called once during daemon startup (or operator-driven
// bootstrap) and is fully idempotent — every sub-operation treats HTTP 409
// Conflict as a successful no-op, so the function is safe to call on every
// restart without risk of duplicating resources.

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zero-day-ai/gibson/internal/keycloak"
)

const gibsonRealmName = "gibson"

// BootstrapGibsonRealm ensures the shared "gibson" Keycloak realm exists and
// is configured with the OIDC client, realm roles, protocol mappers, and
// default scopes required by the Gibson platform.
//
// All sub-operations are best-effort: failures are logged as warnings rather
// than propagated as errors, matching the idempotent pattern used by the per-
// tenant stepCreateRealm in provisioner.go.  This mirrors operational reality:
// individual configuration operations may fail transiently without leaving the
// realm in an unrecoverable state.
//
// Parameters:
//   - ctx: request context; cancellation aborts any in-flight Keycloak calls.
//   - kc: authenticated Keycloak admin client.
//   - oidcClientSecret: shared secret for the "gibson-dashboard" OIDC client.
//   - logger: structured logger; all warnings are emitted at Warn level.
func BootstrapGibsonRealm(ctx context.Context, kc *keycloak.Client, oidcClientSecret string, logger *slog.Logger) error {
	if kc == nil {
		return fmt.Errorf("bootstrap_realm: keycloak client must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	// 1. Create the realm.  409 Conflict means it already exists — treat as success.
	if err := kc.CreateRealm(ctx, keycloak.RealmConfig{
		Name:        gibsonRealmName,
		DisplayName: "Gibson",
		Enabled:     true,
	}); err != nil {
		logger.WarnContext(ctx, "failed to create gibson realm (may already exist)",
			slog.String("realm", gibsonRealmName),
			slog.String("error", err.Error()),
		)
	}

	// Grant our service account admin permissions on the realm so subsequent
	// operations (create client, roles, users) within the realm succeed.
	if err := kc.GrantSelfAdminOnRealm(ctx, gibsonRealmName); err != nil {
		logger.WarnContext(ctx, "failed to grant self-admin on gibson realm",
			slog.String("realm", gibsonRealmName),
			slog.String("error", err.Error()),
		)
	}

	// Disable VERIFY_PROFILE so direct-grant (password) auth works without
	// requiring users to complete their profile via a browser flow.
	kc.DisableRequiredAction(ctx, gibsonRealmName, "VERIFY_PROFILE")

	// Configure User Profile: add tenant_id attribute and allow @ in usernames.
	// Keycloak 24+ silently drops unknown attributes and blocks email-as-username
	// without explicit profile configuration.
	kc.ConfigureUserProfile(ctx, gibsonRealmName)

	// 2. Create the OIDC client used by the dashboard.
	clientUUID, err := kc.CreateOIDCClient(ctx, gibsonRealmName, keycloak.OIDCClientConfig{
		ClientID:     "gibson-dashboard",
		Secret:       oidcClientSecret,
		RedirectURIs: []string{"*"},
	})
	if err != nil {
		logger.WarnContext(ctx, "failed to create gibson-dashboard OIDC client (may already exist)",
			slog.String("realm", gibsonRealmName),
			slog.String("error", err.Error()),
		)
	}

	// 3. Create the standard Gibson realm roles.
	for _, role := range []string{"owner", "admin", "operator", "viewer"} {
		if roleErr := kc.CreateRealmRole(ctx, gibsonRealmName, role, "Gibson "+role+" role"); roleErr != nil {
			logger.WarnContext(ctx, "failed to create realm role (may already exist)",
				slog.String("realm", gibsonRealmName),
				slog.String("role", role),
				slog.String("error", roleErr.Error()),
			)
		}
	}

	// 4. Add protocol mappers to the OIDC client.
	if clientUUID != "" {
		// tenant_id attribute mapper: surfaces the user's tenant_id attribute as
		// a claim on every issued token.
		if mapErr := kc.AddProtocolMapper(ctx, gibsonRealmName, clientUUID, keycloak.ProtocolMapperConfig{
			Name:           "tenant_id",
			Protocol:       "openid-connect",
			ProtocolMapper: "oidc-usermodel-attribute-mapper",
			Config: map[string]string{
				"user.attribute":       "tenant_id",
				"claim.name":           "tenant_id",
				"jsonType.label":       "String",
				"id.token.claim":       "true",
				"access.token.claim":   "true",
				"userinfo.token.claim": "true",
				"multivalued":          "false",
				"aggregate.attrs":      "false",
			},
		}); mapErr != nil {
			logger.WarnContext(ctx, "failed to add tenant_id protocol mapper (may already exist)",
				slog.String("realm", gibsonRealmName),
				slog.String("error", mapErr.Error()),
			)
		}

		// Realm roles mapper: includes the user's realm roles (owner, admin, etc.)
		// in the token under realm_access.roles.
		if mapErr := kc.AddProtocolMapper(ctx, gibsonRealmName, clientUUID, keycloak.ProtocolMapperConfig{
			Name:           "realm roles",
			Protocol:       "openid-connect",
			ProtocolMapper: "oidc-usermodel-realm-role-mapper",
			Config: map[string]string{
				"claim.name":           "realm_access.roles",
				"jsonType.label":       "String",
				"id.token.claim":       "true",
				"access.token.claim":   "true",
				"userinfo.token.claim": "true",
				"multivalued":          "true",
			},
		}); mapErr != nil {
			logger.WarnContext(ctx, "failed to add realm roles mapper (may already exist)",
				slog.String("realm", gibsonRealmName),
				slog.String("error", mapErr.Error()),
			)
		}

		// Add the "email" client scope as a default so tokens include the email claim.
		if scopeErr := kc.AddDefaultClientScope(ctx, gibsonRealmName, clientUUID, "email"); scopeErr != nil {
			logger.WarnContext(ctx, "failed to add email scope to OIDC client",
				slog.String("realm", gibsonRealmName),
				slog.String("error", scopeErr.Error()),
			)
		}
	}

	logger.InfoContext(ctx, "gibson realm bootstrap complete",
		slog.String("realm", gibsonRealmName),
	)

	return nil
}
