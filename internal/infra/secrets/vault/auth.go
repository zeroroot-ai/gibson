// Package vault provides a HashiCorp Vault KV v2 implementation of the
// secrets.Broker interface. It supports Vault Enterprise (namespace
// isolation) and Vault Community Edition (path-prefix isolation) with
// multiple auth methods.
//
// Value encoding convention: secret values are stored in the KV v2 data map
// as {"value": "<base64-standard-encoded bytes>"}. Get decodes this field
// back to the original bytes. This convention is transparent to callers and
// allows arbitrary binary content (including null bytes) to round-trip through
// Vault, which stores key/value pairs as JSON.
//
// Spec: secrets-broker Requirement 3.
package vault

import (
	"context"
	"fmt"
	"io"
	"os"

	approleauth "github.com/openbao/openbao/api/auth/approle/v2"
	"github.com/openbao/openbao/api/v2"
)

// AuthMethod identifies the Vault auth method to use for a provider instance.
type AuthMethod string

const (
	// AuthMethodToken uses a static Vault token. Suitable for development
	// and short-lived automated workflows where token renewal is managed
	// externally. Do not use in production without a token-renewal side-car.
	AuthMethodToken AuthMethod = "token"

	// AuthMethodJWT authenticates by exchanging a caller-supplied JWT
	// against Vault's jwt auth method. The SDK is issuer-agnostic — it
	// posts whatever bearer the caller hands it. In the gibson platform
	// today the caller is the daemon, and the JWT is a SPIRE JWT-SVID
	// acquired from the Workload API socket (ADR-0009 amendment: the
	// platform Vault's auth/jwt mount carries a single SPIRE-only
	// bound_issuer). The earlier "Zitadel client-credentials token"
	// example was vestigial; no runtime code path exchanges a Zitadel
	// JWT for a Vault token.
	AuthMethodJWT AuthMethod = "jwt"

	// AuthMethodAppRole authenticates with a Vault AppRole role_id +
	// secret_id. Suitable for off-cluster deployments.
	AuthMethodAppRole AuthMethod = "approle"

	// AuthMethodAWSIAM authenticates using the calling instance's AWS IAM
	// identity via Vault's aws auth method.
	AuthMethodAWSIAM AuthMethod = "aws_iam"
)

// AuthConfig holds the per-method authentication configuration for the Vault
// provider. Only the fields relevant to the chosen Method need to be set.
//
// JSON tags are explicit + snake_case to make the serialised shape part of
// the SDK's public contract (see Config godoc). External writers — e.g.
// the gibson tenant-operator's WriteTenantBrokerConfig saga step — encode
// the AuthMethod string here and the daemon decodes the same shape at
// per-tenant provider construction time.
type AuthConfig struct {
	// Method selects the Vault auth method. Required.
	Method AuthMethod `json:"method"`

	// Token is the static Vault token. Required when Method == AuthMethodToken.
	Token string `json:"token,omitempty"`

	// Role is the Vault role name. Required for AuthMethodJWT and
	// AuthMethodAppRole.
	Role string `json:"role,omitempty"`

	// JWTPath selects the Vault JWT auth mount path. Defaults to "auth/jwt"
	// when Method is AuthMethodJWT and this field is empty.
	JWTPath string `json:"jwt_path,omitempty"`

	// JWT is the bearer token to exchange with Vault's jwt auth method.
	// Required when Method == AuthMethodJWT.
	JWT string `json:"jwt,omitempty"`

	// AppRoleID is the Vault AppRole role_id. Required when Method is
	// AuthMethodAppRole.
	AppRoleID string `json:"app_role_id,omitempty"`

	// AppRoleSecretID is the Vault AppRole secret_id. Required when Method
	// is AuthMethodAppRole.
	AppRoleSecretID string `json:"app_role_secret_id,omitempty"`
}

// defaultJWTPath is the default Vault JWT auth mount path.
const defaultJWTPath = "auth/jwt"

// authenticate performs a Vault login using the auth method described by cfg
// and attaches the resulting token to client. It is called at construction time.
func authenticate(ctx context.Context, client *api.Client, cfg AuthConfig) error {
	switch cfg.Method {
	case AuthMethodToken:
		if cfg.Token == "" {
			return fmt.Errorf("vault auth method 'token': Token is required")
		}
		client.SetToken(cfg.Token)
		return nil

	case AuthMethodJWT:
		if cfg.Role == "" {
			return fmt.Errorf("vault auth method 'jwt': Role is required")
		}
		if cfg.JWT == "" {
			return fmt.Errorf("vault auth method 'jwt': JWT is required")
		}
		jwtPath := cfg.JWTPath
		if jwtPath == "" {
			jwtPath = defaultJWTPath
		}
		// Write a temporary file for the JWT so we can use the vault SDK's
		// JWT auth handler, which reads from a file path.
		tmpFile, err := os.CreateTemp("", "vault-jwt-*")
		if err != nil {
			return fmt.Errorf("vault auth method 'jwt': failed to create temp file for JWT: %w", err)
		}
		tmpPath := tmpFile.Name()
		defer func() { _ = os.Remove(tmpPath) }()
		if _, err := io.WriteString(tmpFile, cfg.JWT); err != nil {
			_ = tmpFile.Close()
			return fmt.Errorf("vault auth method 'jwt': failed to write JWT to temp file: %w", err)
		}
		if err := tmpFile.Close(); err != nil {
			return fmt.Errorf("vault auth method 'jwt': failed to close JWT temp file: %w", err)
		}

		// Use the logical client directly for JWT auth to avoid a file-path
		// dependency on the jwt auth helper package.
		secret, err := client.Logical().WriteWithContext(ctx, jwtPath+"/login", map[string]interface{}{
			"role": cfg.Role,
			"jwt":  cfg.JWT,
		})
		if err != nil {
			return fmt.Errorf("vault auth method 'jwt' rejected: %w", err)
		}
		if secret == nil || secret.Auth == nil {
			return fmt.Errorf("vault auth method 'jwt': login returned no auth data")
		}
		client.SetToken(secret.Auth.ClientToken)
		return nil

	case AuthMethodAppRole:
		if cfg.AppRoleID == "" {
			return fmt.Errorf("vault auth method 'approle': AppRoleID is required")
		}
		if cfg.AppRoleSecretID == "" {
			return fmt.Errorf("vault auth method 'approle': AppRoleSecretID is required")
		}
		appRoleAuth, err := approleauth.NewAppRoleAuth(
			cfg.AppRoleID,
			&approleauth.SecretID{FromString: cfg.AppRoleSecretID},
		)
		if err != nil {
			return fmt.Errorf("vault auth method 'approle': failed to create auth handler: %w", err)
		}
		authInfo, err := client.Auth().Login(ctx, appRoleAuth)
		if err != nil {
			return fmt.Errorf("vault auth method 'approle' rejected: %w", err)
		}
		if authInfo == nil {
			return fmt.Errorf("vault auth method 'approle': login returned nil auth info")
		}
		return nil

	case AuthMethodAWSIAM:
		// Temporarily unsupported. The OpenBao Go module tree does not
		// publish an auth/aws/ helper (only approle, jwt, kubernetes,
		// ldap, userpass per openbao/openbao @ main), and the
		// HashiCorp helper's *api.Client type is incompatible with
		// OpenBao's. Re-enable per sdk#98 (inline sigv4 implementation
		// or upstream OpenBao auth/aws helper, whichever ships first).
		// The AuthMethodAWSIAM constant stays as a documented API
		// surface so future callers fail at runtime with a clear
		// message rather than at compile time.
		return fmt.Errorf("vault auth method 'aws_iam': not yet supported on OpenBao client (see sdk#98)")

	default:
		return fmt.Errorf("vault: unsupported auth method %q", cfg.Method)
	}
}
