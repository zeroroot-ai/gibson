// Package azurekv provides an Azure Key Vault implementation of the
// secrets.Broker interface using the azsecrets SDK.
//
// # Naming convention and sanitization
//
// Azure Key Vault secret names are limited to characters matching
// [a-zA-Z0-9-]{1,127}. The broker name (e.g. "cred:foo" or
// "provider_config:anthropic:default") may contain characters that violate
// this constraint. The provider sanitizes broker names by applying the
// following rule:
//
//  1. Replace every ":", "/", "_", and "." character with "-".
//  2. Replace any other character not in [a-zA-Z0-9-] with "-".
//  3. Collapse consecutive hyphens into a single hyphen.
//  4. Trim leading and trailing hyphens.
//  5. If the result is empty, return ErrInvalidArgument.
//  6. The full Azure KV secret name is "gibson-tenant-<tenant_id>-<sanitized>".
//  7. If the total length exceeds 127 characters, return ErrInvalidArgument.
//
// Because sanitization is lossy (several different broker names may map to the
// same Azure KV name), callers must ensure uniqueness at the broker name level.
// The broker contract enforces this via the Put-then-Get round-trip test.
//
// # Authentication
//
// Two auth methods are supported:
//
//   - service_principal: uses azidentity.NewClientSecretCredential with a
//     TenantID, ClientID, and ClientSecret.
//   - workload_identity: uses azidentity.NewWorkloadIdentityCredential,
//     which reads the standard Azure Workload Identity environment variables
//     (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_FEDERATED_TOKEN_FILE).
//
// # Delete semantics
//
// Azure Key Vault soft-deletes secrets by default. BeginDeleteSecret is
// called without polling for completion; the secret is immediately
// unavailable from the Get path once the deletion is initiated. A subsequent
// Get on a soft-deleted secret returns 404.
//
// # Value encoding
//
// Azure Key Vault stores secret values as UTF-8 strings. The provider
// base64-encodes binary values before storing them and decodes on Get, so
// arbitrary binary content (including null bytes) round-trips correctly.
//
// Spec: secrets-broker Requirement 4.3.
package azurekv

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// maxValueBytes is the Azure Key Vault practical limit for a secret value.
// AKV allows up to ~25 000 bytes for a secret value.
const maxValueBytes = 25000

// maxAzureSecretNameLength is the maximum length for an Azure KV secret name.
const maxAzureSecretNameLength = 127

// azureNameRe matches characters that are not valid in Azure KV secret names.
var azureNameRe = regexp.MustCompile(`[^a-zA-Z0-9-]`)

// AuthMethod identifies the Azure authentication method.
type AuthMethod string

const (
	// AuthMethodServicePrincipal authenticates using an Azure AD application
	// service principal with a client secret. Requires TenantID, ClientID,
	// and ClientSecret.
	AuthMethodServicePrincipal AuthMethod = "service_principal"

	// AuthMethodWorkloadIdentity authenticates using Azure Workload Identity
	// Federation. The provider reads the standard environment variables
	// (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_FEDERATED_TOKEN_FILE).
	// Suitable for Kubernetes deployments with Azure Workload Identity.
	AuthMethodWorkloadIdentity AuthMethod = "workload_identity"
)

// AuthConfig holds the authentication configuration for the Azure KV provider.
type AuthConfig struct {
	// Method selects the Azure authentication method. Required.
	Method AuthMethod

	// TenantID is the Azure AD tenant (directory) ID. Required for
	// AuthMethodServicePrincipal.
	TenantID string

	// ClientID is the Azure AD application (client) ID. Required for
	// AuthMethodServicePrincipal.
	ClientID string

	// ClientSecret is the Azure AD application client secret. Required for
	// AuthMethodServicePrincipal.
	ClientSecret string
}

// Config holds the per-provider Azure Key Vault configuration.
type Config struct {
	// VaultURL is the Azure Key Vault URL, e.g.
	// "https://my-vault.vault.azure.net/". Required.
	VaultURL string

	// Auth holds the authentication configuration.
	Auth AuthConfig
}

// kvClient is the subset of the azsecrets.Client methods used by the
// provider. Defined as an interface to enable mock injection in unit tests
// via an httptest.Server-backed transport or a direct mock.
type kvClient interface {
	GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
	SetSecret(ctx context.Context, name string, parameters azsecrets.SetSecretParameters, options *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error)
	DeleteSecret(ctx context.Context, name string, options *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error)
	NewListSecretPropertiesPager(options *azsecrets.ListSecretPropertiesOptions) *runtime.Pager[azsecrets.ListSecretPropertiesResponse]
}

// Provider is an Azure Key Vault implementation of secrets.Broker.
// Provider is safe for concurrent use from multiple goroutines.
type Provider struct {
	client kvClient
	cfg    Config
}

// New constructs a Provider from cfg. It validates the configuration,
// initialises the Azure credential, and creates the azsecrets client.
//
// New returns an error when:
//   - cfg.VaultURL is empty.
//   - cfg.Auth.Method is not a recognised value.
//   - The credential cannot be created (e.g., missing required fields).
func New(cfg Config) (*Provider, error) {
	if cfg.VaultURL == "" {
		return nil, fmt.Errorf("azurekv: Config.VaultURL is required")
	}

	cred, err := buildCredential(cfg.Auth)
	if err != nil {
		return nil, err
	}

	c, err := azsecrets.NewClient(cfg.VaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azurekv: failed to create Azure KV client: %w", err)
	}

	return &Provider{client: c, cfg: cfg}, nil
}

// newWithClient constructs a Provider using an injected kvClient.
// Used in unit tests.
func newWithClient(cfg Config, client kvClient) *Provider {
	return &Provider{client: client, cfg: cfg}
}

// buildCredential creates an azcore.TokenCredential from the given AuthConfig.
func buildCredential(cfg AuthConfig) (azcore.TokenCredential, error) {
	switch cfg.Method {
	case AuthMethodServicePrincipal:
		if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
			return nil, fmt.Errorf("azurekv: AuthMethodServicePrincipal requires Auth.TenantID, Auth.ClientID, and Auth.ClientSecret")
		}
		return azidentity.NewClientSecretCredential(cfg.TenantID, cfg.ClientID, cfg.ClientSecret, nil)

	case AuthMethodWorkloadIdentity:
		return azidentity.NewWorkloadIdentityCredential(nil)

	default:
		return nil, fmt.Errorf("azurekv: unsupported auth method %q", cfg.Method)
	}
}

// sanitizeName converts a broker name to a valid Azure KV secret name
// component. See package doc for the full sanitization rule.
//
// The function returns an error when:
//   - The input is empty.
//   - The sanitized result is empty (e.g., all-separator input).
func sanitizeName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%w: secret name is empty", secrets.ErrInvalidArgument)
	}

	// Replace known separators and invalid characters with hyphens.
	sanitized := azureNameRe.ReplaceAllString(name, "-")

	// Collapse consecutive hyphens.
	for strings.Contains(sanitized, "--") {
		sanitized = strings.ReplaceAll(sanitized, "--", "-")
	}

	// Trim leading/trailing hyphens.
	sanitized = strings.Trim(sanitized, "-")

	if sanitized == "" {
		return "", fmt.Errorf("%w: %q sanitizes to empty string", secrets.ErrInvalidArgument, name)
	}

	return sanitized, nil
}

// secretName builds the full Azure KV secret name for a given tenant and
// broker name. The format is:
//
//	gibson-tenant-<tenant_id>-<sanitized_name>
//
// Returns ErrInvalidArgument when sanitization fails or the resulting name
// exceeds maxAzureSecretNameLength characters.
func (p *Provider) secretName(tenant auth.TenantID, name string) (string, error) {
	sanitized, err := sanitizeName(name)
	if err != nil {
		return "", err
	}

	full := fmt.Sprintf("gibson-tenant-%s-%s", tenant.String(), sanitized)

	if len(full) > maxAzureSecretNameLength {
		return "", fmt.Errorf("%w: azure KV secret name %q exceeds %d characters",
			secrets.ErrInvalidArgument, full, maxAzureSecretNameLength)
	}

	return full, nil
}

// tenantNamePrefix returns the secret-name prefix that identifies all secrets
// belonging to a given tenant.
func tenantNamePrefix(tenant auth.TenantID) string {
	return fmt.Sprintf("gibson-tenant-%s-", tenant.String())
}

// Get retrieves the current (latest) value of the named secret for the given
// tenant. Azure KV stores values as strings; the provider encodes binary
// values as base64 on Put and decodes on Get.
//
// Returns secrets.ErrNotFound when the secret does not exist or is deleted.
// Returns secrets.ErrPermissionDenied when Azure denies access.
// Returns secrets.ErrUnavailable for transient errors.
func (p *Provider) Get(ctx context.Context, tenant auth.TenantID, name string) ([]byte, error) {
	kvName, err := p.secretName(tenant, name)
	if err != nil {
		return nil, err
	}

	// Empty version string retrieves the latest version.
	resp, err := p.client.GetSecret(ctx, kvName, "", nil)
	if err != nil {
		return nil, mapAzureError(err, name)
	}

	if resp.Value == nil {
		return nil, fmt.Errorf("%w: %q (secret has no value)", secrets.ErrNotFound, name)
	}

	// Decode the base64-encoded binary payload.
	decoded, decErr := base64.StdEncoding.DecodeString(*resp.Value)
	if decErr != nil {
		// If decoding fails, the value was not stored by this provider
		// (or was stored as plain text). Return the raw bytes.
		return []byte(*resp.Value), nil //nolint:nilerr // intentional fallback: plain-text values skip base64
	}

	return decoded, nil
}

// Put creates or overwrites the named secret for the given tenant. The value
// is base64-encoded before storage so that binary content survives the
// string-only Azure KV storage layer.
//
// Azure KV upserts on each SetSecret call — no separate Create vs Update path.
//
// Returns secrets.ErrTooLarge when len(value) exceeds maxValueBytes.
// Returns secrets.ErrPermissionDenied when Azure denies access.
// Returns secrets.ErrUnavailable for transient errors.
func (p *Provider) Put(ctx context.Context, tenant auth.TenantID, name string, value []byte) error {
	if len(value) > maxValueBytes {
		return fmt.Errorf("%w: %d bytes (max %d)", secrets.ErrTooLarge, len(value), maxValueBytes)
	}

	kvName, err := p.secretName(tenant, name)
	if err != nil {
		return err
	}

	encoded := base64.StdEncoding.EncodeToString(value)

	_, err = p.client.SetSecret(ctx, kvName, azsecrets.SetSecretParameters{
		Value: &encoded,
	}, nil)
	if err != nil {
		return mapAzureError(err, name)
	}

	return nil
}

// Delete performs a soft delete of the named secret in Azure Key Vault.
// Azure KV soft-deletes secrets and the secret becomes unavailable from the
// Get path immediately after deletion is initiated. The deleted secret
// remains in a "deleted" state for the vault's soft-delete retention period.
//
// Deleting a non-existent secret is a no-op (idempotent).
//
// Returns secrets.ErrPermissionDenied when Azure denies access.
// Returns secrets.ErrUnavailable for transient errors.
func (p *Provider) Delete(ctx context.Context, tenant auth.TenantID, name string) error {
	kvName, err := p.secretName(tenant, name)
	if err != nil {
		return err
	}

	_, err = p.client.DeleteSecret(ctx, kvName, nil)
	if err != nil {
		// Treat 404 as a no-op for idempotent delete.
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
			return nil
		}
		return mapAzureError(err, name)
	}

	return nil
}

// List returns the broker names of all secrets belonging to the given tenant
// that match the supplied filter. It paginates through
// NewListSecretPropertiesPager, filtering by the tenant name prefix locally.
//
// Returns secrets.ErrPermissionDenied when Azure denies access.
// Returns secrets.ErrUnavailable for transient errors.
func (p *Provider) List(ctx context.Context, tenant auth.TenantID, filter secrets.Filter) ([]string, error) {
	prefix := tenantNamePrefix(tenant)
	pager := p.client.NewListSecretPropertiesPager(nil)

	var allNames []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, mapAzureError(err, "")
		}

		for _, item := range page.Value {
			if item == nil || item.ID == nil {
				continue
			}

			// The ID field contains the full URI, e.g.:
			// https://vault.azure.net/secrets/gibson-tenant-abc-cred-foo
			// Extract the last path component as the secret name.
			fullID := string(*item.ID)
			parts := strings.Split(fullID, "/")
			secretName := parts[len(parts)-1]

			// Filter to this tenant.
			if !strings.HasPrefix(secretName, prefix) {
				continue
			}

			// Strip the tenant prefix to recover the sanitized broker name.
			sanitizedBroker := strings.TrimPrefix(secretName, prefix)

			// Apply the caller's prefix filter.
			if filter.Prefix != "" && !strings.HasPrefix(sanitizedBroker, filter.Prefix) {
				continue
			}

			allNames = append(allNames, sanitizedBroker)
		}
	}

	// Apply offset and limit.
	if filter.Offset > 0 {
		if filter.Offset >= len(allNames) {
			return nil, nil
		}
		allNames = allNames[filter.Offset:]
	}
	if filter.Limit > 0 && len(allNames) > filter.Limit {
		allNames = allNames[:filter.Limit]
	}

	return allNames, nil
}

// Health performs a lightweight liveness check by paging through secrets with
// a limit of 1. A successful (or empty) result confirms connectivity and
// IAM permissions are intact.
func (p *Provider) Health(ctx context.Context) error {
	pager := p.client.NewListSecretPropertiesPager(nil)
	_, err := pager.NextPage(ctx)
	if err != nil {
		return fmt.Errorf("%w: azure key vault health check failed: %w", secrets.ErrUnavailable, err)
	}
	return nil
}

// Probe performs a write–read–delete round-trip of a canary secret against
// the configured Azure Key Vault, verifying full connectivity and permissions.
func (p *Provider) Probe(ctx context.Context) error {
	canaryName := probeCanaryName()
	probeValue := []byte("__probe__")
	probeTenant := auth.MustNewTenantID("probe-tenant")

	// Write.
	if err := p.Put(ctx, probeTenant, canaryName, probeValue); err != nil {
		return fmt.Errorf("azurekv probe write failed: %w", err)
	}

	// Read. Attempt cleanup regardless of outcome.
	got, readErr := p.Get(ctx, probeTenant, canaryName)
	_ = p.Delete(ctx, probeTenant, canaryName)

	if readErr != nil {
		return fmt.Errorf("azurekv probe read failed: %w", readErr)
	}

	if string(got) != string(probeValue) {
		return fmt.Errorf("azurekv probe value mismatch: wrote %q, got %q", probeValue, got)
	}

	return nil
}

// Capabilities returns the static capability set for the Azure Key Vault
// provider: full read/write/delete/list support, native versioning, and a
// 25 000-byte value ceiling (Azure KV practical limit for secrets).
func (p *Provider) Capabilities() secrets.Capabilities {
	return secrets.Capabilities{
		CanPut:          true,
		CanDelete:       true,
		CanList:         true,
		SupportsVersion: true,
		MaxValueBytes:   maxValueBytes,
	}
}

// mapAzureError translates an Azure SDK error to the appropriate secrets
// sentinel using the HTTP status code from azcore.ResponseError.
//
// Mapping table:
//   - 404 Not Found        → ErrNotFound
//   - 403 Forbidden        → ErrPermissionDenied
//   - 401 Unauthorized     → ErrPermissionDenied
//   - 429 Too Many Requests → ErrUnavailable
//   - 503 Service Unavailable → ErrUnavailable
//   - 400 Bad Request      → ErrInvalidArgument
//   - All other errors     → ErrUnavailable
func mapAzureError(err error, name string) error {
	if err == nil {
		return nil
	}

	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case http.StatusNotFound:
			if name != "" {
				return fmt.Errorf("%w: %q", secrets.ErrNotFound, name)
			}
			return secrets.ErrNotFound

		case http.StatusForbidden, http.StatusUnauthorized:
			return fmt.Errorf("%w: azure denied the request (HTTP %d)", secrets.ErrPermissionDenied, respErr.StatusCode)

		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			return fmt.Errorf("%w: azure service unavailable (HTTP %d)", secrets.ErrUnavailable, respErr.StatusCode)

		case http.StatusBadRequest:
			return fmt.Errorf("%w: azure invalid request: %s", secrets.ErrInvalidArgument, respErr.ErrorCode)
		}
	}

	return fmt.Errorf("%w: %w", secrets.ErrUnavailable, err)
}
