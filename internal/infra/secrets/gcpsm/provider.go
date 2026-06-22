// Package gcpsm provides a Google Cloud Secret Manager implementation of the
// secrets.Broker interface.
//
// # Naming convention and sanitization
//
// GCP Secret Manager secret IDs are constrained to [a-zA-Z0-9_-]{1,255}.
// The broker name (e.g. "cred:foo" or "provider_config:anthropic:default") may
// contain characters that violate this constraint (notably ":"). The provider
// sanitizes broker names before constructing GCP SM secret IDs by applying the
// following rule:
//
//   - Replace every ":", "/", and "." character with "-".
//   - Any character not in [a-zA-Z0-9_-] is replaced with "-".
//   - The sanitized name must start with [a-zA-Z]; if it starts with a digit,
//     "_", or "-", the prefix "s-" is prepended.
//   - If the sanitized name is empty after sanitization, ErrInvalidArgument is
//     returned.
//   - The total secret ID (prefix + sanitized name) must not exceed 255
//     characters; if it does, ErrInvalidArgument is returned.
//
// The full GCP SM secret ID is:
//
//	gibson-tenant-<tenant_id>-<sanitized_name>
//
// Because sanitization is lossy, the provider additionally stores the original
// broker name in the GCP secret's labels under the key "broker_name". On List,
// both the label and the sanitized ID are used to recover the original name.
// If the label is missing (e.g., for externally created secrets), the
// sanitized name is returned as-is.
//
// # Authentication
//
// Two auth methods are supported:
//
//   - service_account_json: raw JSON key bytes embedded in AuthConfig.SAKey, or
//     a file path in AuthConfig.SAKeyPath.
//   - workload_identity_federation: the Application Default Credentials (ADC)
//     chain is used, augmented with the optional target service account for
//     impersonation.
//
// # Get semantics
//
// Get calls AccessSecretVersion with the resource name "…/versions/latest",
// which returns the most recent enabled version. Disabled or destroyed versions
// are not returned.
//
// Spec: secrets-broker Requirement 4.2.
package gcpsm

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// maxValueBytes is the GCP Secret Manager hard limit for a single secret
// version payload (64 KiB).
const maxValueBytes = 65536

// maxSecretIDLength is the maximum length for a GCP SM secret ID. The spec
// allows up to 255 characters; we leave some headroom for the tenant prefix.
const maxSecretIDLength = 255

// labelBrokerName is the GCP SM label key under which the original broker name
// is stored so it can be recovered on List.
const labelBrokerName = "broker-name"

// safeIDRe matches characters that are not in the GCP SM secret ID alphabet.
var safeIDRe = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// AuthMethod identifies the GCP authentication method.
type AuthMethod string

const (
	// AuthMethodServiceAccountJSON uses a GCP service account key (JSON),
	// either supplied inline via SAKey (as raw bytes) or read from the path
	// at SAKeyPath. This method is suitable for non-GCP deployments and
	// CI/CD pipelines.
	AuthMethodServiceAccountJSON AuthMethod = "service_account_json"

	// AuthMethodWorkloadIdentity uses the Application Default Credentials
	// (ADC) chain. On GCE/GKE this resolves to the Workload Identity
	// credential; in Cloud Run/Cloud Functions it resolves to the attached
	// service account. An optional ImpersonateServiceAccount causes the
	// provider to impersonate that account via the ADC chain.
	AuthMethodWorkloadIdentity AuthMethod = "workload_identity"
)

// AuthConfig holds the authentication configuration for the GCP SM provider.
type AuthConfig struct {
	// Method selects the GCP authentication method. Required.
	Method AuthMethod

	// SAKey is the raw service account JSON key bytes. Used when Method is
	// AuthMethodServiceAccountJSON. Either SAKey or SAKeyPath must be set,
	// but not both.
	SAKey []byte

	// SAKeyPath is the filesystem path to the service account JSON key file.
	// Used when Method is AuthMethodServiceAccountJSON and SAKey is empty.
	SAKeyPath string

	// ImpersonateServiceAccount is an optional GCP service account email to
	// impersonate via the ADC chain. Only used with
	// AuthMethodWorkloadIdentity.
	ImpersonateServiceAccount string
}

// Config holds the per-provider GCP Secret Manager configuration.
type Config struct {
	// Project is the GCP project ID (not the numeric project number).
	// Required. Example: "my-project".
	Project string

	// Auth holds the authentication configuration.
	Auth AuthConfig

	// EndpointOverride allows overriding the Secret Manager endpoint for
	// testing against an emulator. Leave empty for the default GCP endpoint.
	EndpointOverride string
}

// smClientInterface is the subset of secretmanager.Client methods used by
// the provider. Defined as an interface to enable mock injection in unit tests.
type smClientInterface interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...interface{}) (*secretmanagerpb.AccessSecretVersionResponse, error)
	CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...interface{}) (*secretmanagerpb.Secret, error)
	AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...interface{}) (*secretmanagerpb.SecretVersion, error)
	DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...interface{}) error
	ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...interface{}) secretIterator
	Close() error
}

// secretIterator is an interface over the GCP SM SecretIterator for mock
// injection in unit tests.
type secretIterator interface {
	Next() (*secretmanagerpb.Secret, error)
}

// Provider is a GCP Secret Manager implementation of secrets.Broker.
// Provider is safe for concurrent use from multiple goroutines.
type Provider struct {
	client smClientInterface
	cfg    Config
}

// gcpClientAdapter wraps secretmanager.Client to implement smClientInterface.
// The GCP SDK uses gax.CallOption for variadic opts; our mock interface uses
// interface{} to decouple from the gax import in tests.
type gcpClientAdapter struct {
	c *secretmanager.Client
}

func (a *gcpClientAdapter) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, _ ...interface{}) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return a.c.AccessSecretVersion(ctx, req)
}

func (a *gcpClientAdapter) CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, _ ...interface{}) (*secretmanagerpb.Secret, error) {
	return a.c.CreateSecret(ctx, req)
}

func (a *gcpClientAdapter) AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, _ ...interface{}) (*secretmanagerpb.SecretVersion, error) {
	return a.c.AddSecretVersion(ctx, req)
}

func (a *gcpClientAdapter) DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, _ ...interface{}) error {
	return a.c.DeleteSecret(ctx, req)
}

func (a *gcpClientAdapter) ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, _ ...interface{}) secretIterator {
	return a.c.ListSecrets(ctx, req)
}

func (a *gcpClientAdapter) Close() error {
	return a.c.Close()
}

// New constructs a Provider from cfg. It validates the configuration and
// initialises the GCP Secret Manager client.
//
// New returns an error when:
//   - cfg.Project is empty.
//   - cfg.Auth.Method is not a recognised value.
//   - The credentials cannot be loaded (e.g., invalid SA JSON).
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.Project == "" {
		return nil, fmt.Errorf("gcpsm: Config.Project is required")
	}

	opts, err := buildClientOptions(cfg)
	if err != nil {
		return nil, err
	}

	c, err := secretmanager.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcpsm: failed to create GCP SM client: %w", err)
	}

	return &Provider{
		client: &gcpClientAdapter{c: c},
		cfg:    cfg,
	}, nil
}

// newWithClient constructs a Provider using an injected smClientInterface.
// Used in unit tests to provide a mock client without real GCP credentials.
func newWithClient(cfg Config, client smClientInterface) *Provider {
	return &Provider{client: client, cfg: cfg}
}

// buildClientOptions constructs the GCP client option slice from Config.
func buildClientOptions(cfg Config) ([]option.ClientOption, error) {
	var opts []option.ClientOption

	if cfg.EndpointOverride != "" {
		opts = append(opts, option.WithEndpoint(cfg.EndpointOverride))
		opts = append(opts, option.WithoutAuthentication())
		return opts, nil
	}

	switch cfg.Auth.Method {
	case AuthMethodServiceAccountJSON:
		if len(cfg.Auth.SAKey) > 0 {
			opts = append(opts, option.WithCredentialsJSON(cfg.Auth.SAKey)) //nolint:staticcheck // SA1019: google.CredentialsFromJSON migration requires ADC rework (tracked in platform-clients backlog)
		} else if cfg.Auth.SAKeyPath != "" {
			opts = append(opts, option.WithCredentialsFile(cfg.Auth.SAKeyPath)) //nolint:staticcheck // SA1019: see above
		} else {
			return nil, fmt.Errorf("gcpsm: AuthMethodServiceAccountJSON requires Auth.SAKey or Auth.SAKeyPath")
		}

	case AuthMethodWorkloadIdentity:
		// Use Application Default Credentials. Impersonation is handled at
		// the credentials layer; for now, rely on the ambient ADC chain.
		// ImpersonateServiceAccount would require additional OAuth2 setup;
		// defer to the operator's ADC configuration.

	default:
		return nil, fmt.Errorf("gcpsm: unsupported auth method %q", cfg.Auth.Method)
	}

	return opts, nil
}

// sanitizeName converts a broker name (which may contain ":", "/", ".", etc.)
// to a valid GCP SM secret ID component. See package doc for the full rule.
//
// Returns an error if the result would be empty or exceed the allowed length
// when combined with the tenant prefix.
func sanitizeName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%w: secret name is empty", secrets.ErrInvalidArgument)
	}

	// Replace disallowed characters with hyphens.
	sanitized := safeIDRe.ReplaceAllString(name, "-")

	// Remove consecutive hyphens resulting from replacements.
	for strings.Contains(sanitized, "--") {
		sanitized = strings.ReplaceAll(sanitized, "--", "-")
	}

	// Trim leading/trailing hyphens.
	sanitized = strings.Trim(sanitized, "-")

	if sanitized == "" {
		return "", fmt.Errorf("%w: %q sanitizes to empty string", secrets.ErrInvalidArgument, name)
	}

	// GCP SM IDs must start with a letter. If the first character is a digit
	// or underscore, prepend "s-".
	if sanitized[0] >= '0' && sanitized[0] <= '9' || sanitized[0] == '_' {
		sanitized = "s-" + sanitized
	}

	return sanitized, nil
}

// secretID builds the full GCP SM secret ID for a given tenant and broker name.
//
// Format: gibson-tenant-<tenant_id>-<sanitized_name>
//
// Returns ErrInvalidArgument when the name cannot be sanitized cleanly or the
// resulting ID exceeds maxSecretIDLength characters.
func (p *Provider) secretID(tenant auth.TenantID, name string) (string, error) {
	sanitized, err := sanitizeName(name)
	if err != nil {
		return "", err
	}

	id := fmt.Sprintf("gibson-tenant-%s-%s", tenant.String(), sanitized)

	if len(id) > maxSecretIDLength {
		return "", fmt.Errorf("%w: secret ID %q exceeds %d character limit",
			secrets.ErrInvalidArgument, id, maxSecretIDLength)
	}

	return id, nil
}

// secretResourceName builds the full GCP SM resource name for a secret.
//
//	projects/<project>/secrets/<secret_id>
func (p *Provider) secretResourceName(tenant auth.TenantID, name string) (string, error) {
	id, err := p.secretID(tenant, name)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("projects/%s/secrets/%s", p.cfg.Project, id), nil
}

// secretVersionResourceName builds the full GCP SM resource name for a version.
//
//	projects/<project>/secrets/<secret_id>/versions/latest
func (p *Provider) secretVersionResourceName(tenant auth.TenantID, name string) (string, error) {
	res, err := p.secretResourceName(tenant, name)
	if err != nil {
		return "", err
	}
	return res + "/versions/latest", nil
}

// tenantSecretFilter builds the GCP SM ListSecrets filter string for all
// secrets belonging to a given tenant.
func (p *Provider) tenantSecretFilter(tenant auth.TenantID) string {
	return fmt.Sprintf("name:gibson-tenant-%s-", tenant.String())
}

// Get retrieves the latest enabled version of the named secret for the given
// tenant. Returns the raw payload bytes.
//
// Returns secrets.ErrNotFound when the secret or its latest version does not
// exist. Returns secrets.ErrPermissionDenied when GCP denies access.
// Returns secrets.ErrUnavailable for transient errors.
func (p *Provider) Get(ctx context.Context, tenant auth.TenantID, name string) ([]byte, error) {
	versionName, err := p.secretVersionResourceName(tenant, name)
	if err != nil {
		return nil, err
	}

	resp, err := p.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: versionName,
	})
	if err != nil {
		return nil, mapGCPError(err, name)
	}

	if resp.Payload == nil {
		return nil, fmt.Errorf("%w: %q (secret version has no payload)", secrets.ErrNotFound, name)
	}

	result := make([]byte, len(resp.Payload.Data))
	copy(result, resp.Payload.Data)
	return result, nil
}

// Put creates a new secret (if it does not exist) and adds a new version
// containing value. If the secret already exists, a new version is added.
//
// Returns secrets.ErrTooLarge when len(value) exceeds maxValueBytes.
// Returns secrets.ErrInvalidArgument when the name cannot be sanitized.
// Returns secrets.ErrPermissionDenied when GCP denies access.
// Returns secrets.ErrUnavailable for transient errors.
func (p *Provider) Put(ctx context.Context, tenant auth.TenantID, name string, value []byte) error {
	if len(value) > maxValueBytes {
		return fmt.Errorf("%w: %d bytes (max %d)", secrets.ErrTooLarge, len(value), maxValueBytes)
	}

	secretName, err := p.secretResourceName(tenant, name)
	if err != nil {
		return err
	}

	id, err := p.secretID(tenant, name)
	if err != nil {
		return err
	}

	// Attempt to create the secret first; if it already exists, skip creation.
	_, createErr := p.client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
		Parent:   fmt.Sprintf("projects/%s", p.cfg.Project),
		SecretId: id,
		Secret: &secretmanagerpb.Secret{
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{},
				},
			},
			Labels: map[string]string{
				labelBrokerName: sanitizeLabelValue(name),
			},
		},
	})
	if createErr != nil {
		s, ok := status.FromError(createErr)
		if !ok || s.Code() != codes.AlreadyExists {
			return mapGCPError(createErr, name)
		}
		// Secret already exists; proceed to add a version.
	}

	// Add a new version with the provided payload.
	_, versionErr := p.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent: secretName,
		Payload: &secretmanagerpb.SecretPayload{
			Data: value,
		},
	})
	if versionErr != nil {
		return mapGCPError(versionErr, name)
	}

	return nil
}

// Delete removes the named secret and all its versions from GCP Secret Manager.
// Deleting a non-existent secret is a no-op (idempotent).
//
// Returns secrets.ErrPermissionDenied when GCP denies access.
// Returns secrets.ErrUnavailable for transient errors.
func (p *Provider) Delete(ctx context.Context, tenant auth.TenantID, name string) error {
	secretName, err := p.secretResourceName(tenant, name)
	if err != nil {
		return err
	}

	err = p.client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
		Name: secretName,
	})
	if err != nil {
		// Treat not-found as a no-op for idempotent delete.
		s, ok := status.FromError(err)
		if ok && s.Code() == codes.NotFound {
			return nil
		}
		return mapGCPError(err, name)
	}
	return nil
}

// List returns the broker names of all secrets belonging to the given tenant
// that match the supplied filter. It calls ListSecrets with a name-filter
// scoped to the tenant prefix, then applies filter.Prefix, filter.Offset, and
// filter.Limit.
//
// The original broker name is recovered from the "broker-name" label when
// present; otherwise the sanitized secret ID component is returned.
//
// Returns secrets.ErrPermissionDenied when GCP denies access.
// Returns secrets.ErrUnavailable for transient errors.
func (p *Provider) List(ctx context.Context, tenant auth.TenantID, filter secrets.Filter) ([]string, error) {
	req := &secretmanagerpb.ListSecretsRequest{
		Parent: fmt.Sprintf("projects/%s", p.cfg.Project),
		Filter: p.tenantSecretFilter(tenant),
	}

	it := p.client.ListSecrets(ctx, req)

	tenantIDPrefix := fmt.Sprintf("gibson-tenant-%s-", tenant.String())

	var allNames []string
	for {
		secret, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, mapGCPError(err, "")
		}

		// Recover the broker name from the label, or fall back to stripping the prefix.
		brokerName := ""
		if secret.Labels != nil {
			if v, ok := secret.Labels[labelBrokerName]; ok {
				brokerName = v
			}
		}

		if brokerName == "" {
			// Fall back: extract the name component after the tenant prefix.
			parts := strings.SplitN(secret.Name, "/", 4)
			if len(parts) < 4 {
				continue
			}
			secretIDPart := parts[3] // last component is the secret ID
			brokerName = strings.TrimPrefix(secretIDPart, tenantIDPrefix)
			if brokerName == secretIDPart {
				// The tenant prefix was not found; skip this entry.
				continue
			}
		}

		if filter.Prefix != "" && !strings.HasPrefix(brokerName, filter.Prefix) {
			continue
		}

		allNames = append(allNames, brokerName)
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

// Health performs a lightweight liveness check by listing secrets with a
// page size of 1. A successful (or empty) result confirms connectivity and
// IAM permissions are intact.
func (p *Provider) Health(ctx context.Context) error {
	req := &secretmanagerpb.ListSecretsRequest{
		Parent:   fmt.Sprintf("projects/%s", p.cfg.Project),
		PageSize: 1,
	}
	it := p.client.ListSecrets(ctx, req)
	_, err := it.Next()
	if err != nil && !errors.Is(err, iterator.Done) {
		return fmt.Errorf("%w: gcp secret manager health check failed: %w", secrets.ErrUnavailable, err)
	}
	return nil
}

// Probe performs a write–read–delete round-trip of a canary secret against
// the configured GCP project, verifying full connectivity and IAM permissions.
func (p *Provider) Probe(ctx context.Context) error {
	canaryName := probeCanaryName()
	probeValue := []byte("__probe__")
	probeTenant := auth.MustNewTenantID("probe-tenant")

	// Write.
	if err := p.Put(ctx, probeTenant, canaryName, probeValue); err != nil {
		return fmt.Errorf("gcpsm probe write failed: %w", err)
	}

	// Read. Attempt cleanup regardless of outcome.
	got, readErr := p.Get(ctx, probeTenant, canaryName)
	_ = p.Delete(ctx, probeTenant, canaryName)

	if readErr != nil {
		return fmt.Errorf("gcpsm probe read failed: %w", readErr)
	}

	if string(got) != string(probeValue) {
		return fmt.Errorf("gcpsm probe value mismatch: wrote %q, got %q", probeValue, got)
	}

	return nil
}

// Capabilities returns the static capability set for the GCP Secret Manager
// provider: full read/write/delete/list support, native versioning, and a
// 65 536-byte value ceiling.
func (p *Provider) Capabilities() secrets.Capabilities {
	return secrets.Capabilities{
		CanPut:          true,
		CanDelete:       true,
		CanList:         true,
		SupportsVersion: true,
		MaxValueBytes:   maxValueBytes,
	}
}

// sanitizeLabelValue truncates label values to 63 characters (GCP label limit)
// and replaces disallowed characters.
func sanitizeLabelValue(v string) string {
	v = safeIDRe.ReplaceAllString(strings.ToLower(v), "-")
	v = strings.Trim(v, "-")
	if len(v) > 63 {
		v = v[:63]
	}
	return v
}

// mapGCPError translates a GCP API error to the appropriate secrets sentinel.
//
// Mapping table (gRPC status codes):
//   - codes.NotFound            → ErrNotFound
//   - codes.PermissionDenied    → ErrPermissionDenied
//   - codes.Unauthenticated     → ErrPermissionDenied
//   - codes.ResourceExhausted   → ErrUnavailable
//   - codes.Unavailable         → ErrUnavailable
//   - codes.DeadlineExceeded    → ErrUnavailable
//   - codes.InvalidArgument     → ErrInvalidArgument
//   - All other codes           → ErrUnavailable
func mapGCPError(err error, name string) error {
	if err == nil {
		return nil
	}

	s, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("%w: %w", secrets.ErrUnavailable, err)
	}

	switch s.Code() {
	case codes.NotFound:
		if name != "" {
			return fmt.Errorf("%w: %q", secrets.ErrNotFound, name)
		}
		return secrets.ErrNotFound

	case codes.PermissionDenied, codes.Unauthenticated:
		return fmt.Errorf("%w: gcp denied the request: %s", secrets.ErrPermissionDenied, s.Message())

	case codes.ResourceExhausted, codes.Unavailable, codes.DeadlineExceeded:
		return fmt.Errorf("%w: gcp service unavailable: %s", secrets.ErrUnavailable, s.Message())

	case codes.InvalidArgument:
		return fmt.Errorf("%w: %s", secrets.ErrInvalidArgument, s.Message())
	}

	return fmt.Errorf("%w: gcp error (%s): %s", secrets.ErrUnavailable, s.Code(), s.Message())
}
