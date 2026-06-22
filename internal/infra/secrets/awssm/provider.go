// Package awssm provides an AWS Secrets Manager implementation of the
// secrets.Broker interface. It authenticates via STS AssumeRole
// (with optional ExternalID for cross-account scenarios) or via static
// credentials for development use only.
//
// # Naming convention
//
// Secret names in AWS Secrets Manager follow the pattern:
//
//	gibson/tenant/<tenant_id>/<name>
//
// The broker name (e.g. "cred:foo" or "provider_config:anthropic:default") is
// appended verbatim after the tenant prefix; colons are valid in AWS SM secret
// names. The provider is name-prefix-agnostic: it stores and retrieves
// whatever broker name it receives without interpreting the prefix structure.
//
// # Value encoding
//
// Values are stored as SecretBinary (raw bytes). AWS SM natively supports
// binary payloads up to 65 536 bytes. The provider never base64-encodes the
// application payload — it passes bytes directly to SecretBinary and returns
// them as-is on Get.
//
// # Delete semantics
//
// DeleteSecret is called with a configurable recovery window (default 7 days).
// AWS SM soft-deletes the secret; it is scheduledfor deletion after the window.
// From the broker's perspective the secret is considered deleted immediately —
// a subsequent Get returns ErrNotFound once the deletion is scheduled.
// SupportsVersion is false because the broker interface only exposes
// get-latest semantics and AWS SM versioning is internal.
//
// Spec: secrets-broker Requirement 4.1.
package awssm

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithy "github.com/aws/smithy-go"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// maxValueBytes is the AWS Secrets Manager hard limit for a single binary
// secret value. This matches the AWS SM 65 536-byte limit for SecretBinary.
const maxValueBytes = 65536

// defaultRecoveryWindowDays is the default recovery window used by Delete.
// AWS SM allows values between 7 and 30. The daemon can override via Config.
const defaultRecoveryWindowDays int32 = 7

// smClient is the subset of the AWS SM client API used by the provider.
// Defined as an interface to enable mock injection in unit tests.
type smClient interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	CreateSecret(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	PutSecretValue(ctx context.Context, params *secretsmanager.PutSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
	DeleteSecret(ctx context.Context, params *secretsmanager.DeleteSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error)
	ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
}

// AuthMethod identifies the AWS authentication method to use.
type AuthMethod string

const (
	// AuthMethodAssumeRole authenticates by assuming an IAM role via STS.
	// This is the primary method for production deployments. The caller
	// provides a RoleArn and an optional ExternalID for cross-account trust.
	AuthMethodAssumeRole AuthMethod = "assume_role"

	// AuthMethodStatic uses a static access key ID and secret access key.
	// Intended for development and testing only; do not use in production.
	AuthMethodStatic AuthMethod = "static"
)

// AuthConfig holds the authentication configuration for the AWS SM provider.
// Only the fields relevant to the selected Method need to be populated.
type AuthConfig struct {
	// Method selects the AWS authentication method. Required.
	Method AuthMethod

	// RoleArn is the IAM role ARN to assume. Required when Method is
	// AuthMethodAssumeRole.
	RoleArn string

	// ExternalID is the optional STS external ID for cross-account role
	// assumption. Leave empty if the role trust policy does not require it.
	ExternalID string

	// AccessKeyID is the static AWS access key ID. Required when Method is
	// AuthMethodStatic.
	AccessKeyID string

	// SecretAccessKey is the static AWS secret access key. Required when
	// Method is AuthMethodStatic.
	SecretAccessKey string
}

// Config holds the per-provider AWS Secrets Manager configuration. A Config
// is supplied once at construction time; the Provider does not mutate it.
type Config struct {
	// Region is the AWS region in which the Secrets Manager service is
	// accessed, e.g. "us-east-1". Required.
	Region string

	// Auth holds the authentication configuration.
	Auth AuthConfig

	// RecoveryWindowDays controls the soft-delete recovery window passed to
	// DeleteSecret. Valid range is 7–30. Defaults to 7 when zero.
	RecoveryWindowDays int32

	// EndpointURL overrides the AWS Secrets Manager endpoint URL. Used in
	// tests and LocalStack integration. Leave empty for the default AWS
	// endpoint.
	EndpointURL string
}

// recoveryWindow returns the effective recovery window in days.
func (c Config) recoveryWindow() int32 {
	if c.RecoveryWindowDays <= 0 {
		return defaultRecoveryWindowDays
	}
	return c.RecoveryWindowDays
}

// Provider is an AWS Secrets Manager implementation of secrets.Broker.
// Each Provider instance is bound to one AWS region and one IAM identity.
// Tenant isolation is provided by secret-name prefix
// "gibson/tenant/<tenant_id>/".
//
// Provider is safe for concurrent use from multiple goroutines. The underlying
// AWS SDK client manages connection pooling and credential refreshes internally.
type Provider struct {
	client smClient
	cfg    Config
}

// New constructs a Provider from cfg. It validates the configuration and
// initialises the AWS SDK client with the appropriate credential provider.
//
// Credential chain for AuthMethodAssumeRole: the ambient credential chain
// (instance profile, ECS task role, environment variables) is used to call
// sts:AssumeRole; the resulting session credentials are used for all Secrets
// Manager API calls. The AWS SDK refreshes the session credentials before they
// expire.
//
// Credential chain for AuthMethodStatic: the supplied access key ID and secret
// are used directly. This method is intended for local development and tests.
//
// New returns an error when:
//   - cfg.Region is empty.
//   - cfg.Auth.Method is AuthMethodAssumeRole and cfg.Auth.RoleArn is empty.
//   - cfg.Auth.Method is AuthMethodStatic and AccessKeyID or SecretAccessKey is empty.
//   - cfg.Auth.Method is not a recognised value.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.Region == "" {
		return nil, fmt.Errorf("awssm: Config.Region is required")
	}

	client, err := buildClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return &Provider{client: client, cfg: cfg}, nil
}

// newWithClient constructs a Provider using an injected smClient. Used in
// unit tests to provide a mock client without real AWS credentials.
func newWithClient(cfg Config, client smClient) *Provider {
	return &Provider{client: client, cfg: cfg}
}

// buildClient constructs an AWS SM SDK client from the given Config.
func buildClient(ctx context.Context, cfg Config) (*secretsmanager.Client, error) {
	var awsCfg aws.Config
	var err error

	switch cfg.Auth.Method {
	case AuthMethodAssumeRole:
		if cfg.Auth.RoleArn == "" {
			return nil, fmt.Errorf("awssm: AuthMethodAssumeRole requires Auth.RoleArn")
		}
		// Load the base config (instance profile, env vars, etc.).
		awsCfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
		if err != nil {
			return nil, fmt.Errorf("awssm: failed to load base AWS config: %w", err)
		}
		// Build the STS client and wrap with an AssumeRole credential provider.
		stsClient := sts.NewFromConfig(awsCfg)
		assumeRoleOpts := func(o *stscreds.AssumeRoleOptions) {
			if cfg.Auth.ExternalID != "" {
				o.ExternalID = aws.String(cfg.Auth.ExternalID)
			}
		}
		creds := stscreds.NewAssumeRoleProvider(stsClient, cfg.Auth.RoleArn, assumeRoleOpts)
		awsCfg.Credentials = aws.NewCredentialsCache(creds)

	case AuthMethodStatic:
		if cfg.Auth.AccessKeyID == "" || cfg.Auth.SecretAccessKey == "" {
			return nil, fmt.Errorf("awssm: AuthMethodStatic requires Auth.AccessKeyID and Auth.SecretAccessKey")
		}
		awsCfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(cfg.Region),
			config.WithCredentialsProvider(aws.NewCredentialsCache(
				newStaticCredentials(cfg.Auth.AccessKeyID, cfg.Auth.SecretAccessKey),
			)),
		)
		if err != nil {
			return nil, fmt.Errorf("awssm: failed to load AWS config with static credentials: %w", err)
		}

	default:
		return nil, fmt.Errorf("awssm: unsupported auth method %q", cfg.Auth.Method)
	}

	opts := []func(*secretsmanager.Options){}
	if cfg.EndpointURL != "" {
		endpoint := cfg.EndpointURL
		opts = append(opts, func(o *secretsmanager.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}

	return secretsmanager.NewFromConfig(awsCfg, opts...), nil
}

// secretName builds the full AWS SM secret name for a given tenant and broker
// name. The resulting name has the form:
//
//	gibson/tenant/<tenant_id>/<name>
//
// Colons in name are preserved; AWS SM supports them in secret names.
func (p *Provider) secretName(tenant auth.TenantID, name string) string {
	return fmt.Sprintf("gibson/tenant/%s/%s", tenant.String(), name)
}

// tenantPrefix returns the name prefix used to identify all secrets belonging
// to a given tenant in ListSecrets filter calls.
func tenantPrefix(tenant auth.TenantID) string {
	return fmt.Sprintf("gibson/tenant/%s/", tenant.String())
}

// brokerName strips the tenant prefix from a full AWS SM secret name, returning
// the original broker name. Returns the full name unchanged if the prefix is
// not present (should not happen in practice).
func (p *Provider) brokerName(tenant auth.TenantID, fullName string) string {
	prefix := tenantPrefix(tenant)
	return strings.TrimPrefix(fullName, prefix)
}

// Get retrieves the current (AWSCURRENT) binary value of the named secret for
// the given tenant.
//
// Returns secrets.ErrNotFound when the secret does not exist or is scheduled
// for deletion. Returns secrets.ErrPermissionDenied when the IAM policy denies
// access. Returns secrets.ErrUnavailable for transient AWS errors.
func (p *Provider) Get(ctx context.Context, tenant auth.TenantID, name string) ([]byte, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(p.secretName(tenant, name)),
		VersionStage: aws.String("AWSCURRENT"),
	}

	out, err := p.client.GetSecretValue(ctx, input)
	if err != nil {
		return nil, mapAWSError(err, name)
	}

	if out.SecretBinary != nil {
		// Return a copy so the caller owns the slice.
		result := make([]byte, len(out.SecretBinary))
		copy(result, out.SecretBinary)
		return result, nil
	}

	// Fall back to SecretString if SecretBinary is absent (e.g., secrets
	// created outside Gibson that use string encoding).
	if out.SecretString != nil {
		return []byte(*out.SecretString), nil
	}

	return nil, fmt.Errorf("%w: %q (secret has no binary or string value)", secrets.ErrNotFound, name)
}

// Put creates or overwrites the named secret for the given tenant. The value
// is stored as SecretBinary. On the first write CreateSecret is called; if the
// secret already exists (ResourceExistsException), PutSecretValue is called
// instead, making Put idempotent with respect to pre-existing secrets.
//
// Returns secrets.ErrTooLarge when len(value) exceeds maxValueBytes (65 536).
// Returns secrets.ErrPermissionDenied when the IAM policy denies access.
// Returns secrets.ErrUnavailable for transient errors.
func (p *Provider) Put(ctx context.Context, tenant auth.TenantID, name string, value []byte) error {
	if len(value) > maxValueBytes {
		return fmt.Errorf("%w: %d bytes (max %d)", secrets.ErrTooLarge, len(value), maxValueBytes)
	}

	secretID := p.secretName(tenant, name)

	// Attempt CreateSecret first (idiomatic for first write).
	_, err := p.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String(secretID),
		SecretBinary: value,
	})
	if err == nil {
		return nil
	}

	// If the secret already exists, fall through to PutSecretValue.
	var existsErr *smtypes.ResourceExistsException
	if errors.As(err, &existsErr) {
		_, putErr := p.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
			SecretId:     aws.String(secretID),
			SecretBinary: value,
		})
		if putErr != nil {
			return mapAWSError(putErr, name)
		}
		return nil
	}

	return mapAWSError(err, name)
}

// Delete schedules the named secret for deletion with the configured recovery
// window. From the broker's perspective the secret is immediately unavailable
// after Delete returns nil; a subsequent Get will return ErrNotFound once the
// deletion is processed.
//
// Deleting a non-existent secret is a no-op (idempotent): if the secret does
// not exist, Delete returns nil.
//
// Returns secrets.ErrPermissionDenied when the IAM policy denies access.
// Returns secrets.ErrUnavailable for transient errors.
func (p *Provider) Delete(ctx context.Context, tenant auth.TenantID, name string) error {
	window := p.cfg.recoveryWindow()
	_, err := p.client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
		SecretId:             aws.String(p.secretName(tenant, name)),
		RecoveryWindowInDays: aws.Int64(int64(window)),
	})
	if err != nil {
		// Treat not-found as a no-op for idempotent delete.
		if isNotFound(err) {
			return nil
		}
		return mapAWSError(err, name)
	}
	return nil
}

// List returns the broker names of all secrets belonging to the given tenant
// that match the supplied filter. It calls ListSecrets with a name-prefix
// filter equal to "gibson/tenant/<tenant_id>/", then strips the tenant prefix
// from each result before applying filter.Prefix, filter.Offset and
// filter.Limit.
//
// Returns secrets.ErrPermissionDenied when the IAM policy denies access.
// Returns secrets.ErrUnavailable for transient errors.
func (p *Provider) List(ctx context.Context, tenant auth.TenantID, filter secrets.Filter) ([]string, error) {
	prefix := tenantPrefix(tenant)

	input := &secretsmanager.ListSecretsInput{
		Filters: []smtypes.Filter{
			{
				Key:    smtypes.FilterNameStringTypeName,
				Values: []string{prefix},
			},
		},
		MaxResults: aws.Int32(100),
	}

	var allNames []string

	// Paginate through all results.
	for {
		out, err := p.client.ListSecrets(ctx, input)
		if err != nil {
			return nil, mapAWSError(err, "")
		}

		for _, s := range out.SecretList {
			if s.Name == nil {
				continue
			}
			brokerName := p.brokerName(tenant, *s.Name)
			// Apply the caller's prefix filter (in addition to the AWS-side prefix).
			if filter.Prefix != "" && !strings.HasPrefix(brokerName, filter.Prefix) {
				continue
			}
			allNames = append(allNames, brokerName)
		}

		if out.NextToken == nil {
			break
		}
		input.NextToken = out.NextToken
	}

	// Apply pagination.
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

// Health performs a lightweight liveness check against AWS Secrets Manager by
// issuing a ListSecrets call with MaxResults=1. A successful (or empty) result
// confirms connectivity and IAM permissions are intact.
//
// Returns secrets.ErrUnavailable when AWS SM is unreachable or returns an
// unexpected error.
func (p *Provider) Health(ctx context.Context) error {
	_, err := p.client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{
		MaxResults: aws.Int32(1),
	})
	if err != nil {
		return fmt.Errorf("%w: aws secrets manager health check failed: %w", secrets.ErrUnavailable, err)
	}
	return nil
}

// Probe performs a write–read–delete round-trip of a canary secret against
// the configured AWS region, verifying full connectivity and IAM permissions.
// The canary name includes a random suffix to prevent collisions across
// concurrent probes.
//
// Probe always attempts cleanup even on failure to avoid leaving canary
// secrets in AWS SM (they still incur a soft-delete recovery window).
func (p *Provider) Probe(ctx context.Context) error {
	canaryName := probeCanaryName()
	probeValue := []byte("__probe__")
	probeTenant := auth.MustNewTenantID("probe-tenant")

	// Write.
	if err := p.Put(ctx, probeTenant, canaryName, probeValue); err != nil {
		return fmt.Errorf("awssm probe write failed: %w", err)
	}

	// Read. Attempt cleanup regardless of outcome.
	got, readErr := p.Get(ctx, probeTenant, canaryName)
	// Best-effort cleanup: schedule immediate deletion (force delete, bypass window).
	_ = p.forceDelete(ctx, probeTenant, canaryName)

	if readErr != nil {
		return fmt.Errorf("awssm probe read failed: %w", readErr)
	}

	if string(got) != string(probeValue) {
		return fmt.Errorf("awssm probe value mismatch: wrote %q, got %q", probeValue, got)
	}

	return nil
}

// forceDelete deletes a secret with ForceDeleteWithoutRecovery set to true,
// bypassing the recovery window. Used by Probe to clean up canary secrets.
func (p *Provider) forceDelete(ctx context.Context, tenant auth.TenantID, name string) error {
	_, err := p.client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
		SecretId:                   aws.String(p.secretName(tenant, name)),
		ForceDeleteWithoutRecovery: aws.Bool(true),
	})
	if err != nil && !isNotFound(err) {
		return mapAWSError(err, name)
	}
	return nil
}

// Capabilities returns the static capability set for the AWS Secrets Manager
// provider: full read/write/delete/list support, no native versioning from
// the broker's perspective (AWSCURRENT staging only), and a 65 536-byte value
// ceiling matching the AWS SM limit for SecretBinary.
func (p *Provider) Capabilities() secrets.Capabilities {
	return secrets.Capabilities{
		CanPut:          true,
		CanDelete:       true,
		CanList:         true,
		SupportsVersion: false,
		MaxValueBytes:   maxValueBytes,
	}
}

// isNotFound returns true when the AWS error represents a "secret not found"
// condition. This covers both ResourceNotFoundException and
// InvalidRequestException for secrets scheduled for deletion.
func isNotFound(err error) bool {
	var notFound *smtypes.ResourceNotFoundException
	if errors.As(err, &notFound) {
		return true
	}
	// Secrets scheduled for deletion return InvalidRequestException with a
	// message indicating the secret is marked for deletion.
	var invalidReq *smtypes.InvalidRequestException
	if errors.As(err, &invalidReq) && invalidReq.Message != nil &&
		strings.Contains(*invalidReq.Message, "marked for deletion") {
		return true
	}
	return false
}

// mapAWSError translates an AWS SDK error to the appropriate secrets sentinel.
//
// Mapping table:
//   - ResourceNotFoundException               → ErrNotFound
//   - AccessDeniedException (code)            → ErrPermissionDenied
//   - ThrottlingException (code)              → ErrUnavailable
//   - InternalServiceError (typed)            → ErrUnavailable
//   - ServiceUnavailableException (code)      → ErrUnavailable
//   - InvalidParameterException (typed)       → ErrInvalidArgument
//   - InvalidRequestException (typed)         → ErrInvalidArgument
//   - ResourceExistsException                 → internal use only (handled in Put)
//   - All other errors                        → ErrUnavailable
//
// AWS SM v2 returns AccessDeniedException, ThrottlingException, and
// ServiceUnavailableException as smithy GenericAPIError values (unmodeled),
// so we detect them by their error code strings via the smithy.APIError interface.
func mapAWSError(err error, name string) error {
	if err == nil {
		return nil
	}

	// Check modeled (typed) errors first.
	var notFound *smtypes.ResourceNotFoundException
	if errors.As(err, &notFound) {
		if name != "" {
			return fmt.Errorf("%w: %q", secrets.ErrNotFound, name)
		}
		return secrets.ErrNotFound
	}

	var internalErr *smtypes.InternalServiceError
	if errors.As(err, &internalErr) {
		return fmt.Errorf("%w: aws internal service error", secrets.ErrUnavailable)
	}

	var invalidParam *smtypes.InvalidParameterException
	if errors.As(err, &invalidParam) {
		return fmt.Errorf("%w: %v", secrets.ErrInvalidArgument, invalidParam.Message)
	}

	var invalidReq *smtypes.InvalidRequestException
	if errors.As(err, &invalidReq) {
		return fmt.Errorf("%w: %v", secrets.ErrInvalidArgument, invalidReq.Message)
	}

	// Check unmodeled errors via the smithy APIError interface (error code strings).
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDeniedException", "AccessDenied":
			return fmt.Errorf("%w: aws denied the request", secrets.ErrPermissionDenied)
		case "ThrottlingException", "Throttling", "RequestThrottledException", "RequestThrottled":
			return fmt.Errorf("%w: aws throttled the request", secrets.ErrUnavailable)
		case "ServiceUnavailableException", "ServiceUnavailable":
			return fmt.Errorf("%w: aws service unavailable", secrets.ErrUnavailable)
		}
	}

	// Catch-all: network failures, unknown status codes, etc.
	return fmt.Errorf("%w: %w", secrets.ErrUnavailable, err)
}
