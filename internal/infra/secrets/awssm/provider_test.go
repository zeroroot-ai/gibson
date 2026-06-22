package awssm

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	smithy "github.com/aws/smithy-go"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// testTenant is the tenant used in all unit tests.
var testTenant = auth.MustNewTenantID("test-tenant")

// ---------------------------------------------------------------------------
// Mock client
// ---------------------------------------------------------------------------

// mockSMClient implements smClient for unit testing. Each method can be
// overridden via the corresponding function field.
type mockSMClient struct {
	getSecretValueFn func(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	createSecretFn   func(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	putSecretValueFn func(ctx context.Context, params *secretsmanager.PutSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
	deleteSecretFn   func(ctx context.Context, params *secretsmanager.DeleteSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error)
	listSecretsFn    func(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
}

func (m *mockSMClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if m.getSecretValueFn != nil {
		return m.getSecretValueFn(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("GetSecretValue not configured")
}

func (m *mockSMClient) CreateSecret(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	if m.createSecretFn != nil {
		return m.createSecretFn(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("CreateSecret not configured")
}

func (m *mockSMClient) PutSecretValue(ctx context.Context, params *secretsmanager.PutSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	if m.putSecretValueFn != nil {
		return m.putSecretValueFn(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("PutSecretValue not configured")
}

func (m *mockSMClient) DeleteSecret(ctx context.Context, params *secretsmanager.DeleteSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error) {
	if m.deleteSecretFn != nil {
		return m.deleteSecretFn(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("DeleteSecret not configured")
}

func (m *mockSMClient) ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	if m.listSecretsFn != nil {
		return m.listSecretsFn(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("ListSecrets not configured")
}

// newTestProvider constructs a Provider with the given mock client.
func newTestProvider(mock *mockSMClient) *Provider {
	return newWithClient(Config{Region: "us-east-1", Auth: AuthConfig{Method: AuthMethodStatic, AccessKeyID: "test", SecretAccessKey: "test"}}, mock)
}

// ---------------------------------------------------------------------------
// Get tests
// ---------------------------------------------------------------------------

func TestGet_Success(t *testing.T) {
	value := []byte("super-secret-value")
	mock := &mockSMClient{
		getSecretValueFn: func(_ context.Context, params *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			expected := "gibson/tenant/test-tenant/cred:dbpass"
			if aws.ToString(params.SecretId) != expected {
				return nil, fmt.Errorf("unexpected SecretId %q, want %q", aws.ToString(params.SecretId), expected)
			}
			return &secretsmanager.GetSecretValueOutput{
				SecretBinary: value,
			}, nil
		},
	}
	p := newTestProvider(mock)

	got, err := p.Get(context.Background(), testTenant, "cred:dbpass")
	if err != nil {
		t.Fatalf("Get() unexpected error: %v", err)
	}
	if string(got) != string(value) {
		t.Errorf("Get() = %q, want %q", got, value)
	}
}

func TestGet_NotFound(t *testing.T) {
	mock := &mockSMClient{
		getSecretValueFn: func(_ context.Context, _ *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			msg := "secret not found"
			return nil, &smtypes.ResourceNotFoundException{Message: &msg}
		},
	}
	p := newTestProvider(mock)

	_, err := p.Get(context.Background(), testTenant, "cred:missing")
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Get() missing secret: want ErrNotFound, got %v", err)
	}
}

func TestGet_AccessDenied(t *testing.T) {
	mock := &mockSMClient{
		getSecretValueFn: func(_ context.Context, _ *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			// AccessDeniedException comes back as a smithy GenericAPIError.
			return nil, &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "access denied"}
		},
	}
	p := newTestProvider(mock)

	_, err := p.Get(context.Background(), testTenant, "cred:forbidden")
	if !errors.Is(err, secrets.ErrPermissionDenied) {
		t.Errorf("Get() access denied: want ErrPermissionDenied, got %v", err)
	}
}

func TestGet_ThrottlingException(t *testing.T) {
	mock := &mockSMClient{
		getSecretValueFn: func(_ context.Context, _ *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			// ThrottlingException comes back as a smithy GenericAPIError.
			return nil, &smithy.GenericAPIError{Code: "ThrottlingException", Message: "rate exceeded"}
		},
	}
	p := newTestProvider(mock)

	_, err := p.Get(context.Background(), testTenant, "cred:throttled")
	if !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("Get() throttled: want ErrUnavailable, got %v", err)
	}
}

func TestGet_InternalServiceError(t *testing.T) {
	mock := &mockSMClient{
		getSecretValueFn: func(_ context.Context, _ *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			msg := "internal error"
			return nil, &smtypes.InternalServiceError{Message: &msg}
		},
	}
	p := newTestProvider(mock)

	_, err := p.Get(context.Background(), testTenant, "cred:broken")
	if !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("Get() internal error: want ErrUnavailable, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Put tests
// ---------------------------------------------------------------------------

func TestPut_Create(t *testing.T) {
	var capturedBinary []byte
	mock := &mockSMClient{
		createSecretFn: func(_ context.Context, params *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
			capturedBinary = params.SecretBinary
			return &secretsmanager.CreateSecretOutput{}, nil
		},
	}
	p := newTestProvider(mock)

	value := []byte("my-api-key")
	if err := p.Put(context.Background(), testTenant, "cred:newkey", value); err != nil {
		t.Fatalf("Put() unexpected error: %v", err)
	}

	if string(capturedBinary) != string(value) {
		t.Errorf("Put() stored binary = %q, want %q", capturedBinary, value)
	}
}

func TestPut_UpdateOnExists(t *testing.T) {
	var updateCalled bool
	mock := &mockSMClient{
		createSecretFn: func(_ context.Context, _ *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
			msg := "secret already exists"
			return nil, &smtypes.ResourceExistsException{Message: &msg}
		},
		putSecretValueFn: func(_ context.Context, params *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
			updateCalled = true
			return &secretsmanager.PutSecretValueOutput{}, nil
		},
	}
	p := newTestProvider(mock)

	if err := p.Put(context.Background(), testTenant, "cred:existing", []byte("new-value")); err != nil {
		t.Fatalf("Put() on existing secret unexpected error: %v", err)
	}
	if !updateCalled {
		t.Error("Put() on existing secret: expected PutSecretValue to be called")
	}
}

func TestPut_TooLarge(t *testing.T) {
	mock := &mockSMClient{}
	p := newTestProvider(mock)

	oversized := make([]byte, maxValueBytes+1)
	err := p.Put(context.Background(), testTenant, "cred:big", oversized)
	if !errors.Is(err, secrets.ErrTooLarge) {
		t.Errorf("Put() oversized: want ErrTooLarge, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Delete tests
// ---------------------------------------------------------------------------

func TestDelete_Success(t *testing.T) {
	mock := &mockSMClient{
		deleteSecretFn: func(_ context.Context, params *secretsmanager.DeleteSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error) {
			if aws.ToInt64(params.RecoveryWindowInDays) != int64(defaultRecoveryWindowDays) {
				return nil, fmt.Errorf("unexpected recovery window %d, want %d",
					aws.ToInt64(params.RecoveryWindowInDays), defaultRecoveryWindowDays)
			}
			return &secretsmanager.DeleteSecretOutput{}, nil
		},
	}
	p := newTestProvider(mock)

	if err := p.Delete(context.Background(), testTenant, "cred:oldkey"); err != nil {
		t.Errorf("Delete() unexpected error: %v", err)
	}
}

func TestDelete_NotFoundIsNoOp(t *testing.T) {
	mock := &mockSMClient{
		deleteSecretFn: func(_ context.Context, _ *secretsmanager.DeleteSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error) {
			msg := "not found"
			return nil, &smtypes.ResourceNotFoundException{Message: &msg}
		},
	}
	p := newTestProvider(mock)

	// Delete of non-existent secret should be a no-op.
	if err := p.Delete(context.Background(), testTenant, "cred:nonexistent"); err != nil {
		t.Errorf("Delete() of non-existent: expected no error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// List tests
// ---------------------------------------------------------------------------

func TestList_WithPrefixFilter(t *testing.T) {
	prefix := tenantPrefix(testTenant)
	mock := &mockSMClient{
		listSecretsFn: func(_ context.Context, _ *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
			return &secretsmanager.ListSecretsOutput{
				SecretList: []smtypes.SecretListEntry{
					{Name: aws.String(prefix + "cred:a")},
					{Name: aws.String(prefix + "cred:b")},
					{Name: aws.String(prefix + "provider_config:anthropic:default")},
				},
			}, nil
		},
	}
	p := newTestProvider(mock)

	names, err := p.List(context.Background(), testTenant, secrets.Filter{Prefix: "cred:"})
	if err != nil {
		t.Fatalf("List() unexpected error: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("List() with prefix 'cred:': want 2 results, got %d: %v", len(names), names)
	}
	for _, n := range names {
		if n != "cred:a" && n != "cred:b" {
			t.Errorf("List() unexpected name %q", n)
		}
	}
}

func TestList_LimitAndOffset(t *testing.T) {
	prefix := tenantPrefix(testTenant)
	mock := &mockSMClient{
		listSecretsFn: func(_ context.Context, _ *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
			return &secretsmanager.ListSecretsOutput{
				SecretList: []smtypes.SecretListEntry{
					{Name: aws.String(prefix + "cred:a")},
					{Name: aws.String(prefix + "cred:b")},
					{Name: aws.String(prefix + "cred:c")},
					{Name: aws.String(prefix + "cred:d")},
				},
			}, nil
		},
	}
	p := newTestProvider(mock)

	names, err := p.List(context.Background(), testTenant, secrets.Filter{Offset: 1, Limit: 2})
	if err != nil {
		t.Fatalf("List() offset/limit unexpected error: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("List() with offset=1 limit=2: want 2, got %d: %v", len(names), names)
	}
	if names[0] != "cred:b" || names[1] != "cred:c" {
		t.Errorf("List() with offset=1 limit=2: want [cred:b, cred:c], got %v", names)
	}
}

// ---------------------------------------------------------------------------
// Health tests
// ---------------------------------------------------------------------------

func TestHealth_OK(t *testing.T) {
	mock := &mockSMClient{
		listSecretsFn: func(_ context.Context, _ *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
			return &secretsmanager.ListSecretsOutput{}, nil
		},
	}
	p := newTestProvider(mock)
	if err := p.Health(context.Background()); err != nil {
		t.Errorf("Health() healthy: unexpected error: %v", err)
	}
}

func TestHealth_Unavailable(t *testing.T) {
	mock := &mockSMClient{
		listSecretsFn: func(_ context.Context, _ *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
			// ServiceUnavailableException comes back as a smithy GenericAPIError.
			return nil, &smithy.GenericAPIError{Code: "ServiceUnavailableException", Message: "service unavailable"}
		},
	}
	p := newTestProvider(mock)
	err := p.Health(context.Background())
	if !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("Health() unavailable: want ErrUnavailable, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Capabilities test
// ---------------------------------------------------------------------------

func TestCapabilities(t *testing.T) {
	p := newTestProvider(&mockSMClient{})
	caps := p.Capabilities()
	if !caps.CanPut {
		t.Error("Capabilities().CanPut = false, want true")
	}
	if !caps.CanDelete {
		t.Error("Capabilities().CanDelete = false, want true")
	}
	if !caps.CanList {
		t.Error("Capabilities().CanList = false, want true")
	}
	if caps.SupportsVersion {
		t.Error("Capabilities().SupportsVersion = true, want false")
	}
	if caps.MaxValueBytes != maxValueBytes {
		t.Errorf("Capabilities().MaxValueBytes = %d, want %d", caps.MaxValueBytes, maxValueBytes)
	}
}

// ---------------------------------------------------------------------------
// Probe test
// ---------------------------------------------------------------------------

func TestProbe_Success(t *testing.T) {
	var storedValues = make(map[string][]byte)

	mock := &mockSMClient{
		createSecretFn: func(_ context.Context, params *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
			storedValues[aws.ToString(params.Name)] = params.SecretBinary
			return &secretsmanager.CreateSecretOutput{}, nil
		},
		getSecretValueFn: func(_ context.Context, params *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			v, ok := storedValues[aws.ToString(params.SecretId)]
			if !ok {
				msg := "not found"
				return nil, &smtypes.ResourceNotFoundException{Message: &msg}
			}
			return &secretsmanager.GetSecretValueOutput{SecretBinary: v}, nil
		},
		deleteSecretFn: func(_ context.Context, params *secretsmanager.DeleteSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error) {
			delete(storedValues, aws.ToString(params.SecretId))
			return &secretsmanager.DeleteSecretOutput{}, nil
		},
	}
	p := newTestProvider(mock)

	if err := p.Probe(context.Background()); err != nil {
		t.Errorf("Probe() unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Secret name helpers
// ---------------------------------------------------------------------------

func TestSecretName(t *testing.T) {
	p := newTestProvider(&mockSMClient{})
	tenant := auth.MustNewTenantID("my-tenant")

	name := p.secretName(tenant, "cred:foo")
	expected := "gibson/tenant/my-tenant/cred:foo"
	if name != expected {
		t.Errorf("secretName() = %q, want %q", name, expected)
	}

	// Verify provider_config naming with colons.
	name2 := p.secretName(tenant, "provider_config:anthropic:default")
	expected2 := "gibson/tenant/my-tenant/provider_config:anthropic:default"
	if name2 != expected2 {
		t.Errorf("secretName() for provider_config = %q, want %q", name2, expected2)
	}
}

func TestBrokerName(t *testing.T) {
	p := newTestProvider(&mockSMClient{})
	tenant := auth.MustNewTenantID("my-tenant")

	got := p.brokerName(tenant, "gibson/tenant/my-tenant/cred:foo")
	if got != "cred:foo" {
		t.Errorf("brokerName() = %q, want %q", got, "cred:foo")
	}
}

// ---------------------------------------------------------------------------
// Error mapping exhaustive test
// ---------------------------------------------------------------------------

func TestMapAWSError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		wantIs error
	}{
		{
			name:   "ResourceNotFoundException",
			err:    &smtypes.ResourceNotFoundException{Message: aws.String("not found")},
			wantIs: secrets.ErrNotFound,
		},
		{
			name:   "AccessDeniedException (smithy generic)",
			err:    &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"},
			wantIs: secrets.ErrPermissionDenied,
		},
		{
			name:   "ThrottlingException (smithy generic)",
			err:    &smithy.GenericAPIError{Code: "ThrottlingException", Message: "throttled"},
			wantIs: secrets.ErrUnavailable,
		},
		{
			name:   "InternalServiceError",
			err:    &smtypes.InternalServiceError{Message: aws.String("internal")},
			wantIs: secrets.ErrUnavailable,
		},
		{
			name:   "ServiceUnavailableException (smithy generic)",
			err:    &smithy.GenericAPIError{Code: "ServiceUnavailableException", Message: "unavailable"},
			wantIs: secrets.ErrUnavailable,
		},
		{
			name:   "InvalidParameterException",
			err:    &smtypes.InvalidParameterException{Message: aws.String("bad param")},
			wantIs: secrets.ErrInvalidArgument,
		},
		{
			name:   "InvalidRequestException",
			err:    &smtypes.InvalidRequestException{Message: aws.String("bad request")},
			wantIs: secrets.ErrInvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapAWSError(tt.err, "testname")
			if !errors.Is(got, tt.wantIs) {
				t.Errorf("mapAWSError(%T): want errors.Is(%v), got %v", tt.err, tt.wantIs, got)
			}
		})
	}
}
