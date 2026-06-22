package gcpsm

import (
	"context"
	"errors"
	"testing"

	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// testTenant is the tenant used in all unit tests.
var testTenant = auth.MustNewTenantID("test-tenant")

// ---------------------------------------------------------------------------
// Mock client
// ---------------------------------------------------------------------------

// mockSMClient implements smClientInterface for unit testing.
type mockSMClient struct {
	accessSecretVersionFn func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...interface{}) (*secretmanagerpb.AccessSecretVersionResponse, error)
	createSecretFn        func(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...interface{}) (*secretmanagerpb.Secret, error)
	addSecretVersionFn    func(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...interface{}) (*secretmanagerpb.SecretVersion, error)
	deleteSecretFn        func(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...interface{}) error
	listSecretsFn         func(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...interface{}) secretIterator
}

func (m *mockSMClient) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...interface{}) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	if m.accessSecretVersionFn != nil {
		return m.accessSecretVersionFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.NotFound, "not found")
}

func (m *mockSMClient) CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...interface{}) (*secretmanagerpb.Secret, error) {
	if m.createSecretFn != nil {
		return m.createSecretFn(ctx, req, opts...)
	}
	return &secretmanagerpb.Secret{}, nil
}

func (m *mockSMClient) AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...interface{}) (*secretmanagerpb.SecretVersion, error) {
	if m.addSecretVersionFn != nil {
		return m.addSecretVersionFn(ctx, req, opts...)
	}
	return &secretmanagerpb.SecretVersion{}, nil
}

func (m *mockSMClient) DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...interface{}) error {
	if m.deleteSecretFn != nil {
		return m.deleteSecretFn(ctx, req, opts...)
	}
	return nil
}

func (m *mockSMClient) ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...interface{}) secretIterator {
	if m.listSecretsFn != nil {
		return m.listSecretsFn(ctx, req, opts...)
	}
	return &staticSecretIterator{}
}

func (m *mockSMClient) Close() error { return nil }

// staticSecretIterator is a mock secretIterator backed by a slice of secrets.
type staticSecretIterator struct {
	secrets []*secretmanagerpb.Secret
	pos     int
	err     error
}

func (it *staticSecretIterator) Next() (*secretmanagerpb.Secret, error) {
	if it.err != nil {
		return nil, it.err
	}
	if it.pos >= len(it.secrets) {
		return nil, iterator.Done
	}
	s := it.secrets[it.pos]
	it.pos++
	return s, nil
}

// newTestProvider constructs a Provider with a mock client and a test project.
func newTestProvider(mock *mockSMClient) *Provider {
	return newWithClient(Config{Project: "test-project"}, mock)
}

// ---------------------------------------------------------------------------
// Sanitization tests
// ---------------------------------------------------------------------------

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"cred:foo", "cred-foo", false},
		// Underscores are valid in GCP SM IDs; only colons/slashes/dots are replaced.
		{"provider_config:anthropic:default", "provider_config-anthropic-default", false},
		{"simple", "simple", false},
		{"with/slash", "with-slash", false},
		{"with.dot", "with-dot", false},
		{"123-starts-digit", "s-123-starts-digit", false},
		// Leading underscore is valid in GCP SM IDs but must start with [a-zA-Z]
		// per the spec constraint; the "s-" prefix applies to leading non-letter.
		{"_starts-underscore", "s-_starts-underscore", false},
		{"", "", true},    // empty → error
		{":::", "", true}, // all-separator → error after trimming
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := sanitizeName(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("sanitizeName(%q): expected error, got %q", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Errorf("sanitizeName(%q): unexpected error: %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("sanitizeName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Get tests
// ---------------------------------------------------------------------------

func TestGet_Success(t *testing.T) {
	value := []byte("super-secret-value")
	mock := &mockSMClient{
		accessSecretVersionFn: func(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest, _ ...interface{}) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			expectedSuffix := "/versions/latest"
			if len(req.Name) < len(expectedSuffix) || req.Name[len(req.Name)-len(expectedSuffix):] != expectedSuffix {
				return nil, status.Errorf(codes.NotFound, "unexpected version name: %q", req.Name)
			}
			return &secretmanagerpb.AccessSecretVersionResponse{
				Payload: &secretmanagerpb.SecretPayload{
					Data: value,
				},
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
		accessSecretVersionFn: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest, _ ...interface{}) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return nil, status.Error(codes.NotFound, "secret not found")
		},
	}
	p := newTestProvider(mock)

	_, err := p.Get(context.Background(), testTenant, "cred:missing")
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Get() missing: want ErrNotFound, got %v", err)
	}
}

func TestGet_PermissionDenied(t *testing.T) {
	mock := &mockSMClient{
		accessSecretVersionFn: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest, _ ...interface{}) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return nil, status.Error(codes.PermissionDenied, "permission denied")
		},
	}
	p := newTestProvider(mock)

	_, err := p.Get(context.Background(), testTenant, "cred:forbidden")
	if !errors.Is(err, secrets.ErrPermissionDenied) {
		t.Errorf("Get() forbidden: want ErrPermissionDenied, got %v", err)
	}
}

func TestGet_ResourceExhausted(t *testing.T) {
	mock := &mockSMClient{
		accessSecretVersionFn: func(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest, _ ...interface{}) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return nil, status.Error(codes.ResourceExhausted, "quota exceeded")
		},
	}
	p := newTestProvider(mock)

	_, err := p.Get(context.Background(), testTenant, "cred:quota")
	if !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("Get() quota: want ErrUnavailable, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Put tests
// ---------------------------------------------------------------------------

func TestPut_Create(t *testing.T) {
	var versionPayload []byte
	mock := &mockSMClient{
		createSecretFn: func(_ context.Context, _ *secretmanagerpb.CreateSecretRequest, _ ...interface{}) (*secretmanagerpb.Secret, error) {
			return &secretmanagerpb.Secret{}, nil
		},
		addSecretVersionFn: func(_ context.Context, req *secretmanagerpb.AddSecretVersionRequest, _ ...interface{}) (*secretmanagerpb.SecretVersion, error) {
			versionPayload = req.Payload.Data
			return &secretmanagerpb.SecretVersion{}, nil
		},
	}
	p := newTestProvider(mock)

	value := []byte("my-api-key")
	if err := p.Put(context.Background(), testTenant, "cred:newkey", value); err != nil {
		t.Fatalf("Put() unexpected error: %v", err)
	}

	if string(versionPayload) != string(value) {
		t.Errorf("Put() stored payload = %q, want %q", versionPayload, value)
	}
}

func TestPut_AlreadyExists_StillAddsVersion(t *testing.T) {
	var addVersionCalled bool
	mock := &mockSMClient{
		createSecretFn: func(_ context.Context, _ *secretmanagerpb.CreateSecretRequest, _ ...interface{}) (*secretmanagerpb.Secret, error) {
			return nil, status.Error(codes.AlreadyExists, "already exists")
		},
		addSecretVersionFn: func(_ context.Context, _ *secretmanagerpb.AddSecretVersionRequest, _ ...interface{}) (*secretmanagerpb.SecretVersion, error) {
			addVersionCalled = true
			return &secretmanagerpb.SecretVersion{}, nil
		},
	}
	p := newTestProvider(mock)

	if err := p.Put(context.Background(), testTenant, "cred:existing", []byte("new-value")); err != nil {
		t.Fatalf("Put() on existing: unexpected error: %v", err)
	}
	if !addVersionCalled {
		t.Error("Put() on existing: expected AddSecretVersion to be called")
	}
}

func TestPut_TooLarge(t *testing.T) {
	p := newTestProvider(&mockSMClient{})
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
		deleteSecretFn: func(_ context.Context, _ *secretmanagerpb.DeleteSecretRequest, _ ...interface{}) error {
			return nil
		},
	}
	p := newTestProvider(mock)
	if err := p.Delete(context.Background(), testTenant, "cred:oldkey"); err != nil {
		t.Errorf("Delete() unexpected error: %v", err)
	}
}

func TestDelete_NotFoundIsNoOp(t *testing.T) {
	mock := &mockSMClient{
		deleteSecretFn: func(_ context.Context, _ *secretmanagerpb.DeleteSecretRequest, _ ...interface{}) error {
			return status.Error(codes.NotFound, "not found")
		},
	}
	p := newTestProvider(mock)
	if err := p.Delete(context.Background(), testTenant, "cred:nonexistent"); err != nil {
		t.Errorf("Delete() of non-existent: expected no error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// List tests
// ---------------------------------------------------------------------------

func TestList_WithLabelBrokerName(t *testing.T) {
	// Simulate ListSecrets returning entries with broker-name labels.
	mock := &mockSMClient{
		listSecretsFn: func(_ context.Context, _ *secretmanagerpb.ListSecretsRequest, _ ...interface{}) secretIterator {
			return &staticSecretIterator{
				secrets: []*secretmanagerpb.Secret{
					{
						Name:   "projects/test-project/secrets/gibson-tenant-test-tenant-cred-a",
						Labels: map[string]string{labelBrokerName: "cred:a"},
					},
					{
						Name:   "projects/test-project/secrets/gibson-tenant-test-tenant-cred-b",
						Labels: map[string]string{labelBrokerName: "cred:b"},
					},
					{
						Name:   "projects/test-project/secrets/gibson-tenant-test-tenant-provider-config-anthropic-default",
						Labels: map[string]string{labelBrokerName: "provider_config:anthropic:default"},
					},
				},
			}
		},
	}
	p := newTestProvider(mock)

	names, err := p.List(context.Background(), testTenant, secrets.Filter{Prefix: "cred:"})
	if err != nil {
		t.Fatalf("List() unexpected error: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("List() with prefix 'cred:': want 2, got %d: %v", len(names), names)
	}
}

func TestList_NoFilter(t *testing.T) {
	mock := &mockSMClient{
		listSecretsFn: func(_ context.Context, _ *secretmanagerpb.ListSecretsRequest, _ ...interface{}) secretIterator {
			return &staticSecretIterator{
				secrets: []*secretmanagerpb.Secret{
					{Name: "projects/test-project/secrets/gibson-tenant-test-tenant-cred-a", Labels: map[string]string{labelBrokerName: "cred:a"}},
					{Name: "projects/test-project/secrets/gibson-tenant-test-tenant-cred-b", Labels: map[string]string{labelBrokerName: "cred:b"}},
				},
			}
		},
	}
	p := newTestProvider(mock)

	names, err := p.List(context.Background(), testTenant, secrets.Filter{})
	if err != nil {
		t.Fatalf("List() unexpected error: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("List() no filter: want 2, got %d", len(names))
	}
}

// ---------------------------------------------------------------------------
// Health tests
// ---------------------------------------------------------------------------

func TestHealth_OK(t *testing.T) {
	mock := &mockSMClient{
		listSecretsFn: func(_ context.Context, _ *secretmanagerpb.ListSecretsRequest, _ ...interface{}) secretIterator {
			return &staticSecretIterator{}
		},
	}
	p := newTestProvider(mock)
	if err := p.Health(context.Background()); err != nil {
		t.Errorf("Health() healthy: unexpected error: %v", err)
	}
}

func TestHealth_Unavailable(t *testing.T) {
	mock := &mockSMClient{
		listSecretsFn: func(_ context.Context, _ *secretmanagerpb.ListSecretsRequest, _ ...interface{}) secretIterator {
			return &staticSecretIterator{
				err: status.Error(codes.Unavailable, "service unavailable"),
			}
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
	if !caps.SupportsVersion {
		t.Error("Capabilities().SupportsVersion = false, want true")
	}
	if caps.MaxValueBytes != maxValueBytes {
		t.Errorf("Capabilities().MaxValueBytes = %d, want %d", caps.MaxValueBytes, maxValueBytes)
	}
}

// ---------------------------------------------------------------------------
// Probe test
// ---------------------------------------------------------------------------

func TestProbe_Success(t *testing.T) {
	stored := make(map[string][]byte)

	mock := &mockSMClient{
		createSecretFn: func(_ context.Context, req *secretmanagerpb.CreateSecretRequest, _ ...interface{}) (*secretmanagerpb.Secret, error) {
			return &secretmanagerpb.Secret{Name: req.Parent + "/secrets/" + req.SecretId}, nil
		},
		addSecretVersionFn: func(_ context.Context, req *secretmanagerpb.AddSecretVersionRequest, _ ...interface{}) (*secretmanagerpb.SecretVersion, error) {
			stored[req.Parent] = req.Payload.Data
			return &secretmanagerpb.SecretVersion{}, nil
		},
		accessSecretVersionFn: func(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest, _ ...interface{}) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			// Strip the /versions/latest suffix to find the secret parent.
			parent := req.Name
			if idx := len(parent) - len("/versions/latest"); idx > 0 {
				parent = parent[:idx]
			}
			v, ok := stored[parent]
			if !ok {
				return nil, status.Error(codes.NotFound, "not found")
			}
			return &secretmanagerpb.AccessSecretVersionResponse{
				Payload: &secretmanagerpb.SecretPayload{Data: v},
			}, nil
		},
		deleteSecretFn: func(_ context.Context, req *secretmanagerpb.DeleteSecretRequest, _ ...interface{}) error {
			delete(stored, req.Name)
			return nil
		},
	}
	p := newTestProvider(mock)
	if err := p.Probe(context.Background()); err != nil {
		t.Errorf("Probe() unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error mapping test
// ---------------------------------------------------------------------------

func TestMapGCPError(t *testing.T) {
	tests := []struct {
		name   string
		code   codes.Code
		wantIs error
	}{
		{"NotFound", codes.NotFound, secrets.ErrNotFound},
		{"PermissionDenied", codes.PermissionDenied, secrets.ErrPermissionDenied},
		{"Unauthenticated", codes.Unauthenticated, secrets.ErrPermissionDenied},
		{"ResourceExhausted", codes.ResourceExhausted, secrets.ErrUnavailable},
		{"Unavailable", codes.Unavailable, secrets.ErrUnavailable},
		{"DeadlineExceeded", codes.DeadlineExceeded, secrets.ErrUnavailable},
		{"InvalidArgument", codes.InvalidArgument, secrets.ErrInvalidArgument},
		{"Internal", codes.Internal, secrets.ErrUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := status.Error(tt.code, "test error")
			got := mapGCPError(err, "testname")
			if !errors.Is(got, tt.wantIs) {
				t.Errorf("mapGCPError(%v): want errors.Is(%v), got %v", tt.code, tt.wantIs, got)
			}
		})
	}
}
