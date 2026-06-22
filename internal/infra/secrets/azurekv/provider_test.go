package azurekv

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// testTenant is the tenant used in all unit tests.
var testTenant = auth.MustNewTenantID("test-tenant")

// ---------------------------------------------------------------------------
// Mock Azure REST API server helpers
// ---------------------------------------------------------------------------

// secretResponseFn builds the JSON body for a successful GetSecret or SetSecret response.
// The vaultURL must match the test server URL to pass the azsecrets ID validation.
func secretResponseFn(vaultURL, name, value string) string {
	// Ensure trailing slash is removed from vaultURL.
	vaultURL = strings.TrimSuffix(vaultURL, "/")
	return fmt.Sprintf(`{
		"id": "%s/secrets/%s/abc123",
		"value": %q,
		"attributes": {"enabled": true}
	}`, vaultURL, name, value)
}

// mockMux is a mux that can access the test server's URL for response building.
type mockMux struct {
	handlers map[string]func(w http.ResponseWriter, r *http.Request, srvURL string)
	srvURL   string
}

func newMockMux() *mockMux {
	return &mockMux{handlers: make(map[string]func(http.ResponseWriter, *http.Request, string))}
}

func (m *mockMux) handle(prefix string, h func(http.ResponseWriter, *http.Request, string)) {
	m.handlers[prefix] = h
}

func (m *mockMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for prefix, h := range m.handlers {
		if strings.HasPrefix(r.URL.Path, prefix) {
			h(w, r, m.srvURL)
			return
		}
	}
	// Log unmatched requests to help debugging.
	_ = r.URL.Path // used for debugging; remove log in production
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprint(w, `{"error":{"code":"SecretNotFound","message":"not found"}}`)
}

// buildProviderFromMockMux creates a Provider pointing at a mock TLS server.
// Retries are disabled to keep tests fast.
func buildProviderFromMockMux(t *testing.T, mux *mockMux) *Provider {
	t.Helper()

	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	// Give the mux access to the server URL for building correct response IDs.
	mux.srvURL = srv.URL

	cred := &noopCredential{}
	client, err := azsecrets.NewClient(srv.URL, cred, &azsecrets.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: srv.Client(),
			Retry: policy.RetryOptions{
				MaxRetries: 0,
				RetryDelay: time.Millisecond,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create azsecrets client: %v", err)
	}

	return newWithClient(Config{VaultURL: srv.URL}, client)
}

// buildProviderFromMockServer creates a Provider pointing at the mock TLS server.
// It uses a static no-op credential and sets up the azsecrets client to hit
// the test server URL. TLS is required by the azsecrets SDK for authenticated requests.
// Retries are disabled to keep tests fast.
func buildProviderFromMockServer(t *testing.T, handler http.Handler) *Provider {
	t.Helper()

	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	cred := &noopCredential{}
	client, err := azsecrets.NewClient(srv.URL, cred, &azsecrets.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: srv.Client(),
			Retry: policy.RetryOptions{
				MaxRetries: 0,
				RetryDelay: time.Millisecond,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create azsecrets client: %v", err)
	}

	return newWithClient(Config{VaultURL: srv.URL}, client)
}

// noopCredential is a no-op azcore.TokenCredential that returns a dummy token.
// Used to avoid real Azure auth in unit tests.
type noopCredential struct{}

func (n *noopCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token"}, nil
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
		{"provider_config:anthropic:default", "provider-config-anthropic-default", false},
		{"simple", "simple", false},
		{"with/slash", "with-slash", false},
		{"with.dot", "with-dot", false},
		{"", "", true},    // empty → error
		{":::", "", true}, // all-separators → empty after trim → error
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
// Get tests via httptest.Server
// ---------------------------------------------------------------------------

func TestGet_Success(t *testing.T) {
	value := []byte("super-secret-value")
	encoded := base64.StdEncoding.EncodeToString(value)

	mux := newMockMux()
	mux.handle("/secrets/", func(w http.ResponseWriter, r *http.Request, srvURL string) {
		if r.Method != http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = fmt.Fprint(w, `{"error":{"code":"MethodNotAllowed","message":"wrong method"}}`)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		name := ""
		if len(parts) >= 2 {
			name = parts[1]
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, secretResponseFn(srvURL, name, encoded))
	})

	p := buildProviderFromMockMux(t, mux)

	got, err := p.Get(context.Background(), testTenant, "cred:dbpass")
	if err != nil {
		t.Fatalf("Get() unexpected error: %v", err)
	}
	if string(got) != string(value) {
		t.Errorf("Get() = %q, want %q", got, value)
	}
}

func TestGet_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, `{"error":{"code":"SecretNotFound","message":"not found"}}`)
	})

	p := buildProviderFromMockServer(t, mux)

	_, err := p.Get(context.Background(), testTenant, "cred:missing")
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Get() missing: want ErrNotFound, got %v", err)
	}
}

func TestGet_Forbidden(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":{"code":"Forbidden","message":"access denied"}}`)
	})

	p := buildProviderFromMockServer(t, mux)

	_, err := p.Get(context.Background(), testTenant, "cred:forbidden")
	if !errors.Is(err, secrets.ErrPermissionDenied) {
		t.Errorf("Get() forbidden: want ErrPermissionDenied, got %v", err)
	}
}

func TestGet_ServiceUnavailable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprint(w, `{"error":{"code":"ServiceUnavailable","message":"unavailable"}}`)
	})

	p := buildProviderFromMockServer(t, mux)

	_, err := p.Get(context.Background(), testTenant, "cred:unavailable")
	if !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("Get() unavailable: want ErrUnavailable, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Put tests
// ---------------------------------------------------------------------------

// mockKVClient is a direct mock of kvClient used for Put/Delete tests where the
// httptest.Server approach encounters body-reading issues with the Azure SDK pipeline.
type mockKVClient struct {
	getSecretFn                    func(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
	setSecretFn                    func(ctx context.Context, name string, parameters azsecrets.SetSecretParameters, options *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error)
	deleteSecretFn                 func(ctx context.Context, name string, options *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error)
	newListSecretPropertiesPagerFn func(options *azsecrets.ListSecretPropertiesOptions) *runtime.Pager[azsecrets.ListSecretPropertiesResponse]
}

func (m *mockKVClient) GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	if m.getSecretFn != nil {
		return m.getSecretFn(ctx, name, version, options)
	}
	return azsecrets.GetSecretResponse{}, &azcore.ResponseError{StatusCode: http.StatusNotFound}
}

func (m *mockKVClient) SetSecret(ctx context.Context, name string, parameters azsecrets.SetSecretParameters, options *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
	if m.setSecretFn != nil {
		return m.setSecretFn(ctx, name, parameters, options)
	}
	return azsecrets.SetSecretResponse{}, nil
}

func (m *mockKVClient) DeleteSecret(ctx context.Context, name string, options *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error) {
	if m.deleteSecretFn != nil {
		return m.deleteSecretFn(ctx, name, options)
	}
	return azsecrets.DeleteSecretResponse{}, nil
}

func (m *mockKVClient) NewListSecretPropertiesPager(options *azsecrets.ListSecretPropertiesOptions) *runtime.Pager[azsecrets.ListSecretPropertiesResponse] {
	if m.newListSecretPropertiesPagerFn != nil {
		return m.newListSecretPropertiesPagerFn(options)
	}
	return runtime.NewPager(runtime.PagingHandler[azsecrets.ListSecretPropertiesResponse]{
		More: func(azsecrets.ListSecretPropertiesResponse) bool { return false },
		Fetcher: func(ctx context.Context, cur *azsecrets.ListSecretPropertiesResponse) (azsecrets.ListSecretPropertiesResponse, error) {
			return azsecrets.ListSecretPropertiesResponse{}, nil
		},
	})
}

func TestPut_Success(t *testing.T) {
	var capturedValue string

	mock := &mockKVClient{
		setSecretFn: func(_ context.Context, name string, params azsecrets.SetSecretParameters, _ *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
			if params.Value != nil {
				capturedValue = *params.Value
			}
			val := capturedValue
			id := azsecrets.ID("https://test.vault.azure.net/secrets/" + name)
			return azsecrets.SetSecretResponse{
				Secret: azsecrets.Secret{
					ID:    &id,
					Value: &val,
				},
			}, nil
		},
	}
	p := newWithClient(Config{VaultURL: "https://test.vault.azure.net"}, mock)

	value := []byte("my-api-key")
	if err := p.Put(context.Background(), testTenant, "cred:newkey", value); err != nil {
		t.Fatalf("Put() unexpected error: %v", err)
	}

	// Verify the stored value is base64-encoded.
	decoded, err := base64.StdEncoding.DecodeString(capturedValue)
	if err != nil {
		t.Fatalf("Put() stored value is not valid base64: %v", err)
	}
	if string(decoded) != string(value) {
		t.Errorf("Put() decoded stored value = %q, want %q", decoded, value)
	}
}

func TestPut_TooLarge(t *testing.T) {
	p := buildProviderFromMockServer(t, http.NewServeMux())
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
	mock := &mockKVClient{
		deleteSecretFn: func(_ context.Context, name string, _ *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error) {
			id := azsecrets.ID("https://test.vault.azure.net/secrets/" + name)
			return azsecrets.DeleteSecretResponse{
				DeletedSecret: azsecrets.DeletedSecret{
					ID: &id,
				},
			}, nil
		},
	}
	p := newWithClient(Config{VaultURL: "https://test.vault.azure.net"}, mock)
	if err := p.Delete(context.Background(), testTenant, "cred:oldkey"); err != nil {
		t.Errorf("Delete() unexpected error: %v", err)
	}
}

func TestDelete_NotFoundIsNoOp(t *testing.T) {
	mock := &mockKVClient{
		deleteSecretFn: func(_ context.Context, _ string, _ *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error) {
			return azsecrets.DeleteSecretResponse{}, &azcore.ResponseError{StatusCode: http.StatusNotFound}
		},
	}
	p := newWithClient(Config{VaultURL: "https://test.vault.azure.net"}, mock)
	if err := p.Delete(context.Background(), testTenant, "cred:nonexistent"); err != nil {
		t.Errorf("Delete() not found should be no-op, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// List tests
// ---------------------------------------------------------------------------

func TestList_WithPrefix(t *testing.T) {
	prefix := tenantNamePrefix(testTenant)

	mock := &mockKVClient{
		newListSecretPropertiesPagerFn: func(_ *azsecrets.ListSecretPropertiesOptions) *runtime.Pager[azsecrets.ListSecretPropertiesResponse] {
			idA := azsecrets.ID("https://test.vault.azure.net/secrets/" + prefix + "cred-a")
			idB := azsecrets.ID("https://test.vault.azure.net/secrets/" + prefix + "cred-b")
			idC := azsecrets.ID("https://test.vault.azure.net/secrets/" + prefix + "provider-config-anthropic-default")
			enabled := true
			items := []*azsecrets.SecretProperties{
				{ID: &idA, Attributes: &azsecrets.SecretAttributes{Enabled: &enabled}},
				{ID: &idB, Attributes: &azsecrets.SecretAttributes{Enabled: &enabled}},
				{ID: &idC, Attributes: &azsecrets.SecretAttributes{Enabled: &enabled}},
			}
			called := false
			return runtime.NewPager(runtime.PagingHandler[azsecrets.ListSecretPropertiesResponse]{
				More: func(r azsecrets.ListSecretPropertiesResponse) bool { return !called },
				Fetcher: func(ctx context.Context, cur *azsecrets.ListSecretPropertiesResponse) (azsecrets.ListSecretPropertiesResponse, error) {
					called = true
					return azsecrets.ListSecretPropertiesResponse{
						SecretPropertiesListResult: azsecrets.SecretPropertiesListResult{Value: items},
					}, nil
				},
			})
		},
	}
	p := newWithClient(Config{VaultURL: "https://test.vault.azure.net"}, mock)

	names, err := p.List(context.Background(), testTenant, secrets.Filter{Prefix: "cred-"})
	if err != nil {
		t.Fatalf("List() unexpected error: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("List() with prefix 'cred-': want 2, got %d: %v", len(names), names)
	}
}

// ---------------------------------------------------------------------------
// Health tests
// ---------------------------------------------------------------------------

func TestHealth_OK(t *testing.T) {
	mock := &mockKVClient{
		newListSecretPropertiesPagerFn: func(_ *azsecrets.ListSecretPropertiesOptions) *runtime.Pager[azsecrets.ListSecretPropertiesResponse] {
			called := false
			return runtime.NewPager(runtime.PagingHandler[azsecrets.ListSecretPropertiesResponse]{
				More: func(r azsecrets.ListSecretPropertiesResponse) bool { return !called },
				Fetcher: func(ctx context.Context, cur *azsecrets.ListSecretPropertiesResponse) (azsecrets.ListSecretPropertiesResponse, error) {
					called = true
					return azsecrets.ListSecretPropertiesResponse{}, nil
				},
			})
		},
	}
	p := newWithClient(Config{VaultURL: "https://test.vault.azure.net"}, mock)
	if err := p.Health(context.Background()); err != nil {
		t.Errorf("Health() healthy: unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Capabilities test
// ---------------------------------------------------------------------------

func TestCapabilities(t *testing.T) {
	p := newWithClient(Config{VaultURL: "https://test.vault.azure.net"}, nil)
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
// Error mapping test
// ---------------------------------------------------------------------------

func TestMapAzureError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantIs     error
	}{
		{"404", http.StatusNotFound, secrets.ErrNotFound},
		{"403", http.StatusForbidden, secrets.ErrPermissionDenied},
		{"401", http.StatusUnauthorized, secrets.ErrPermissionDenied},
		{"429", http.StatusTooManyRequests, secrets.ErrUnavailable},
		{"503", http.StatusServiceUnavailable, secrets.ErrUnavailable},
		{"400", http.StatusBadRequest, secrets.ErrInvalidArgument},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &azcore.ResponseError{StatusCode: tt.statusCode}
			got := mapAzureError(err, "testname")
			if !errors.Is(got, tt.wantIs) {
				t.Errorf("mapAzureError(HTTP %d): want errors.Is(%v), got %v", tt.statusCode, tt.wantIs, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Secret name helper tests
// ---------------------------------------------------------------------------

func TestSecretName(t *testing.T) {
	p := newWithClient(Config{VaultURL: "https://test.vault.azure.net"}, nil)
	tenant := auth.MustNewTenantID("my-tenant")

	name, err := p.secretName(tenant, "cred:foo")
	if err != nil {
		t.Fatalf("secretName() unexpected error: %v", err)
	}
	expected := "gibson-tenant-my-tenant-cred-foo"
	if name != expected {
		t.Errorf("secretName() = %q, want %q", name, expected)
	}
}

// Ensure azidentity import is used (used in New() via buildCredential which
// references azidentity.NewWorkloadIdentityCredential).
var _ = (*azidentity.WorkloadIdentityCredential)(nil)
