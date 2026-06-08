package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/idp"
	"github.com/zeroroot-ai/gibson/internal/types"
	"github.com/zeroroot-ai/sdk/auth"
)

// --- test doubles -----------------------------------------------------------

type cgKeyProvider struct{}

func (cgKeyProvider) GetEncryptionKey(context.Context) ([]byte, error) {
	return []byte(strings.Repeat("k", 32)), nil
}
func (cgKeyProvider) Name() string                              { return "test" }
func (cgKeyProvider) Health(context.Context) types.HealthStatus { return types.HealthStatus{} }
func (cgKeyProvider) Close() error                              { return nil }

func newAdapterTestMinter(t *testing.T) *capabilitygrant.Minter {
	t.Helper()
	m, err := capabilitygrant.NewMinter(context.Background(), capabilitygrant.Config{
		Issuer:      "https://test.daemon",
		Audience:    "test-daemon",
		KeyProvider: cgKeyProvider{},
		KeyID:       "k1",
	})
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	return m
}

// stubIDP is a minimal idp.AdminClient: only Create/Delete carry behavior.
type stubIDP struct {
	accountID string
	createErr error
	deleted   []string
}

func (s *stubIDP) CreateServiceAccount(_ context.Context, _ idp.CreateServiceAccountRequest) (*idp.ServiceAccount, error) {
	if s.createErr != nil {
		return nil, s.createErr
	}
	return &idp.ServiceAccount{AccountID: s.accountID}, nil
}
func (s *stubIDP) DeleteServiceAccount(_ context.Context, accountID string) error {
	s.deleted = append(s.deleted, accountID)
	return nil
}
func (s *stubIDP) ListServiceAccounts(_ context.Context, _ idp.ListServiceAccountsRequest) (*idp.ListServiceAccountsResponse, error) {
	return &idp.ListServiceAccountsResponse{}, nil
}
func (s *stubIDP) GetUserProfile(_ context.Context, _ string) (*idp.UserProfile, error) {
	return nil, idp.ErrNotFound
}
func (s *stubIDP) UpdateUserProfile(_ context.Context, _ string, _ idp.UpdateUserProfileRequest) (*idp.UserProfile, error) {
	return nil, idp.ErrNotFound
}
func (s *stubIDP) AddTenantMember(_ context.Context, _ idp.TenantMembershipRequest) error { return nil }
func (s *stubIDP) RemoveTenantMember(_ context.Context, _ idp.TenantMembershipRequest) error {
	return nil
}
func (s *stubIDP) EnsureHumanUser(_ context.Context, _ idp.EnsureHumanUserRequest) (string, error) {
	return "", nil
}
func (s *stubIDP) RevokeUserSessions(_ context.Context, _ string) (idp.RevokeUserSessionsResult, error) {
	return idp.RevokeUserSessionsResult{}, nil
}
func (s *stubIDP) Close() error { return nil }

func adapterTestCtx(t *testing.T) (context.Context, auth.TenantID) {
	t.Helper()
	tenant, err := auth.NewTenantID("acme")
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithIdentity(context.Background(), auth.Identity{
		Subject: "user-admin",
		Issuer:  auth.IssuerOIDC,
		Tenant:  tenant,
	})
	return ctx, tenant
}

// --- tests ------------------------------------------------------------------

// TestPluginPrincipalAdapter_MintsCGBootstrapWithPluginPrincipalSubject is the
// guard for gibson#673: the plugin enrollment must mint a CG bootstrap token
// (NOT an OAuth secret) whose subject is the unified `plugin_principal:<id>` —
// the same identity the `secret can_resolve` tuples and the runtime CG-JWT use.
// A mismatch here is silent at compile time and breaks plugin secret resolution.
func TestPluginPrincipalAdapter_MintsCGBootstrapWithPluginPrincipalSubject(t *testing.T) {
	minter := newAdapterTestMinter(t)
	fake := &stubIDP{accountID: "acct-1"}
	a := &idpPluginPrincipalAdapter{client: fake, cgMinter: minter}
	ctx, tenant := adapterTestCtx(t)

	principalID, token, expiresAt, err := a.CreatePrincipal(ctx, tenant, "install-1", "my-plugin", time.Hour)
	if err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}
	if principalID != "plugin_principal:acct-1" {
		t.Errorf("principalID = %q, want %q", principalID, "plugin_principal:acct-1")
	}
	if token == "" {
		t.Fatal("expected non-empty bootstrap token")
	}
	if expiresAt.Before(time.Now()) {
		t.Error("expiresAt should be in the future")
	}

	// The token must be a valid CG bootstrap token whose claims agree with the
	// principal — this is what makes the runtime CG-JWT authorize against the
	// can_resolve tuples.
	claims, err := minter.VerifyBootstrapToken(token)
	if err != nil {
		t.Fatalf("VerifyBootstrapToken: %v", err)
	}
	if claims.PrincipalID != principalID {
		t.Errorf("token sub = %q, want %q", claims.PrincipalID, principalID)
	}
	if claims.Kind != "plugin" {
		t.Errorf("token kind = %q, want plugin", claims.Kind)
	}
	if claims.Name != "my-plugin" || claims.TenantID != "acme" || claims.OwnerUserID != "user-admin" {
		t.Errorf("unexpected claims: %+v", claims)
	}
	if len(fake.deleted) != 0 {
		t.Errorf("no rollback expected, got deletes: %v", fake.deleted)
	}
}

func TestPluginPrincipalAdapter_NilMinterFailsLoud(t *testing.T) {
	fake := &stubIDP{accountID: "acct-1"}
	a := &idpPluginPrincipalAdapter{client: fake, cgMinter: nil}
	ctx, tenant := adapterTestCtx(t)

	if _, _, _, err := a.CreatePrincipal(ctx, tenant, "install-1", "p", time.Hour); err == nil {
		t.Fatal("expected error when CG minter is nil")
	}
	// No service account should be created when the minter is absent.
	if len(fake.deleted) != 0 {
		t.Errorf("unexpected deletes: %v", fake.deleted)
	}
}

func TestPluginPrincipalAdapter_NoCallerIdentityFails(t *testing.T) {
	a := &idpPluginPrincipalAdapter{client: &stubIDP{accountID: "acct-1"}, cgMinter: newAdapterTestMinter(t)}
	tenant, _ := auth.NewTenantID("acme")
	if _, _, _, err := a.CreatePrincipal(context.Background(), tenant, "install-1", "p", time.Hour); err == nil {
		t.Fatal("expected error when caller identity is absent")
	}
}

func TestPluginPrincipalAdapter_DeleteStripsPrefix(t *testing.T) {
	fake := &stubIDP{accountID: "acct-1"}
	a := &idpPluginPrincipalAdapter{client: fake, cgMinter: newAdapterTestMinter(t)}
	if err := a.DeletePrincipal(context.Background(), "plugin_principal:acct-1"); err != nil {
		t.Fatalf("DeletePrincipal: %v", err)
	}
	if len(fake.deleted) != 1 || fake.deleted[0] != "acct-1" {
		t.Errorf("DeleteServiceAccount called with %v, want [acct-1]", fake.deleted)
	}
}
