package api

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/keycloak"
	"github.com/zero-day-ai/gibson/internal/provisioner"
)

// ---------------------------------------------------------------------------
// Minimal test doubles for the provisioner dependencies
// ---------------------------------------------------------------------------

// stubKCForAPITest is a minimal KeycloakAdmin for the api-layer test.
// It only needs to succeed or fail as configured.
type stubKCForAPITest struct {
	createUserID  string
	createUserErr error
	createOrgID   string
	createOrgErr  error
	addMemberErr  error
}

func (s *stubKCForAPITest) CreateUser(_ context.Context, _ keycloak.UserConfig) (string, error) {
	return s.createUserID, s.createUserErr
}
func (s *stubKCForAPITest) DeleteUser(_ context.Context, _ string) error { return nil }
func (s *stubKCForAPITest) CreateOrganization(_ context.Context, _, _, _ string) (string, error) {
	return s.createOrgID, s.createOrgErr
}
func (s *stubKCForAPITest) GetOrganizationByAlias(_ context.Context, _ string) (*provisioner.OrgRepresentation, error) {
	return nil, provisioner.ErrNotFound
}
func (s *stubKCForAPITest) DeleteOrganization(_ context.Context, _ string) error { return nil }
func (s *stubKCForAPITest) AddOrganizationMember(_ context.Context, _, _ string) error {
	return s.addMemberErr
}
func (s *stubKCForAPITest) RemoveOrganizationMember(_ context.Context, _, _ string) error {
	return nil
}
func (s *stubKCForAPITest) ListOrganizationMembers(_ context.Context, _ string) ([]provisioner.OrgMemberRepresentation, error) {
	return nil, nil
}

// stubAuthzForAPITest is a minimal authz.Authorizer for the api-layer test.
type stubAuthzForAPITest struct {
	writeErr error
}

func (s *stubAuthzForAPITest) Check(_ context.Context, _, _, _ string) (bool, error) { return true, nil }
func (s *stubAuthzForAPITest) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (s *stubAuthzForAPITest) Write(_ context.Context, _ []authz.Tuple) error {
	return s.writeErr
}
func (s *stubAuthzForAPITest) Delete(_ context.Context, _ []authz.Tuple) error { return nil }
func (s *stubAuthzForAPITest) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubAuthzForAPITest) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubAuthzForAPITest) StoreID() string { return "" }
func (s *stubAuthzForAPITest) ModelID() string { return "" }
func (s *stubAuthzForAPITest) Close() error    { return nil }

// stubProvisionerForAPITest satisfies tenantProvisionerIface via a type
// assertion — we access the internal interface through the provisioner package.
// Since provisioner.SignupHandler is constructed with NewSignupHandler which
// takes a *Provisioner (not the interface), we need to work around this.
//
// Strategy: construct a SignupHandler using the package-internal fields by
// constructing through the exported NewSignupHandler and accepting that the
// Provisioner will be nil (it panics on nil redis), OR we build the handler
// directly as an unexported struct literal since we're in the api_test package
// which is a separate package.
//
// Because we're in the `api` package (same compilation unit as server.go), and
// provisioner.SignupHandler fields are unexported, the cleanest approach is to
// use provisioner.NewSignupHandler with a nil *Provisioner and intercept at
// the interface level.
//
// The SignupHandler.provisioner field is a tenantProvisionerIface (unexported).
// We can't set it from outside the package.
//
// Resolution: The api-level test validates only the gRPC status mapping.
// We build a test SignupHandler where the KC creates a user and org, adds a
// member, and the authz write succeeds — then confirms the provisioner call
// (which fails because Provisioner is nil with a nil redis) triggers a proper
// codes.Internal.  Alternatively we can construct a REAL provisioner with a
// miniredis — but that's overkill for a handler unit test.
//
// Simplest correct approach: test only the nil-handler case (Unavailable) and
// the error mapping cases via a thin wrapper.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestSignupTenant_NilHandler_ReturnsUnavailable verifies that a DaemonServer
// with no signupHandler wired returns codes.Unavailable.
func TestSignupTenant_NilHandler_ReturnsUnavailable(t *testing.T) {
	srv := &DaemonServer{logger: slog.Default()}

	_, err := srv.SignupTenant(context.Background(), &SignupTenantRequest{
		Email:       "alice@example.com",
		Password:    "securepassword123",
		CompanyName: "Acme Corp",
		Plan:        "free",
	})

	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// TestSignupTenant_InvalidInput_ReturnsInvalidArgument verifies that
// ErrInvalidSignupInput from the handler maps to codes.InvalidArgument.
func TestSignupTenant_InvalidInput_ReturnsInvalidArgument(t *testing.T) {
	// Build a handler where the KC succeeds but we submit an invalid request.
	// The validation happens before any KC call, so KC stubs don't matter.
	kc := &stubKCForAPITest{}
	az := &stubAuthzForAPITest{}

	// Build a SignupHandler using the provisioner package's exported constructor.
	// The *Provisioner is nil — that's OK because with an invalid input the
	// handler returns before reaching the provisioner call.
	h := provisioner.NewSignupHandler(kc, az, nil, slog.Default())

	srv := &DaemonServer{
		signupHandler: h,
		logger:        slog.Default(),
	}

	// Email is invalid — should fail validation before any KC call.
	_, err := srv.SignupTenant(context.Background(), &SignupTenantRequest{
		Email:       "not-an-email",
		Password:    "securepassword123",
		CompanyName: "Acme Corp",
		Plan:        "free",
	})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err),
		"validation failure must map to InvalidArgument")
}

// TestSignupTenant_EmailConflict_ReturnsAlreadyExists verifies that
// ErrEmailAlreadyExists from the handler maps to codes.AlreadyExists.
func TestSignupTenant_EmailConflict_ReturnsAlreadyExists(t *testing.T) {
	kc := &stubKCForAPITest{
		createUserErr: provisioner.ErrConflict, // email already registered in Keycloak
	}
	az := &stubAuthzForAPITest{}

	h := provisioner.NewSignupHandler(kc, az, nil, slog.Default())
	srv := &DaemonServer{signupHandler: h, logger: slog.Default()}

	_, err := srv.SignupTenant(context.Background(), &SignupTenantRequest{
		Email:       "alice@example.com",
		Password:    "securepassword123",
		CompanyName: "Acme Corp",
		Plan:        "free",
	})

	require.Error(t, err)
	assert.Equal(t, codes.AlreadyExists, status.Code(err),
		"duplicate email must map to AlreadyExists")
}

// TestSignupTenant_KCCreateUserFails_ReturnsInternal verifies that an
// unexpected KC error (not a conflict) maps to codes.Internal.
func TestSignupTenant_KCCreateUserFails_ReturnsInternal(t *testing.T) {
	kc := &stubKCForAPITest{
		createUserErr: errors.New("KC server error"),
	}
	az := &stubAuthzForAPITest{}

	h := provisioner.NewSignupHandler(kc, az, nil, slog.Default())
	srv := &DaemonServer{signupHandler: h, logger: slog.Default()}

	_, err := srv.SignupTenant(context.Background(), &SignupTenantRequest{
		Email:       "alice@example.com",
		Password:    "securepassword123",
		CompanyName: "Acme Corp",
		Plan:        "free",
	})

	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err),
		"unexpected KC error must map to codes.Internal")
}

// TestSignupTenant_RequestFieldMapping verifies that proto fields are correctly
// mapped to the SignupRequest (i.e. the handler passes the right values to
// the domain layer).  We confirm by checking the validation error message
// which includes the email value.
func TestSignupTenant_RequestFieldMapping(t *testing.T) {
	kc := &stubKCForAPITest{}
	az := &stubAuthzForAPITest{}
	h := provisioner.NewSignupHandler(kc, az, nil, slog.Default())
	srv := &DaemonServer{signupHandler: h, logger: slog.Default()}

	// Submit an invalid plan — the error message should reference "diamond".
	_, err := srv.SignupTenant(context.Background(), &SignupTenantRequest{
		Email:       "alice@example.com",
		Password:    "securepassword123",
		CompanyName: "Acme Corp",
		Plan:        "diamond",
	})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "diamond", "error should include the invalid plan value")
}
