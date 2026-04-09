package provisioner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/zero-day-ai/gibson/internal/keycloak"
)

// -------------------------------------------------------------------------
// Test helper: mock Keycloak server
// -------------------------------------------------------------------------

// keycloakTestServer wraps httptest.Server with helpers for configuring
// per-request responses in unit tests.
type keycloakTestServer struct {
	*httptest.Server

	// handlers maps "METHOD /path" to a handler function.
	// If the path ends with "/*" it matches any suffix.
	handlers map[string]http.HandlerFunc
}

func newKeycloakTestServer(t *testing.T) *keycloakTestServer {
	t.Helper()
	s := &keycloakTestServer{handlers: map[string]http.HandlerFunc{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		for k, h := range s.handlers {
			if k == key || (strings.HasSuffix(k, "/*") && strings.HasPrefix(key, k[:len(k)-1])) {
				h(w, r)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// on registers a handler for a specific "METHOD /path" combination.
func (s *keycloakTestServer) on(method, path string, handler http.HandlerFunc) {
	s.handlers[method+" "+path] = handler
}

// tokenOK installs a handler that satisfies the client-credentials token request.
func (s *keycloakTestServer) tokenOK(t *testing.T) {
	t.Helper()
	s.on("POST", "/realms/master/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	})
}

// newTestAdminClient builds a KeycloakAdmin wired to the mock server.
// The admin credentials are synthetic; the token endpoint on the mock server
// is set up by tokenOK before calling this.
func newTestAdminClient(t *testing.T, srv *keycloakTestServer) KeycloakAdmin {
	t.Helper()
	client := keycloak.NewClient(srv.URL, "master", "test-client", "test-secret", nil)
	// Prime the token cache so tests don't need a real token endpoint (unless
	// they explicitly call tokenOK).
	client.PrimeTokenCache("test-token", time.Now().Add(time.Hour))

	return &keycloakAdminClient{
		client: client,
		realm:  "gibson",
		tracer: noopTracer(),
		logger: nil,
	}
}

// -------------------------------------------------------------------------
// CreateUser
// -------------------------------------------------------------------------

func TestCreateUser_Success(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("POST", "/admin/realms/gibson/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/admin/realms/gibson/users/user-uuid-1")
		w.WriteHeader(http.StatusCreated)
	})

	ka := newTestAdminClient(t, srv)
	userID, err := ka.CreateUser(context.Background(), keycloak.UserConfig{
		Username: "alice",
		Email:    "alice@example.com",
		Enabled:  true,
	})

	require.NoError(t, err)
	assert.Equal(t, "user-uuid-1", userID)
}

func TestCreateUser_Conflict(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("POST", "/admin/realms/gibson/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	})

	ka := newTestAdminClient(t, srv)
	_, err := ka.CreateUser(context.Background(), keycloak.UserConfig{Username: "alice"})

	assert.ErrorIs(t, err, ErrConflict)
}

func TestCreateUser_Forbidden(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("POST", "/admin/realms/gibson/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	ka := newTestAdminClient(t, srv)
	_, err := ka.CreateUser(context.Background(), keycloak.UserConfig{Username: "alice"})

	assert.ErrorIs(t, err, ErrForbidden)
}

// -------------------------------------------------------------------------
// DeleteUser
// -------------------------------------------------------------------------

func TestDeleteUser_Success(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("DELETE", "/admin/realms/gibson/users/user-uuid-1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	ka := newTestAdminClient(t, srv)
	err := ka.DeleteUser(context.Background(), "user-uuid-1")
	assert.NoError(t, err)
}

func TestDeleteUser_NotFound(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("DELETE", "/admin/realms/gibson/users/missing", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	ka := newTestAdminClient(t, srv)
	err := ka.DeleteUser(context.Background(), "missing")
	assert.ErrorIs(t, err, ErrNotFound)
}

// -------------------------------------------------------------------------
// CreateOrganization
// -------------------------------------------------------------------------

func TestCreateOrganization_Success(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("POST", "/admin/realms/gibson/organizations", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/admin/realms/gibson/organizations/org-uuid-1")
		w.WriteHeader(http.StatusCreated)
	})

	ka := newTestAdminClient(t, srv)
	orgID, err := ka.CreateOrganization(context.Background(), "Acme Corp", "acme-corp", "Test org")

	require.NoError(t, err)
	assert.Equal(t, "org-uuid-1", orgID)
}

func TestCreateOrganization_Conflict(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("POST", "/admin/realms/gibson/organizations", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	})

	ka := newTestAdminClient(t, srv)
	_, err := ka.CreateOrganization(context.Background(), "Acme Corp", "acme-corp", "")
	assert.ErrorIs(t, err, ErrConflict)
}

// -------------------------------------------------------------------------
// GetOrganizationByAlias
// -------------------------------------------------------------------------

func TestGetOrganizationByAlias_Found(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("GET", "/admin/realms/gibson/organizations", func(w http.ResponseWriter, r *http.Request) {
		orgs := []OrgRepresentation{
			{ID: "org-uuid-1", Alias: "acme-corp", Name: "Acme Corp", Enabled: true},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(orgs)
	})

	ka := newTestAdminClient(t, srv)
	org, err := ka.GetOrganizationByAlias(context.Background(), "acme-corp")

	require.NoError(t, err)
	assert.Equal(t, "org-uuid-1", org.ID)
	assert.Equal(t, "acme-corp", org.Alias)
}

func TestGetOrganizationByAlias_NotFound(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("GET", "/admin/realms/gibson/organizations", func(w http.ResponseWriter, r *http.Request) {
		// Empty list — no match.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]OrgRepresentation{})
	})

	ka := newTestAdminClient(t, srv)
	_, err := ka.GetOrganizationByAlias(context.Background(), "missing-org")
	assert.ErrorIs(t, err, ErrNotFound)
}

// -------------------------------------------------------------------------
// DeleteOrganization
// -------------------------------------------------------------------------

func TestDeleteOrganization_Success(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("DELETE", "/admin/realms/gibson/organizations/org-uuid-1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	ka := newTestAdminClient(t, srv)
	err := ka.DeleteOrganization(context.Background(), "org-uuid-1")
	assert.NoError(t, err)
}

func TestDeleteOrganization_NotFound(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("DELETE", "/admin/realms/gibson/organizations/missing", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	ka := newTestAdminClient(t, srv)
	err := ka.DeleteOrganization(context.Background(), "missing")
	assert.ErrorIs(t, err, ErrNotFound)
}

// -------------------------------------------------------------------------
// AddOrganizationMember
// -------------------------------------------------------------------------

func TestAddOrganizationMember_Success(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("POST", "/admin/realms/gibson/organizations/org-1/members", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	ka := newTestAdminClient(t, srv)
	err := ka.AddOrganizationMember(context.Background(), "org-1", "user-1")
	assert.NoError(t, err)
}

func TestAddOrganizationMember_Conflict_IsIdempotent(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("POST", "/admin/realms/gibson/organizations/org-1/members", func(w http.ResponseWriter, r *http.Request) {
		// Already a member — should be treated as success.
		w.WriteHeader(http.StatusConflict)
	})

	ka := newTestAdminClient(t, srv)
	err := ka.AddOrganizationMember(context.Background(), "org-1", "user-1")
	assert.NoError(t, err, "409 from AddOrganizationMember should be treated as success")
}

func TestAddOrganizationMember_NotFound(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("POST", "/admin/realms/gibson/organizations/no-org/members", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	ka := newTestAdminClient(t, srv)
	err := ka.AddOrganizationMember(context.Background(), "no-org", "user-1")
	assert.ErrorIs(t, err, ErrNotFound)
}

// -------------------------------------------------------------------------
// RemoveOrganizationMember
// -------------------------------------------------------------------------

func TestRemoveOrganizationMember_Success(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("DELETE", "/admin/realms/gibson/organizations/org-1/members/user-1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	ka := newTestAdminClient(t, srv)
	err := ka.RemoveOrganizationMember(context.Background(), "org-1", "user-1")
	assert.NoError(t, err)
}

func TestRemoveOrganizationMember_NotFound(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("DELETE", "/admin/realms/gibson/organizations/org-1/members/ghost", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	ka := newTestAdminClient(t, srv)
	err := ka.RemoveOrganizationMember(context.Background(), "org-1", "ghost")
	assert.ErrorIs(t, err, ErrNotFound)
}

// -------------------------------------------------------------------------
// ListOrganizationMembers
// -------------------------------------------------------------------------

func TestListOrganizationMembers_Success(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("GET", "/admin/realms/gibson/organizations/org-1/members", func(w http.ResponseWriter, r *http.Request) {
		members := []OrgMemberRepresentation{
			{ID: "user-1", Username: "alice", Email: "alice@example.com"},
			{ID: "user-2", Username: "bob", Email: "bob@example.com"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(members)
	})

	ka := newTestAdminClient(t, srv)
	members, err := ka.ListOrganizationMembers(context.Background(), "org-1")

	require.NoError(t, err)
	assert.Len(t, members, 2)
	assert.Equal(t, "alice", members[0].Username)
	assert.Equal(t, "bob", members[1].Username)
}

func TestListOrganizationMembers_NotFound(t *testing.T) {
	srv := newKeycloakTestServer(t)
	srv.on("GET", "/admin/realms/gibson/organizations/no-org/members", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	ka := newTestAdminClient(t, srv)
	_, err := ka.ListOrganizationMembers(context.Background(), "no-org")
	assert.ErrorIs(t, err, ErrNotFound)
}

// -------------------------------------------------------------------------
// Test helpers
// -------------------------------------------------------------------------

// noopTracer returns a no-op OTel tracer so span calls don't panic in tests.
func noopTracer() trace.Tracer {
	return noop.NewTracerProvider().Tracer("test")
}
