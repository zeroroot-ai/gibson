package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeKeycloak is a minimal in-process Keycloak stub backed by an httptest.Server.
// It tracks call counts and can be configured to return specific status codes for
// individual operations.
type fakeKeycloak struct {
	server     *httptest.Server
	mu         sync.Mutex
	tokenCalls int
	responses  map[string]int // path prefix → override status code
}

func newFakeKeycloak(t *testing.T) *fakeKeycloak {
	t.Helper()

	fk := &fakeKeycloak{
		responses: make(map[string]int),
	}

	mux := http.NewServeMux()

	// Token endpoint — always returns a short-lived token.
	mux.HandleFunc("/realms/master/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		fk.mu.Lock()
		fk.tokenCalls++
		fk.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "test-token",
			ExpiresIn:   300,
			TokenType:   "Bearer",
		})
	})

	// Health endpoint.
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Generic admin handler — dispatches based on method and path.
	mux.HandleFunc("/admin/realms", func(w http.ResponseWriter, r *http.Request) {
		fk.handleAdmin(w, r)
	})
	mux.HandleFunc("/admin/realms/", func(w http.ResponseWriter, r *http.Request) {
		fk.handleAdmin(w, r)
	})

	fk.server = httptest.NewServer(mux)
	t.Cleanup(fk.server.Close)

	return fk
}

// handleAdmin routes admin API requests to per-method helpers.
func (fk *fakeKeycloak) handleAdmin(w http.ResponseWriter, r *http.Request) {
	// Check for override status codes registered by individual tests.
	fk.mu.Lock()
	for prefix, code := range fk.responses {
		if strings.HasPrefix(r.URL.Path, prefix) {
			fk.mu.Unlock()
			w.WriteHeader(code)
			return
		}
	}
	fk.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		fk.handleGet(w, r)
	case http.MethodPost:
		fk.handlePost(w, r)
	case http.MethodPut:
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (fk *fakeKeycloak) handleGet(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case path == "/admin/realms":
		// List realms
		realms := []RealmRepresentation{
			{ID: "master", Realm: "master", DisplayName: "Master", Enabled: true},
		}
		respond(w, http.StatusOK, realms)

	case isRealmRoot(path):
		// GET /admin/realms/{realm}
		realm := realmFromPath(path)
		respond(w, http.StatusOK, RealmRepresentation{
			ID: realm, Realm: realm, DisplayName: realm, Enabled: true,
		})

	case strings.Contains(path, "/users/") && strings.HasSuffix(path, "/sessions"):
		respond(w, http.StatusOK, []SessionRepresentation{
			{ID: "sess-1", Username: "alice", UserID: "uid-1", IPAddress: "127.0.0.1"},
		})

	case strings.Contains(path, "/users/") && strings.HasSuffix(path, "/role-mappings/realm"):
		respond(w, http.StatusOK, []RoleRepresentation{
			{ID: "rid-1", Name: "admin", Composite: false},
		})

	case strings.Contains(path, "/users/") && !strings.Contains(path, "/role-mappings") && !strings.Contains(path, "/sessions") && !strings.Contains(path, "/groups"):
		// GET /admin/realms/{realm}/users/{id}
		respond(w, http.StatusOK, UserRepresentation{
			ID: "uid-1", Username: "alice", Email: "alice@example.com", Enabled: true,
		})

	case strings.HasSuffix(path, "/users"):
		// List users
		respond(w, http.StatusOK, []UserRepresentation{
			{ID: "uid-1", Username: "alice", Email: "alice@example.com", Enabled: true},
		})

	case strings.Contains(path, "/roles/"):
		// GET /admin/realms/{realm}/roles/{roleName}
		parts := strings.Split(path, "/roles/")
		roleName := parts[len(parts)-1]
		respond(w, http.StatusOK, RoleRepresentation{
			ID: "rid-" + roleName, Name: roleName, Composite: false,
		})

	case strings.HasSuffix(path, "/groups"):
		respond(w, http.StatusOK, []GroupRepresentation{
			{ID: "gid-1", Name: "developers", Path: "/developers"},
		})

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (fk *fakeKeycloak) handlePost(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case path == "/admin/realms":
		w.Header().Set("Location", fk.server.URL+"/admin/realms/new-realm")
		w.WriteHeader(http.StatusCreated)

	case strings.HasSuffix(path, "/clients"):
		w.Header().Set("Location", fk.server.URL+path+"/client-uuid-123")
		w.WriteHeader(http.StatusCreated)

	case strings.HasSuffix(path, "/users"):
		w.Header().Set("Location", fk.server.URL+path+"/user-uuid-456")
		w.WriteHeader(http.StatusCreated)

	case strings.HasSuffix(path, "/roles"):
		w.WriteHeader(http.StatusCreated)

	case strings.HasSuffix(path, "/role-mappings/realm"):
		w.WriteHeader(http.StatusNoContent)

	case strings.HasSuffix(path, "/groups"):
		w.Header().Set("Location", fk.server.URL+path+"/group-uuid-789")
		w.WriteHeader(http.StatusCreated)

	case strings.Contains(path, "/protocol-mappers/models"):
		w.WriteHeader(http.StatusCreated)

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// setOverride registers a fixed status code response for all requests whose
// path starts with the given prefix. Pass 0 to remove an override.
func (fk *fakeKeycloak) setOverride(prefix string, code int) {
	fk.mu.Lock()
	defer fk.mu.Unlock()
	if code == 0 {
		delete(fk.responses, prefix)
	} else {
		fk.responses[prefix] = code
	}
}

// respond writes a JSON-encoded body with the given status code.
func respond(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// isRealmRoot returns true for /admin/realms/{realm} (one path segment after /realms/).
func isRealmRoot(path string) bool {
	trimmed := strings.TrimPrefix(path, "/admin/realms/")
	return trimmed != "" && !strings.Contains(trimmed, "/")
}

// realmFromPath extracts the realm name from /admin/realms/{realm}/...
func realmFromPath(path string) string {
	trimmed := strings.TrimPrefix(path, "/admin/realms/")
	parts := strings.SplitN(trimmed, "/", 2)
	return parts[0]
}

// newTestClient constructs a Client wired to the provided fake server.
func newTestClient(fk *fakeKeycloak) *Client {
	return NewClient(fk.server.URL, "master", "admin-cli", "secret",
		slog.Default())
}

// -------------------------------------------------------------------------
// Token cache tests
// -------------------------------------------------------------------------

func TestGetToken_CachesToken(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)
	ctx := context.Background()

	tok1, err := c.getToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, "test-token", tok1)

	tok2, err := c.getToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, tok1, tok2)

	// Only one token endpoint call should have been made.
	fk.mu.Lock()
	calls := fk.tokenCalls
	fk.mu.Unlock()
	assert.Equal(t, 1, calls, "token should be served from cache on second call")
}

func TestGetToken_RefreshesExpiredToken(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)
	ctx := context.Background()

	// Prime the cache with an already-expired entry.
	c.token.mu.Lock()
	c.token.token = "old-token"
	c.token.expiresAt = time.Now().Add(-1 * time.Second)
	c.token.mu.Unlock()

	tok, err := c.getToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, "test-token", tok)

	fk.mu.Lock()
	calls := fk.tokenCalls
	fk.mu.Unlock()
	assert.Equal(t, 1, calls)
}

func TestGetToken_ConcurrentRefresh(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)
	ctx := context.Background()

	// Force all goroutines to see an empty cache so they all race to refresh.
	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			tok, err := c.getToken(ctx)
			assert.NoError(t, err)
			assert.Equal(t, "test-token", tok)
		}()
	}

	wg.Wait()

	// The mutex ensures only one actual refresh call reaches the token endpoint.
	fk.mu.Lock()
	calls := fk.tokenCalls
	fk.mu.Unlock()
	assert.Equal(t, 1, calls, "concurrent callers should coalesce into one token fetch")
}

func TestDoRequest_Retries401(t *testing.T) {
	var callCount int32

	// Build a server that returns 401 on the first admin call, then 200.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/master/protocol/openid-connect/token":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(tokenResponse{
				AccessToken: "fresh-token",
				ExpiresIn:   300,
			})
		case "/admin/realms":
			n := atomic.AddInt32(&callCount, 1)
			if n == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]RealmRepresentation{})
		}
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "master", "admin-cli", "secret", slog.Default())

	realms, err := c.ListRealms(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, realms)
	assert.Equal(t, int32(2), atomic.LoadInt32(&callCount),
		"admin endpoint should be called twice: once for 401, once for retry")
}

// -------------------------------------------------------------------------
// Health tests
// -------------------------------------------------------------------------

func TestHealth_OK(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)
	assert.NoError(t, c.Health(context.Background()))
}

func TestHealth_Unavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "master", "admin-cli", "secret", slog.Default())
	err := c.Health(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "503")
}

// -------------------------------------------------------------------------
// Realm tests
// -------------------------------------------------------------------------

func TestCreateRealm_Success(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	err := c.CreateRealm(context.Background(), RealmConfig{
		Name:        "acme",
		DisplayName: "ACME Corp",
		Enabled:     true,
	})
	require.NoError(t, err)
}

func TestCreateRealm_AlreadyExists(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	fk.setOverride("/admin/realms", http.StatusConflict)

	// 409 must be treated as success.
	err := c.CreateRealm(context.Background(), RealmConfig{Name: "acme", Enabled: true})
	require.NoError(t, err)
}

func TestGetRealm(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	realm, err := c.GetRealm(context.Background(), "acme")
	require.NoError(t, err)
	require.NotNil(t, realm)
	assert.Equal(t, "acme", realm.Realm)
}

func TestDeleteRealm(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	err := c.DeleteRealm(context.Background(), "acme")
	require.NoError(t, err)
}

func TestListRealms(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	realms, err := c.ListRealms(context.Background())
	require.NoError(t, err)
	require.Len(t, realms, 1)
	assert.Equal(t, "master", realms[0].Realm)
}

// -------------------------------------------------------------------------
// OIDC client tests
// -------------------------------------------------------------------------

func TestCreateOIDCClient_Success(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	uuid, err := c.CreateOIDCClient(context.Background(), "acme", OIDCClientConfig{
		ClientID:     "my-app",
		Secret:       "super-secret",
		RedirectURIs: []string{"https://app.example.com/callback"},
		WebOrigins:   []string{"https://app.example.com"},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, uuid)
}

func TestCreateOIDCClient_AlreadyExists(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	fk.setOverride("/admin/realms/acme/clients", http.StatusConflict)

	uuid, err := c.CreateOIDCClient(context.Background(), "acme", OIDCClientConfig{
		ClientID: "my-app",
	})
	require.NoError(t, err)
	assert.Empty(t, uuid)
}

// -------------------------------------------------------------------------
// User tests
// -------------------------------------------------------------------------

func TestCreateUser_Success(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	id, err := c.CreateUser(context.Background(), "acme", UserConfig{
		Username:      "alice",
		Email:         "alice@example.com",
		Enabled:       true,
		EmailVerified: true,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, id)
}

func TestCreateUser_WithPassword(t *testing.T) {
	var body map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/master/protocol/openid-connect/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "tok", ExpiresIn: 300})
		case "/admin/realms/acme/users":
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.Header().Set("Location", r.URL.String()+"/uid-789")
			w.WriteHeader(http.StatusCreated)
		}
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "master", "admin-cli", "secret", slog.Default())

	_, err := c.CreateUser(context.Background(), "acme", UserConfig{
		Username:          "bob",
		Email:             "bob@example.com",
		Enabled:           true,
		Password:          "pass123",
		TemporaryPassword: true,
	})
	require.NoError(t, err)

	// Verify credentials were included in the request.
	creds, ok := body["credentials"].([]interface{})
	require.True(t, ok, "credentials must be present in request body")
	require.Len(t, creds, 1)
	cred := creds[0].(map[string]interface{})
	assert.Equal(t, "password", cred["type"])
	assert.Equal(t, "pass123", cred["value"])
	assert.Equal(t, true, cred["temporary"])
}

func TestCreateUser_AlreadyExists(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	fk.setOverride("/admin/realms/acme/users", http.StatusConflict)

	id, err := c.CreateUser(context.Background(), "acme", UserConfig{Username: "alice"})
	require.NoError(t, err)
	assert.Empty(t, id)
}

func TestGetUser(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	user, err := c.GetUser(context.Background(), "acme", "uid-1")
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "alice", user.Username)
}

func TestListUsers(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	users, err := c.ListUsers(context.Background(), "acme", ListUsersOpts{Max: 50})
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Equal(t, "alice", users[0].Username)
}

func TestListUsers_DefaultMax(t *testing.T) {
	var capturedQuery string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/master/protocol/openid-connect/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "tok", ExpiresIn: 300})
		case "/admin/realms/acme/users":
			capturedQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]UserRepresentation{})
		}
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "master", "admin-cli", "secret", slog.Default())
	_, err := c.ListUsers(context.Background(), "acme", ListUsersOpts{})
	require.NoError(t, err)
	assert.Contains(t, capturedQuery, "max=100", "default max must be 100")
}

func TestUpdateUser(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	err := c.UpdateUser(context.Background(), "acme", "uid-1", map[string]interface{}{
		"firstName": "Alice",
		"lastName":  "Smith",
	})
	require.NoError(t, err)
}

func TestDeleteUser(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	err := c.DeleteUser(context.Background(), "acme", "uid-1")
	require.NoError(t, err)
}

func TestGetUserSessions(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	sessions, err := c.GetUserSessions(context.Background(), "acme", "uid-1")
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, "alice", sessions[0].Username)
}

// -------------------------------------------------------------------------
// Role tests
// -------------------------------------------------------------------------

func TestCreateRealmRole_Success(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	err := c.CreateRealmRole(context.Background(), "acme", "security-analyst", "Read security findings")
	require.NoError(t, err)
}

func TestCreateRealmRole_AlreadyExists(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	fk.setOverride("/admin/realms/acme/roles", http.StatusConflict)

	err := c.CreateRealmRole(context.Background(), "acme", "security-analyst", "")
	require.NoError(t, err)
}

func TestAssignRealmRoles(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	err := c.AssignRealmRoles(context.Background(), "acme", "uid-1", []string{"admin", "viewer"})
	require.NoError(t, err)
}

func TestAssignRealmRoles_Empty(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	// Should be a no-op without making any HTTP calls.
	err := c.AssignRealmRoles(context.Background(), "acme", "uid-1", nil)
	require.NoError(t, err)
}

func TestGetUserRealmRoles(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	roles, err := c.GetUserRealmRoles(context.Background(), "acme", "uid-1")
	require.NoError(t, err)
	require.Len(t, roles, 1)
	assert.Equal(t, "admin", roles[0].Name)
}

// -------------------------------------------------------------------------
// Group tests
// -------------------------------------------------------------------------

func TestCreateGroup_Success(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	id, err := c.CreateGroup(context.Background(), "acme", "developers", map[string][]string{
		"department": {"engineering"},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, id)
}

func TestCreateGroup_AlreadyExists(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	fk.setOverride("/admin/realms/acme/groups", http.StatusConflict)

	id, err := c.CreateGroup(context.Background(), "acme", "developers", nil)
	require.NoError(t, err)
	assert.Empty(t, id)
}

func TestAddUserToGroup(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	err := c.AddUserToGroup(context.Background(), "acme", "uid-1", "gid-1")
	require.NoError(t, err)
}

func TestListGroups(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	groups, err := c.ListGroups(context.Background(), "acme")
	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Equal(t, "developers", groups[0].Name)
}

// -------------------------------------------------------------------------
// Protocol mapper tests
// -------------------------------------------------------------------------

func TestAddProtocolMapper_Success(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	err := c.AddProtocolMapper(context.Background(), "acme", "client-uuid-123", ProtocolMapperConfig{
		Name:           "tenant-id",
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-hardcoded-claim-mapper",
		Config: map[string]string{
			"claim.name":  "tenant_id",
			"claim.value": "acme",
		},
	})
	require.NoError(t, err)
}

func TestAddProtocolMapper_AlreadyExists(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	fk.setOverride("/admin/realms/acme/clients/client-uuid-123/protocol-mappers/models", http.StatusConflict)

	err := c.AddProtocolMapper(context.Background(), "acme", "client-uuid-123", ProtocolMapperConfig{
		Name:           "tenant-id",
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-hardcoded-claim-mapper",
	})
	require.NoError(t, err)
}

// -------------------------------------------------------------------------
// Error propagation tests
// -------------------------------------------------------------------------

func TestCreateRealm_ServerError(t *testing.T) {
	fk := newFakeKeycloak(t)
	c := newTestClient(fk)

	fk.setOverride("/admin/realms", http.StatusInternalServerError)

	err := c.CreateRealm(context.Background(), RealmConfig{Name: "broken"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestGetRealm_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/master/protocol/openid-connect/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "tok", ExpiresIn: 300})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "master", "admin-cli", "secret", slog.Default())

	_, err := c.GetRealm(context.Background(), "ghost")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestContextCancellation(t *testing.T) {
	// Server that blocks for longer than the test context allows.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "tok", ExpiresIn: 300})
			return
		}
		// Simulate a very slow response.
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	c := NewClient(srv.URL, "master", "admin-cli", "secret", slog.Default())

	_, err := c.ListRealms(ctx)
	require.Error(t, err)
}

// -------------------------------------------------------------------------
// locationID helper tests
// -------------------------------------------------------------------------

func TestLocationID(t *testing.T) {
	tests := []struct {
		name     string
		location string
		want     string
	}{
		{
			name:     "standard keycloak location",
			location: "http://keycloak:8080/admin/realms/acme/users/abc-123-def",
			want:     "abc-123-def",
		},
		{
			name:     "trailing slash",
			location: "http://keycloak:8080/admin/realms/acme/users/abc-123-def/",
			want:     "abc-123-def",
		},
		{
			name:     "empty location",
			location: "",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: make(http.Header)}
			if tt.location != "" {
				resp.Header.Set("Location", tt.location)
			}
			got := locationID(resp)
			assert.Equal(t, tt.want, got)
		})
	}
}

// -------------------------------------------------------------------------
// NewClient defaults test
// -------------------------------------------------------------------------

func TestNewClient_NilLogger(t *testing.T) {
	// Must not panic when nil logger is provided.
	c := NewClient("http://localhost:8080", "master", "id", "secret", nil)
	require.NotNil(t, c)
	require.NotNil(t, c.logger)
}

func TestNewClient_StripsTrailingSlash(t *testing.T) {
	c := NewClient("http://localhost:8080/", "master", "id", "secret", slog.Default())
	assert.Equal(t, "http://localhost:8080", c.baseURL)
}

// -------------------------------------------------------------------------
// Token 80% expiry TTL test
// -------------------------------------------------------------------------

func TestTokenTTL_EightyPercent(t *testing.T) {
	const expiresIn = 100 // seconds

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "tok",
			ExpiresIn:   expiresIn,
		})
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "master", "id", "secret", slog.Default())

	before := time.Now()
	_, err := c.getToken(context.Background())
	require.NoError(t, err)

	c.token.mu.RLock()
	expiresAt := c.token.expiresAt
	c.token.mu.RUnlock()

	// The cache TTL must be approximately 80 seconds (80% of 100).
	effectiveTTL := expiresAt.Sub(before)
	expectedTTL := time.Duration(float64(expiresIn)*0.8) * time.Second

	// Allow ±2s for test execution time.
	assert.InDelta(t, expectedTTL.Seconds(), effectiveTTL.Seconds(), 2,
		fmt.Sprintf("expected TTL ~%v, got %v", expectedTTL, effectiveTTL))
}
