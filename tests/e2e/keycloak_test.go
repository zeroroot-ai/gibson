//go:build e2e
// +build e2e

package e2e

// keycloak_test.go contains end-to-end integration tests for the Keycloak Admin
// REST API client and the provisioner's create_realm step.
//
// These tests spin up a real Keycloak 26 container via testcontainers-go and
// exercise the full client surface: realm lifecycle, user CRUD, role assignment,
// OIDC client creation, protocol mapper addition, idempotency (409 handling),
// and the provisioner pipeline wired to a live Keycloak instance.
//
// Run with:
//
//	go test -tags=e2e -timeout=5m ./tests/e2e/... -run TestKeycloak
//	go test -tags=e2e -timeout=5m ./tests/e2e/... -run TestProvisioner
//
// The Keycloak container typically takes 30-60 seconds to become ready.
// The tests share a single container across all test functions via
// TestMain-style package-level setup so startup cost is paid once.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zero-day-ai/gibson/internal/keycloak"
	"github.com/zero-day-ai/gibson/internal/provisioner"
)

// ---------------------------------------------------------------------------
// Package-level Keycloak container lifecycle
// ---------------------------------------------------------------------------

// keycloakBaseURL is set once by TestMain and shared across all tests in the
// package. Tests skip themselves when the URL is empty.
var keycloakBaseURL string

// newKCClient returns a Keycloak Client configured for the test container.
// It authenticates using the master-realm admin-cli service account with the
// default admin/admin credentials created by KEYCLOAK_ADMIN_PASSWORD.
//
// Keycloak's built-in admin-cli client in the master realm uses a password
// grant, but the Admin REST API can be reached with a Bearer token obtained
// via the direct access grant for admin / admin. Because NewClient uses the
// client_credentials grant and admin-cli is a public client (no secret), we
// create a short-lived token manually and prime the cache, or we rely on the
// admin-cli having client_credentials enabled. In practice for tests we use
// a direct token fetch helper (fetchAdminToken) and inject it via the public
// token cache fields.
//
// A simpler approach: create a dedicated service account client in the master
// realm. For integration tests we use the admin password grant to obtain a
// token and pin it into the client's token cache with a long TTL.
func newKCClient(t *testing.T, baseURL string) *keycloak.Client {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError, // Reduce noise; switch to LevelDebug to troubleshoot.
	}))

	// Obtain a real access token via admin password grant.
	token := fetchAdminToken(t, baseURL)

	// Construct the client and prime its token cache so it does not need a
	// service-account grant. We use the admin-cli clientID with an empty
	// secret. The primed cache means getToken returns immediately without
	// hitting the token endpoint; the 401-retry logic is still exercised
	// whenever the token expires mid-test.
	c := keycloak.NewClient(baseURL, "master", "admin-cli", "", logger)
	c.PrimeTokenCache(token, time.Now().Add(5*time.Minute))

	return c
}

// fetchAdminToken obtains a short-lived access token from Keycloak for the
// admin user using the password grant against admin-cli in the master realm.
func fetchAdminToken(t *testing.T, baseURL string) string {
	t.Helper()

	tokenURL := baseURL + "/realms/master/protocol/openid-connect/token"

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "admin-cli")
	form.Set("username", "admin")
	form.Set("password", "admin")

	resp, err := http.PostForm(tokenURL, form)
	require.NoError(t, err, "fetch admin token: HTTP request failed")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"fetch admin token: expected 200 from token endpoint")

	var tr struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tr),
		"fetch admin token: parse token response")
	require.NotEmpty(t, tr.AccessToken, "fetch admin token: empty access_token")

	return tr.AccessToken
}

// uniqueRealm returns a unique realm name safe for parallel test use.
func uniqueRealm(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// ---------------------------------------------------------------------------
// TestKeycloakClient_Health
// ---------------------------------------------------------------------------

// TestKeycloakClient_Health verifies that the client can reach the health endpoint.
func TestKeycloakClient_Health(t *testing.T) {
	if keycloakBaseURL == "" {
		t.Skip("keycloakBaseURL not initialised; run with TestMain or set KEYCLOAK_URL env var")
	}

	c := newKCClient(t, keycloakBaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, c.Health(ctx), "Health check must succeed against running container")
}

// ---------------------------------------------------------------------------
// TestKeycloakClient_RealmLifecycle
// ---------------------------------------------------------------------------

// TestKeycloakClient_RealmLifecycle exercises Create → Get → List → Delete
// for a realm in a single sequential flow.
func TestKeycloakClient_RealmLifecycle(t *testing.T) {
	if keycloakBaseURL == "" {
		t.Skip("keycloakBaseURL not initialised")
	}

	c := newKCClient(t, keycloakBaseURL)
	ctx := context.Background()
	realm := uniqueRealm("lifecycle")

	// --- Create ---
	err := c.CreateRealm(ctx, keycloak.RealmConfig{
		Name:        realm,
		DisplayName: "Lifecycle Test Realm",
		Enabled:     true,
	})
	require.NoError(t, err, "CreateRealm must succeed")

	// Ensure cleanup even on test failure.
	t.Cleanup(func() {
		_ = c.DeleteRealm(context.Background(), realm)
	})

	// --- Get ---
	rep, err := c.GetRealm(ctx, realm)
	require.NoError(t, err, "GetRealm must succeed")
	require.NotNil(t, rep)
	assert.Equal(t, realm, rep.Realm, "realm name must match")
	assert.Equal(t, "Lifecycle Test Realm", rep.DisplayName)
	assert.True(t, rep.Enabled, "realm must be enabled")

	// --- List ---
	realms, err := c.ListRealms(ctx)
	require.NoError(t, err, "ListRealms must succeed")
	var found bool
	for _, r := range realms {
		if r.Realm == realm {
			found = true
			break
		}
	}
	assert.True(t, found, "created realm must appear in ListRealms result")

	// --- Delete ---
	err = c.DeleteRealm(ctx, realm)
	require.NoError(t, err, "DeleteRealm must succeed")

	// Verify deletion by attempting to get the realm — must return 404.
	_, err = c.GetRealm(ctx, realm)
	require.Error(t, err, "GetRealm after deletion must fail")
	assert.Contains(t, err.Error(), "404", "error must indicate not-found")

	t.Logf("realm lifecycle verified: realm=%s", realm)
}

// ---------------------------------------------------------------------------
// TestKeycloakClient_UserCRUD
// ---------------------------------------------------------------------------

// TestKeycloakClient_UserCRUD exercises Create → Get → List → Update → Delete
// for a user within a freshly created realm.
func TestKeycloakClient_UserCRUD(t *testing.T) {
	if keycloakBaseURL == "" {
		t.Skip("keycloakBaseURL not initialised")
	}

	c := newKCClient(t, keycloakBaseURL)
	ctx := context.Background()
	realm := uniqueRealm("usercrud")

	require.NoError(t, c.CreateRealm(ctx, keycloak.RealmConfig{
		Name: realm, DisplayName: "User CRUD Realm", Enabled: true,
	}))
	t.Cleanup(func() { _ = c.DeleteRealm(context.Background(), realm) })

	// --- Create user ---
	userID, err := c.CreateUser(ctx, realm, keycloak.UserConfig{
		Username:      "alice",
		Email:         "alice@example.com",
		FirstName:     "Alice",
		LastName:      "Smith",
		Enabled:       true,
		EmailVerified: true,
	})
	require.NoError(t, err, "CreateUser must succeed")
	require.NotEmpty(t, userID, "CreateUser must return a user UUID")

	// --- Get user ---
	user, err := c.GetUser(ctx, realm, userID)
	require.NoError(t, err, "GetUser must succeed")
	require.NotNil(t, user)
	assert.Equal(t, "alice", user.Username)
	assert.Equal(t, "alice@example.com", user.Email)
	assert.Equal(t, "Alice", user.FirstName)
	assert.Equal(t, "Smith", user.LastName)
	assert.True(t, user.Enabled)
	assert.True(t, user.EmailVerified)
	assert.Equal(t, userID, user.ID)

	// --- List users ---
	users, err := c.ListUsers(ctx, realm, keycloak.ListUsersOpts{Max: 50})
	require.NoError(t, err, "ListUsers must succeed")
	require.NotEmpty(t, users, "ListUsers must return at least one user")
	var foundUser bool
	for _, u := range users {
		if u.ID == userID {
			foundUser = true
			assert.Equal(t, "alice", u.Username)
			break
		}
	}
	assert.True(t, foundUser, "created user must appear in ListUsers result")

	// --- List users with search filter ---
	searchResults, err := c.ListUsers(ctx, realm, keycloak.ListUsersOpts{
		Search: "alice",
		Max:    10,
	})
	require.NoError(t, err, "ListUsers with Search must succeed")
	require.NotEmpty(t, searchResults, "search must find alice")
	assert.Equal(t, "alice", searchResults[0].Username)

	// --- Update user ---
	err = c.UpdateUser(ctx, realm, userID, map[string]interface{}{
		"firstName": "Alicia",
		"lastName":  "Johnson",
	})
	require.NoError(t, err, "UpdateUser must succeed")

	// Verify update was persisted.
	updated, err := c.GetUser(ctx, realm, userID)
	require.NoError(t, err, "GetUser after update must succeed")
	assert.Equal(t, "Alicia", updated.FirstName, "FirstName update must be persisted")
	assert.Equal(t, "Johnson", updated.LastName, "LastName update must be persisted")

	// --- Delete user ---
	err = c.DeleteUser(ctx, realm, userID)
	require.NoError(t, err, "DeleteUser must succeed")

	// Verify deletion: subsequent ListUsers must not include the deleted user.
	after, err := c.ListUsers(ctx, realm, keycloak.ListUsersOpts{Max: 100})
	require.NoError(t, err)
	for _, u := range after {
		assert.NotEqual(t, userID, u.ID, "deleted user must not appear in ListUsers")
	}

	t.Logf("user CRUD verified: realm=%s, user_id=%s", realm, userID)
}

// ---------------------------------------------------------------------------
// TestKeycloakClient_RoleAssignment
// ---------------------------------------------------------------------------

// TestKeycloakClient_RoleAssignment exercises: Create realm → Create role →
// Create user → Assign role → Get user roles → Verify role is present.
func TestKeycloakClient_RoleAssignment(t *testing.T) {
	if keycloakBaseURL == "" {
		t.Skip("keycloakBaseURL not initialised")
	}

	c := newKCClient(t, keycloakBaseURL)
	ctx := context.Background()
	realm := uniqueRealm("roletest")

	require.NoError(t, c.CreateRealm(ctx, keycloak.RealmConfig{
		Name: realm, Enabled: true,
	}))
	t.Cleanup(func() { _ = c.DeleteRealm(context.Background(), realm) })

	// --- Create roles ---
	for _, role := range []string{"security-analyst", "viewer"} {
		err := c.CreateRealmRole(ctx, realm, role, "Test role: "+role)
		require.NoError(t, err, "CreateRealmRole(%q) must succeed", role)
	}

	// --- Create user ---
	userID, err := c.CreateUser(ctx, realm, keycloak.UserConfig{
		Username: "bob",
		Email:    "bob@example.com",
		Enabled:  true,
	})
	require.NoError(t, err, "CreateUser must succeed")
	require.NotEmpty(t, userID)

	// --- Assign roles ---
	err = c.AssignRealmRoles(ctx, realm, userID, []string{"security-analyst", "viewer"})
	require.NoError(t, err, "AssignRealmRoles must succeed")

	// --- Get user roles ---
	roles, err := c.GetUserRealmRoles(ctx, realm, userID)
	require.NoError(t, err, "GetUserRealmRoles must succeed")

	// Build a set of assigned role names for easy membership checks.
	assigned := make(map[string]bool, len(roles))
	for _, r := range roles {
		assigned[r.Name] = true
	}

	assert.True(t, assigned["security-analyst"],
		"security-analyst must be in user's realm roles; got %v", roles)
	assert.True(t, assigned["viewer"],
		"viewer must be in user's realm roles; got %v", roles)

	t.Logf("role assignment verified: realm=%s, user=%s, roles=%v",
		realm, userID, keys(assigned))
}

// ---------------------------------------------------------------------------
// TestKeycloakClient_OIDCClientSetup
// ---------------------------------------------------------------------------

// TestKeycloakClient_OIDCClientSetup exercises realm creation followed by
// OIDC confidential client creation and verifies the client UUID is returned.
func TestKeycloakClient_OIDCClientSetup(t *testing.T) {
	if keycloakBaseURL == "" {
		t.Skip("keycloakBaseURL not initialised")
	}

	c := newKCClient(t, keycloakBaseURL)
	ctx := context.Background()
	realm := uniqueRealm("oidctest")

	require.NoError(t, c.CreateRealm(ctx, keycloak.RealmConfig{
		Name: realm, Enabled: true,
	}))
	t.Cleanup(func() { _ = c.DeleteRealm(context.Background(), realm) })

	// --- Create OIDC client ---
	clientUUID, err := c.CreateOIDCClient(ctx, realm, keycloak.OIDCClientConfig{
		ClientID:     "my-dashboard",
		Secret:       "super-secret-value",
		RedirectURIs: []string{"https://app.example.com/callback"},
		WebOrigins:   []string{"https://app.example.com"},
	})
	require.NoError(t, err, "CreateOIDCClient must succeed")
	require.NotEmpty(t, clientUUID, "CreateOIDCClient must return a UUID")

	// Verify the client exists by fetching the realm clients via the Admin API
	// directly (the client package does not expose a GetClient method, so we
	// probe via the Admin REST API using the same credentials).
	verifyOIDCClientExists(t, c, keycloakBaseURL, realm, "my-dashboard")

	t.Logf("OIDC client setup verified: realm=%s, client_id=my-dashboard, uuid=%s",
		realm, clientUUID)
}

// verifyOIDCClientExists calls GET /admin/realms/{realm}/clients?clientId={id}
// and asserts that exactly one result is returned with the expected clientId.
func verifyOIDCClientExists(t *testing.T, c *keycloak.Client, baseURL, realm, clientID string) {
	t.Helper()

	// Use the client's own HTTP mechanism by checking the health endpoint to
	// confirm connectivity, then call the Admin API directly with a fresh token.
	token := fetchAdminToken(t, baseURL)

	reqURL := fmt.Sprintf("%s/admin/realms/%s/clients?clientId=%s",
		baseURL, url.PathEscape(realm), url.QueryEscape(clientID))

	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, reqURL, nil)
	require.NoError(t, err)
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	require.NoError(t, err, "GET clients must succeed")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "GET clients must return 200")

	var clients []struct {
		ClientID string `json:"clientId"`
		ID       string `json:"id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&clients))
	require.NotEmpty(t, clients, "client list must not be empty for clientId=%s", clientID)
	assert.Equal(t, clientID, clients[0].ClientID, "returned clientId must match")
	// Suppress unused variable warning; c is passed for potential future use.
	_ = c
}

// ---------------------------------------------------------------------------
// TestKeycloakClient_ProtocolMapper
// ---------------------------------------------------------------------------

// TestKeycloakClient_ProtocolMapper exercises creating a realm, an OIDC client,
// and adding a hardcoded-claim protocol mapper to that client.
func TestKeycloakClient_ProtocolMapper(t *testing.T) {
	if keycloakBaseURL == "" {
		t.Skip("keycloakBaseURL not initialised")
	}

	c := newKCClient(t, keycloakBaseURL)
	ctx := context.Background()
	realm := uniqueRealm("mappertest")

	require.NoError(t, c.CreateRealm(ctx, keycloak.RealmConfig{
		Name: realm, Enabled: true,
	}))
	t.Cleanup(func() { _ = c.DeleteRealm(context.Background(), realm) })

	// Create the OIDC client first.
	clientUUID, err := c.CreateOIDCClient(ctx, realm, keycloak.OIDCClientConfig{
		ClientID:     "mapper-client",
		RedirectURIs: []string{"*"},
	})
	require.NoError(t, err, "CreateOIDCClient must succeed")
	require.NotEmpty(t, clientUUID, "client UUID must not be empty")

	// --- Add protocol mapper ---
	err = c.AddProtocolMapper(ctx, realm, clientUUID, keycloak.ProtocolMapperConfig{
		Name:           "tenant-id-claim",
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-hardcoded-claim-mapper",
		Config: map[string]string{
			"claim.name":           "tenant_id",
			"claim.value":          realm,
			"jsonType.label":       "String",
			"id.token.claim":       "true",
			"access.token.claim":   "true",
			"userinfo.token.claim": "true",
		},
	})
	require.NoError(t, err, "AddProtocolMapper must succeed")

	// Verify the mapper was persisted by fetching it from the Admin API.
	verifyProtocolMapperExists(t, keycloakBaseURL, realm, clientUUID, "tenant-id-claim")

	t.Logf("protocol mapper verified: realm=%s, client=%s, mapper=tenant-id-claim", realm, clientUUID)
}

// verifyProtocolMapperExists calls
// GET /admin/realms/{realm}/clients/{uuid}/protocol-mappers/models
// and asserts that a mapper with the given name is present.
func verifyProtocolMapperExists(t *testing.T, baseURL, realm, clientUUID, mapperName string) {
	t.Helper()

	token := fetchAdminToken(t, baseURL)

	reqURL := fmt.Sprintf("%s/admin/realms/%s/clients/%s/protocol-mappers/models",
		baseURL, url.PathEscape(realm), url.PathEscape(clientUUID))

	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, reqURL, nil)
	require.NoError(t, err)
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	require.NoError(t, err, "GET protocol-mappers must succeed")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "GET protocol-mappers must return 200")

	var mappers []struct {
		Name string `json:"name"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&mappers))

	var found bool
	for _, m := range mappers {
		if m.Name == mapperName {
			found = true
			break
		}
	}
	assert.True(t, found, "mapper %q must be present; got %v", mapperName, mappers)
}

// ---------------------------------------------------------------------------
// TestKeycloakClient_Idempotency
// ---------------------------------------------------------------------------

// TestKeycloakClient_Idempotency verifies that creating the same realm, user,
// and role twice produces no error — 409 Conflict must be treated as success.
func TestKeycloakClient_Idempotency(t *testing.T) {
	if keycloakBaseURL == "" {
		t.Skip("keycloakBaseURL not initialised")
	}

	c := newKCClient(t, keycloakBaseURL)
	ctx := context.Background()
	realm := uniqueRealm("idempotent")

	// --- Realm idempotency ---
	cfg := keycloak.RealmConfig{
		Name: realm, DisplayName: "Idempotency Test", Enabled: true,
	}
	require.NoError(t, c.CreateRealm(ctx, cfg), "first CreateRealm must succeed")
	t.Cleanup(func() { _ = c.DeleteRealm(context.Background(), realm) })

	require.NoError(t, c.CreateRealm(ctx, cfg),
		"second CreateRealm (409) must be treated as success")

	// --- Role idempotency ---
	require.NoError(t, c.CreateRealmRole(ctx, realm, "analyst", "Analyst role"),
		"first CreateRealmRole must succeed")
	require.NoError(t, c.CreateRealmRole(ctx, realm, "analyst", "Analyst role"),
		"second CreateRealmRole (409) must be treated as success")

	// --- User idempotency ---
	userCfg := keycloak.UserConfig{
		Username: "idempotent-user",
		Email:    "idempotent@example.com",
		Enabled:  true,
	}
	id1, err := c.CreateUser(ctx, realm, userCfg)
	require.NoError(t, err, "first CreateUser must succeed")
	require.NotEmpty(t, id1, "first CreateUser must return a UUID")

	id2, err := c.CreateUser(ctx, realm, userCfg)
	require.NoError(t, err, "second CreateUser (409) must be treated as success")
	assert.Empty(t, id2,
		"second CreateUser on conflict must return empty UUID (no new resource)")

	// --- OIDC client idempotency ---
	oidcCfg := keycloak.OIDCClientConfig{
		ClientID:     "idempotent-client",
		RedirectURIs: []string{"*"},
	}
	cid1, err := c.CreateOIDCClient(ctx, realm, oidcCfg)
	require.NoError(t, err, "first CreateOIDCClient must succeed")
	require.NotEmpty(t, cid1)

	cid2, err := c.CreateOIDCClient(ctx, realm, oidcCfg)
	require.NoError(t, err, "second CreateOIDCClient (409) must be treated as success")
	assert.Empty(t, cid2,
		"second CreateOIDCClient on conflict must return empty UUID")

	// --- Protocol mapper idempotency ---
	mapperCfg := keycloak.ProtocolMapperConfig{
		Name:           "idempotent-mapper",
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-hardcoded-claim-mapper",
		Config: map[string]string{
			"claim.name":  "env",
			"claim.value": "test",
		},
	}
	require.NoError(t, c.AddProtocolMapper(ctx, realm, cid1, mapperCfg),
		"first AddProtocolMapper must succeed")
	require.NoError(t, c.AddProtocolMapper(ctx, realm, cid1, mapperCfg),
		"second AddProtocolMapper (409) must be treated as success")

	t.Logf("idempotency verified: realm=%s", realm)
}

// ---------------------------------------------------------------------------
// TestKeycloakClient_GroupOperations
// ---------------------------------------------------------------------------

// TestKeycloakClient_GroupOperations exercises group creation, listing, and
// adding a user to a group.
func TestKeycloakClient_GroupOperations(t *testing.T) {
	if keycloakBaseURL == "" {
		t.Skip("keycloakBaseURL not initialised")
	}

	c := newKCClient(t, keycloakBaseURL)
	ctx := context.Background()
	realm := uniqueRealm("grouptest")

	require.NoError(t, c.CreateRealm(ctx, keycloak.RealmConfig{
		Name: realm, Enabled: true,
	}))
	t.Cleanup(func() { _ = c.DeleteRealm(context.Background(), realm) })

	// --- Create group ---
	groupID, err := c.CreateGroup(ctx, realm, "security-ops", map[string][]string{
		"department": {"security"},
		"clearance":  {"level-2"},
	})
	require.NoError(t, err, "CreateGroup must succeed")
	require.NotEmpty(t, groupID, "CreateGroup must return a UUID")

	// --- List groups ---
	groups, err := c.ListGroups(ctx, realm)
	require.NoError(t, err, "ListGroups must succeed")
	var foundGroup bool
	for _, g := range groups {
		if g.Name == "security-ops" {
			foundGroup = true
			assert.NotEmpty(t, g.ID)
			break
		}
	}
	assert.True(t, foundGroup, "created group must appear in ListGroups")

	// --- Create user and add to group ---
	userID, err := c.CreateUser(ctx, realm, keycloak.UserConfig{
		Username: "charlie",
		Email:    "charlie@example.com",
		Enabled:  true,
	})
	require.NoError(t, err, "CreateUser must succeed")
	require.NotEmpty(t, userID)

	err = c.AddUserToGroup(ctx, realm, userID, groupID)
	require.NoError(t, err, "AddUserToGroup must succeed")

	// --- Group idempotency ---
	gid2, err := c.CreateGroup(ctx, realm, "security-ops", nil)
	require.NoError(t, err, "second CreateGroup (409) must be treated as success")
	assert.Empty(t, gid2, "second CreateGroup on conflict must return empty UUID")

	t.Logf("group operations verified: realm=%s, group=%s, user=%s", realm, groupID, userID)
}

// ---------------------------------------------------------------------------
// TestKeycloakClient_TokenRefresh
// ---------------------------------------------------------------------------

// TestKeycloakClient_TokenRefresh verifies that the 401-retry mechanism works
// by expiring the cached token mid-test and confirming the next operation
// succeeds after re-authentication.
func TestKeycloakClient_TokenRefresh(t *testing.T) {
	if keycloakBaseURL == "" {
		t.Skip("keycloakBaseURL not initialised")
	}

	c := newKCClient(t, keycloakBaseURL)
	ctx := context.Background()

	// Confirm baseline operation works.
	_, err := c.ListRealms(ctx)
	require.NoError(t, err, "initial ListRealms must succeed")

	// Expire the cached token so the next request triggers a 401 and forces
	// a token refresh. We do this by priming the cache with an expired bogus
	// token. The client's 401-retry logic will then fetch a fresh token.
	c.PrimeTokenCache("expired-token-value", time.Now().Add(-1*time.Second))

	// The next call must still succeed because the 401 triggers one refresh
	// attempt with real credentials.
	realms, err := c.ListRealms(ctx)
	require.NoError(t, err, "ListRealms after token expiry must succeed via 401-retry")
	require.NotNil(t, realms, "realms must not be nil after token refresh")

	t.Logf("token refresh verified: %d realms visible after refresh", len(realms))
}

// ---------------------------------------------------------------------------
// TestProvisionerWithKeycloak
// ---------------------------------------------------------------------------

// TestProvisionerWithKeycloak exercises the full provisioner pipeline with a
// live Keycloak instance. It verifies that the create_realm step successfully
// creates the realm, OIDC client, roles, protocol mapper, and owner user.
func TestProvisionerWithKeycloak(t *testing.T) {
	if keycloakBaseURL == "" {
		t.Skip("keycloakBaseURL not initialised")
	}

	ctx := context.Background()

	// Wire up miniredis for the provisioner's Redis dependency.
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	// Construct the Keycloak client wired to the test container.
	kc := newKCClient(t, keycloakBaseURL)

	tenantID := uniqueRealm("prov")
	t.Cleanup(func() {
		// Best-effort realm cleanup after test.
		_ = kc.DeleteRealm(context.Background(), tenantID)
	})

	// Construct the provisioner with the Keycloak client and minimal stubs for
	// the other dependencies.
	apiKeys := &stubProvisionAPIKeys{rawKey: "gsk_keycloak-e2e_deadbeef"}
	prov := provisioner.New(redisClient, &provisionerTenantAdapter{}, apiKeys, nil, logger).
		WithKeycloak(kc)

	req := provisioner.ProvisionRequest{
		TenantID:    tenantID,
		DisplayName: "Keycloak E2E Tenant",
		Tier:        "team",
		OwnerEmail:  "owner@e2e.example.com",
	}

	// --- Run provisioner ---
	adminCtx := adminCtxFor(tenantID)
	result, err := prov.ProvisionTenant(adminCtx, req)
	require.NoError(t, err, "ProvisionTenant with Keycloak must succeed")
	require.NotNil(t, result)
	assert.Equal(t, "completed", result.Status,
		"provisioning must complete; got status %q", result.Status)

	// --- Verify realm was created in Keycloak ---
	realm, err := kc.GetRealm(ctx, tenantID)
	require.NoError(t, err, "realm must exist in Keycloak after provisioning")
	assert.Equal(t, tenantID, realm.Realm)
	assert.True(t, realm.Enabled, "provisioned realm must be enabled")

	// --- Verify OIDC client exists ---
	verifyOIDCClientExists(t, kc, keycloakBaseURL, tenantID, "gibson-dashboard")

	// --- Verify standard roles exist ---
	for _, roleName := range []string{"owner", "admin", "operator", "viewer"} {
		verifyRealmRoleExists(t, keycloakBaseURL, tenantID, roleName)
	}

	// --- Verify owner user was created and has the owner role ---
	ownerUsers, err := kc.ListUsers(ctx, tenantID, keycloak.ListUsersOpts{
		Email: "owner@e2e.example.com",
		Max:   10,
	})
	require.NoError(t, err, "ListUsers for owner email must succeed")
	require.NotEmpty(t, ownerUsers, "owner user must exist in the provisioned realm")

	ownerUser := ownerUsers[0]
	assert.Equal(t, "owner@e2e.example.com", ownerUser.Email)
	assert.True(t, ownerUser.Enabled, "owner user must be enabled")
	assert.True(t, ownerUser.EmailVerified, "owner user email must be verified")

	ownerRoles, err := kc.GetUserRealmRoles(ctx, tenantID, ownerUser.ID)
	require.NoError(t, err, "GetUserRealmRoles for owner must succeed")

	var hasOwnerRole bool
	for _, r := range ownerRoles {
		if r.Name == "owner" {
			hasOwnerRole = true
			break
		}
	}
	assert.True(t, hasOwnerRole,
		"owner user must have the 'owner' realm role; got roles: %v", ownerRoles)

	// --- Verify provisioner idempotency: second run must complete cleanly ---
	result2, err := prov.ProvisionTenant(adminCtx, req)
	require.NoError(t, err, "second ProvisionTenant (idempotent re-run) must succeed")
	require.NotNil(t, result2)
	assert.Equal(t, "completed", result2.Status, "idempotent re-run must still report completed")

	t.Logf("provisioner with Keycloak verified: tenant=%s, status=%s, owner_roles=%v",
		tenantID, result.Status, ownerRoles)
}

// verifyRealmRoleExists calls GET /admin/realms/{realm}/roles/{role} and
// asserts HTTP 200 is returned, confirming the role was created.
func verifyRealmRoleExists(t *testing.T, baseURL, realm, roleName string) {
	t.Helper()

	token := fetchAdminToken(t, baseURL)

	reqURL := fmt.Sprintf("%s/admin/realms/%s/roles/%s",
		baseURL, url.PathEscape(realm), url.PathEscape(roleName))

	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, reqURL, nil)
	require.NoError(t, err)
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	require.NoError(t, err, "GET role %q must succeed", roleName)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"role %q must exist in realm %q (expected 200)", roleName, realm)
}

// ---------------------------------------------------------------------------
// TestKeycloakClient_AssignRealmRoles_Empty
// ---------------------------------------------------------------------------

// TestKeycloakClient_AssignRealmRoles_Empty verifies the nil/empty role list
// fast-path: AssignRealmRoles with zero role names must be a no-op.
func TestKeycloakClient_AssignRealmRoles_Empty(t *testing.T) {
	if keycloakBaseURL == "" {
		t.Skip("keycloakBaseURL not initialised")
	}

	c := newKCClient(t, keycloakBaseURL)
	ctx := context.Background()
	realm := uniqueRealm("emptyroles")

	require.NoError(t, c.CreateRealm(ctx, keycloak.RealmConfig{
		Name: realm, Enabled: true,
	}))
	t.Cleanup(func() { _ = c.DeleteRealm(context.Background(), realm) })

	userID, err := c.CreateUser(ctx, realm, keycloak.UserConfig{
		Username: "noroles",
		Email:    "noroles@example.com",
		Enabled:  true,
	})
	require.NoError(t, err)

	// Empty assignment must succeed without making any HTTP calls.
	require.NoError(t, c.AssignRealmRoles(ctx, realm, userID, nil),
		"empty AssignRealmRoles must be a no-op")
	require.NoError(t, c.AssignRealmRoles(ctx, realm, userID, []string{}),
		"empty slice AssignRealmRoles must be a no-op")

	t.Logf("empty role assignment verified: realm=%s", realm)
}

// ---------------------------------------------------------------------------
// Helper: provisionerTenantAdapter
//
// A minimal provisioner.TenantCreator that stores tenant state in a local map.
// Used for TestProvisionerWithKeycloak to avoid a dependency on miniredis-backed
// TenantService, keeping the test focused on the Keycloak integration.
// ---------------------------------------------------------------------------

type provisionerTenantAdapter struct {
	tenants map[string]map[string]string
}

func (a *provisionerTenantAdapter) CreateTenant(_ context.Context, tenantID, displayName string, config map[string]string) (interface{}, error) {
	if a.tenants == nil {
		a.tenants = make(map[string]map[string]string)
	}
	if _, exists := a.tenants[tenantID]; exists {
		return a.tenants[tenantID], nil // idempotent
	}
	record := make(map[string]string, len(config)+2)
	for k, v := range config {
		record[k] = v
	}
	record["tenant_id"] = tenantID
	record["display_name"] = displayName
	record["status"] = "provisioning"
	a.tenants[tenantID] = record
	return record, nil
}

func (a *provisionerTenantAdapter) GetTenant(_ context.Context, tenantID string) (interface{}, error) {
	if a.tenants == nil || a.tenants[tenantID] == nil {
		return nil, fmt.Errorf("tenant %q not found", tenantID)
	}
	return a.tenants[tenantID], nil
}

func (a *provisionerTenantAdapter) UpdateTenant(_ context.Context, tenantID string, updates map[string]string) (interface{}, error) {
	if a.tenants == nil || a.tenants[tenantID] == nil {
		return nil, fmt.Errorf("tenant %q not found", tenantID)
	}
	for k, v := range updates {
		a.tenants[tenantID][k] = v
	}
	return a.tenants[tenantID], nil
}

// ---------------------------------------------------------------------------
// Container lifecycle: TestMain
// ---------------------------------------------------------------------------

// TestMain starts the shared Keycloak container once for all tests in this
// package, sets keycloakBaseURL, and tears down the container after all tests
// complete. This amortises the 30-60 second startup cost across the whole suite.
//
// Individual tests skip themselves when keycloakBaseURL is empty (e.g. if
// KEYCLOAK_URL is set by CI for an external instance).
func TestMain(m *testing.M) {
	// Allow callers to point at a pre-existing Keycloak instance by setting
	// KEYCLOAK_URL. This is useful in CI environments where Keycloak is already
	// running as a sidecar service.
	if envURL := os.Getenv("KEYCLOAK_URL"); envURL != "" {
		keycloakBaseURL = strings.TrimRight(envURL, "/")
		os.Exit(m.Run())
	}

	// No external Keycloak configured — start the container.
	//
	// TestMain cannot use *testing.T so we use a minimal stand-in for logging
	// and call os.Exit on failure.
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "quay.io/keycloak/keycloak:26.0",
		ExposedPorts: []string{"8080/tcp"},
		Cmd:          []string{"start-dev"},
		Env: map[string]string{
			"KEYCLOAK_ADMIN":          "admin",
			"KEYCLOAK_ADMIN_PASSWORD": "admin",
		},
		WaitingFor: wait.ForHTTP("/health/ready").
			WithPort("8080/tcp").
			WithStartupTimeout(120 * time.Second).
			WithStatusCodeMatcher(func(status int) bool {
				return status == http.StatusOK
			}),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "keycloak_test: TestMain: failed to start container: %v\n", err)
		os.Exit(1)
	}

	host, err := container.Host(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keycloak_test: TestMain: get host: %v\n", err)
		_ = container.Terminate(ctx)
		os.Exit(1)
	}

	port, err := container.MappedPort(ctx, "8080")
	if err != nil {
		fmt.Fprintf(os.Stderr, "keycloak_test: TestMain: get port: %v\n", err)
		_ = container.Terminate(ctx)
		os.Exit(1)
	}

	keycloakBaseURL = fmt.Sprintf("http://%s:%s", host, port.Port())
	fmt.Fprintf(os.Stderr, "keycloak_test: container ready at %s\n", keycloakBaseURL)

	code := m.Run()

	if termErr := container.Terminate(ctx); termErr != nil {
		fmt.Fprintf(os.Stderr, "keycloak_test: container termination error: %v\n", termErr)
	}

	os.Exit(code)
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

// keys returns the keys of a map[string]bool as a slice, for use in log
// messages and assertion failure output.
func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
