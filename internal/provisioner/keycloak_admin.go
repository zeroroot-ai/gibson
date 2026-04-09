// Package provisioner contains the SaaS tenant provisioning pipeline.
//
// This file (keycloak_admin.go) implements the KeycloakAdmin interface defined
// in design.md Component 1. It wraps the internal/keycloak.Client (which owns
// client-credentials token management, HTTP retry on 401, etc.) and adds:
//
//   - Keycloak Organizations API (KC 26.0+): CreateOrganization,
//     GetOrganizationByAlias, DeleteOrganization, AddOrganizationMember,
//     RemoveOrganizationMember, ListOrganizationMembers.
//   - User lifecycle: CreateUser, DeleteUser.
//   - OTel span emitted on every exported method so provisioner traces appear
//     in Jaeger/Langfuse.
//   - Typed sentinel errors (ErrNotFound, ErrConflict, ErrForbidden) so the
//     SignupHandler can distinguish "org already exists" from "server error".
//
// Implementation choice: raw net/http via the existing keycloak.Client
// (instead of a third-party library like gocloak). This avoids adding a new
// dependency for a relatively small surface area, keeps the code transparent,
// and re-uses the battle-tested token-refresh logic already in keycloak.Client.
//
// Keycloak Organizations REST API path prefix (KC 26.0):
//
//	/admin/realms/{realm}/organizations
//
// Reference: https://www.keycloak.org/docs-api/26.0/rest-api/index.html#Organizations
package provisioner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/keycloak"
)

// Sentinel errors returned by KeycloakAdmin implementations.
// The SignupHandler checks for these to decide whether to short-circuit or rollback.
var (
	// ErrNotFound indicates the requested resource does not exist in Keycloak.
	ErrNotFound = errors.New("keycloak: resource not found")

	// ErrConflict indicates the resource already exists (HTTP 409).
	// Callers may treat this as success for idempotent create operations.
	ErrConflict = errors.New("keycloak: resource already exists")

	// ErrForbidden indicates the admin credentials lack the required privilege.
	ErrForbidden = errors.New("keycloak: forbidden — check admin client roles")
)

// OrgRepresentation is the Keycloak Organization object returned by the
// Admin REST API (KC 26.0 Organizations feature).
type OrgRepresentation struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Alias       string            `json:"alias"`
	Description string            `json:"description,omitempty"`
	Enabled     bool              `json:"enabled"`
	Attributes  map[string][]string `json:"attributes,omitempty"`
}

// OrgMemberRepresentation is a Keycloak user entry returned as an org member.
type OrgMemberRepresentation struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// KeycloakAdmin is the interface the provisioner uses to manage Keycloak
// users and Organizations. All methods must be safe for concurrent use.
//
// Implementations must emit an OTel span per call and return typed sentinel
// errors (ErrNotFound / ErrConflict / ErrForbidden) where appropriate.
type KeycloakAdmin interface {
	// CreateUser creates a new user in the managed realm and returns the Keycloak user UUID.
	// Returns ErrConflict if a user with the same username/email already exists.
	CreateUser(ctx context.Context, cfg keycloak.UserConfig) (userID string, err error)

	// DeleteUser permanently deletes a user by UUID from the managed realm.
	// Returns ErrNotFound if the user does not exist (safe to ignore on rollback).
	DeleteUser(ctx context.Context, userID string) error

	// CreateOrganization creates a new Keycloak Organization in the managed realm.
	// Returns the organization UUID and ErrConflict if the alias already exists.
	CreateOrganization(ctx context.Context, name, alias, description string) (orgID string, err error)

	// GetOrganizationByAlias fetches an Organization by its alias (tenant slug).
	// Returns ErrNotFound if no matching organization exists.
	GetOrganizationByAlias(ctx context.Context, alias string) (*OrgRepresentation, error)

	// DeleteOrganization permanently deletes an Organization by UUID.
	// Returns ErrNotFound if the org does not exist (safe to ignore on rollback).
	DeleteOrganization(ctx context.Context, orgID string) error

	// AddOrganizationMember adds an existing Keycloak user to an Organization.
	// Returns ErrNotFound if either the org or user does not exist.
	AddOrganizationMember(ctx context.Context, orgID, userID string) error

	// RemoveOrganizationMember removes a user from an Organization.
	// Returns ErrNotFound if the org or membership does not exist (safe to ignore).
	RemoveOrganizationMember(ctx context.Context, orgID, userID string) error

	// ListOrganizationMembers returns all members of an Organization.
	ListOrganizationMembers(ctx context.Context, orgID string) ([]OrgMemberRepresentation, error)
}

// keycloakAdminClient implements KeycloakAdmin using the internal keycloak.Client.
type keycloakAdminClient struct {
	// client is the underlying HTTP client for the Keycloak Admin REST API.
	// It handles token caching and 401-retry transparently.
	client *keycloak.Client

	// realm is the Keycloak realm managed by this client.
	realm string

	// tracer emits OTel spans for each provisioner operation.
	tracer trace.Tracer

	// logger for debug/error output from this client.
	logger *slog.Logger
}

// NewKeycloakAdminClient constructs a KeycloakAdmin backed by the existing
// keycloak.Client token-management infrastructure.
//
// The adminCfg must have Endpoint and Realm populated, plus at least one auth
// mode (ClientID+ClientSecret or Username+Password). Call
// config.ValidateKeycloakAdminConfig before this function to enforce that
// invariant at daemon startup.
//
// The returned client is safe for concurrent use.
func NewKeycloakAdminClient(adminCfg config.KeycloakAdminConfig, logger *slog.Logger) (KeycloakAdmin, error) {
	if adminCfg.Endpoint == "" {
		return nil, fmt.Errorf("keycloak_admin: Endpoint is required")
	}
	if adminCfg.Realm == "" {
		return nil, fmt.Errorf("keycloak_admin: Realm is required")
	}
	return newKeycloakAdminClientFromKCClient(
		keycloak.NewClient(adminCfg.Endpoint, "master", adminCfg.ClientID, adminCfg.ClientSecret, logger),
		adminCfg.Realm,
		logger,
	), nil
}

// newKeycloakAdminClientFromKCClient is a low-level constructor that accepts an
// already-configured keycloak.Client. It is used by NewKeycloakAdminClient and
// by integration tests that need to prime the token cache before calling any
// Admin API method.
//
// The returned *keycloakAdminClient can be used via the KeycloakAdmin interface
// and also exposes PrimeToken for integration-test token injection.
func newKeycloakAdminClientFromKCClient(kc *keycloak.Client, realm string, logger *slog.Logger) *keycloakAdminClient {
	if logger == nil {
		logger = slog.Default()
	}
	return &keycloakAdminClient{
		client: kc,
		realm:  realm,
		tracer: otel.Tracer("gibson.provisioner.keycloak_admin"),
		logger: logger,
	}
}

// PrimeToken injects a pre-obtained access token into the underlying keycloak.Client
// token cache. This is used by integration tests that obtain a token via the
// admin password grant (which admin-cli in Keycloak's master realm supports) and
// then inject it so the client does not attempt its own client_credentials grant.
//
// Not for production use — call NewKeycloakAdminClient with a real client secret instead.
func (k *keycloakAdminClient) PrimeToken(token string, expiresAt time.Time) {
	k.client.PrimeTokenCache(token, expiresAt)
}

// TokenPrimer is implemented by keycloakAdminClient and is used by integration
// tests to inject a pre-obtained admin token so the client skips client_credentials.
// It is intentionally a narrow interface separate from KeycloakAdmin to keep the
// production interface clean.
type TokenPrimer interface {
	PrimeToken(token string, expiresAt time.Time)
}

// NewKeycloakAdminClientWithToken creates a KeycloakAdmin that uses the supplied
// pre-obtained access token. Intended for integration tests that cannot configure
// a real client_credentials service account on the test Keycloak container.
//
// The returned value satisfies both KeycloakAdmin and TokenPrimer.
//
// Not for production use.
func NewKeycloakAdminClientWithToken(endpoint, realm, token string, logger *slog.Logger) (KeycloakAdmin, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("keycloak_admin: Endpoint is required")
	}
	if realm == "" {
		return nil, fmt.Errorf("keycloak_admin: Realm is required")
	}

	kcClient := keycloak.NewClient(endpoint, "master", "admin-cli", "", logger)

	c := newKeycloakAdminClientFromKCClient(kcClient, realm, logger)
	c.PrimeToken(token, time.Now().Add(5*time.Minute))
	return c, nil
}

// -------------------------------------------------------------------------
// User management
// -------------------------------------------------------------------------

// CreateUser implements KeycloakAdmin.
func (k *keycloakAdminClient) CreateUser(ctx context.Context, cfg keycloak.UserConfig) (string, error) {
	ctx, span := k.tracer.Start(ctx, "keycloak.CreateUser",
		trace.WithAttributes(
			attribute.String("keycloak.realm", k.realm),
			attribute.String("keycloak.user.username", cfg.Username),
			attribute.String("keycloak.user.email", cfg.Email),
		),
	)
	defer span.End()

	path := fmt.Sprintf("/admin/realms/%s/users", url.PathEscape(k.realm))

	body := map[string]any{
		"username":      cfg.Username,
		"email":         cfg.Email,
		"firstName":     cfg.FirstName,
		"lastName":      cfg.LastName,
		"enabled":       cfg.Enabled,
		"emailVerified": cfg.EmailVerified,
	}
	if len(cfg.RequiredActions) > 0 {
		body["requiredActions"] = cfg.RequiredActions
	}
	if len(cfg.Attributes) > 0 {
		body["attributes"] = cfg.Attributes
	}
	if cfg.Password != "" {
		body["credentials"] = []map[string]any{
			{
				"type":      "password",
				"value":     cfg.Password,
				"temporary": cfg.TemporaryPassword,
			},
		}
	}

	resp, err := k.client.DoAdminRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("keycloak.CreateUser: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		span.SetStatus(codes.Error, "conflict")
		return "", fmt.Errorf("keycloak.CreateUser username=%q: %w", cfg.Username, ErrConflict)
	}
	if resp.StatusCode == http.StatusForbidden {
		span.SetStatus(codes.Error, "forbidden")
		return "", ErrForbidden
	}
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("keycloak.CreateUser: unexpected status %d: %s", resp.StatusCode, body)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", err
	}

	userID := locationID(resp)
	span.SetAttributes(attribute.String("keycloak.user.id", userID))
	return userID, nil
}

// DeleteUser implements KeycloakAdmin.
func (k *keycloakAdminClient) DeleteUser(ctx context.Context, userID string) error {
	ctx, span := k.tracer.Start(ctx, "keycloak.DeleteUser",
		trace.WithAttributes(
			attribute.String("keycloak.realm", k.realm),
			attribute.String("keycloak.user.id", userID),
		),
	)
	defer span.End()

	path := fmt.Sprintf("/admin/realms/%s/users/%s", url.PathEscape(k.realm), url.PathEscape(userID))
	resp, err := k.client.DoAdminRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("keycloak.DeleteUser: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("keycloak.DeleteUser userID=%q: %w", userID, ErrNotFound)
	}
	if resp.StatusCode == http.StatusForbidden {
		return ErrForbidden
	}
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("keycloak.DeleteUser: unexpected status %d: %s", resp.StatusCode, body)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// -------------------------------------------------------------------------
// Organization management (Keycloak 26.0+ Organizations API)
// -------------------------------------------------------------------------

// CreateOrganization implements KeycloakAdmin.
func (k *keycloakAdminClient) CreateOrganization(ctx context.Context, name, alias, description string) (string, error) {
	ctx, span := k.tracer.Start(ctx, "keycloak.CreateOrganization",
		trace.WithAttributes(
			attribute.String("keycloak.realm", k.realm),
			attribute.String("keycloak.org.alias", alias),
		),
	)
	defer span.End()

	path := fmt.Sprintf("/admin/realms/%s/organizations", url.PathEscape(k.realm))

	body := map[string]any{
		"name":        name,
		"alias":       alias,
		"description": description,
		"enabled":     true,
	}

	resp, err := k.client.DoAdminRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("keycloak.CreateOrganization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		span.SetStatus(codes.Error, "conflict")
		return "", fmt.Errorf("keycloak.CreateOrganization alias=%q: %w", alias, ErrConflict)
	}
	if resp.StatusCode == http.StatusForbidden {
		return "", ErrForbidden
	}
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("keycloak.CreateOrganization: unexpected status %d: %s", resp.StatusCode, b)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", err
	}

	orgID := locationID(resp)
	span.SetAttributes(attribute.String("keycloak.org.id", orgID))
	return orgID, nil
}

// GetOrganizationByAlias implements KeycloakAdmin.
// Keycloak's organization listing supports filtering by `search` query param
// which matches against alias and name.
func (k *keycloakAdminClient) GetOrganizationByAlias(ctx context.Context, alias string) (*OrgRepresentation, error) {
	ctx, span := k.tracer.Start(ctx, "keycloak.GetOrganizationByAlias",
		trace.WithAttributes(
			attribute.String("keycloak.realm", k.realm),
			attribute.String("keycloak.org.alias", alias),
		),
	)
	defer span.End()

	path := fmt.Sprintf("/admin/realms/%s/organizations?search=%s",
		url.PathEscape(k.realm), url.QueryEscape(alias))

	resp, err := k.client.DoAdminRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("keycloak.GetOrganizationByAlias: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("keycloak.GetOrganizationByAlias alias=%q: %w", alias, ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("keycloak.GetOrganizationByAlias: unexpected status %d: %s", resp.StatusCode, b)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("keycloak.GetOrganizationByAlias: read body: %w", err)
	}

	var orgs []OrgRepresentation
	if err := json.Unmarshal(b, &orgs); err != nil {
		return nil, fmt.Errorf("keycloak.GetOrganizationByAlias: parse response: %w", err)
	}

	// The search is a fuzzy match — filter by exact alias.
	for i := range orgs {
		if orgs[i].Alias == alias {
			span.SetAttributes(attribute.String("keycloak.org.id", orgs[i].ID))
			return &orgs[i], nil
		}
	}

	return nil, fmt.Errorf("keycloak.GetOrganizationByAlias alias=%q: %w", alias, ErrNotFound)
}

// DeleteOrganization implements KeycloakAdmin.
func (k *keycloakAdminClient) DeleteOrganization(ctx context.Context, orgID string) error {
	ctx, span := k.tracer.Start(ctx, "keycloak.DeleteOrganization",
		trace.WithAttributes(
			attribute.String("keycloak.realm", k.realm),
			attribute.String("keycloak.org.id", orgID),
		),
	)
	defer span.End()

	path := fmt.Sprintf("/admin/realms/%s/organizations/%s", url.PathEscape(k.realm), url.PathEscape(orgID))
	resp, err := k.client.DoAdminRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("keycloak.DeleteOrganization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("keycloak.DeleteOrganization orgID=%q: %w", orgID, ErrNotFound)
	}
	if resp.StatusCode == http.StatusForbidden {
		return ErrForbidden
	}
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("keycloak.DeleteOrganization: unexpected status %d: %s", resp.StatusCode, b)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// AddOrganizationMember implements KeycloakAdmin.
// Keycloak's organization membership endpoint accepts a user ID in the request body
// as a UserRepresentation with only the id field set.
func (k *keycloakAdminClient) AddOrganizationMember(ctx context.Context, orgID, userID string) error {
	ctx, span := k.tracer.Start(ctx, "keycloak.AddOrganizationMember",
		trace.WithAttributes(
			attribute.String("keycloak.realm", k.realm),
			attribute.String("keycloak.org.id", orgID),
			attribute.String("keycloak.user.id", userID),
		),
	)
	defer span.End()

	path := fmt.Sprintf("/admin/realms/%s/organizations/%s/members",
		url.PathEscape(k.realm), url.PathEscape(orgID))

	// The KC 26 Organizations API accepts a plain string userID in the body.
	// Encode it as a JSON string (not an object) per the spec.
	resp, err := k.client.DoAdminRequest(ctx, http.MethodPost, path, userID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("keycloak.AddOrganizationMember: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("keycloak.AddOrganizationMember orgID=%q userID=%q: %w", orgID, userID, ErrNotFound)
	}
	if resp.StatusCode == http.StatusConflict {
		// Already a member — treat as success for idempotency.
		k.effectiveLogger().DebugContext(ctx, "keycloak.AddOrganizationMember: user already a member (409 ignored)",
			slog.String("orgID", orgID), slog.String("userID", userID))
		return nil
	}
	if resp.StatusCode == http.StatusForbidden {
		return ErrForbidden
	}
	// KC 26 returns 201 Created on success.
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("keycloak.AddOrganizationMember: unexpected status %d: %s", resp.StatusCode, b)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// RemoveOrganizationMember implements KeycloakAdmin.
func (k *keycloakAdminClient) RemoveOrganizationMember(ctx context.Context, orgID, userID string) error {
	ctx, span := k.tracer.Start(ctx, "keycloak.RemoveOrganizationMember",
		trace.WithAttributes(
			attribute.String("keycloak.realm", k.realm),
			attribute.String("keycloak.org.id", orgID),
			attribute.String("keycloak.user.id", userID),
		),
	)
	defer span.End()

	path := fmt.Sprintf("/admin/realms/%s/organizations/%s/members/%s",
		url.PathEscape(k.realm), url.PathEscape(orgID), url.PathEscape(userID))

	resp, err := k.client.DoAdminRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("keycloak.RemoveOrganizationMember: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("keycloak.RemoveOrganizationMember orgID=%q userID=%q: %w", orgID, userID, ErrNotFound)
	}
	if resp.StatusCode == http.StatusForbidden {
		return ErrForbidden
	}
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("keycloak.RemoveOrganizationMember: unexpected status %d: %s", resp.StatusCode, b)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// ListOrganizationMembers implements KeycloakAdmin.
func (k *keycloakAdminClient) ListOrganizationMembers(ctx context.Context, orgID string) ([]OrgMemberRepresentation, error) {
	ctx, span := k.tracer.Start(ctx, "keycloak.ListOrganizationMembers",
		trace.WithAttributes(
			attribute.String("keycloak.realm", k.realm),
			attribute.String("keycloak.org.id", orgID),
		),
	)
	defer span.End()

	path := fmt.Sprintf("/admin/realms/%s/organizations/%s/members",
		url.PathEscape(k.realm), url.PathEscape(orgID))

	resp, err := k.client.DoAdminRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("keycloak.ListOrganizationMembers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("keycloak.ListOrganizationMembers orgID=%q: %w", orgID, ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("keycloak.ListOrganizationMembers: unexpected status %d: %s", resp.StatusCode, b)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("keycloak.ListOrganizationMembers: read body: %w", err)
	}

	var members []OrgMemberRepresentation
	if err := json.Unmarshal(b, &members); err != nil {
		return nil, fmt.Errorf("keycloak.ListOrganizationMembers: parse response: %w", err)
	}

	span.SetAttributes(attribute.Int("keycloak.org.member_count", len(members)))
	return members, nil
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

// effectiveLogger returns the client's logger, falling back to slog.Default()
// when the logger field is nil (e.g., in unit tests that pass nil).
func (k *keycloakAdminClient) effectiveLogger() *slog.Logger {
	if k.logger != nil {
		return k.logger
	}
	return slog.Default()
}

// locationID extracts the last path segment from the Location header of a
// 201 Created response. Keycloak uses this convention to return the UUID of
// newly created resources.
//
// Mirrors the same helper in internal/keycloak/client.go — having a local
// copy avoids exporting it from that package just for provisioner's use.
func locationID(resp *http.Response) string {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return ""
	}
	parts := strings.Split(strings.TrimRight(loc, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}
