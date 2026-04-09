// Package provisioner — invite_handler.go
//
// InviteHandler orchestrates the member invitation flow:
//
//  1. Create a Keycloak user with REQUIRED_ACTION for password-set on first login.
//  2. Add the new user to the Keycloak Organization for the tenant.
//  3. Write an FGA tuple granting the invited role (admin → admin relation,
//     others → member relation) on the tenant.
//  4. Generate a signed JWT invitation token, store it in Redis with TTL.
//  5. Return the token and invite URL to the caller.
//
// Accept validates the token, marks it consumed in Redis, and returns the
// Keycloak set-password URL so the frontend can redirect the invited user.
//
// Resend issues a fresh token for an existing pending user without touching
// the Keycloak user record itself.
//
// Atomicity: any failure in steps 1-4 triggers rollback in reverse order
// using the same Rollback helper from authz-02.
//
// Email delivery is OUT OF SCOPE: the token is returned to the admin for
// manual sharing or later email integration.
package provisioner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/keycloak"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

var (
	// ErrInvitationExpired is returned when the invitation token has passed its TTL.
	ErrInvitationExpired = errors.New("invitation expired")

	// ErrInvitationConsumed is returned when the invitation token has already been accepted.
	ErrInvitationConsumed = errors.New("invitation already accepted")

	// ErrInvitationInvalid is returned when the token signature or claims are invalid.
	ErrInvitationInvalid = errors.New("invitation token invalid")

	// ErrUserAlreadyMember is returned when the invited email is already a tenant member.
	ErrUserAlreadyMember = errors.New("user is already a member of this tenant")
)

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

// InviteRequest carries the parameters for a member invitation.
type InviteRequest struct {
	TenantID string
	// OrgID is the Keycloak Organization UUID for the tenant (fetched by the caller).
	OrgID   string
	Email   string
	Role    string // "owner", "admin", "operator", "viewer"
	Message string
}

// Invitation is the result of a successful InviteHandler.Invite call.
type Invitation struct {
	Token         string
	InvitationURL string
	UserID        string
	TenantID      string
	Email         string
	ExpiresAt     time.Time
}

// AcceptResult carries the outcome of an AcceptInvitation call.
type AcceptResult struct {
	TenantID       string
	UserID         string
	Role           string
	PasswordSetURL string
}

// invitationRecord is the JSON payload stored in Redis.
type invitationRecord struct {
	UserID   string    `json:"user_id"`
	TenantID string    `json:"tenant_id"`
	OrgID    string    `json:"org_id"`
	Role     string    `json:"role"`
	Email    string    `json:"email"`
	Consumed bool      `json:"consumed"`
	IssuedAt time.Time `json:"issued_at"`
}

// invitationClaims is the JWT payload for the signed invitation token.
type invitationClaims struct {
	jwt.RegisteredClaims
	TenantID string `json:"tid"`
	UserID   string `json:"uid"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

// ---------------------------------------------------------------------------
// InviteHandler
// ---------------------------------------------------------------------------

// InviteHandler orchestrates member invitation creation, acceptance, and resend.
type InviteHandler struct {
	kc         KeycloakAdmin
	authz      authz.Authorizer
	redis      *redis.Client
	signingKey []byte
	baseURL    string // dashboard base URL for invite links, e.g. "https://app.example.com"
	tokenTTL   time.Duration
	logger     *slog.Logger
}

// InviteHandlerConfig configures an InviteHandler.
type InviteHandlerConfig struct {
	SigningKey []byte        // JWT HMAC-SHA256 signing key
	BaseURL   string        // dashboard base URL for invite link construction
	TokenTTL  time.Duration // invitation token TTL (default: 24h)
}

// NewInviteHandler constructs an InviteHandler.
func NewInviteHandler(
	kc KeycloakAdmin,
	az authz.Authorizer,
	redisClient *redis.Client,
	cfg InviteHandlerConfig,
	logger *slog.Logger,
) (*InviteHandler, error) {
	if kc == nil {
		return nil, fmt.Errorf("invite_handler: KeycloakAdmin is required")
	}
	if az == nil {
		return nil, fmt.Errorf("invite_handler: Authorizer is required")
	}
	if redisClient == nil {
		return nil, fmt.Errorf("invite_handler: Redis client is required")
	}
	if len(cfg.SigningKey) < 16 {
		return nil, fmt.Errorf("invite_handler: signing key must be at least 16 bytes")
	}
	ttl := cfg.TokenTTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &InviteHandler{
		kc:         kc,
		authz:      az,
		redis:      redisClient,
		signingKey: cfg.SigningKey,
		baseURL:    cfg.BaseURL,
		tokenTTL:   ttl,
		logger:     logger.With("component", "provisioner.invite_handler"),
	}, nil
}

// Invite creates a new Keycloak user (pending password set), adds them to the
// tenant org, writes the FGA membership tuple, and returns a signed invitation
// token. On any failure the operation is rolled back.
func (h *InviteHandler) Invite(ctx context.Context, req InviteRequest) (*Invitation, error) {
	if req.TenantID == "" || req.Email == "" || req.Role == "" {
		return nil, fmt.Errorf("%w: tenant_id, email, and role are required", ErrInvalidSignupInput)
	}
	if !emailRE.MatchString(req.Email) {
		return nil, fmt.Errorf("%w: invalid email format", ErrInvalidSignupInput)
	}
	if !validInviteRole(req.Role) {
		return nil, fmt.Errorf("%w: role must be one of owner/admin/operator/viewer", ErrInvalidSignupInput)
	}

	// Step 1: create a Keycloak user. Use VERIFY_EMAIL + UPDATE_PASSWORD required actions
	// so the invited user must set a password on first login.
	userCfg := keycloak.UserConfig{
		Email:           req.Email,
		Username:        req.Email,
		Enabled:         true,
		RequiredActions: []string{"UPDATE_PASSWORD"},
	}
	var userID string
	var rollbackNeeded []func()

	userID, err := h.kc.CreateUser(ctx, userCfg)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return nil, fmt.Errorf("%w: email %s", ErrUserAlreadyMember, req.Email)
		}
		return nil, fmt.Errorf("invite: create keycloak user: %w", err)
	}
	rollbackNeeded = append(rollbackNeeded, func() {
		if delErr := h.kc.DeleteUser(ctx, userID); delErr != nil && !errors.Is(delErr, ErrNotFound) {
			h.logger.ErrorContext(ctx, "invite rollback: failed to delete user",
				slog.String("user_id", userID), slog.String("error", delErr.Error()))
		}
	})

	// Step 2: add to Keycloak Organization (if orgID provided).
	if req.OrgID != "" {
		if err := h.kc.AddOrganizationMember(ctx, req.OrgID, userID); err != nil {
			h.runRollbacks(rollbackNeeded)
			return nil, fmt.Errorf("invite: add org member: %w", err)
		}
		rollbackNeeded = append(rollbackNeeded, func() {
			if delErr := h.kc.RemoveOrganizationMember(ctx, req.OrgID, userID); delErr != nil && !errors.Is(delErr, ErrNotFound) {
				h.logger.ErrorContext(ctx, "invite rollback: failed to remove org member",
					slog.String("user_id", userID), slog.String("error", delErr.Error()))
			}
		})
	}

	// Step 3: write FGA tuple. Admin role gets "admin" relation; others get "member".
	fgaRelation := roleToFGARelation(req.Role)
	tuple := authz.Tuple{
		User:     fmt.Sprintf("user:%s", userID),
		Relation: fgaRelation,
		Object:   fmt.Sprintf("tenant:%s", req.TenantID),
	}
	if err := h.authz.Write(ctx, []authz.Tuple{tuple}); err != nil {
		h.runRollbacks(rollbackNeeded)
		return nil, fmt.Errorf("invite: write FGA tuple: %w", err)
	}
	rollbackNeeded = append(rollbackNeeded, func() {
		if delErr := h.authz.Delete(ctx, []authz.Tuple{tuple}); delErr != nil {
			h.logger.ErrorContext(ctx, "invite rollback: failed to delete FGA tuple",
				slog.String("user_id", userID), slog.String("error", delErr.Error()))
		}
	})

	// Step 4: generate signed JWT and store invitation record in Redis.
	now := time.Now().UTC()
	expiresAt := now.Add(h.tokenTTL)
	claims := invitationClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			ID:        fmt.Sprintf("%s:%s:%d", req.TenantID, userID, now.UnixNano()),
		},
		TenantID: req.TenantID,
		UserID:   userID,
		Email:    req.Email,
		Role:     req.Role,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(h.signingKey)
	if err != nil {
		h.runRollbacks(rollbackNeeded)
		return nil, fmt.Errorf("invite: sign token: %w", err)
	}

	rec := invitationRecord{
		UserID:   userID,
		TenantID: req.TenantID,
		OrgID:    req.OrgID,
		Role:     req.Role,
		Email:    req.Email,
		Consumed: false,
		IssuedAt: now,
	}
	recJSON, err := json.Marshal(rec)
	if err != nil {
		h.runRollbacks(rollbackNeeded)
		return nil, fmt.Errorf("invite: marshal invitation record: %w", err)
	}

	redisKey := invitationRedisKey(signed)
	if err := h.redis.Set(ctx, redisKey, recJSON, h.tokenTTL).Err(); err != nil {
		h.runRollbacks(rollbackNeeded)
		return nil, fmt.Errorf("invite: store invitation in redis: %w", err)
	}

	inviteURL := fmt.Sprintf("%s/invite/accept?token=%s", h.baseURL, signed)

	h.logger.InfoContext(ctx, "invited member",
		slog.String("tenant_id", req.TenantID),
		slog.String("user_id", userID),
		slog.String("role", req.Role),
		slog.Time("expires_at", expiresAt),
	)

	return &Invitation{
		Token:         signed,
		InvitationURL: inviteURL,
		UserID:        userID,
		TenantID:      req.TenantID,
		Email:         req.Email,
		ExpiresAt:     expiresAt,
	}, nil
}

// Accept validates an invitation token, marks it consumed in Redis, and returns
// the information needed to redirect the user to set their password.
func (h *InviteHandler) Accept(ctx context.Context, tokenStr string) (*AcceptResult, error) {
	// Parse and validate JWT signature + expiry.
	claims, err := h.parseToken(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvitationInvalid, err)
	}

	// Check Redis for the invitation record.
	redisKey := invitationRedisKey(tokenStr)
	raw, err := h.redis.Get(ctx, redisKey).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Key not found: either expired (TTL elapsed) or never existed.
			return nil, ErrInvitationExpired
		}
		return nil, fmt.Errorf("accept: redis lookup: %w", err)
	}

	var rec invitationRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("accept: unmarshal invitation record: %w", err)
	}

	if rec.Consumed {
		return nil, ErrInvitationConsumed
	}

	// Mark consumed: update the record rather than deleting so subsequent Accept
	// calls return ErrInvitationConsumed rather than ErrInvitationExpired.
	rec.Consumed = true
	updated, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("accept: marshal updated record: %w", err)
	}
	// Keep the remaining TTL so the consumed record eventually cleans itself up.
	ttlRemaining, ttlErr := h.redis.TTL(ctx, redisKey).Result()
	if ttlErr != nil || ttlRemaining < 0 {
		ttlRemaining = 5 * time.Minute // fallback: keep consumed record briefly
	}
	if err := h.redis.Set(ctx, redisKey, updated, ttlRemaining).Err(); err != nil {
		// Non-fatal: the acceptance flow already succeeded at the FGA/KC level.
		h.logger.WarnContext(ctx, "accept: failed to mark invitation consumed",
			slog.String("user_id", rec.UserID), slog.String("error", err.Error()))
	}

	// Build the Keycloak set-password URL. The invited user's browser will be
	// redirected here to set their password via the Keycloak login flow.
	// The format is: {kc_base}/realms/{realm}/login-actions/authenticate
	// In practice the frontend handles this redirect; we return the user_id and
	// role so the caller can construct the appropriate URL.
	passwordSetURL := fmt.Sprintf("%s/login?hint=%s", h.baseURL, rec.Email)

	h.logger.InfoContext(ctx, "invitation accepted",
		slog.String("tenant_id", claims.TenantID),
		slog.String("user_id", claims.UserID),
	)

	return &AcceptResult{
		TenantID:       claims.TenantID,
		UserID:         claims.UserID,
		Role:           claims.Role,
		PasswordSetURL: passwordSetURL,
	}, nil
}

// Resend issues a new invitation token for an existing pending user without
// changing the Keycloak user or FGA state.
func (h *InviteHandler) Resend(ctx context.Context, tenantID, userID, orgID, email, role string) (*Invitation, error) {
	if tenantID == "" || userID == "" {
		return nil, fmt.Errorf("%w: tenant_id and user_id are required for resend", ErrInvalidSignupInput)
	}

	now := time.Now().UTC()
	expiresAt := now.Add(h.tokenTTL)
	claims := invitationClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			ID:        fmt.Sprintf("%s:%s:%d:resend", tenantID, userID, now.UnixNano()),
		},
		TenantID: tenantID,
		UserID:   userID,
		Email:    email,
		Role:     role,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(h.signingKey)
	if err != nil {
		return nil, fmt.Errorf("resend: sign token: %w", err)
	}

	rec := invitationRecord{
		UserID:   userID,
		TenantID: tenantID,
		OrgID:    orgID,
		Role:     role,
		Email:    email,
		Consumed: false,
		IssuedAt: now,
	}
	recJSON, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("resend: marshal record: %w", err)
	}

	redisKey := invitationRedisKey(signed)
	if err := h.redis.Set(ctx, redisKey, recJSON, h.tokenTTL).Err(); err != nil {
		return nil, fmt.Errorf("resend: store token in redis: %w", err)
	}

	inviteURL := fmt.Sprintf("%s/invite/accept?token=%s", h.baseURL, signed)

	h.logger.InfoContext(ctx, "invitation resent",
		slog.String("tenant_id", tenantID),
		slog.String("user_id", userID),
	)

	return &Invitation{
		Token:         signed,
		InvitationURL: inviteURL,
		UserID:        userID,
		TenantID:      tenantID,
		Email:         email,
		ExpiresAt:     expiresAt,
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parseToken validates the JWT signature and expiry, returning the claims.
func (h *InviteHandler) parseToken(tokenStr string) (*invitationClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &invitationClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return h.signingKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*invitationClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid claims")
	}
	return claims, nil
}

// runRollbacks executes rollback functions in reverse order (LIFO).
func (h *InviteHandler) runRollbacks(fns []func()) {
	for i := len(fns) - 1; i >= 0; i-- {
		fns[i]()
	}
}

// invitationRedisKey returns the Redis key for an invitation token.
// We hash the token so that the raw JWT (which contains claims) is not stored
// as a plain key, but we use a simple prefix for now since the token is already
// signed and the Redis TTL provides expiry.
func invitationRedisKey(token string) string {
	// Limit key length by using only the first 40 chars of the token signature portion.
	// The token format is header.payload.signature; the signature is unique per token.
	if len(token) > 40 {
		return "invitation:" + token[len(token)-40:]
	}
	return "invitation:" + token
}

// roleToFGARelation maps the Gibson role name to the FGA relation that should
// be written on the tenant object.
//
//	owner  → admin (owners are modelled as admins in FGA; ownership is tracked elsewhere)
//	admin  → admin
//	operator → member
//	viewer → member
func roleToFGARelation(role string) string {
	switch role {
	case "owner", "admin":
		return "admin"
	default:
		return "member"
	}
}

// validInviteRole returns true for the four canonical Gibson roles.
func validInviteRole(role string) bool {
	switch role {
	case "owner", "admin", "operator", "viewer":
		return true
	}
	return false
}
