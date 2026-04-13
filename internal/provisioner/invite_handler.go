// Package provisioner — invite_handler.go
//
// InviteHandler orchestrates the member invitation flow:
//
//  1. Write an FGA tuple granting the invited role (admin → admin relation,
//     others → member relation) on the tenant.
//  2. Generate a signed JWT invitation token, store it in Redis with TTL.
//  3. Return the token and invite URL to the caller.
//
// Accept validates the token, marks it consumed in Redis, and returns the
// information needed to complete signup via Better Auth.
//
// Resend issues a fresh token for an existing pending invitation.
//
// User account creation is handled by Better Auth in the dashboard. The invite
// token is used after the user signs up to link their Better Auth account to
// the tenant with the pre-provisioned FGA role.
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
	Email    string
	Role     string // "owner", "admin", "operator", "viewer"
	Message  string
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
// The kc parameter is accepted but ignored for backward-compatibility with
// existing call sites during the Better Auth migration; pass nil.
func NewInviteHandler(
	kc interface{}, // deprecated: ignored; was KeycloakAdmin
	az authz.Authorizer,
	redisClient *redis.Client,
	cfg InviteHandlerConfig,
	logger *slog.Logger,
) (*InviteHandler, error) {
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
		authz:      az,
		redis:      redisClient,
		signingKey: cfg.SigningKey,
		baseURL:    cfg.BaseURL,
		tokenTTL:   ttl,
		logger:     logger.With("component", "provisioner.invite_handler"),
	}, nil
}

// Invite writes an FGA pre-authorization tuple for the invited email and returns
// a signed invitation token. The invited user must sign up via Better Auth and
// then Accept the invitation token to complete their tenant membership.
//
// Note: the FGA tuple uses a placeholder "invite:{email}" subject. On Accept,
// callers should re-write the tuple with the actual Better Auth user UUID.
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

	// Use a stable invite-scoped placeholder so FGA tuples can be looked up
	// before the user completes Better Auth signup.
	userID := fmt.Sprintf("invite:%s", req.Email)

	// Write FGA pre-authorization tuple. Admin role gets "admin" relation; others "member".
	fgaRelation := roleToFGARelation(req.Role)
	tuple := authz.Tuple{
		User:     fmt.Sprintf("user:%s", userID),
		Relation: fgaRelation,
		Object:   fmt.Sprintf("tenant:%s", req.TenantID),
	}
	var rollbackNeeded []func()
	if err := h.authz.Write(ctx, []authz.Tuple{tuple}); err != nil {
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

// Resend issues a new invitation token for an existing pending invite without
// changing the FGA state.
func (h *InviteHandler) Resend(ctx context.Context, tenantID, userID, email, role string) (*Invitation, error) {
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
