// Package provisioner — signup_handler.go
//
// SignupHandler orchestrates the full SaaS tenant signup flow.  It is the
// canonical implementation of the 11-step sequence defined in design.md
// Component 2.  All Keycloak admin calls go through KeycloakAdmin; all FGA
// writes go through authz.Authorizer; downstream tenant resource provisioning
// goes through *Provisioner.
//
// Flow summary (design.md Component 2):
//  1. Validate email, password, company_name, plan.
//  2. Slugify company_name → tenantID; validate against ^[a-z0-9-]+$.
//  3. kc.CreateUser  → capture userID.
//  4. kc.CreateOrganization(tenantID, companyName) → capture orgID;
//     on ErrConflict, GetOrganizationByAlias to fetch existing.
//  5. kc.AddOrganizationMember(orgID, userID).
//  6. authz.Write [{user:<userID>, admin, tenant:<tenantID>}].
//  7. provisioner.ProvisionTenant(tenantID, plan).
//  8. Emit audit event tenant_created.
//  9. Return SignupResponse.
//  10. On ANY failure at steps 3-7, call rollback.UndoSignup then return error.
//  11. Emit audit event tenant_signup_failed on failure path.
//
// Sentinel errors returned to callers (used by gRPC handler for status mapping):
//
//	ErrInvalidSignupInput  → codes.InvalidArgument
//	ErrEmailAlreadyExists  → codes.AlreadyExists
//	ErrSignupFailed        → codes.Internal
package provisioner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"unicode"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/keycloak"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

var (
	// ErrInvalidSignupInput is returned when the signup request fails validation.
	// The gRPC handler maps this to codes.InvalidArgument.
	ErrInvalidSignupInput = errors.New("invalid signup input")

	// ErrEmailAlreadyExists is returned when the email is already registered.
	// The gRPC handler maps this to codes.AlreadyExists.
	ErrEmailAlreadyExists = errors.New("email already exists")

	// ErrSignupFailed is returned when any non-validation, non-conflict step
	// in the signup pipeline fails.  The gRPC handler maps this to codes.Internal.
	ErrSignupFailed = errors.New("signup failed")
)

// ---------------------------------------------------------------------------
// Validation constants
// ---------------------------------------------------------------------------

var (
	// emailRE is a permissive RFC-5322-inspired regex sufficient for signup
	// pre-validation.  Definitive validation happens server-side in Keycloak.
	emailRE = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

	// slugRE rejects tenant IDs that don't match the allowed character set.
	slugRE = regexp.MustCompile(`^[a-z0-9-]+$`)

	// validPlans is the set of billing plans the signup handler accepts.
	validPlans = map[string]bool{
		"free":       true,
		"indie":      true,
		"pro":        true,
		"team":       true,
		"business":   true,
		"enterprise": true,
	}

	// passwordMinLength enforces a minimum credential strength.
	passwordMinLength = 12
)

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

// SignupRequest carries the four fields submitted on the signup form.
type SignupRequest struct {
	Email       string
	Password    string
	CompanyName string
	Plan        string
}

// SignupResponse carries the identifiers created during signup and the URL the
// dashboard should redirect the user to.
type SignupResponse struct {
	UserID            string
	TenantID          string
	OrganizationAlias string
	RedirectURL       string
}

// ---------------------------------------------------------------------------
// SignupHandler
// ---------------------------------------------------------------------------

// tenantProvisionerIface is the narrow provisioner surface SignupHandler uses.
// Using an interface lets tests swap in a stub without a live Redis connection.
type tenantProvisionerIface interface {
	ProvisionTenant(ctx context.Context, req ProvisionRequest) (*ProvisionResult, error)
}

// rollbackerIface is the narrow rollback surface SignupHandler uses.
// Using an interface lets tests swap in a mock for rollback assertions.
type rollbackerIface interface {
	UndoSignup(ctx context.Context, userID, orgID, tenantID string) error
}

// SignupHandler orchestrates the full tenant signup pipeline.
//
// It is safe for concurrent use.  Construct with NewSignupHandler.
type SignupHandler struct {
	kc          KeycloakAdmin
	authz       authz.Authorizer
	provisioner tenantProvisionerIface
	rollback    rollbackerIface
	logger      *slog.Logger
}

// NewSignupHandler constructs a SignupHandler.
//
// All non-logger parameters must be non-nil.
func NewSignupHandler(kc KeycloakAdmin, az authz.Authorizer, prov *Provisioner, logger *slog.Logger) *SignupHandler {
	if logger == nil {
		logger = slog.Default()
	}
	rb := NewRollback(kc, az, logger)
	return &SignupHandler{
		kc:          kc,
		authz:       az,
		provisioner: prov,
		rollback:    rb,
		logger:      logger.With("component", "provisioner.signup_handler"),
	}
}

// Signup executes the full 11-step signup flow.
//
// On success it returns a *SignupResponse.  On validation failure it returns
// ErrInvalidSignupInput.  On duplicate email it returns ErrEmailAlreadyExists.
// On any other pipeline failure it rolls back all created state and returns
// ErrSignupFailed.
func (s *SignupHandler) Signup(ctx context.Context, req SignupRequest) (*SignupResponse, error) {
	// -----------------------------------------------------------------------
	// Step 1: Validate inputs.
	// -----------------------------------------------------------------------
	if err := s.validateRequest(req); err != nil {
		return nil, err
	}

	// -----------------------------------------------------------------------
	// Step 2: Derive and validate tenantID.
	// -----------------------------------------------------------------------
	tenantID := slugify(req.CompanyName)
	if tenantID == "" || !slugRE.MatchString(tenantID) {
		return nil, fmt.Errorf("%w: company_name %q cannot be slugified to a valid tenant ID",
			ErrInvalidSignupInput, req.CompanyName)
	}

	s.logger.InfoContext(ctx, "starting tenant signup",
		slog.String("email", req.Email),
		slog.String("tenant_id", tenantID),
		slog.String("plan", req.Plan),
	)

	// Track state for rollback.
	var userID, orgID string

	// onFailure rolls back whatever state was created and wraps the original
	// error as ErrSignupFailed.  It also emits the tenant_signup_failed event.
	onFailure := func(cause error) error {
		s.logger.WarnContext(ctx, "signup failed, rolling back",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", userID),
			slog.String("org_id", orgID),
			slog.String("error", cause.Error()),
		)
		s.emitEvent(ctx, "tenant_signup_failed",
			slog.String("tenant_id", tenantID),
			slog.String("email", req.Email),
			slog.String("error", cause.Error()),
		)
		if rbErr := s.rollback.UndoSignup(ctx, userID, orgID, tenantID); rbErr != nil {
			s.logger.ErrorContext(ctx, "rollback encountered errors",
				slog.String("tenant_id", tenantID),
				slog.String("rollback_error", rbErr.Error()),
			)
		}
		return fmt.Errorf("%w: %w", ErrSignupFailed, cause)
	}

	// -----------------------------------------------------------------------
	// Step 3: Create the Keycloak user.
	// -----------------------------------------------------------------------
	emailDomain := emailDomain(req.Email)
	uid, err := s.kc.CreateUser(ctx, keycloak.UserConfig{
		Username:      req.Email,
		Email:         req.Email,
		Enabled:       true,
		EmailVerified: false,
		Password:      req.Password,
	})
	if err != nil {
		if errors.Is(err, ErrConflict) {
			s.emitEvent(ctx, "tenant_signup_failed",
				slog.String("email", req.Email),
				slog.String("reason", "email_already_exists"),
			)
			return nil, fmt.Errorf("%w: %s", ErrEmailAlreadyExists, req.Email)
		}
		return nil, onFailure(fmt.Errorf("create Keycloak user: %w", err))
	}
	userID = uid

	// -----------------------------------------------------------------------
	// Step 4: Create the Keycloak Organization (handle 409 gracefully).
	// -----------------------------------------------------------------------
	oid, err := s.kc.CreateOrganization(ctx, req.CompanyName, tenantID,
		fmt.Sprintf("Tenant organization for %s (%s)", req.CompanyName, emailDomain))
	if err != nil {
		if errors.Is(err, ErrConflict) {
			// Organization already exists — fetch the existing one.
			s.logger.InfoContext(ctx, "signup: org alias already exists, fetching existing org",
				slog.String("tenant_id", tenantID),
			)
			existing, getErr := s.kc.GetOrganizationByAlias(ctx, tenantID)
			if getErr != nil {
				return nil, onFailure(fmt.Errorf("fetch existing org after conflict: %w", getErr))
			}
			oid = existing.ID
		} else {
			return nil, onFailure(fmt.Errorf("create Keycloak organization: %w", err))
		}
	}
	orgID = oid

	// -----------------------------------------------------------------------
	// Step 5: Add the user as an organization member.
	// -----------------------------------------------------------------------
	if err := s.kc.AddOrganizationMember(ctx, orgID, userID); err != nil {
		return nil, onFailure(fmt.Errorf("add org member: %w", err))
	}

	// -----------------------------------------------------------------------
	// Step 6: Write the FGA admin tuple.
	// -----------------------------------------------------------------------
	tuple := authz.Tuple{
		User:     fmt.Sprintf("user:%s", userID),
		Relation: "admin",
		Object:   fmt.Sprintf("tenant:%s", tenantID),
	}
	if err := s.authz.Write(ctx, []authz.Tuple{tuple}); err != nil {
		return nil, onFailure(fmt.Errorf("write FGA tuple: %w", err))
	}

	// -----------------------------------------------------------------------
	// Step 7: Provision downstream tenant resources (Langfuse, API key, etc.).
	// -----------------------------------------------------------------------
	if _, err := s.provisioner.ProvisionTenant(ctx, ProvisionRequest{
		TenantID:    tenantID,
		DisplayName: req.CompanyName,
		Tier:        req.Plan,
		OwnerEmail:  req.Email,
		OwnerUserID: userID,
	}); err != nil {
		return nil, onFailure(fmt.Errorf("provision tenant resources: %w", err))
	}

	// -----------------------------------------------------------------------
	// Step 8: Emit success audit event.
	// -----------------------------------------------------------------------
	s.emitEvent(ctx, "tenant_created",
		slog.String("user_id", userID),
		slog.String("tenant_id", tenantID),
		slog.String("email", req.Email),
	)

	s.logger.InfoContext(ctx, "tenant signup completed",
		slog.String("user_id", userID),
		slog.String("tenant_id", tenantID),
		slog.String("org_id", orgID),
	)

	// -----------------------------------------------------------------------
	// Step 9: Return response.
	// -----------------------------------------------------------------------
	return &SignupResponse{
		UserID:            userID,
		TenantID:          tenantID,
		OrganizationAlias: tenantID,
		RedirectURL:       "/login",
	}, nil
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

// validateRequest checks the four required signup fields.
// Returns ErrInvalidSignupInput on any validation failure.
func (s *SignupHandler) validateRequest(req SignupRequest) error {
	if req.Email == "" || !emailRE.MatchString(req.Email) {
		return fmt.Errorf("%w: email %q is not a valid email address", ErrInvalidSignupInput, req.Email)
	}
	if len(req.Password) < passwordMinLength {
		return fmt.Errorf("%w: password must be at least %d characters", ErrInvalidSignupInput, passwordMinLength)
	}
	if strings.TrimSpace(req.CompanyName) == "" {
		return fmt.Errorf("%w: company_name must not be empty", ErrInvalidSignupInput)
	}
	if !validPlans[req.Plan] {
		return fmt.Errorf("%w: plan %q is not valid (must be one of: free, indie, pro, team, business, enterprise)", ErrInvalidSignupInput, req.Plan)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Slug helper
// ---------------------------------------------------------------------------

// slugify converts a company name to a lowercase alphanumeric slug with hyphens.
//
// Rules:
//   - Lowercase all characters.
//   - Replace any run of non-alphanumeric characters with a single hyphen.
//   - Trim leading and trailing hyphens.
//   - Collapse consecutive hyphens into one.
//
// Examples:
//
//	"Zero Day AI"   → "zero-day-ai"
//	"Acme Corp."    → "acme-corp"
//	"  foo--bar  "  → "foo-bar"
func slugify(s string) string {
	s = strings.ToLower(s)

	var b strings.Builder
	prevWasHyphen := false
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			prevWasHyphen = false
		} else {
			if !prevWasHyphen && b.Len() > 0 {
				b.WriteByte('-')
				prevWasHyphen = true
			}
		}
	}

	result := strings.TrimRight(b.String(), "-")
	return result
}

// ---------------------------------------------------------------------------
// Domain extraction helper
// ---------------------------------------------------------------------------

// emailDomain extracts the domain portion from an email address.
// Returns an empty string if the email is malformed.
func emailDomain(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// ---------------------------------------------------------------------------
// Audit event helper
// ---------------------------------------------------------------------------

// emitEvent logs a structured audit event using slog.
// Each audit event has an "event_type" key and zero or more additional fields.
func (s *SignupHandler) emitEvent(ctx context.Context, eventType string, attrs ...slog.Attr) {
	args := make([]any, 0, len(attrs)+2)
	args = append(args, "event_type", eventType)
	for _, a := range attrs {
		args = append(args, a.Key, a.Value.Any())
	}
	s.logger.InfoContext(ctx, "audit", args...)
}
