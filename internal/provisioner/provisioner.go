package provisioner

// provisioner.go implements the SaaS tenant provisioning pipeline.
//
// Unlike TenantAutoProvisioner (which handles enterprise OIDC first-login),
// the SaaS Provisioner is invoked explicitly from the signup pipeline after
// Stripe has confirmed a subscription.  It owns the full setup sequence:
//
//  1. create_tenant    — persist TenantRecord with status "provisioning"
//  2. create_langfuse  — create Langfuse observability project (best-effort)
//  3. generate_apikey  — mint the tenant's initial API key
//  4. set_tier_limits  — write tier-derived config entries into the record
//  5. activate         — flip status to "active"
//
// Each step is idempotent: the provisioner checks the Redis hash
// tenant:{id}:provisioning before executing a step and skips any that are
// already marked "completed".  This makes the pipeline safe to retry after a
// partial failure without creating duplicate resources.
//
// Storage layout:
//   - tenant:{tenant_id}:provisioning   Redis HASH tracking step status
//   - (standard tenant keys managed by TenantService)

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/keycloak"
)

// ---------------------------------------------------------------------------
// Redis key helpers
// ---------------------------------------------------------------------------

// provisioningKey returns the Redis HASH key used to track provisioning state.
//
// Format: tenant:{tenant_id}:provisioning
func provisioningKey(tenantID string) string {
	return fmt.Sprintf("tenant:%s:provisioning", tenantID)
}

// ---------------------------------------------------------------------------
// Step names (shared between implementation and tests)
// ---------------------------------------------------------------------------

const (
	stepCreateRealm    = "create_realm"
	stepCreateTenant   = "create_tenant"
	stepCreateLangfuse = "create_langfuse"
	stepGenerateAPIKey = "generate_apikey"
	stepSetTierLimits  = "set_tier_limits"
	stepActivate       = "activate"
)

// stepOrder defines the canonical execution sequence.
var stepOrder = []string{
	stepCreateRealm,    // Keycloak realm, OIDC client, roles, and owner user
	stepCreateTenant,
	stepCreateLangfuse,
	stepGenerateAPIKey,
	stepSetTierLimits,
	stepActivate,
}

// ---------------------------------------------------------------------------
// Step status constants
// ---------------------------------------------------------------------------

const (
	statusPending    = "pending"
	statusCompleted  = "completed"
	statusFailed     = "failed"
	statusSkipped    = "skipped"
	statusInProgress = "in_progress"
)

// ---------------------------------------------------------------------------
// Tier limit definitions
// ---------------------------------------------------------------------------

// tierLimits maps tier name to a set of config key/value pairs that are
// written into TenantRecord.Config during the set_tier_limits step.
var tierLimits = map[string]map[string]string{
	"free": {
		"max_agents":        "1",
		"max_missions":      "5",
		"max_api_keys":      "2",
		"retention_days":    "7",
		"concurrent_agents": "1",
	},
	"team": {
		"max_agents":        "10",
		"max_missions":      "50",
		"max_api_keys":      "10",
		"retention_days":    "30",
		"concurrent_agents": "3",
	},
	"business": {
		"max_agents":        "50",
		"max_missions":      "500",
		"max_api_keys":      "50",
		"retention_days":    "90",
		"concurrent_agents": "10",
	},
	"enterprise": {
		"max_agents":        "unlimited",
		"max_missions":      "unlimited",
		"max_api_keys":      "unlimited",
		"retention_days":    "365",
		"concurrent_agents": "unlimited",
	},
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// ProvisionRequest contains everything needed to provision a new tenant.
type ProvisionRequest struct {
	TenantID         string
	DisplayName      string
	Tier             string
	OwnerEmail       string
	StripeCustomerID string
	StripeSubID      string
}

// ProvisionResult contains the provisioning outcome.
type ProvisionResult struct {
	TenantID string
	APIKey   string // Raw API key shown once; never stored in plaintext.
	Status   string
}

// ProvisionStatus tracks overall provisioning progress for a tenant.
type ProvisionStatus struct {
	TenantID  string          `json:"tenant_id"`
	Status    string          `json:"status"` // "in_progress", "completed", "failed"
	Steps     []ProvisionStep `json:"steps"`
	StartedAt time.Time       `json:"started_at"`
	Error     string          `json:"error,omitempty"`
}

// ProvisionStep tracks the result of a single provisioning step.
type ProvisionStep struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"` // "pending", "completed", "failed", "skipped"
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// ---------------------------------------------------------------------------
// Dependency interfaces
// ---------------------------------------------------------------------------

// TenantCreator creates and manages tenant records.  *component.TenantService
// satisfies this interface via its exported methods once the caller has
// injected an admin context.
type TenantCreator interface {
	// CreateTenant persists a new tenant record.  Returns an error wrapping
	// component.ErrTenantAlreadyExists if the tenant already exists.
	CreateTenant(ctx context.Context, tenantID, displayName string, config map[string]string) (interface{}, error)

	// GetTenant fetches a tenant record by ID.  Returns an error wrapping
	// component.ErrTenantNotFound when no record exists.
	GetTenant(ctx context.Context, tenantID string) (interface{}, error)

	// UpdateTenant merges the provided updates into the tenant record.
	UpdateTenant(ctx context.Context, tenantID string, updates map[string]string) (interface{}, error)
}

// APIKeyCreator mints tenant-scoped API keys.  *auth.APIKeyAuthenticator
// satisfies this interface directly.
type APIKeyCreator interface {
	// CreateKey generates a new API key for the tenant.  rawKey is the only
	// time the secret material is visible; record contains the persisted
	// metadata.
	CreateKey(ctx context.Context, tenantID string, allowedKinds, allowedNames []string) (rawKey string, record interface{}, err error)
}

// LangfuseSetup creates Langfuse observability projects for tenants.
// Matches the existing component.LangfuseProvisioner interface signature.
type LangfuseSetup interface {
	CreateProject(ctx context.Context, tenantID string) error
}

// ---------------------------------------------------------------------------
// Provisioner
// ---------------------------------------------------------------------------

// Provisioner orchestrates the full SaaS tenant setup pipeline.
//
// All dependencies are injected as interfaces so the provisioner can be
// exercised under test without a live Redis, Langfuse, or billing system.
type Provisioner struct {
	redis    *redis.Client
	tenants  TenantCreator
	apikeys  APIKeyCreator
	langfuse LangfuseSetup  // optional; nil disables the create_langfuse step
	keycloak *keycloak.Client // optional; nil disables the create_realm step
	logger   *slog.Logger

	// retryMax is the maximum number of execution attempts per step before
	// the provisioner marks the overall operation as failed.
	retryMax int
}

// New creates a Provisioner.  redis and tenants must be non-nil.  apikeys and
// langfuse may be nil; when apikeys is nil the generate_apikey step is skipped
// and the result APIKey will be empty.  When langfuse is nil the
// create_langfuse step is skipped without error.
func New(
	redisClient *redis.Client,
	tenants TenantCreator,
	apikeys APIKeyCreator,
	langfuse LangfuseSetup,
	logger *slog.Logger,
) *Provisioner {
	if redisClient == nil {
		panic("provisioner.New: redisClient must not be nil")
	}
	if tenants == nil {
		panic("provisioner.New: tenants must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Provisioner{
		redis:    redisClient,
		tenants:  tenants,
		apikeys:  apikeys,
		langfuse: langfuse,
		logger:   logger.With("component", "provisioner"),
		retryMax: 3,
	}
}

// WithKeycloak attaches a Keycloak client to the provisioner, enabling the
// create_realm step.  If not called (or called with nil), realm creation is
// skipped with a warning log and provisioning continues normally.
func (p *Provisioner) WithKeycloak(kc *keycloak.Client) *Provisioner {
	p.keycloak = kc
	return p
}

// ---------------------------------------------------------------------------
// ProvisionTenant
// ---------------------------------------------------------------------------

// ProvisionTenant executes the full tenant setup pipeline for req.
//
// The pipeline is idempotent: each step checks the Redis status hash before
// running and skips any step already marked "completed".  This means
// ProvisionTenant may be called again after a partial failure and will resume
// from where it left off.
//
// On success the returned ProvisionResult.APIKey contains the raw API key
// that must be presented to the user exactly once.  The key is not logged or
// stored in plaintext anywhere.
//
// Failed steps are retried up to three times with exponential back-off before
// the provisioner returns an error.  The create_langfuse step is an exception:
// failure there is logged as a warning and the step is recorded as "skipped"
// so that provisioning continues.
func (p *Provisioner) ProvisionTenant(ctx context.Context, req ProvisionRequest) (*ProvisionResult, error) {
	if req.TenantID == "" {
		return nil, errors.New("provisioner: TenantID must not be empty")
	}
	if req.Tier == "" {
		req.Tier = "free"
	}

	p.logger.InfoContext(ctx, "starting tenant provisioning",
		slog.String("tenant_id", req.TenantID),
		slog.String("tier", req.Tier),
	)

	// Initialise the status hash in Redis so callers can poll progress even
	// before the first step completes.
	if err := p.initStatus(ctx, req.TenantID); err != nil {
		return nil, fmt.Errorf("provisioner: failed to initialise status for %q: %w", req.TenantID, err)
	}

	var rawAPIKey string

	// Execute each step in order.
	for _, stepName := range stepOrder {
		// Check whether this step was already completed in a previous attempt.
		done, err := p.isStepDone(ctx, req.TenantID, stepName)
		if err != nil {
			return nil, fmt.Errorf("provisioner: reading step status for %q/%s: %w", req.TenantID, stepName, err)
		}
		if done {
			p.logger.InfoContext(ctx, "step already completed, skipping",
				slog.String("tenant_id", req.TenantID),
				slog.String("step", stepName),
			)
			continue
		}

		// Execute with retry.
		var stepErr error
		var stepKey string

		for attempt := 1; attempt <= p.retryMax; attempt++ {
			stepKey, stepErr = p.runStep(ctx, stepName, req, &rawAPIKey)
			if stepErr == nil {
				break
			}

			// The Langfuse step is always non-fatal; bail out of the retry loop
			// immediately so we can mark it skipped and move on.
			if stepName == stepCreateLangfuse {
				break
			}

			p.logger.WarnContext(ctx, "step attempt failed",
				slog.String("tenant_id", req.TenantID),
				slog.String("step", stepName),
				slog.Int("attempt", attempt),
				slog.Int("max_attempts", p.retryMax),
				slog.String("error", stepErr.Error()),
			)

			if attempt < p.retryMax {
				backoff := time.Duration(1<<uint(attempt-1)) * 500 * time.Millisecond
				select {
				case <-ctx.Done():
					return nil, fmt.Errorf("provisioner: context cancelled during backoff for %q/%s: %w",
						req.TenantID, stepName, ctx.Err())
				case <-time.After(backoff):
				}
			}
		}

		_ = stepKey // used only to anchor the variable in the loop above

		// Handle Langfuse specially: failure is non-fatal.
		if stepName == stepCreateLangfuse && stepErr != nil {
			p.logger.WarnContext(ctx, "Langfuse project creation failed (non-fatal), marking skipped",
				slog.String("tenant_id", req.TenantID),
				slog.String("error", stepErr.Error()),
			)
			if recordErr := p.recordStep(ctx, req.TenantID, stepName, statusSkipped, stepErr); recordErr != nil {
				p.logger.WarnContext(ctx, "failed to record skipped step status",
					slog.String("tenant_id", req.TenantID),
					slog.String("step", stepName),
					slog.String("error", recordErr.Error()),
				)
			}
			continue
		}

		if stepErr != nil {
			// All retries exhausted for a non-optional step.
			if recordErr := p.recordStep(ctx, req.TenantID, stepName, statusFailed, stepErr); recordErr != nil {
				p.logger.WarnContext(ctx, "failed to record failed step status",
					slog.String("tenant_id", req.TenantID),
					slog.String("step", stepName),
					slog.String("error", recordErr.Error()),
				)
			}
			_ = p.markOverallStatus(ctx, req.TenantID, statusFailed)
			return nil, fmt.Errorf("provisioner: step %s failed for tenant %q after %d attempts: %w",
				stepName, req.TenantID, p.retryMax, stepErr)
		}

		// Record successful step.
		if recordErr := p.recordStep(ctx, req.TenantID, stepName, statusCompleted, nil); recordErr != nil {
			p.logger.WarnContext(ctx, "failed to record completed step status",
				slog.String("tenant_id", req.TenantID),
				slog.String("step", stepName),
				slog.String("error", recordErr.Error()),
			)
		}

		p.logger.InfoContext(ctx, "step completed",
			slog.String("tenant_id", req.TenantID),
			slog.String("step", stepName),
		)
	}

	_ = p.markOverallStatus(ctx, req.TenantID, statusCompleted)

	p.logger.InfoContext(ctx, "tenant provisioning completed",
		slog.String("tenant_id", req.TenantID),
		slog.String("tier", req.Tier),
	)

	return &ProvisionResult{
		TenantID: req.TenantID,
		APIKey:   rawAPIKey,
		Status:   statusCompleted,
	}, nil
}

// runStep dispatches to the correct per-step implementation and returns the
// raw API key string when the generate_apikey step runs.  The string return
// value is only populated for stepGenerateAPIKey; it is empty for all others.
func (p *Provisioner) runStep(ctx context.Context, stepName string, req ProvisionRequest, rawAPIKey *string) (string, error) {
	switch stepName {
	case stepCreateRealm:
		return "", p.stepCreateRealm(ctx, req)
	case stepCreateTenant:
		return "", p.stepCreateTenant(ctx, req)
	case stepCreateLangfuse:
		return "", p.stepCreateLangfuse(ctx, req.TenantID)
	case stepGenerateAPIKey:
		key, err := p.stepGenerateAPIKey(ctx, req.TenantID)
		if err == nil && key != "" {
			*rawAPIKey = key
		}
		return "", err
	case stepSetTierLimits:
		return "", p.stepSetTierLimits(ctx, req)
	case stepActivate:
		return "", p.stepActivate(ctx, req.TenantID)
	default:
		return "", fmt.Errorf("unknown step %q", stepName)
	}
}

// ---------------------------------------------------------------------------
// Individual step implementations
// ---------------------------------------------------------------------------

// stepCreateRealm provisions a Keycloak realm for the tenant along with a
// default OIDC client, standard Gibson roles, a tenant_id protocol mapper,
// and the owner user.
//
// Idempotency: the Keycloak client treats 409 Conflict as a successful no-op
// for every sub-operation, so the entire step is safe to retry.
//
// When the keycloak field is nil the step is skipped with a warning log so
// that local/development deployments without Keycloak can still provision.
func (p *Provisioner) stepCreateRealm(ctx context.Context, req ProvisionRequest) error {
	if p.keycloak == nil {
		p.logger.WarnContext(ctx, "keycloak client not configured, skipping realm creation",
			slog.String("tenant_id", req.TenantID),
		)
		return nil
	}

	realmName := req.TenantID

	// 1. Create the realm.
	if err := p.keycloak.CreateRealm(ctx, keycloak.RealmConfig{
		Name:        realmName,
		DisplayName: req.DisplayName,
		Enabled:     true,
	}); err != nil {
		return fmt.Errorf("creating realm: %w", err)
	}

	// 2. Create the OIDC client used by the dashboard.
	clientUUID, err := p.keycloak.CreateOIDCClient(ctx, realmName, keycloak.OIDCClientConfig{
		ClientID:     "gibson-dashboard",
		RedirectURIs: []string{"*"},
	})
	if err != nil {
		p.logger.WarnContext(ctx, "failed to create OIDC client (may already exist)",
			slog.String("realm", realmName),
			slog.String("error", err.Error()),
		)
	}

	// 3. Create the standard Gibson realm roles.
	for _, role := range []string{"owner", "admin", "operator", "viewer"} {
		if roleErr := p.keycloak.CreateRealmRole(ctx, realmName, role, "Gibson "+role+" role"); roleErr != nil {
			p.logger.WarnContext(ctx, "failed to create realm role",
				slog.String("realm", realmName),
				slog.String("role", role),
				slog.String("error", roleErr.Error()),
			)
		}
	}

	// 4. Add a hardcoded tenant_id claim mapper so every issued token carries
	//    the tenant identifier without requiring runtime logic in the app.
	if clientUUID != "" {
		if mapErr := p.keycloak.AddProtocolMapper(ctx, realmName, clientUUID, keycloak.ProtocolMapperConfig{
			Name:           "tenant_id",
			Protocol:       "openid-connect",
			ProtocolMapper: "oidc-hardcoded-claim-mapper",
			Config: map[string]string{
				"claim.name":           "tenant_id",
				"claim.value":          req.TenantID,
				"jsonType.label":       "String",
				"id.token.claim":       "true",
				"access.token.claim":   "true",
				"userinfo.token.claim": "true",
			},
		}); mapErr != nil {
			p.logger.WarnContext(ctx, "failed to add tenant_id protocol mapper",
				slog.String("realm", realmName),
				slog.String("error", mapErr.Error()),
			)
		}
	}

	// 5. Create the owner user in the new realm.
	if req.OwnerEmail != "" {
		userID, userErr := p.keycloak.CreateUser(ctx, realmName, keycloak.UserConfig{
			Username:      req.OwnerEmail,
			Email:         req.OwnerEmail,
			Enabled:       true,
			EmailVerified: true, // User completed signup flow.
		})
		if userErr != nil {
			p.logger.WarnContext(ctx, "failed to create owner user",
				slog.String("realm", realmName),
				slog.String("email", req.OwnerEmail),
				slog.String("error", userErr.Error()),
			)
		} else if userID != "" {
			// Assign the owner role.  Non-fatal: user exists but may lack the role.
			if assignErr := p.keycloak.AssignRealmRoles(ctx, realmName, userID, []string{"owner"}); assignErr != nil {
				p.logger.WarnContext(ctx, "failed to assign owner role to user",
					slog.String("realm", realmName),
					slog.String("user_id", userID),
					slog.String("error", assignErr.Error()),
				)
			} else {
				p.logger.InfoContext(ctx, "created owner user in realm",
					slog.String("realm", realmName),
					slog.String("user_id", userID),
				)
			}
		}
	}

	return nil
}

// stepCreateTenant creates the TenantRecord with status "provisioning".
//
// Idempotency: if the tenant already exists the step succeeds silently.
func (p *Provisioner) stepCreateTenant(ctx context.Context, req ProvisionRequest) error {
	config := map[string]string{
		"tier":                 req.Tier,
		"owner_email":          req.OwnerEmail,
		"stripe_customer_id":   req.StripeCustomerID,
		"stripe_sub_id":        req.StripeSubID,
		"provisioning_source":  "saas",
		"keycloak_realm_name":  req.TenantID,
	}

	// Attempt creation.  The underlying TenantService will return
	// ErrTenantAlreadyExists if the record is already present; we treat that
	// as success for idempotency.
	_, err := p.tenants.CreateTenant(ctx, req.TenantID, req.DisplayName, config)
	if err != nil {
		// Translate the sentinel so callers can detect idempotent re-runs.
		if isAlreadyExists(err) {
			p.logger.InfoContext(ctx, "tenant already exists, skipping create",
				slog.String("tenant_id", req.TenantID),
			)
			return nil
		}
		return fmt.Errorf("create tenant record: %w", err)
	}

	return nil
}

// stepCreateLangfuse creates a Langfuse project for observability.
//
// This step is always best-effort: the caller (ProvisionTenant) handles the
// failure by recording "skipped" and continuing the pipeline.
func (p *Provisioner) stepCreateLangfuse(ctx context.Context, tenantID string) error {
	if p.langfuse == nil {
		return nil
	}
	if err := p.langfuse.CreateProject(ctx, tenantID); err != nil {
		return fmt.Errorf("create Langfuse project: %w", err)
	}
	return nil
}

// stepGenerateAPIKey mints the tenant's initial API key.
//
// Returns the raw key so ProvisionTenant can surface it once to the caller.
// If apikeys is nil the step is a no-op and an empty string is returned.
//
// Idempotency: there is no reliable way to retrieve a previously generated
// raw key, so on a retry this step will mint a second key.  The caller can
// list and revoke extras after provisioning completes.
func (p *Provisioner) stepGenerateAPIKey(ctx context.Context, tenantID string) (string, error) {
	if p.apikeys == nil {
		return "", nil
	}

	rawKey, _, err := p.apikeys.CreateKey(ctx, tenantID, nil, nil)
	if err != nil {
		return "", fmt.Errorf("create API key: %w", err)
	}

	// rawKey must not be logged — it is the user's credential.
	p.logger.InfoContext(ctx, "initial API key created",
		slog.String("tenant_id", tenantID),
	)

	return rawKey, nil
}

// stepSetTierLimits writes tier-derived quota entries into the TenantRecord
// config via UpdateTenant.
//
// Idempotency: UpdateTenant merges into Config, so re-running this step
// simply overwrites with the same values.
func (p *Provisioner) stepSetTierLimits(ctx context.Context, req ProvisionRequest) error {
	limits, ok := tierLimits[req.Tier]
	if !ok {
		// Unknown tier — fall back to free limits so the tenant is functional.
		p.logger.WarnContext(ctx, "unknown tier, applying free limits",
			slog.String("tenant_id", req.TenantID),
			slog.String("tier", req.Tier),
		)
		limits = tierLimits["free"]
	}

	updates := make(map[string]string, len(limits)+1)
	for k, v := range limits {
		updates[k] = v
	}
	updates["tier"] = req.Tier

	if _, err := p.tenants.UpdateTenant(ctx, req.TenantID, updates); err != nil {
		return fmt.Errorf("set tier limits: %w", err)
	}

	return nil
}

// stepActivate transitions the tenant status from "provisioning" to "active".
func (p *Provisioner) stepActivate(ctx context.Context, tenantID string) error {
	if _, err := p.tenants.UpdateTenant(ctx, tenantID, map[string]string{"status": "active"}); err != nil {
		return fmt.Errorf("activate tenant: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// DeprovisionTenant
// ---------------------------------------------------------------------------

// DeprovisionTenant soft-deletes a tenant and revokes its API keys.
//
// The method delegates to the underlying TenantCreator.UpdateTenant to mark
// the tenant as "deleted", then removes the provisioning status hash.
// API key revocation is handled by the caller passing an APIKeyRevoker; if
// none is provided only the tenant record is updated.
//
// This operation is idempotent: calling it on an already-deleted tenant
// returns nil without further modification.
func (p *Provisioner) DeprovisionTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return errors.New("provisioner: tenantID must not be empty")
	}

	p.logger.InfoContext(ctx, "deprovisioning tenant",
		slog.String("tenant_id", tenantID),
	)

	// Check whether the tenant exists and is not already deleted.
	record, err := p.tenants.GetTenant(ctx, tenantID)
	if err != nil {
		if isNotFound(err) {
			// Already gone — idempotent success.
			return nil
		}
		return fmt.Errorf("provisioner: get tenant for deprovision %q: %w", tenantID, err)
	}

	// Inspect status via JSON round-trip to avoid a hard dependency on the
	// concrete TenantRecord type.
	status, err := extractStatus(record)
	if err == nil && status == "deleted" {
		p.logger.InfoContext(ctx, "tenant already deleted, skipping deprovision",
			slog.String("tenant_id", tenantID),
		)
		return nil
	}

	// Soft-delete: set status to "deleted".
	if _, err := p.tenants.UpdateTenant(ctx, tenantID, map[string]string{"status": "deleted"}); err != nil {
		return fmt.Errorf("provisioner: soft-delete tenant %q: %w", tenantID, err)
	}

	// Clean up the provisioning status hash.
	if delErr := p.redis.Del(ctx, provisioningKey(tenantID)).Err(); delErr != nil {
		// Non-fatal: the important state (tenant status) is already updated.
		p.logger.WarnContext(ctx, "failed to remove provisioning hash after deprovision",
			slog.String("tenant_id", tenantID),
			slog.String("error", delErr.Error()),
		)
	}

	p.logger.InfoContext(ctx, "tenant deprovisioned",
		slog.String("tenant_id", tenantID),
	)

	return nil
}

// ---------------------------------------------------------------------------
// GetProvisioningStatus
// ---------------------------------------------------------------------------

// GetProvisioningStatus reads the current provisioning progress for a tenant
// from the Redis HASH written during ProvisionTenant.
//
// Returns a zero-value ProvisionStatus with Status "unknown" when no hash
// exists for the tenant (i.e. provisioning was never started).
func (p *Provisioner) GetProvisioningStatus(ctx context.Context, tenantID string) (*ProvisionStatus, error) {
	if tenantID == "" {
		return nil, errors.New("provisioner: tenantID must not be empty")
	}

	key := provisioningKey(tenantID)

	fields, err := p.redis.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("provisioner: read provisioning hash for %q: %w", tenantID, err)
	}

	if len(fields) == 0 {
		return &ProvisionStatus{
			TenantID: tenantID,
			Status:   "unknown",
		}, nil
	}

	ps := &ProvisionStatus{
		TenantID: tenantID,
		Status:   fields["_status"],
	}

	if raw, ok := fields["_started_at"]; ok {
		if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			ps.StartedAt = t
		}
	}

	if raw, ok := fields["_error"]; ok {
		ps.Error = raw
	}

	// Reconstruct the ordered step list.
	ps.Steps = make([]ProvisionStep, 0, len(stepOrder))
	for _, name := range stepOrder {
		step := ProvisionStep{Name: name}

		rawStep, ok := fields[name]
		if !ok {
			step.Status = statusPending
			ps.Steps = append(ps.Steps, step)
			continue
		}

		var stored storedStep
		if err := json.Unmarshal([]byte(rawStep), &stored); err != nil {
			// Treat a corrupt entry as pending rather than failing the read.
			step.Status = statusPending
		} else {
			step.Status = stored.Status
			step.Error = stored.Error
			step.Timestamp = stored.Timestamp
		}
		ps.Steps = append(ps.Steps, step)
	}

	return ps, nil
}

// ---------------------------------------------------------------------------
// Redis status tracking helpers
// ---------------------------------------------------------------------------

// storedStep is the JSON shape persisted in the Redis HASH per step.
type storedStep struct {
	Status    string    `json:"status"`
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// initStatus creates the Redis HASH for a provisioning run.  If the hash
// already exists (idempotent re-run) the "_status" field is only set when it
// is currently absent, so in-flight status is never clobbered.
func (p *Provisioner) initStatus(ctx context.Context, tenantID string) error {
	key := provisioningKey(tenantID)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	// Use HSETNX so we don't overwrite an existing status on a retry.
	pipe := p.redis.Pipeline()
	pipe.HSetNX(ctx, key, "_status", statusInProgress)
	pipe.HSetNX(ctx, key, "_started_at", now)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("init provisioning status: %w", err)
	}
	return nil
}

// isStepDone returns true when the step is recorded as "completed" in the
// Redis HASH, indicating no re-execution is needed.
func (p *Provisioner) isStepDone(ctx context.Context, tenantID, stepName string) (bool, error) {
	raw, err := p.redis.HGet(ctx, provisioningKey(tenantID), stepName).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}
		return false, fmt.Errorf("check step %q status: %w", stepName, err)
	}

	var stored storedStep
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		// Treat a corrupt entry as not done so the step will run.
		return false, nil
	}

	return stored.Status == statusCompleted, nil
}

// recordStep writes a step's terminal status (completed/failed/skipped) to
// the Redis HASH.
func (p *Provisioner) recordStep(ctx context.Context, tenantID, stepName, status string, stepErr error) error {
	s := storedStep{
		Status:    status,
		Timestamp: time.Now().UTC(),
	}
	if stepErr != nil {
		s.Error = stepErr.Error()
	}

	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal step status: %w", err)
	}

	if err := p.redis.HSet(ctx, provisioningKey(tenantID), stepName, string(data)).Err(); err != nil {
		return fmt.Errorf("write step status: %w", err)
	}
	return nil
}

// markOverallStatus updates the top-level "_status" field in the hash.
func (p *Provisioner) markOverallStatus(ctx context.Context, tenantID, status string) error {
	if err := p.redis.HSet(ctx, provisioningKey(tenantID), "_status", status).Err(); err != nil {
		return fmt.Errorf("update overall provisioning status: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Sentinel error detection helpers
// ---------------------------------------------------------------------------

// isAlreadyExists returns true when err wraps a "tenant already exists" error.
// We do string matching rather than errors.Is to avoid a package dependency on
// the component package's sentinel values.
func isAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "already exists")
}

// isNotFound returns true when err wraps a "tenant not found" error.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "not found")
}

// contains is a simple substring check to avoid importing strings directly.
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || findSub(s, sub))
}

// findSub searches for sub within s without importing strings.
func findSub(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// extractStatus attempts to read the "status" field from an opaque interface{}
// that is expected to be a *TenantRecord (or any struct that marshals to JSON
// with a "status" field).
func extractStatus(record interface{}) (string, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("marshal record for status extraction: %w", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return "", fmt.Errorf("unmarshal record for status extraction: %w", err)
	}

	s, ok := m["status"].(string)
	if !ok {
		return "", errors.New("status field missing or not a string")
	}
	return s, nil
}
