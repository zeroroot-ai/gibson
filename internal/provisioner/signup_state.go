// Package provisioner — signup_state.go
//
// ProvisioningStateStore is the interface for CRUD operations on signup
// provisioning state. Implementations may be backed by Postgres (production)
// or a test double.
//
// PgProvisioningStore is the Postgres-backed implementation that reads and
// writes the tenant_provisioning table. It replaces the previous Redis
// HASH-backed SignupStateStore.
//
// Design principles:
//   - No business logic. The store is a thin CRUD layer.
//   - No retries. Callers (pipeline, handlers) own retry decisions.
//   - Fail fast on database errors. Every method returns the raw error.
//   - Parameterised queries only ($1, $2, …). No string interpolation.
package provisioner

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// ProvisioningStateStore defines the CRUD operations on provisioning state
// used by the signup pipeline and its step handlers.
//
// All implementations must be safe for concurrent use.
type ProvisioningStateStore interface {
	// Create inserts a new provisioning record for the given user.
	// If a record already exists for the user it is overwritten (idempotent re-init).
	Create(ctx context.Context, userID string, state SignupState) error

	// Get retrieves the provisioning state for the given user.
	// Returns (nil, nil) when no record exists.
	Get(ctx context.Context, userID string) (*SignupState, error)

	// UpdateField sets a single named field in the provisioning record.
	// Recognised field names: "status", "current_step", "error",
	// "step_status_fga", "step_status_provision".
	UpdateField(ctx context.Context, userID, field, value string) error

	// IncrRetry atomically increments the retry counter for the given step
	// ("fga", "provision") in the step_statuses JSONB column and returns the
	// new count.
	IncrRetry(ctx context.Context, userID, step string) (int, error)

	// SetFailed transitions the record to status=failed with the supplied
	// step name and error message.
	SetFailed(ctx context.Context, userID, step, errMsg string) error

	// SetCompleted transitions the record to status=active and sets completed_at.
	SetCompleted(ctx context.Context, userID string) error
}

// PgProvisioningStore is the Postgres-backed implementation of
// ProvisioningStateStore. It operates against the tenant_provisioning table
// created by RunMigrations.
type PgProvisioningStore struct {
	db *sql.DB
}

// NewPgProvisioningStore creates a PgProvisioningStore backed by the given
// *sql.DB. The db must be non-nil.
func NewPgProvisioningStore(db *sql.DB) *PgProvisioningStore {
	if db == nil {
		panic("signup_state: db must not be nil")
	}
	return &PgProvisioningStore{db: db}
}

// Create inserts or replaces the provisioning record for the given user.
//
// Uses INSERT … ON CONFLICT (user_id) DO UPDATE to make the call idempotent:
// re-initiating a signup for the same user resets all fields to the supplied
// state values.
func (s *PgProvisioningStore) Create(ctx context.Context, userID string, state SignupState) error {
	// Serialise step_statuses map to JSONB.
	stepJSON, err := marshalStepStatuses(state.StepStatuses)
	if err != nil {
		return fmt.Errorf("signup_state: Create for user %q: %w", userID, err)
	}

	const query = `
INSERT INTO tenant_provisioning (
    user_id, tenant_slug, org_name, email, plan,
    status, current_step, step_statuses, error,
    created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9,
    now(), now()
)
ON CONFLICT (user_id) DO UPDATE SET
    tenant_slug   = EXCLUDED.tenant_slug,
    org_name      = EXCLUDED.org_name,
    email         = EXCLUDED.email,
    plan          = EXCLUDED.plan,
    status        = EXCLUDED.status,
    current_step  = EXCLUDED.current_step,
    step_statuses = EXCLUDED.step_statuses,
    error         = EXCLUDED.error,
    updated_at    = now()`

	_, execErr := s.db.ExecContext(ctx, query,
		userID,
		state.TenantID,
		state.CompanyName,
		state.Email,
		state.Plan,
		state.Status,
		state.CurrentStep,
		stepJSON,
		state.Error,
	)
	if execErr != nil {
		return fmt.Errorf("signup_state: Create for user %q: %w", userID, execErr)
	}
	return nil
}

// Get retrieves the provisioning record for the given user.
// Returns (nil, nil) when no record exists (sql.ErrNoRows is not an error here).
func (s *PgProvisioningStore) Get(ctx context.Context, userID string) (*SignupState, error) {
	const query = `
SELECT tenant_slug, org_name, email, plan, status,
       current_step, step_statuses, error,
       EXTRACT(EPOCH FROM created_at)::BIGINT,
       COALESCE(EXTRACT(EPOCH FROM completed_at)::BIGINT, 0)
FROM   tenant_provisioning
WHERE  user_id = $1`

	var (
		tenantSlug   string
		orgName      string
		email        string
		plan         string
		status       string
		currentStep  string
		stepJSON     []byte
		errMsg       string
		createdAt    int64
		completedAt  int64
	)

	err := s.db.QueryRowContext(ctx, query, userID).Scan(
		&tenantSlug,
		&orgName,
		&email,
		&plan,
		&status,
		&currentStep,
		&stepJSON,
		&errMsg,
		&createdAt,
		&completedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("signup_state: Get for user %q: %w", userID, err)
	}

	stepStatuses, err := unmarshalStepStatuses(stepJSON)
	if err != nil {
		return nil, fmt.Errorf("signup_state: Get for user %q: unmarshal step_statuses: %w", userID, err)
	}

	return &SignupState{
		Status:       status,
		Email:        email,
		CompanyName:  orgName,
		TenantID:     tenantSlug,
		Plan:         plan,
		CurrentStep:  currentStep,
		StepStatuses: stepStatuses,
		Error:        errMsg,
		CreatedAt:    createdAt,
		CompletedAt:  completedAt,
	}, nil
}

// UpdateField sets a single named field on the provisioning record.
//
// Supported field names and their SQL column mappings:
//
//	"status"              → status
//	"current_step"        → current_step
//	"error"               → error
//	"step_status_fga"     → step_statuses JSONB path update for "fga" key
//	"step_status_provision" → step_statuses JSONB path update for "provision" key
func (s *PgProvisioningStore) UpdateField(ctx context.Context, userID, field, value string) error {
	var query string
	var args []interface{}

	switch field {
	case "status":
		query = `UPDATE tenant_provisioning SET status = $2, updated_at = now() WHERE user_id = $1`
		args = []interface{}{userID, value}
	case "current_step":
		query = `UPDATE tenant_provisioning SET current_step = $2, updated_at = now() WHERE user_id = $1`
		args = []interface{}{userID, value}
	case "error":
		query = `UPDATE tenant_provisioning SET error = $2, updated_at = now() WHERE user_id = $1`
		args = []interface{}{userID, value}
	case "step_status_fga":
		query = `UPDATE tenant_provisioning
		         SET step_statuses = jsonb_set(step_statuses, '{fga}', to_jsonb($2::text), true),
		             updated_at = now()
		         WHERE user_id = $1`
		args = []interface{}{userID, value}
	case "step_status_provision":
		query = `UPDATE tenant_provisioning
		         SET step_statuses = jsonb_set(step_statuses, '{provision}', to_jsonb($2::text), true),
		             updated_at = now()
		         WHERE user_id = $1`
		args = []interface{}{userID, value}
	default:
		return fmt.Errorf("signup_state: UpdateField: unsupported field %q", field)
	}

	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("signup_state: UpdateField %q for user %q: %w", field, userID, err)
	}
	return nil
}

// IncrRetry atomically increments the retry counter for the given step in the
// step_statuses JSONB column and returns the new count.
//
// The counter is stored as a numeric value at the path {step}_retry in the
// step_statuses object, e.g. step_statuses->'fga_retry'.
//
// Supported step names: "fga", "provision".
func (s *PgProvisioningStore) IncrRetry(ctx context.Context, userID, step string) (int, error) {
	// Validate step against the known set to prevent any inadvertent SQL injection
	// (step values come from internal constants, never user input).
	knownSteps := map[string]string{
		"fga":       "fga_retry",
		"provision": "provision_retry",
	}
	retryKey, ok := knownSteps[step]
	if !ok {
		return 0, fmt.Errorf("signup_state: IncrRetry: unknown step %q", step)
	}

	// JSON path for jsonb_set, e.g. '{fga_retry}'.
	// This is safe to embed in the query because retryKey comes from a fixed map.
	path := "{" + retryKey + "}"

	// Atomically increment the retry counter stored in step_statuses JSONB.
	// The query reads the current value with COALESCE (defaulting to 0), adds 1,
	// writes it back via jsonb_set, and returns the updated value.
	// The path and key are embedded as literals (not user input) for jsonb_set
	// because the jsonb_set path argument cannot be passed as a query parameter.
	query := `
UPDATE tenant_provisioning
SET    step_statuses = jsonb_set(
           step_statuses,
           '` + path + `',
           to_jsonb(COALESCE((step_statuses->>'` + retryKey + `')::INT, 0) + 1),
           true
       ),
       updated_at = now()
WHERE  user_id = $1
RETURNING COALESCE((step_statuses->>'` + retryKey + `')::INT, 0) + 1`

	var newCount int
	err := s.db.QueryRowContext(ctx, query, userID).Scan(&newCount)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("signup_state: IncrRetry %q for user %q: record not found", step, userID)
	}
	if err != nil {
		return 0, fmt.Errorf("signup_state: IncrRetry %q for user %q: %w", step, userID, err)
	}
	return newCount, nil
}

// SetFailed transitions the record to status=failed with the given step and
// error message.
func (s *PgProvisioningStore) SetFailed(ctx context.Context, userID, step, errMsg string) error {
	const query = `
UPDATE tenant_provisioning
SET    status       = 'failed',
       current_step = $2,
       error        = $3,
       updated_at   = now()
WHERE  user_id = $1`

	if _, err := s.db.ExecContext(ctx, query, userID, step, errMsg); err != nil {
		return fmt.Errorf("signup_state: SetFailed for user %q step %q: %w", userID, step, err)
	}
	return nil
}

// SetCompleted transitions the record to status=active and stamps completed_at.
// Using "active" matches the tenant_provisioning CHECK constraint.
func (s *PgProvisioningStore) SetCompleted(ctx context.Context, userID string) error {
	const query = `
UPDATE tenant_provisioning
SET    status       = 'active',
       completed_at = now(),
       updated_at   = now()
WHERE  user_id = $1`

	if _, err := s.db.ExecContext(ctx, query, userID); err != nil {
		return fmt.Errorf("signup_state: SetCompleted for user %q: %w", userID, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

// marshalStepStatuses serialises the step_statuses map to a JSON byte slice
// suitable for insertion into a JSONB column. A nil map becomes "{}".
func marshalStepStatuses(statuses map[string]string) ([]byte, error) {
	if statuses == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(statuses)
}

// unmarshalStepStatuses deserialises the JSONB step_statuses column into a
// map[string]string. An empty or null JSON object returns an empty (non-nil) map.
func unmarshalStepStatuses(data []byte) (map[string]string, error) {
	if len(data) == 0 || string(data) == "null" {
		return map[string]string{}, nil
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]string{}
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Compile-time interface guard
// ---------------------------------------------------------------------------

// Ensure PgProvisioningStore satisfies ProvisioningStateStore at compile time.
var _ ProvisioningStateStore = (*PgProvisioningStore)(nil)

// ---------------------------------------------------------------------------
// Time sentinel (used by SetCompleted idempotency check callers)
// ---------------------------------------------------------------------------

// nowUnix returns the current Unix timestamp in seconds.
// Kept as a variable so tests can override it.
var nowUnix = func() int64 { return time.Now().Unix() }
