// Package provisioner — signup_event.go
//
// Defines SignupEventType constants, Redis stream constants, and the
// SignupState struct that mirrors the tenant_provisioning table schema
// for in-process state tracking during the signup pipeline.
//
// This file contains no business logic — it is the shared vocabulary for the
// signup pipeline, pipeline consumer, and individual step handlers.
//
// Better Auth migration notes:
//   - EventSignupOrgCreated has been removed: Better Auth creates the user and
//     organisation inside the dashboard before calling InitiateSignup, so the
//     daemon pipeline no longer needs an "org" step.
//   - SignupStateKeyFmt has been removed: provisioning state is now stored in
//     the tenant_provisioning Postgres table, not in Redis HASH keys.
//   - The pipeline now routes EventSignupRequested directly to handleFGA.
package provisioner

// SignupEventType identifies the type of a signup pipeline event.
type SignupEventType string

const (
	// EventSignupRequested is the initial event emitted by InitiateSignup.
	// The FGAHandler now consumes this event directly (org creation is handled
	// by Better Auth in the dashboard before InitiateSignup is called).
	EventSignupRequested SignupEventType = "signup.requested"

	// EventSignupFGAWritten is emitted by FGAHandler on success.
	// The ProvisionHandler consumes this event.
	EventSignupFGAWritten SignupEventType = "signup.fga_written"

	// EventSignupCompleted is emitted by ProvisionHandler on success.
	// The provisioning page sees status=active after this event.
	EventSignupCompleted SignupEventType = "signup.completed"

	// EventSignupStepFailed is emitted when a handler fails.
	// The pipeline consumer retries up to 3 times before emitting EventSignupFailed.
	EventSignupStepFailed SignupEventType = "signup.step_failed"

	// EventSignupFailed is emitted after all retries are exhausted.
	// The provisioning page sees status=failed after this event.
	EventSignupFailed SignupEventType = "signup.failed"
)

// String returns the string representation of the SignupEventType.
func (t SignupEventType) String() string {
	return string(t)
}

// Redis Stream constants for the signup pipeline.
const (
	// SignupStreamKey is the Redis Stream key used to publish and consume
	// signup pipeline events. The pipeline consumer group reads from this stream.
	SignupStreamKey = "signup:events:stream"

	// SignupConsumerGroup is the Redis consumer group name for the signup pipeline.
	// Each daemon pod subscribes with its hostname as the consumer name, providing
	// pod-level isolation for the Pending Entries List (PEL).
	SignupConsumerGroup = "signup-pipeline"
)

// SignupState holds the in-process provisioning state for a signup.
//
// This struct is populated from the tenant_provisioning Postgres table
// by PgProvisioningStore.Get(). Fields map to table columns.
//
// The OrgID and RetryCountOrg fields have been removed:
//   - OrgID: Keycloak org creation is no longer a daemon pipeline step.
//     Better Auth creates the organisation in the dashboard.
//   - RetryCountOrg: the org step no longer exists, so its retry counter
//     is also gone.
type SignupState struct {
	// Status is the overall signup status:
	// "requested", "provisioning", "active", "failed".
	Status string

	// Email is the new user's email address.
	Email string

	// CompanyName is the human-readable organisation name submitted at signup.
	CompanyName string

	// TenantID is the slugified company_name used as the Better Auth org slug,
	// FGA tenant object, and tenant_provisioning.tenant_slug.
	TenantID string

	// Plan is the billing plan ("free", "indie", "pro", "team", "business",
	// "enterprise").
	Plan string

	// CurrentStep is the name of the step currently being executed or most
	// recently completed ("fga", "provision").
	CurrentStep string

	// StepStatuses maps step name to its status string
	// ("pending", "running", "completed", "failed").
	// Keys: "fga", "provision".
	StepStatuses map[string]string

	// Error is the error message from the last failed step.
	// Empty when status is not "failed".
	Error string

	// RetryCountFGA is the number of times FGAHandler has been retried.
	RetryCountFGA int

	// RetryCountProv is the number of times ProvisionHandler has been retried.
	RetryCountProv int

	// CreatedAt is the Unix timestamp (seconds) when the signup was initiated.
	CreatedAt int64

	// CompletedAt is the Unix timestamp (seconds) when provisioning completed.
	// Zero when not yet completed.
	CompletedAt int64
}
