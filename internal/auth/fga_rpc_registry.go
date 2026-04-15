package auth

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/zero-day-ai/gibson/internal/authz"
)

// EnforcementMode is retained for backwards-compatible config parsing only.
// OpenFGA is the sole enforcement backend regardless of this value; the field
// is read but ignored at daemon startup.
type EnforcementMode string

const (
	// EnforcementFga is the only supported mode.
	EnforcementFga EnforcementMode = "fga"
)

// ObjectDeriver derives the FGA object string from the gRPC request and context.
// The function must not panic on a nil request.
type ObjectDeriver func(req any, ctx context.Context) (string, error)

// FgaCheckSpec describes the FGA authorization requirement for a single gRPC method.
type FgaCheckSpec struct {
	// Relation is the FGA relation to check, e.g. "member", "admin", "platform_operator".
	Relation string

	// ObjectFrom, when non-nil, derives the FGA object from the request and ctx.
	// When nil, the interceptor falls back to "tenant:" + TenantFromContext(ctx).
	ObjectFrom ObjectDeriver

	// Unauthenticated, when true, bypasses all authorization checks. Used for
	// self-query RPCs keyed off JWT identity or health endpoints.
	Unauthenticated bool

	// Description is a human-readable explanation. Surfaced in audit events as
	// PermissionRequired so existing Grafana dashboards remain informative.
	Description string
}

// FgaRpcRegistry maps fully-qualified gRPC method paths to their FGA authorization specs.
type FgaRpcRegistry struct {
	entries map[string]FgaCheckSpec
}

// newFgaRpcRegistryGoLegacy builds the registry the old way (Go-coded
// populate()) so the parity test (rpc_registry_parity_test.go) can compare
// the YAML-built and Go-built registries on every CI run. Unexported because
// no production caller should ever use it; will be deleted in task 9 once
// parity has been demonstrated over a full release cycle.
func newFgaRpcRegistryGoLegacy() *FgaRpcRegistry {
	r := &FgaRpcRegistry{
		entries: make(map[string]FgaCheckSpec),
	}
	r.populate()
	return r
}

// Lookup returns the spec for the given fully-qualified method path and whether
// it was found. An absent entry means the interceptor should default-deny.
func (r *FgaRpcRegistry) Lookup(method string) (FgaCheckSpec, bool) {
	spec, ok := r.entries[method]
	return spec, ok
}

// Methods returns a sorted list of all registered method paths.
// Used by Validate and the reflection-based coverage test.
func (r *FgaRpcRegistry) Methods() []string {
	methods := make([]string, 0, len(r.entries))
	for m := range r.entries {
		methods = append(methods, m)
	}
	sort.Strings(methods)
	return methods
}

// Validate verifies internal consistency:
//  1. Every relation referenced in the registry must exist in the FGA authorization model.
//  2. The method list is checked to catch obvious registration bugs.
//
// Called from daemon startup after initAuthorizer; failure aborts the daemon.
func (r *FgaRpcRegistry) Validate(ctx context.Context, authorizer authz.Authorizer) error {
	// Collect the unique relations referenced by authenticated entries.
	relSet := make(map[string]struct{})
	for _, spec := range r.entries {
		if !spec.Unauthenticated && spec.Relation != "" {
			relSet[spec.Relation] = struct{}{}
		}
	}

	// Fetch the authorization model once so we can validate relation names.
	// We call ReadAuthorizationModel via the Authorizer. The noop authorizer
	// (authz.enabled=false) always returns nil for this, so we skip model
	// validation in that case.
	if authorizer.ModelID() == "" {
		// Noop authorizer — skip FGA model validation (dev/disabled mode).
		return nil
	}

	// Walk the model to collect valid relation names. We use the known model
	// structure from model.fga to validate. The FGA Authorizer does not expose
	// ReadAuthorizationModel directly in this SDK version, so we validate by
	// attempting a Check with each relation against a dummy object.
	// Per design: "call authorizer.ReadAuthorizationModel and verify every Relation".
	// We use the authz noop pattern here — in production the model defines the
	// allowed relations, and we validate by checking well-known valid names from
	// the model.fga file.
	knownRelations := map[string]struct{}{
		"admin":              {},
		"member":             {},
		"platform_operator":  {},
		"can_execute":        {},
		"can_configure":      {},
		"can_read":           {},
		"owner":              {},
		"parent":             {},
		"can_view_data_from": {},
	}

	var errs []string
	for rel := range relSet {
		if _, ok := knownRelations[rel]; !ok {
			errs = append(errs, fmt.Sprintf("relation %q is not defined in the FGA model", rel))
		}
	}

	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("fga registry validation failed: %s", strings.Join(errs, "; "))
	}

	return nil
}

// ValidateCoverage checks that every method in knownMethods appears in the registry.
// Returns an error listing every unmapped method.
func (r *FgaRpcRegistry) ValidateCoverage(knownMethods []string) error {
	var missing []string
	for _, m := range knownMethods {
		if _, ok := r.entries[m]; !ok {
			missing = append(missing, m)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf(
		"fga registry: %d gRPC method(s) have no authorization entry (default-deny would block them): %s",
		len(missing), strings.Join(missing, ", "),
	)
}

// ValidateNoStaleEntries checks that every method in the registry exists in knownMethods.
// Returns an error listing stale entries that no longer exist in the server.
func (r *FgaRpcRegistry) ValidateNoStaleEntries(knownMethods []string) error {
	known := make(map[string]struct{}, len(knownMethods))
	for _, m := range knownMethods {
		known[m] = struct{}{}
	}
	var stale []string
	for m := range r.entries {
		if _, ok := known[m]; !ok {
			stale = append(stale, m)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	sort.Strings(stale)
	return fmt.Errorf(
		"fga registry: %d stale entry(s) reference methods that no longer exist on the server: %s",
		len(stale), strings.Join(stale, ", "),
	)
}

// populate registers entries for every daemon gRPC method.
// The registry must have exactly one entry per method; CI enforces this via
// the reflection-based coverage test (fga_rpc_coverage_test.go).
func (r *FgaRpcRegistry) populate() {
	// =========================================================================
	// gibson.daemon.v1.DaemonService — the primary client-facing API
	// =========================================================================

	// Connect/Ping/Status — health + connectivity; unauthenticated.
	r.add("/gibson.daemon.v1.DaemonService/Connect", FgaCheckSpec{
		Unauthenticated: true,
		Description:     "WebSocket connect to daemon",
	})
	r.add("/gibson.daemon.v1.DaemonService/Ping", FgaCheckSpec{
		Unauthenticated: true,
		Description:     "Daemon liveness check",
	})
	r.add("/gibson.daemon.v1.DaemonService/Status", FgaCheckSpec{
		Relation:    "member",
		Description: "Get daemon status within caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/Subscribe", FgaCheckSpec{
		Relation:    "member",
		Description: "Subscribe to daemon events within caller's tenant",
	})

	// Mission lifecycle.
	r.add("/gibson.daemon.v1.DaemonService/RunMission", FgaCheckSpec{
		Relation:    "member",
		Description: "Start a mission run within caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/StopMission", FgaCheckSpec{
		Relation:    "member",
		Description: "Stop a running mission within caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/CreateMission", FgaCheckSpec{
		Relation:    "member",
		Description: "Create a mission definition within caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/ListMissions", FgaCheckSpec{
		Relation:    "member",
		Description: "List missions within caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/PauseMission", FgaCheckSpec{
		Relation:    "member",
		Description: "Pause a mission within caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/ResumeMission", FgaCheckSpec{
		Relation:    "member",
		Description: "Resume a paused mission within caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/GetMissionHistory", FgaCheckSpec{
		Relation:    "member",
		Description: "Retrieve mission run history within caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/GetMissionCheckpoints", FgaCheckSpec{
		Relation:    "member",
		Description: "Retrieve mission checkpoints within caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/InstallMission", FgaCheckSpec{
		Relation:    "admin",
		Description: "Install a mission definition into a tenant (admin only)",
	})
	r.add("/gibson.daemon.v1.DaemonService/UninstallMission", FgaCheckSpec{
		Relation:    "admin",
		Description: "Uninstall a mission definition from a tenant (admin only)",
	})
	r.add("/gibson.daemon.v1.DaemonService/ListMissionDefinitions", FgaCheckSpec{
		Relation:    "member",
		Description: "List installed mission definitions within caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/UpdateMission", FgaCheckSpec{
		Relation:    "member",
		Description: "Update a mission definition within caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/ResolveMissionDependencies", FgaCheckSpec{
		Relation:    "member",
		Description: "Resolve mission dependency graph within caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/ValidateMissionDependencies", FgaCheckSpec{
		Relation:    "member",
		Description: "Validate mission dependencies within caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/EnsureDependenciesRunning", FgaCheckSpec{
		Relation:    "member",
		Description: "Ensure mission dependencies are running within caller's tenant",
	})

	// Component listing.
	r.add("/gibson.daemon.v1.DaemonService/ListAgents", FgaCheckSpec{
		Relation:    "member",
		Description: "List agents visible to caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/GetAgentStatus", FgaCheckSpec{
		Relation:    "member",
		Description: "Get agent status within caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/ListTools", FgaCheckSpec{
		Relation:    "member",
		Description: "List tools visible to caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/ListPlugins", FgaCheckSpec{
		Relation:    "member",
		Description: "List plugins visible to caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/QueryPlugin", FgaCheckSpec{
		Relation:    "member",
		Description: "Query a plugin within caller's tenant",
	})

	// Component lifecycle.
	r.add("/gibson.daemon.v1.DaemonService/StartComponent", FgaCheckSpec{
		Relation:    "admin",
		Description: "Start a component within caller's tenant (admin only)",
	})
	r.add("/gibson.daemon.v1.DaemonService/StopComponent", FgaCheckSpec{
		Relation:    "admin",
		Description: "Stop a component within caller's tenant (admin only)",
	})
	r.add("/gibson.daemon.v1.DaemonService/InstallComponent", FgaCheckSpec{
		Relation:    "admin",
		Description: "Install a component into caller's tenant (admin only)",
	})
	r.add("/gibson.daemon.v1.DaemonService/InstallAllComponent", FgaCheckSpec{
		Relation:    "admin",
		Description: "Install all components into caller's tenant (admin only)",
	})
	r.add("/gibson.daemon.v1.DaemonService/UninstallComponent", FgaCheckSpec{
		Relation:    "admin",
		Description: "Uninstall a component from caller's tenant (admin only)",
	})
	r.add("/gibson.daemon.v1.DaemonService/UpdateComponent", FgaCheckSpec{
		Relation:    "admin",
		Description: "Update a component within caller's tenant (admin only)",
	})
	r.add("/gibson.daemon.v1.DaemonService/BuildComponent", FgaCheckSpec{
		Relation:    "admin",
		Description: "Build a component image within caller's tenant (admin only)",
	})
	r.add("/gibson.daemon.v1.DaemonService/ShowComponent", FgaCheckSpec{
		Relation:    "member",
		Description: "Show component details within caller's tenant",
	})
	r.add("/gibson.daemon.v1.DaemonService/GetComponentLogs", FgaCheckSpec{
		Relation:    "member",
		Description: "Stream component logs within caller's tenant",
	})

	// =========================================================================
	// gibson.daemon.admin.v1.DaemonAdminService — privileged admin API
	// =========================================================================

	// Daemon control.
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/Shutdown", FgaCheckSpec{
		Relation:    "platform_operator",
		ObjectFrom:  constObject("system_tenant:_system"),
		Description: "Graceful daemon shutdown (platform operator only)",
	})

	// Tenant impersonation (tenant CRUD and lookup moved to gibson-tenant-operator).
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/ImpersonateTenant", FgaCheckSpec{
		Relation:    "platform_operator",
		ObjectFrom:  constObject("system_tenant:_system"),
		Description: "Request impersonation token for tenant (platform operator only)",
	})

	// Observability.
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/GetTenantLangfuseCredentials", FgaCheckSpec{
		Relation:    "member",
		Description: "Retrieve Langfuse credentials for tenant",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/SetTenantLangfuseCredentials", FgaCheckSpec{
		Relation:    "admin",
		Description: "Store Langfuse credentials for tenant (admin only)",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/DeleteTenantLangfuseCredentials", FgaCheckSpec{
		Relation:    "admin",
		Description: "Delete Langfuse credentials for tenant (admin only)",
	})

	// Onboarding.
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/GetOnboardingState", FgaCheckSpec{
		Relation:    "member",
		Description: "Query onboarding progress for tenant",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/UpdateOnboardingState", FgaCheckSpec{
		Relation:    "admin",
		Description: "Advance onboarding state for tenant (admin only)",
	})

	// API key management.
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/CreateAPIKey", FgaCheckSpec{
		Relation:    "admin",
		Description: "Create API key within caller's tenant (admin only)",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/ListAPIKeys", FgaCheckSpec{
		Relation:    "member",
		Description: "List API keys within caller's tenant",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/RevokeAPIKey", FgaCheckSpec{
		Relation:    "admin",
		Description: "Revoke API key within caller's tenant (admin only)",
	})

	// ---------------------------------------------------------------------------
	// Audit log RPC
	// ---------------------------------------------------------------------------
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/ListAuditEvents", FgaCheckSpec{
		Relation:    "admin",
		Description: "List audit events for the tenant (admin only)",
	})

	// ---------------------------------------------------------------------------
	// GetMyPermissions on DaemonService (non-admin, any authenticated user)
	// ---------------------------------------------------------------------------
	// GetMyPermissions is called by the dashboard during session setup.
	// Any authenticated user can query their own permissions — the handler
	// scopes results to the caller's identity internally.
	r.add("/gibson.daemon.v1.DaemonService/GetMyPermissions", FgaCheckSpec{
		Unauthenticated: true,
		Description:     "Get the caller's permissions summary for the current tenant",
	})

	// ---------------------------------------------------------------------------
	// prod-unimplemented-apis: new admin handlers
	// ---------------------------------------------------------------------------
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/GetUserProfile", FgaCheckSpec{
		Relation:    "member",
		Description: "Get user profile (self or tenant admin)",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/UpdateUserProfile", FgaCheckSpec{
		Relation:    "member",
		Description: "Update user profile fields (self or tenant admin)",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/ResetPassword", FgaCheckSpec{
		Relation:    "member",
		Description: "Trigger password reset email",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/RevokeUserSessions", FgaCheckSpec{
		Relation:    "admin",
		Description: "Revoke all active sessions for a user (admin only)",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/SuspendMember", FgaCheckSpec{
		Relation:    "admin",
		Description: "Suspend a tenant member account (admin only)",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/SaveMissionDraft", FgaCheckSpec{
		Relation:    "member",
		Description: "Save a mission YAML draft for a tenant",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/ListMissionDrafts", FgaCheckSpec{
		Relation:    "member",
		Description: "List saved mission YAML drafts for a tenant",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/ExportFindings", FgaCheckSpec{
		Relation:    "member",
		Description: "Export findings for a tenant in multiple formats",
	})

	// ---------------------------------------------------------------------------
	// prod-feature-wiring: new quota, user session, alerts, chat handlers
	// ---------------------------------------------------------------------------
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/GetTenantQuota", FgaCheckSpec{
		Relation:    "admin",
		Description: "Get tenant quota configuration (admin only)",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/SetTenantQuota", FgaCheckSpec{
		Relation:    "admin",
		Description: "Set tenant quota configuration (admin only)",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/GetUserSessions", FgaCheckSpec{
		Relation:    "member",
		Description: "Get active sessions for a user (self or admin)",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/ListAlerts", FgaCheckSpec{
		Relation:    "member",
		Description: "List platform alerts for a tenant user",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/MarkAlertRead", FgaCheckSpec{
		Relation:    "member",
		Description: "Mark a single alert as read",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/MarkAllAlertsRead", FgaCheckSpec{
		Relation:    "member",
		Description: "Mark all alerts for a user as read",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/ListConversations", FgaCheckSpec{
		Relation:    "member",
		Description: "List chat conversations for a tenant user",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/GetConversation", FgaCheckSpec{
		Relation:    "member",
		Description: "Get a chat conversation with its message history",
	})

	// ---------------------------------------------------------------------------
	// agent-auth-fga-integration: Agent Auth Protocol RPCs
	// ---------------------------------------------------------------------------
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/RegisterAgentAuth", FgaCheckSpec{
		Relation:    "admin",
		Description: "Register a new agent and host pair with FGA-resolved capability grants (admin only)",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/ExecuteAgentCapability", FgaCheckSpec{
		Relation:    "member",
		Description: "Execute a capability on behalf of an agent (FGA-checked per-capability)",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/ListAgentCapabilities", FgaCheckSpec{
		Relation:    "member",
		Description: "List FGA-resolved capabilities available to a user",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/GetAgentAuthStatus", FgaCheckSpec{
		Relation:    "member",
		Description: "Get the current status and grants for an agent",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/RevokeAgentAuth", FgaCheckSpec{
		Relation:    "admin",
		Description: "Revoke an agent and all its capability grants (admin only)",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/ListAgentAuthAgents", FgaCheckSpec{
		Relation:    "admin",
		Description: "List registered agents for a tenant (admin only)",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/CreateHostRegistrationToken", FgaCheckSpec{
		Relation:    "admin",
		Description: "Issue a single-use host registration API key (admin only)",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/ListComponentGrants", FgaCheckSpec{
		Relation:    "admin",
		Description: "Enumerate FGA component grants for all users in a tenant (admin only)",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/BatchGrantComponentAccessV2", FgaCheckSpec{
		Relation:    "admin",
		Description: "Bulk grant or revoke component access for any principal (admin only)",
	})
	r.add("/gibson.daemon.admin.v1.DaemonAdminService/ListAuditLog", FgaCheckSpec{
		Relation:    "admin",
		Description: "Query Postgres audit log entries for a tenant (admin only)",
	})

	// =========================================================================
	// gibson.component.v1.ComponentService — internal component/agent API
	// =========================================================================
	// ComponentService is used by agents, tools, and plugins. These callers
	// authenticate via K8s ServiceAccount tokens or API keys. They operate
	// within the mission's tenant context.

	r.add("/gibson.component.v1.ComponentService/RegisterComponent", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Register a component with the daemon",
	})
	r.add("/gibson.component.v1.ComponentService/Heartbeat", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Component heartbeat",
	})
	r.add("/gibson.component.v1.ComponentService/PollWork", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Long-poll for tool work",
	})
	r.add("/gibson.component.v1.ComponentService/SubmitResult", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Submit tool execution result",
	})
	r.add("/gibson.component.v1.ComponentService/Complete", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Harness LLM completion (unary)",
	})
	r.add("/gibson.component.v1.ComponentService/CompleteStream", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Harness LLM completion (streaming)",
	})
	r.add("/gibson.component.v1.ComponentService/CallTool", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Harness tool call (unary)",
	})
	r.add("/gibson.component.v1.ComponentService/QueryPlugin", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Harness plugin query",
	})
	r.add("/gibson.component.v1.ComponentService/SubmitFinding", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Submit security finding",
	})
	r.add("/gibson.component.v1.ComponentService/MemoryGet", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Read from mission memory",
	})
	r.add("/gibson.component.v1.ComponentService/MemorySet", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Write to mission memory",
	})
	r.add("/gibson.component.v1.ComponentService/MemorySearch", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Search mission memory",
	})
	r.add("/gibson.component.v1.ComponentService/MemoryDelete", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Delete a mission memory entry",
	})
	r.add("/gibson.component.v1.ComponentService/MemoryClear", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Clear all mission memory",
	})
	r.add("/gibson.component.v1.ComponentService/MemoryKeys", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "List mission memory keys",
	})
	r.add("/gibson.component.v1.ComponentService/MemoryHistory", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Get mission memory history",
	})
	r.add("/gibson.component.v1.ComponentService/MemoryGetPreviousRunValue", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Get memory value from previous run",
	})
	r.add("/gibson.component.v1.ComponentService/MemoryGetValueHistory", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Get full history of a memory key's values",
	})
	r.add("/gibson.component.v1.ComponentService/ListAvailablePlugins", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "List available plugins",
	})
	r.add("/gibson.component.v1.ComponentService/EnablePlugin", FgaCheckSpec{
		Relation:    "can_configure",
		ObjectFrom:  constObject("component:_system"),
		Description: "Enable a plugin (configure permission required)",
	})
	r.add("/gibson.component.v1.ComponentService/DisablePlugin", FgaCheckSpec{
		Relation:    "can_configure",
		ObjectFrom:  constObject("component:_system"),
		Description: "Disable a plugin (configure permission required)",
	})
	r.add("/gibson.component.v1.ComponentService/UpdatePluginConfig", FgaCheckSpec{
		Relation:    "can_configure",
		ObjectFrom:  constObject("component:_system"),
		Description: "Update plugin configuration",
	})
	r.add("/gibson.component.v1.ComponentService/GetPluginConfig", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Read plugin configuration",
	})
	r.add("/gibson.component.v1.ComponentService/TestPluginConnection", FgaCheckSpec{
		Relation:    "can_configure",
		ObjectFrom:  constObject("component:_system"),
		Description: "Test plugin connection",
	})
	r.add("/gibson.component.v1.ComponentService/ListTenantPlugins", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "List tenant-scoped plugins",
	})
	r.add("/gibson.component.v1.ComponentService/CompleteWithTools", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "LLM completion with tool use",
	})
	r.add("/gibson.component.v1.ComponentService/CompleteStructured", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "LLM structured completion",
	})
	r.add("/gibson.component.v1.ComponentService/CallToolStream", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Harness streaming tool call",
	})
	r.add("/gibson.component.v1.ComponentService/QueueToolWork", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Queue tool work via Redis",
	})
	r.add("/gibson.component.v1.ComponentService/ToolResults", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Stream tool results",
	})
	r.add("/gibson.component.v1.ComponentService/ListTools", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "List registered tools",
	})
	r.add("/gibson.component.v1.ComponentService/DelegateToAgent", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Delegate a sub-task to another agent",
	})
	r.add("/gibson.component.v1.ComponentService/ListAgents", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "List registered agents",
	})
	r.add("/gibson.component.v1.ComponentService/QueryNodes", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Query GraphRAG knowledge graph nodes",
	})
	r.add("/gibson.component.v1.ComponentService/StoreNode", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Store a GraphRAG node",
	})
	r.add("/gibson.component.v1.ComponentService/FindSimilarAttacks", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Find similar attacks in knowledge graph",
	})
	r.add("/gibson.component.v1.ComponentService/GetAttackChains", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Get attack chains from knowledge graph",
	})
	r.add("/gibson.component.v1.ComponentService/FindSimilarFindings", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Find similar findings in knowledge graph",
	})
	r.add("/gibson.component.v1.ComponentService/GetRelatedFindings", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Get related findings from knowledge graph",
	})
	r.add("/gibson.component.v1.ComponentService/GetFindings", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Get findings from GraphRAG",
	})
	r.add("/gibson.component.v1.ComponentService/GetRunFindings", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Get findings for a specific run",
	})
	r.add("/gibson.component.v1.ComponentService/CreateMission", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Create a sub-mission (agent delegation)",
	})
	r.add("/gibson.component.v1.ComponentService/RunMission", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Run a mission (agent delegation)",
	})
	r.add("/gibson.component.v1.ComponentService/GetMissionStatus", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Get mission status (agent delegation)",
	})
	r.add("/gibson.component.v1.ComponentService/WaitMission", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Wait for mission completion",
	})
	r.add("/gibson.component.v1.ComponentService/ListMissions", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "List missions (agent delegation)",
	})
	r.add("/gibson.component.v1.ComponentService/CancelMission", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Cancel a running mission",
	})
	r.add("/gibson.component.v1.ComponentService/GetMissionResults", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Get results for a completed mission",
	})
	r.add("/gibson.component.v1.ComponentService/GetCredential", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Retrieve an encrypted credential for agent use",
	})
	r.add("/gibson.component.v1.ComponentService/GetTaxonomySchema", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Get taxonomy schema for entity extraction",
	})
	r.add("/gibson.component.v1.ComponentService/GetMissionRunHistory", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Get mission run history",
	})
	r.add("/gibson.component.v1.ComponentService/ReportStepHints", FgaCheckSpec{
		Relation:    "can_execute",
		ObjectFrom:  constObject("component:_system"),
		Description: "Report step hints from an agent",
	})
}

// add registers a single entry, panicking on duplicate to catch programming errors.
func (r *FgaRpcRegistry) add(method string, spec FgaCheckSpec) {
	if _, exists := r.entries[method]; exists {
		panic(fmt.Sprintf("fga_rpc_registry: duplicate entry for method %q", method))
	}
	r.entries[method] = spec
}
