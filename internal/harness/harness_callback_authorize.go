package harness

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/zero-day-ai/gibson/internal/authz"
	harnesspb "github.com/zero-day-ai/sdk/api/gen/gibson/harness/v1"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ComponentAuthzMetrics is a narrow interface for emitting component authz metrics.
// It is implemented by *observability.OTelMetricsRecorder. Defining it here avoids
// an import cycle (harness is already imported by observability).
type ComponentAuthzMetrics interface {
	// RecordComponentAuthz increments the component authz total counter.
	// decision is "allow" or "deny".
	RecordComponentAuthz(ctx context.Context, action, decision string)
}

// WithComponentAuthzMetrics wires metrics emission into the Authorize handler.
// When not set, the handler operates without emitting authz counters.
func WithComponentAuthzMetrics(m ComponentAuthzMetrics) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.componentAuthzMetrics = m
	}
}

// RunAuthzState holds the authz context for a mission run.
// It mirrors mission.MissionAuthzState but lives in this package to avoid
// the harness→mission→eval→harness import cycle.
type RunAuthzState struct {
	RunID     string
	UserID    string
	TenantID  string
	Status    string // "active", "completed", "cancelled"
	StartedAt interface{}
}

// RunAuthzLookup is a narrow interface that the daemon's mission.MissionAuthzStore
// satisfies. It is defined here to avoid importing the mission package and
// creating a circular import (harness→mission→eval→harness).
type RunAuthzLookup interface {
	// Get retrieves the authz state for a run ID.
	// Returns an error wrapping ErrMissionAuthzNotFound when the key does not exist.
	Get(ctx context.Context, runID string) (*RunAuthzState, error)
}

// ErrRunNotFound is the sentinel error returned by RunAuthzLookup.Get when the
// run_id is not found. Adapters from mission.MissionAuthzStore must translate
// mission.ErrMissionAuthzNotFound to this sentinel.
var ErrRunNotFound = errors.New("run authz state not found")

// WithAuthzStore wires the RunAuthzLookup into HarnessCallbackService so that
// the Authorize RPC handler can look up the run's owning user and mission status.
//
// One-code-path slice deploy#195: required for every daemon. The previous
// "not set → Unimplemented (SDK falls back to allow)" branch was a silent
// authz-bypass surface and has been removed.
func WithAuthzStore(store RunAuthzLookup) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.authzStore = store
	}
}

// WithComponentAuthorizer wires the FGA Authorizer into HarnessCallbackService.
// The authorizer is called for every component Authorize RPC after the mission
// run state has been verified as active.
//
// One-code-path slice deploy#195: required for every daemon. The previous
// "not set → allowed=true" branch was a silent authz-bypass surface and has
// been removed.
func WithComponentAuthorizer(a authz.Authorizer) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.componentAuthorizer = a
	}
}

// Authorize implements HarnessCallbackService_AuthorizeServer.
//
// Flow:
//  1. Look up run_id in authzStore → NotFound if missing.
//  2. Verify mission is still active → FailedPrecondition if completed/cancelled.
//  3. Derive FGA check: user:<user_id> can_<action> <resource>.
//  4. Call Authorizer.Check → Unavailable if FGA is unreachable.
//  5. Return AuthorizeResponse{allowed, reason}.
//  6. Emit audit event with decision.
func (s *HarnessCallbackService) Authorize(ctx context.Context, req *harnesspb.AuthorizeRequest) (*harnesspb.AuthorizeResponse, error) {
	// One-code-path slice deploy#195: authzStore and componentAuthorizer are
	// required at daemon startup. We deliberately do NOT add a nil-guard here
	// — the old "graceful Unimplemented" / "graceful allow" branches were
	// silent authz-bypasses. A misconfigured daemon now panics on the first
	// Authorize call instead of silently allowing every component.

	runID := req.GetRunId()
	action := req.GetAction()
	resource := req.GetResource()

	if runID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "authorize: run_id is required")
	}
	if action == "" || resource == "" {
		return nil, status.Errorf(codes.InvalidArgument, "authorize: action and resource are required")
	}

	// 1. Look up authz state.
	runState, err := s.authzStore.Get(ctx, runID)
	if err != nil {
		if errors.Is(err, ErrRunNotFound) {
			s.logger.Warn("authorize: run not found in authz store",
				slog.String("run_id", runID),
			)
			return nil, status.Errorf(codes.NotFound, "authorize: run_id not found")
		}
		s.logger.Error("authorize: failed to get authz state",
			slog.String("run_id", runID),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Unavailable, "authorize: authz store error")
	}

	// 2. Verify mission is active.
	if runState.Status != "active" {
		s.logger.Info("authorize: mission run is no longer active",
			slog.String("run_id", runID),
			slog.String("status", runState.Status),
			slog.String("action", action),
			slog.String("resource", resource),
		)
		s.emitComponentAuthzAudit(ctx, runState, action, resource, false, "mission_inactive")
		return nil, status.Errorf(codes.FailedPrecondition, "authorize: mission run is not active (status=%s)", runState.Status)
	}

	// 3. Derive FGA check parameters.
	// One-code-path slice deploy#195: the daemon always has a real FGA
	// authorizer — there is no longer a "no authorizer wired → allow" branch.
	// user format:   "user:<subject>"
	// relation:      "can_<action>"  (FGA model uses "can_execute", "can_read", etc.)
	// object format: caller-provided resource string (e.g., "tool:nmap", "system:192.168.1.1")
	fgaUser := fmt.Sprintf("user:%s", runState.UserID)
	fgaRelation := "can_" + strings.ToLower(action)
	fgaObject := deriveFGAObject(resource)

	allowed, checkErr := s.componentAuthorizer.Check(ctx, fgaUser, fgaRelation, fgaObject)
	if checkErr != nil {
		s.logger.Error("authorize: FGA check failed",
			slog.String("run_id", runID),
			slog.String("fga_user", fgaUser),
			slog.String("fga_relation", fgaRelation),
			slog.String("fga_object", fgaObject),
			slog.String("error", checkErr.Error()),
		)
		// FGA unavailable — return Unavailable so SDK can apply fail-open/closed policy.
		return nil, status.Errorf(codes.Unavailable, "authorize: authorization service error")
	}

	// 4. Emit audit event and metrics.
	reason := "fga_allow"
	if !allowed {
		reason = "fga_deny"
	}
	s.emitComponentAuthzAudit(ctx, runState, action, resource, allowed, reason)

	// Increment the component_authz_total counter for Prometheus/alerting.
	if s.componentAuthzMetrics != nil {
		decision := "allow"
		if !allowed {
			decision = "deny"
		}
		s.componentAuthzMetrics.RecordComponentAuthz(ctx, action, decision)
	}

	if !allowed {
		s.logger.Info("authorize: denied by FGA",
			slog.String("run_id", runID),
			slog.String("user_id", runState.UserID),
			slog.String("action", action),
			slog.String("resource", resource),
			slog.String("fga_relation", fgaRelation),
			slog.String("fga_object", fgaObject),
		)
		return &harnesspb.AuthorizeResponse{Allowed: false, Reason: "not_authorized"}, nil
	}

	s.logger.Debug("authorize: allowed",
		slog.String("run_id", runID),
		slog.String("action", action),
		slog.String("resource", resource),
	)
	return &harnesspb.AuthorizeResponse{Allowed: true, Reason: reason}, nil
}

// deriveFGAObject maps a component resource string to an FGA object identifier.
//
// Resource strings follow the convention: "type:name" (e.g., "tool:nmap",
// "system:192.168.1.1"). When no colon is present, the resource is treated as
// a component name.
func deriveFGAObject(resource string) string {
	if strings.Contains(resource, ":") {
		// Pass through as-is — caller already provides a typed object.
		return resource
	}
	// Unqualified names are assumed to be component objects.
	return "component:" + resource
}

// emitComponentAuthzAudit logs a structured audit record for the component authz decision.
// This provides the component_authz_decision audit trail.
//
// Fields are logged at INFO level. The trace_id is included for cross-system correlation.
func (s *HarnessCallbackService) emitComponentAuthzAudit(
	ctx context.Context,
	state *RunAuthzState,
	action, resource string,
	allowed bool,
	reason string,
) {
	eventType := "component_authz_allow"
	if !allowed {
		eventType = "component_authz_deny"
	}

	traceID := ""
	if spanCtx := trace.SpanFromContext(ctx).SpanContext(); spanCtx.IsValid() {
		traceID = spanCtx.TraceID().String()
	}

	s.logger.InfoContext(ctx, "component_authz_decision",
		slog.String("audit_event", eventType),
		slog.String("run_id", state.RunID),
		slog.String("user_id", state.UserID),
		slog.String("tenant_id", state.TenantID),
		slog.String("action", action),
		slog.String("resource", resource),
		slog.Bool("allowed", allowed),
		slog.String("reason", reason),
		slog.String("trace_id", traceID),
	)
}
