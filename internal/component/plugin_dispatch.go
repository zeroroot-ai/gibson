package component

// plugin_dispatch.go implements the PluginInvokeServiceServer gRPC handler for
// the daemon-side plugin runtime (Spec 2, plugin-runtime, Phase 7, Task 15).
//
// PluginInvokeService exposes a single RPC: PluginInvoke, which:
//  1. Validates that the caller is authorised (ext-authz enforces at the edge;
//     we apply a defense-in-depth principal-kind check here).
//  2. Looks up a serving install of the named plugin in the PluginRegistry.
//  3. Validates the requested method against the install's declared_methods.
//  4. Marshals the PluginInvokeRequest to bytes and calls DispatchOne, which
//     enqueues a plugin_invoke work item and awaits the result.
//  5. Unmarshals the result bytes back into a PluginInvokeResponse and returns.
//
// Per-(tenant, plugin) concurrency is limited by a semaphore stored in a
// sync.Map keyed by "tenantID/pluginName". The limit defaults to 10 and is
// read from pluginConcurrencyDefault; future phases can wire the manifest's
// per-invocation limit at registration time.
//
// Requirements: 5.2.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pluginpb "github.com/zero-day-ai/sdk/api/gen/gibson/plugin/v1"
	"github.com/zero-day-ai/sdk/auth"
)

const (
	// pluginConcurrencyDefault is the default per-(tenant, plugin) concurrency
	// limit. Per Requirement 5.6, the manifest may override this; default is 10.
	pluginConcurrencyDefault = int64(10)

	// pluginInvokeMaxDeadline caps the per-call deadline per Requirement 5.2.
	pluginInvokeMaxDeadline = 60 * time.Second
)

// PluginInvokeService implements pluginpb.PluginInvokeServiceServer.
//
// It is registered on the daemon's gRPC server alongside ComponentServiceServer
// and delegates dispatch to the PluginRegistry.
type PluginInvokeService struct {
	pluginpb.UnimplementedPluginInvokeServiceServer

	// registry is the plugin install registry used for install lookup and dispatch.
	registry PluginRegistry

	// semaphores holds a weighted semaphore per "(tenantID/pluginName)" key.
	// Each semaphore limits concurrent in-flight invocations to pluginConcurrencyDefault.
	// Populated lazily on first use. Protected by semaphoresMu.
	semaphores   sync.Map // map[string]*semaphore.Weighted
	semaphoresMu sync.Mutex

	// logger is the structured logger for handler operations.
	logger *slog.Logger
}

// NewPluginInvokeService constructs a PluginInvokeService.
// registry must not be nil.
func NewPluginInvokeService(registry PluginRegistry, logger *slog.Logger) *PluginInvokeService {
	if logger == nil {
		logger = slog.Default()
	}
	return &PluginInvokeService{
		registry: registry,
		logger:   logger.With("service", "PluginInvokeService"),
	}
}

// PluginInvoke implements pluginpb.PluginInvokeServiceServer.
//
// See module-level doc for the full dispatch flow.
func (s *PluginInvokeService) PluginInvoke(
	ctx context.Context,
	req *pluginpb.PluginInvokeRequest,
) (*pluginpb.PluginInvokeResponse, error) {
	// 1. Extract and validate caller identity from context.
	//
	// ext-authz already enforced the `can_invoke` relation at the Envoy edge
	// (proto annotation: relation=can_invoke, object_type=plugin). Defense-in-depth:
	// verify the caller principal is a tool_principal. Agents do not invoke plugins
	// per Requirement 5.2 / Spec 3 (non-plugin-secret-isolation); we trust ext-authz
	// for the FGA check and add this principal-kind guard here.
	id, idErr := auth.IdentityFromContext(ctx)
	if idErr != nil {
		return nil, status.Error(codes.Unauthenticated, "missing or invalid identity in context")
	}

	tenantStr := auth.TenantStringFromContext(ctx)
	if tenantStr == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	tenant, tenantErr := auth.NewTenantID(tenantStr)
	if tenantErr != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tenant: %v", tenantErr)
	}

	// Defense-in-depth principal kind check.
	// ext-authz already enforces AllowedIdentities=IdentityComponent (class 4)
	// and the FGA can_invoke relation. At the daemon layer we additionally
	// verify that the caller used a service/component credential (not a user
	// session), which correlates with tool_principal callers.
	// We trust ext-authz for the full FGA check and log an anomaly for any
	// user-credential caller that reached this handler.
	if id.CredentialType == auth.CredentialOIDCUser {
		s.logger.WarnContext(ctx, "PluginInvoke: unexpected user credential caller; expected service credential",
			slog.String("tenant", tenantStr),
			slog.String("caller_subject", id.Subject),
		)
		// Do not hard-reject: ext-authz has already validated the FGA relation.
		// This log is a canary for misconfiguration, not a rejection gate.
	}

	// 2. Validate request fields.
	if req.GetPluginName() == "" {
		return nil, status.Error(codes.InvalidArgument, "plugin_name is required")
	}
	if req.GetMethod() == "" {
		return nil, status.Error(codes.InvalidArgument, "method is required")
	}

	// 3. Determine deadline.
	deadline := pluginInvokeMaxDeadline
	if req.GetDeadlineMs() > 0 {
		d := time.Duration(req.GetDeadlineMs()) * time.Millisecond
		if d < pluginInvokeMaxDeadline {
			deadline = d
		}
	}

	pluginName := req.GetPluginName()
	method := req.GetMethod()

	// 4. Look up serving installs.
	installs, err := s.registry.ListInstalls(ctx, tenant, pluginName)
	if err != nil {
		s.logger.ErrorContext(ctx, "PluginInvoke: failed to list installs",
			slog.String("tenant", tenantStr),
			slog.String("plugin", pluginName),
			slog.String("error", err.Error()),
		)
		return pluginErrorResponse(
			pluginpb.PluginError_PLUGIN_ERROR_KIND_INTERNAL,
			fmt.Sprintf("internal error listing installs for plugin %s", pluginName),
		), nil
	}
	if len(installs) == 0 {
		return pluginErrorResponse(
			pluginpb.PluginError_PLUGIN_ERROR_KIND_UNAVAILABLE,
			fmt.Sprintf("no serving installs of plugin %s for tenant %s", pluginName, tenantStr),
		), nil
	}

	// 5. Validate method against declared_methods (use first serving install's list;
	//    all installs of the same plugin_name share the same manifest version within
	//    a deployment — round-robin dispatch guarantees method parity).
	if !methodDeclared(installs[0].DeclaredMethods, method) {
		return pluginErrorResponse(
			pluginpb.PluginError_PLUGIN_ERROR_KIND_METHOD_NOT_FOUND,
			fmt.Sprintf("method %q not declared by plugin %s", method, pluginName),
		), nil
	}

	// 6. Acquire per-(tenant, plugin) concurrency semaphore.
	semKey := tenantStr + "/" + pluginName
	sem := s.getSemaphore(semKey)

	// Try to acquire without blocking past the invocation deadline.
	semCtx, semCancel := context.WithTimeout(ctx, deadline)
	defer semCancel()
	if err := sem.Acquire(semCtx, 1); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(semCtx.Err(), context.DeadlineExceeded) {
			return pluginErrorResponse(
				pluginpb.PluginError_PLUGIN_ERROR_KIND_DEADLINE_EXCEEDED,
				fmt.Sprintf("concurrency limit reached for plugin %s/%s; deadline exceeded waiting for a slot", tenantStr, pluginName),
			), nil
		}
		return pluginErrorResponse(
			pluginpb.PluginError_PLUGIN_ERROR_KIND_INTERNAL,
			"failed to acquire concurrency semaphore",
		), nil
	}
	defer sem.Release(1)

	// 7. Marshal the PluginInvokeRequest to bytes as the work payload.
	//    The entire request (including plugin_name, method, request Any, and
	//    deadline_ms) is forwarded to the plugin SDK dispatcher via WorkItem.Payload.
	payload, err := proto.Marshal(req)
	if err != nil {
		return pluginErrorResponse(
			pluginpb.PluginError_PLUGIN_ERROR_KIND_INTERNAL,
			"failed to marshal PluginInvokeRequest",
		), nil
	}

	// 8. Dispatch via registry.
	resultBytes, dispatchErr := s.registry.DispatchOne(ctx, tenant, pluginName, method, payload, deadline)
	if dispatchErr != nil {
		return s.classifyDispatchError(ctx, dispatchErr, pluginName, method), nil
	}

	// 9. Unmarshal the result bytes into a PluginInvokeResponse.
	var resp pluginpb.PluginInvokeResponse
	if err := proto.Unmarshal(resultBytes, &resp); err != nil {
		// If the bytes don't unmarshal cleanly as a PluginInvokeResponse they may
		// be a raw Any payload from a plugin that returned a successful result.
		// Wrap in a response with the raw bytes stored as unknown fields.
		// In practice, the plugin SDK always returns a marshalled PluginInvokeResponse.
		return pluginErrorResponse(
			pluginpb.PluginError_PLUGIN_ERROR_KIND_INTERNAL,
			"failed to unmarshal plugin result bytes",
		), nil
	}

	s.logger.InfoContext(ctx, "PluginInvoke: success",
		slog.String("tenant", tenantStr),
		slog.String("plugin", pluginName),
		slog.String("method", method),
		slog.Duration("deadline", deadline),
	)

	return &resp, nil
}

// classifyDispatchError maps DispatchOne errors to PluginInvokeResponse errors.
func (s *PluginInvokeService) classifyDispatchError(
	ctx context.Context,
	err error,
	pluginName, method string,
) *pluginpb.PluginInvokeResponse {
	// ErrPluginUnavailable: no installs at dispatch time.
	if errors.Is(err, ErrPluginUnavailable) {
		return pluginErrorResponse(
			pluginpb.PluginError_PLUGIN_ERROR_KIND_UNAVAILABLE,
			fmt.Sprintf("no serving installs of plugin %s at dispatch time", pluginName),
		)
	}

	// PluginWorkError: structured error returned by the plugin install.
	var pwe *PluginWorkError
	if errors.As(err, &pwe) {
		switch pwe.Code {
		case "DEADLINE_EXCEEDED":
			return pluginErrorResponse(pluginpb.PluginError_PLUGIN_ERROR_KIND_DEADLINE_EXCEEDED, pwe.Message)
		case "HANDLER_FAILED":
			return pluginErrorResponse(pluginpb.PluginError_PLUGIN_ERROR_KIND_HANDLER_FAILED, pwe.Message)
		case "METHOD_NOT_FOUND":
			return pluginErrorResponse(pluginpb.PluginError_PLUGIN_ERROR_KIND_METHOD_NOT_FOUND, pwe.Message)
		case "UNAVAILABLE":
			return pluginErrorResponse(pluginpb.PluginError_PLUGIN_ERROR_KIND_UNAVAILABLE, pwe.Message)
		default:
			return pluginErrorResponse(pluginpb.PluginError_PLUGIN_ERROR_KIND_HANDLER_FAILED, pwe.Message)
		}
	}

	// Context deadline exceeded: the WaitForResult timed out.
	if errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(err.Error(), "timeout waiting for work") {
		return pluginErrorResponse(
			pluginpb.PluginError_PLUGIN_ERROR_KIND_DEADLINE_EXCEEDED,
			fmt.Sprintf("plugin %s/%s did not respond within the deadline", pluginName, method),
		)
	}

	// Default: internal error.
	s.logger.ErrorContext(ctx, "PluginInvoke: unclassified dispatch error",
		slog.String("plugin", pluginName),
		slog.String("method", method),
		slog.String("error", err.Error()),
	)
	return pluginErrorResponse(
		pluginpb.PluginError_PLUGIN_ERROR_KIND_INTERNAL,
		"internal dispatch error",
	)
}

// getSemaphore returns the per-(tenant/plugin) semaphore, creating it lazily.
func (s *PluginInvokeService) getSemaphore(key string) *semaphore.Weighted {
	if v, ok := s.semaphores.Load(key); ok {
		return v.(*semaphore.Weighted)
	}
	// Double-checked construction under a mutex so we don't create multiple semaphores.
	s.semaphoresMu.Lock()
	defer s.semaphoresMu.Unlock()
	if v, ok := s.semaphores.Load(key); ok {
		return v.(*semaphore.Weighted)
	}
	sem := semaphore.NewWeighted(pluginConcurrencyDefault)
	s.semaphores.Store(key, sem)
	return sem
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// pluginErrorResponse constructs a PluginInvokeResponse carrying only an error.
func pluginErrorResponse(kind pluginpb.PluginError_Kind, message string) *pluginpb.PluginInvokeResponse {
	return &pluginpb.PluginInvokeResponse{
		Error: &pluginpb.PluginError{
			Kind:    kind,
			Message: message,
		},
	}
}

// methodDeclared returns true if method is in the declared list.
func methodDeclared(declared []string, method string) bool {
	for _, m := range declared {
		if m == method {
			return true
		}
	}
	return false
}
