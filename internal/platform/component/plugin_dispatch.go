// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// plugin_dispatch.go implements the PluginInvokeServiceServer gRPC handler for
// the daemon-side plugin runtime (Spec 2, plugin-runtime, Phase 7, Task 15).
//
// PluginInvokeService exposes a single RPC: PluginInvoke, which:
//  1. Authorizes the caller against the exact plugin (can_invoke on
//     plugin:<tenant>/<PluginName>) IN THIS HANDLER — the gateway cannot, its
//     object derives from the request body (gibson#1245); authorizeInvoke.
//  2. Looks up a serving install of the named plugin in the ComponentInstallRegistry.
//  3. Validates the requested method against the install's declared_methods.
//  4. Marshals the PluginInvokeRequest to bytes and calls DispatchOne, which
//     enqueues a plugin_invoke work item and awaits the result.
//  5. Wraps the plugin's raw JSON result bytes into PluginInvokeResponse.result
//     (a JSON byte envelope, the mirror of request.request.value) and returns.
//     Go-first plugins submit their handler's JSON output verbatim via
//     SubmitResult; there is no proto message typing on the plugin path
//     (ADR-0065).
//
// Per-(tenant, plugin) concurrency is limited by a semaphore stored in a
// sync.Map keyed by "tenantID/componentName". The limit defaults to 10 and is
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
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/dispatchpolicy"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	pluginpb "github.com/zeroroot-ai/sdk/api/gen/gibson/plugin/v1"
	"github.com/zeroroot-ai/sdk/auth"
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
// and delegates dispatch to the ComponentInstallRegistry.
type PluginInvokeService struct {
	pluginpb.UnimplementedPluginInvokeServiceServer

	// registry is the plugin install registry used for install lookup and dispatch.
	registry ComponentInstallRegistry

	// semaphores holds a weighted semaphore per "(tenantID/componentName)" key.
	// Each semaphore limits concurrent in-flight invocations to pluginConcurrencyDefault.
	// Populated lazily on first use. Protected by semaphoresMu.
	semaphores   sync.Map // map[string]*semaphore.Weighted
	semaphoresMu sync.Mutex

	// logger is the structured logger for handler operations.
	logger *slog.Logger

	// deploymentShape is the untrusted-execution isolation policy (ADR-0010 /
	// gibson#997), from GIBSON_UNTRUSTED_EXEC. The zero value (ShapeSetecOnly)
	// fail-closes: an unwired service denies untrusted plugin invocation.
	deploymentShape dispatchpolicy.DeploymentShape

	// authorizer performs the per-plugin can_invoke FGA check (gibson#1245).
	// PluginInvoke's registry rule derives its FGA object from the request's
	// PluginName field (tenant_and_field('PluginName')), which ext-authz cannot
	// see — the gateway runs the coarse checks and passes through, so the
	// exact-object decision has to be made HERE. Set via WithAuthorizer; a nil
	// authorizer fail-closes (every invocation denies), matching the credential
	// endpoints (service_credential_authz.go, callback_credential_authz.go).
	authorizer authz.Authorizer
}

// NewPluginInvokeService constructs a PluginInvokeService.
// registry must not be nil. shape is the daemon's untrusted-execution
// deployment shape; the zero value (ShapeSetecOnly) fail-closes.
func NewPluginInvokeService(registry ComponentInstallRegistry, shape dispatchpolicy.DeploymentShape, logger *slog.Logger) *PluginInvokeService {
	if logger == nil {
		logger = slog.Default()
	}
	return &PluginInvokeService{
		registry:        registry,
		logger:          logger.With("service", "PluginInvokeService"),
		deploymentShape: shape,
	}
}

// WithAuthorizer wires the FGA authorizer used for the per-plugin can_invoke
// check (gibson#1245). The daemon always wires a real FGA client
// (grpc.go, one-code-path slice deploy#195); a service left without one denies
// every invocation (fail-closed), so this is not optional in production.
func (s *PluginInvokeService) WithAuthorizer(az authz.Authorizer) *PluginInvokeService {
	s.authorizer = az
	return s
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
	// The per-plugin `can_invoke` FGA check is made in THIS handler, not at the
	// edge: PluginInvoke's registry rule derives its FGA object from the request
	// PluginName field (tenant_and_field('PluginName')), which ext-authz cannot
	// see, so the gateway runs the coarse checks and passes through (gibson#1245).
	// authorizeInvoke below asks the exact-object question. The principal-kind
	// check here is an additional defense-in-depth signal, not the gate.
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

	// Defense-in-depth principal kind check. ext-authz enforces
	// AllowedIdentities=IdentityComponent (class 4), and authorizeInvoke below
	// makes the per-plugin can_invoke decision. At the daemon layer we
	// additionally log any user-credential caller that reached this handler,
	// which correlates with the tool_principal callers the model expects.
	if id.CredentialType == auth.CredentialOIDCUser {
		s.logger.WarnContext(ctx, "PluginInvoke: unexpected user credential caller; expected service credential",
			slog.String("tenant", tenantStr),
			slog.String("caller_subject", id.Subject),
		)
		// Do not hard-reject on credential kind alone: authorizeInvoke is the
		// authoritative gate. This log is a canary for misconfiguration.
	}

	// 2. Validate request fields.
	if req.GetPluginName() == "" {
		return nil, status.Error(codes.InvalidArgument, "plugin_name is required")
	}
	if req.GetMethod() == "" {
		return nil, status.Error(codes.InvalidArgument, "method is required")
	}

	// 2b. Per-plugin authorization (gibson#1245). Ask FGA the exact-object
	//     question the gateway could not form: can this caller can_invoke
	//     plugin:<tenant>/<PluginName>? Fail-closed on every axis. Runs before
	//     any install lookup or dispatch, so an unauthorized caller learns
	//     nothing about the named plugin (not even whether it is installed).
	if err := s.authorizeInvoke(ctx, req.GetPluginName()); err != nil {
		return nil, err
	}

	// 3. Determine deadline.
	deadline := pluginInvokeMaxDeadline
	if req.GetDeadlineMs() > 0 {
		d := time.Duration(req.GetDeadlineMs()) * time.Millisecond
		if d < pluginInvokeMaxDeadline {
			deadline = d
		}
	}

	componentName := req.GetPluginName()
	method := req.GetMethod()

	// 4. Look up serving installs.
	installs, err := s.registry.ListInstalls(ctx, tenant, componentName)
	if err != nil {
		s.logger.ErrorContext(ctx, "PluginInvoke: failed to list installs",
			slog.String("tenant", tenantStr),
			slog.String("plugin", componentName),
			slog.String("error", err.Error()),
		)
		return pluginErrorResponse(
			pluginpb.PluginError_PLUGIN_ERROR_KIND_INTERNAL,
			fmt.Sprintf("internal error listing installs for plugin %s", componentName),
		), nil
	}
	if len(installs) == 0 {
		return pluginErrorResponse(
			pluginpb.PluginError_PLUGIN_ERROR_KIND_UNAVAILABLE,
			fmt.Sprintf("no serving installs of plugin %s for tenant %s", componentName, tenantStr),
		), nil
	}

	// 5. Validate method against declared_methods (use first serving install's list;
	//    all installs of the same plugin_name share the same manifest version within
	//    a deployment — round-robin dispatch guarantees method parity).
	if !methodDeclared(installs[0].DeclaredMethods, method) {
		return pluginErrorResponse(
			pluginpb.PluginError_PLUGIN_ERROR_KIND_METHOD_NOT_FOUND,
			fmt.Sprintf("method %q not declared by plugin %s", method, componentName),
		), nil
	}

	// 5b. Dispatch-policy gate (ADR-0010 / gibson#997). PluginInvoke dispatches
	//     in-process via the work queue; there is no sandboxed plugin dispatch.
	//     An UNTRUSTED plugin therefore must not execute under the hosted
	//     setec-only shape — deny before dispatch, no in-process fallback. All
	//     installs of one plugin_name share a manifest within a deployment, so
	//     the first install's trust classification is authoritative. Mirrors
	//     harness.CallToolProto's gate.
	if dispatchpolicy.Decide(installs[0].ContentTrust, false, s.deploymentShape) == dispatchpolicy.Deny {
		s.logger.WarnContext(ctx, "PluginInvoke: denied untrusted plugin with no sandboxed dispatch",
			slog.String("tenant", tenantStr),
			slog.String("plugin", componentName),
		)
		return pluginErrorResponse(
			pluginpb.PluginError_PLUGIN_ERROR_KIND_UNAUTHORIZED,
			fmt.Sprintf("plugin %s is untrusted but has no sandboxed dispatch; GIBSON_UNTRUSTED_EXEC=setec-only forbids in-process execution", componentName),
		), nil
	}

	// 6. Acquire per-(tenant, plugin) concurrency semaphore.
	semKey := tenantStr + "/" + componentName
	sem := s.getSemaphore(semKey)

	// Try to acquire without blocking past the invocation deadline.
	semCtx, semCancel := context.WithTimeout(ctx, deadline)
	defer semCancel()
	if err := sem.Acquire(semCtx, 1); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(semCtx.Err(), context.DeadlineExceeded) {
			return pluginErrorResponse(
				pluginpb.PluginError_PLUGIN_ERROR_KIND_DEADLINE_EXCEEDED,
				fmt.Sprintf("concurrency limit reached for plugin %s/%s; deadline exceeded waiting for a slot", tenantStr, componentName),
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
	resultBytes, dispatchErr := s.registry.DispatchOne(ctx, tenant, componentName, method, payload, deadline)
	if dispatchErr != nil {
		return s.classifyDispatchError(ctx, dispatchErr, componentName, method), nil
	}

	// 9. Wrap the plugin's raw JSON result bytes into the response.
	//    Go-first plugins (SDK plugin/dispatch) submit their handler's JSON
	//    output verbatim: SubmitResult(workID, respJSON, nil). resultBytes is
	//    therefore raw JSON, not a marshalled PluginInvokeResponse — the daemon
	//    carries it in PluginInvokeResponse.result.value, the mirror of the
	//    request's request.value. There is no proto message typing on the plugin
	//    path (ADR-0065): the result is opaque JSON bytes, and the tool caller
	//    decodes result.value with the method's output schema. A nil/empty result
	//    is legal — a method may return no body.
	resp := &pluginpb.PluginInvokeResponse{}
	if len(resultBytes) > 0 {
		resp.Result = &anypb.Any{Value: resultBytes}
	}

	s.logger.InfoContext(ctx, "PluginInvoke: success",
		slog.String("tenant", tenantStr),
		slog.String("plugin", componentName),
		slog.String("method", method),
		slog.Duration("deadline", deadline),
	)

	return resp, nil
}

// relationCanInvoke is the FGA relation that grants plugin invocation. Per
// internal/platform/authz/model.fga the `plugin` type declares
//
//	define can_invoke: [tool_principal, tenant#member]
//
// so a tool_principal (a component's own typed CG-JWT subject, ADR-0045) or a
// tenant member may invoke; every other subject is refused structurally.
const relationCanInvoke = "can_invoke"

// authorizeInvoke is the per-PLUGIN authorization gate for
// PluginInvokeService/PluginInvoke (gibson#1245).
//
// PluginInvoke's registry rule is object_deriver=tenant_and_field('PluginName'),
// so the FGA object is plugin:<tenant>/<PluginName>. That name lives in the
// request body, which ext-authz never sees — the gateway runs the coarse checks
// (identity class = COMPONENT, tenant cross-check, revocation) and passes
// through. Before this, the handler trusted the gateway for the FGA relation and
// dispatched without any per-plugin check, so any component that reached the RPC
// could invoke any plugin in its header-asserted tenant.
//
// This asks the exact question the gateway builds for every non-field-derived
// rule: user = the caller's typed FGA principal (componentFGAUser, mirroring
// ext-authz), relation = can_invoke, object = authz.PluginObject(tenant, name) —
// the same triple the writers seed tuples against, so Check matches Write.
//
// Fail-closed on every axis: no tenant, no identity, no authorizer wired, or an
// FGA error all deny. Returns gRPC status errors so a refusal is a
// PERMISSION_DENIED on the wire, distinct from a plugin-unavailable result.
func (s *PluginInvokeService) authorizeInvoke(ctx context.Context, pluginName string) error {
	if pluginName == "" {
		return status.Error(codes.InvalidArgument, "plugin_name is required")
	}

	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" || tenant == auth.SystemTenantString {
		s.logInvokeDeny(ctx, "", pluginName, "no_tenant_in_context")
		return status.Error(codes.PermissionDenied,
			"plugin invocation denied: no tenant in context")
	}

	identity, err := auth.IdentityFromContext(ctx)
	if err != nil || identity.Subject == "" {
		s.logInvokeDeny(ctx, tenant, pluginName, "no_caller_identity")
		return status.Error(codes.Unauthenticated,
			"plugin invocation denied: no caller identity")
	}

	if s.authorizer == nil {
		// No authorizer wired means no decision can be made. Deny rather than
		// dispatch: an undecidable authorization question is a deny. The daemon
		// always wires one (grpc.go, one-code-path slice deploy#195); this
		// branch catches a misconfigured or partially-constructed service.
		s.logInvokeDeny(ctx, tenant, pluginName, "no_authorizer_configured")
		return status.Error(codes.PermissionDenied,
			"plugin invocation denied: authorization unavailable")
	}

	fgaUser := componentFGAUser(identity.Subject)
	fgaObject := authz.PluginObject(tenant, pluginName)

	allowed, checkErr := s.authorizer.Check(ctx, fgaUser, relationCanInvoke, fgaObject)
	if checkErr != nil {
		s.logger.ErrorContext(ctx, "plugin invocation: FGA check failed",
			slog.String("fga_user", fgaUser),
			slog.String("fga_relation", relationCanInvoke),
			slog.String("fga_object", fgaObject),
			slog.String("error", checkErr.Error()),
		)
		return status.Error(codes.Unavailable,
			"plugin invocation: authorization service error")
	}
	if !allowed {
		s.logInvokeDeny(ctx, tenant, pluginName, "fga_no_can_invoke",
			slog.String("fga_user", fgaUser),
			slog.String("fga_object", fgaObject),
		)
		return status.Error(codes.PermissionDenied,
			"plugin invocation denied: caller has no can_invoke on this plugin")
	}
	return nil
}

// logInvokeDeny emits the structured deny record for a refused plugin
// invocation. The plugin NAME is an identifier (never secret material) and is
// logged; s.logger is guaranteed non-nil by NewPluginInvokeService.
func (s *PluginInvokeService) logInvokeDeny(ctx context.Context, tenant, plugin, reason string, extra ...slog.Attr) {
	attrs := []any{
		"event", "plugin.invoke.denied",
		"audit_event", "plugin_invoke_deny",
		"decision", "deny",
		"decision_reason", reason,
		"tenant_id", tenant,
		"plugin_name", plugin,
	}
	for _, a := range extra {
		attrs = append(attrs, a.Key, a.Value.String())
	}
	s.logger.WarnContext(ctx, "plugin invocation denied", attrs...)
}

// classifyDispatchError maps DispatchOne errors to PluginInvokeResponse errors.
func (s *PluginInvokeService) classifyDispatchError(
	ctx context.Context,
	err error,
	componentName, method string,
) *pluginpb.PluginInvokeResponse {
	// ErrComponentUnavailable: no installs at dispatch time.
	if errors.Is(err, ErrComponentUnavailable) {
		return pluginErrorResponse(
			pluginpb.PluginError_PLUGIN_ERROR_KIND_UNAVAILABLE,
			fmt.Sprintf("no serving installs of plugin %s at dispatch time", componentName),
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
			fmt.Sprintf("plugin %s/%s did not respond within the deadline", componentName, method),
		)
	}

	// Default: internal error.
	s.logger.ErrorContext(ctx, "PluginInvoke: unclassified dispatch error",
		slog.String("plugin", componentName),
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
