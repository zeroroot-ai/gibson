// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
)

// TaskGrantVerifier verifies a daemon-minted task grant and returns its
// claims. The daemon backs it with capabilitygrant.LocalVerifier over its own
// Minter; tests fake it.
type TaskGrantVerifier interface {
	Verify(ctx context.Context, token string) (sdkcg.Claims, error)
}

// WithTaskGrantVerifier wires the verifier the callback listener uses to bind a
// request to the task grant it carries (gibson#1605). get is read per request,
// because the Minter is built during daemon Start, after the callback service
// options are assembled. A nil result means no daemon key exists yet, and a
// request that presents a task grant then is refused rather than trusted.
func WithTaskGrantVerifier(get func() TaskGrantVerifier) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.taskGrantVerifier = get
	}
}

// taskGrantHeader is the request metadata key a dispatched component presents
// its task grant on. It is the same header ext-authz reads at the edge; Envoy
// forwards it upstream unchanged.
const taskGrantHeader = "x-capability-grant"

// componentTokenType is the typ of a registered component's self-signed token
// (ADR-0045). Such a token is the component's own identity, verified at the
// edge against the daemon's key descriptor, and carries no mission scope. It is
// not a task grant, so the scope check below does not apply to it.
const componentTokenType = "agent+jwt"

// contextCarrier is satisfied by every HarnessCallbackService request message:
// each carries a ContextInfo that names the mission the call is for.
type contextCarrier interface {
	GetContext() *harnesspb.ContextInfo
}

// checkTaskGrantScope binds a callback request to the task grant it carries.
//
// ext-authz accepts a daemon-minted task grant as the sole credential of an
// off-cluster component (gibson#1605). The edge verifies the signature, the
// tenant and the method, but it cannot see the request body. So the daemon
// closes the last gap here: a grant minted for mission A must not present a
// ContextInfo naming mission B, and the grant's tenant must be the tenant the
// request resolved to.
//
// A request that carries no grant, or a component's own agent+jwt, passes
// through untouched: the first is a peer the listener policy already admitted
// on its SPIFFE identity, the second is a registered component whose identity
// the edge asserted. A grant that is present but cannot be verified is a hard
// failure, never a pass-through.
func checkTaskGrantScope(ctx context.Context, req any, get func() TaskGrantVerifier, method string, logger *slog.Logger) (context.Context, error) {
	token, ok := taskGrantFromMetadata(ctx)
	if !ok {
		return ctx, nil
	}
	if get == nil {
		return ctx, deny(ctx, logger, method, "no task-grant verifier wired",
			status.Error(codes.Unauthenticated, "task grant presented but this daemon cannot verify one"))
	}
	verifier := get()
	if verifier == nil {
		return ctx, deny(ctx, logger, method, "no daemon signing key yet",
			status.Error(codes.Unauthenticated, "task grant presented but this daemon cannot verify one"))
	}
	claims, err := verifier.Verify(ctx, token)
	if err != nil {
		reason := "invalid"
		if errors.Is(err, sdkcg.ErrExpired) {
			reason = "expired"
		}
		return ctx, deny(ctx, logger, method, "task grant "+reason,
			status.Error(codes.Unauthenticated, "task grant "+reason))
	}
	if tenant := auth.TenantStringFromContext(ctx); tenant != claims.Tenant.String() {
		return ctx, deny(ctx, logger, method, "task grant tenant does not match the request tenant",
			status.Error(codes.PermissionDenied, "task grant is for another tenant"))
	}
	if carrier, ok := req.(contextCarrier); ok {
		if info := carrier.GetContext(); info != nil && info.GetMissionId() != "" && info.GetMissionId() != claims.MissionID {
			return ctx, deny(ctx, logger, method, "task grant mission does not match ContextInfo.mission_id",
				status.Error(codes.PermissionDenied, "task grant is for another mission"))
		}
	}
	// The verified claims travel with the request. A handler that must know
	// which job or which task a callback belongs to reads them from there,
	// never from a request field the caller filled in.
	return withTaskGrantClaims(ctx, claims), nil
}

func deny(ctx context.Context, logger *slog.Logger, method, reason string, err error) error {
	if logger != nil {
		logger.WarnContext(ctx, "harness callback: task grant refused",
			"event", "callback.authz.task_grant_refused",
			"method", method,
			"reason", reason,
		)
	}
	return err
}

// taskGrantFromMetadata returns the task grant on the request, and whether one
// is present. A component's own agent+jwt in the same header is reported as
// absent: it is not a task grant.
func taskGrantFromMetadata(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	for _, v := range md.Get(taskGrantHeader) {
		v = strings.TrimSpace(v)
		if strings.HasPrefix(strings.ToLower(v), "bearer ") {
			v = strings.TrimSpace(v[7:])
		}
		if v == "" {
			continue
		}
		if tokenType(v) == componentTokenType {
			return "", false
		}
		return v, true
	}
	return "", false
}

// tokenType reads the typ of a compact JWT header without trusting it. It is
// used only to route: a task grant is verified in full before any claim is
// read.
func tokenType(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	var h struct {
		Typ string `json:"typ"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return ""
	}
	return h.Typ
}

// taskGrantScopeInterceptors builds the unary and stream interceptors that run
// checkTaskGrantScope on every callback RPC. They run after the SDK auth
// interceptor, because the tenant they compare against is the one that
// interceptor placed on the context.
func taskGrantScopeInterceptors(get func() TaskGrantVerifier, logger *slog.Logger) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	unary := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		scoped, err := checkTaskGrantScope(ctx, req, get, info.FullMethod, logger)
		if err != nil {
			return nil, err
		}
		return handler(scoped, req)
	}
	stream := func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, &taskGrantScopedStream{ServerStream: ss, get: get, method: info.FullMethod, logger: logger})
	}
	return unary, stream
}

// taskGrantScopedStream checks each received message of a streaming RPC. The
// first message of a callback stream carries the ContextInfo, and a later
// message may name another mission, so every message is checked.
type taskGrantScopedStream struct {
	grpc.ServerStream
	get    func() TaskGrantVerifier
	method string
	logger *slog.Logger
	// scoped is the request context with the verified claims, set on the
	// first message that carries a grant.
	scoped context.Context
}

// Context returns the request context with the verified task-grant claims on
// it, so a streaming handler reads the same claims a unary one does.
func (s *taskGrantScopedStream) Context() context.Context {
	if s.scoped != nil {
		return s.scoped
	}
	return s.ServerStream.Context()
}

func (s *taskGrantScopedStream) RecvMsg(m any) error {
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return fmt.Errorf("recv callback stream message: %w", err)
	}
	scoped, err := checkTaskGrantScope(s.ServerStream.Context(), m, s.get, s.method, s.logger)
	if err != nil {
		return err
	}
	s.scoped = scoped
	return nil
}
