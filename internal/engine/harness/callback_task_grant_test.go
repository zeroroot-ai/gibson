// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
)

// fakeGrantVerifier answers with fixed claims, or an error, for any token.
type fakeGrantVerifier struct {
	claims sdkcg.Claims
	err    error
	seen   string
}

func (f *fakeGrantVerifier) Verify(_ context.Context, token string) (sdkcg.Claims, error) {
	f.seen = token
	if f.err != nil {
		return sdkcg.Claims{}, f.err
	}
	return f.claims, nil
}

func grantClaims(t *testing.T, tenant, mission string) sdkcg.Claims {
	t.Helper()
	id, err := auth.NewTenantID(tenant)
	if err != nil {
		t.Fatalf("NewTenantID(%q): %v", tenant, err)
	}
	return sdkcg.Claims{
		Subject:   "component:agent:claude",
		Tenant:    id,
		MissionID: mission,
		TaskID:    "task-1",
	}
}

// compactJWT builds an unsigned three-part token with the given header typ, so
// the routing peek (not the signature) is what the test exercises.
func compactJWT(typ string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"` + typ + `","kid":"k"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	return hdr + "." + body + ".sig"
}

func grantCtx(tenant, token string) context.Context {
	ctx := auth.ContextWithTenantString(context.Background(), tenant)
	if token == "" {
		return ctx
	}
	return metadata.NewIncomingContext(ctx, metadata.Pairs(taskGrantHeader, token))
}

func observeReq(mission string) *harnesspb.ObserveRequest {
	return &harnesspb.ObserveRequest{Context: &harnesspb.ContextInfo{MissionId: mission, AgentName: "claude"}}
}

const scopeMethod = "/gibson.harness.v1.HarnessCallbackService/Observe"

func getter(v TaskGrantVerifier) func() TaskGrantVerifier {
	return func() TaskGrantVerifier { return v }
}

// TestWithTaskGrantVerifier_WiresTheGetter: the option is what puts the
// verifier on the service, and the service reads it per request.
func TestWithTaskGrantVerifier_WiresTheGetter(t *testing.T) {
	v := &fakeGrantVerifier{}
	s := &HarnessCallbackService{}
	WithTaskGrantVerifier(getter(v))(s)
	if s.taskGrantVerifier == nil || s.taskGrantVerifier() != TaskGrantVerifier(v) {
		t.Fatal("the option must wire the getter the service reads")
	}
}

// TestTokenType_RoutesWithoutTrusting: the peek only routes between the two
// credential kinds, so anything unreadable is simply not a component token.
func TestTokenType_RoutesWithoutTrusting(t *testing.T) {
	if got := tokenType(compactJWT(componentTokenType)); got != componentTokenType {
		t.Errorf("typ = %q, want %q", got, componentTokenType)
	}
	for _, bad := range []string{"", "a.b", "!!!.b.c", string([]byte{0x41}) + ".b.c"} {
		if got := tokenType(bad); got == componentTokenType {
			t.Errorf("tokenType(%q) = %q; an unreadable header must never route to the component path", bad, got)
		}
	}
}

// TestTaskGrantFromMetadata: an empty header value, a bearer prefix and a
// missing metadata block each behave as the routing needs.
func TestTaskGrantFromMetadata(t *testing.T) {
	if _, ok := taskGrantFromMetadata(context.Background()); ok {
		t.Error("no metadata means no grant")
	}
	empty := metadata.NewIncomingContext(context.Background(), metadata.Pairs(taskGrantHeader, "   "))
	if _, ok := taskGrantFromMetadata(empty); ok {
		t.Error("an empty header value is not a grant")
	}
	two := metadata.NewIncomingContext(context.Background(),
		metadata.MD{taskGrantHeader: []string{"", "Bearer " + compactJWT("JWT")}})
	got, ok := taskGrantFromMetadata(two)
	if !ok || got != compactJWT("JWT") {
		t.Errorf("token = %q ok = %v, want the first readable value, bare", got, ok)
	}
}

// TestTaskGrantScopeInterceptors_UnaryRunsTheHandlerWhenTheGrantMatches: a
// grant that names this tenant and this mission reaches the handler untouched.
func TestTaskGrantScopeInterceptors_UnaryRunsTheHandlerWhenTheGrantMatches(t *testing.T) {
	v := &fakeGrantVerifier{claims: grantClaims(t, "acme", "m-1")}
	unary, _ := taskGrantScopeInterceptors(getter(v), slog.Default())
	called := false
	resp, err := unary(grantCtx("acme", compactJWT("JWT")), observeReq("m-1"),
		&grpc.UnaryServerInfo{FullMethod: scopeMethod},
		func(context.Context, any) (any, error) { called = true; return "ok", nil })
	if err != nil || !called || resp != "ok" {
		t.Fatalf("a matching grant must reach the handler: err=%v called=%v resp=%v", err, called, resp)
	}
}

// TestTaskGrantScopeInterceptors_StreamPropagatesARecvError: a transport error
// is returned as-is, not turned into an authorization refusal.
func TestTaskGrantScopeInterceptors_StreamPropagatesARecvError(t *testing.T) {
	v := &fakeGrantVerifier{claims: grantClaims(t, "acme", "m-1")}
	_, stream := taskGrantScopeInterceptors(getter(v), nil)
	want := errors.New("connection reset")
	err := stream(nil, &failingRecvStream{ctx: grantCtx("acme", compactJWT("JWT")), err: want},
		&grpc.StreamServerInfo{FullMethod: scopeMethod},
		func(_ any, ss grpc.ServerStream) error {
			var m harnesspb.ObserveRequest
			return ss.RecvMsg(&m) //nolint:wrapcheck // the test asserts on the wrapped transport error
		})
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want the transport error", err)
	}
}

// failingRecvStream fails the receive, standing in for a dropped connection.
type failingRecvStream struct {
	grpc.ServerStream
	ctx context.Context
	err error
}

func (s *failingRecvStream) Context() context.Context { return s.ctx }
func (s *failingRecvStream) RecvMsg(any) error        { return s.err }

// TestCheckTaskGrantScope_LogsARefusal: a refusal is logged with its reason, so
// an operator can tell a mismatched grant from an expired one.
func TestCheckTaskGrantScope_LogsARefusal(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	v := &fakeGrantVerifier{claims: grantClaims(t, "acme", "m-A")}
	if _, err := checkTaskGrantScope(grantCtx("acme", compactJWT("JWT")), observeReq("m-B"),
		getter(v), scopeMethod, logger); err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(buf.String(), "callback.authz.task_grant_refused") {
		t.Fatalf("the refusal must be logged with its event name, got %q", buf.String())
	}
}

func TestCheckTaskGrantScope_NoGrantPassesThrough(t *testing.T) {
	v := &fakeGrantVerifier{claims: grantClaims(t, "acme", "m-1")}
	if _, err := checkTaskGrantScope(grantCtx("acme", ""), observeReq("m-1"), getter(v), scopeMethod, nil); err != nil {
		t.Fatalf("no grant must pass: %v", err)
	}
	if v.seen != "" {
		t.Fatal("verifier must not run without a grant")
	}
}

func TestCheckTaskGrantScope_ComponentTokenIsNotATaskGrant(t *testing.T) {
	v := &fakeGrantVerifier{err: errors.New("must not be called")}
	_, err := checkTaskGrantScope(grantCtx("acme", compactJWT(componentTokenType)), observeReq("m-1"), getter(v), scopeMethod, nil)
	if err != nil {
		t.Fatalf("agent+jwt is the component's own identity, not a task grant: %v", err)
	}
}

func TestCheckTaskGrantScope_AcceptsMatchingGrant(t *testing.T) {
	v := &fakeGrantVerifier{claims: grantClaims(t, "acme", "m-1")}
	_, err := checkTaskGrantScope(grantCtx("acme", compactJWT("JWT")), observeReq("m-1"), getter(v), scopeMethod, nil)
	if err != nil {
		t.Fatalf("matching grant must pass: %v", err)
	}
	if v.seen == "" {
		t.Fatal("verifier must see the token")
	}
}

func TestCheckTaskGrantScope_BearerPrefixIsTolerated(t *testing.T) {
	v := &fakeGrantVerifier{claims: grantClaims(t, "acme", "m-1")}
	ctx := metadata.NewIncomingContext(auth.ContextWithTenantString(context.Background(), "acme"),
		metadata.Pairs(taskGrantHeader, "Bearer "+compactJWT("JWT")))
	if _, err := checkTaskGrantScope(ctx, observeReq("m-1"), getter(v), scopeMethod, nil); err != nil {
		t.Fatalf("bearer-prefixed grant must pass: %v", err)
	}
	if v.seen != compactJWT("JWT") {
		t.Fatalf("token handed to the verifier = %q, want the bare token", v.seen)
	}
}

func TestCheckTaskGrantScope_WrongMissionIsDenied(t *testing.T) {
	v := &fakeGrantVerifier{claims: grantClaims(t, "acme", "m-A")}
	_, err := checkTaskGrantScope(grantCtx("acme", compactJWT("JWT")), observeReq("m-B"), getter(v), scopeMethod, nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("grant for mission A presenting mission B must be PermissionDenied, got %v", err)
	}
}

func TestCheckTaskGrantScope_WrongTenantIsDenied(t *testing.T) {
	v := &fakeGrantVerifier{claims: grantClaims(t, "acme", "m-1")}
	_, err := checkTaskGrantScope(grantCtx("other", compactJWT("JWT")), observeReq("m-1"), getter(v), scopeMethod, nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("grant for another tenant must be PermissionDenied, got %v", err)
	}
}

func TestCheckTaskGrantScope_ExpiredIsUnauthenticated(t *testing.T) {
	v := &fakeGrantVerifier{err: sdkcg.ErrExpired}
	_, err := checkTaskGrantScope(grantCtx("acme", compactJWT("JWT")), observeReq("m-1"), getter(v), scopeMethod, nil)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expired grant must be Unauthenticated, got %v", err)
	}
}

func TestCheckTaskGrantScope_NoVerifierRefusesAPresentedGrant(t *testing.T) {
	_, err := checkTaskGrantScope(grantCtx("acme", compactJWT("JWT")), observeReq("m-1"), nil, scopeMethod, nil)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("a grant this daemon cannot verify must be refused, got %v", err)
	}
	_, err = checkTaskGrantScope(grantCtx("acme", compactJWT("JWT")), observeReq("m-1"), getter(nil), scopeMethod, nil)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("a nil verifier must refuse, got %v", err)
	}
}

func TestCheckTaskGrantScope_RequestWithoutContextSkipsMissionCheck(t *testing.T) {
	v := &fakeGrantVerifier{claims: grantClaims(t, "acme", "m-1")}
	_, err := checkTaskGrantScope(grantCtx("acme", compactJWT("JWT")), struct{}{}, getter(v), scopeMethod, nil)
	if err != nil {
		t.Fatalf("a message with no ContextInfo has no mission to compare: %v", err)
	}
}

func TestTaskGrantScopeInterceptors_UnaryDeniesBeforeTheHandler(t *testing.T) {
	v := &fakeGrantVerifier{claims: grantClaims(t, "acme", "m-A")}
	unary, _ := taskGrantScopeInterceptors(getter(v), nil)
	called := false
	_, err := unary(grantCtx("acme", compactJWT("JWT")), observeReq("m-B"),
		&grpc.UnaryServerInfo{FullMethod: scopeMethod},
		func(context.Context, any) (any, error) { called = true; return nil, nil })
	if status.Code(err) != codes.PermissionDenied || called {
		t.Fatalf("handler must not run on a mismatched grant: err=%v called=%v", err, called)
	}
}

// recvStream feeds one message to RecvMsg.
type recvStream struct {
	grpc.ServerStream
	ctx context.Context
	msg *harnesspb.ObserveRequest
}

func (s *recvStream) Context() context.Context { return s.ctx }

// RecvMsg fills m the way a real stream would. proto.Merge, not assignment: a
// generated message carries a lock, so copying the value by hand is a vet
// error and, in a real stream, a race.
func (s *recvStream) RecvMsg(m any) error {
	req, ok := m.(*harnesspb.ObserveRequest)
	if !ok {
		return errors.New("recvStream: unexpected message type")
	}
	proto.Merge(req, s.msg)
	return nil
}

func TestTaskGrantScopeInterceptors_StreamChecksEachMessage(t *testing.T) {
	v := &fakeGrantVerifier{claims: grantClaims(t, "acme", "m-A")}
	_, stream := taskGrantScopeInterceptors(getter(v), nil)
	var got error
	err := stream(nil, &recvStream{ctx: grantCtx("acme", compactJWT("JWT")), msg: observeReq("m-B")},
		&grpc.StreamServerInfo{FullMethod: scopeMethod},
		func(_ any, ss grpc.ServerStream) error {
			var m harnesspb.ObserveRequest
			got = ss.RecvMsg(&m)
			return got //nolint:wrapcheck // the test asserts on the interceptor's own error, so it must not be wrapped
		})
	if status.Code(err) != codes.PermissionDenied || status.Code(got) != codes.PermissionDenied {
		t.Fatalf("stream message for another mission must be refused: %v / %v", err, got)
	}
}

// TestCheckTaskGrantScope_CarriesTheClaimsOnTheContext: a handler that must
// know which job a callback belongs to reads the verified claims, never a
// request field the caller filled in.
func TestCheckTaskGrantScope_CarriesTheClaimsOnTheContext(t *testing.T) {
	v := &fakeGrantVerifier{claims: grantClaims(t, "acme", "m-1")}
	scoped, err := checkTaskGrantScope(grantCtx("acme", compactJWT("JWT")), observeReq("m-1"),
		getter(v), scopeMethod, nil)
	if err != nil {
		t.Fatalf("checkTaskGrantScope: %v", err)
	}
	claims, ok := TaskGrantClaimsFromContext(scoped)
	if !ok {
		t.Fatal("the verified claims must reach the handler")
	}
	if claims.MissionID != "m-1" || claims.TaskID != "task-1" {
		t.Fatalf("claims = %+v", claims)
	}
}

// TestTaskGrantClaimsFromContext_AbsentForOtherCredentials: a request
// authenticated some other way carries no claims, and a handler that needs them
// must refuse rather than guess.
func TestTaskGrantClaimsFromContext_AbsentForOtherCredentials(t *testing.T) {
	if _, ok := TaskGrantClaimsFromContext(context.Background()); ok {
		t.Fatal("a request with no task grant must carry no claims")
	}
	plain, err := checkTaskGrantScope(grantCtx("acme", ""), observeReq("m-1"), getter(nil), scopeMethod, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := TaskGrantClaimsFromContext(plain); ok {
		t.Fatal("a pass-through must add no claims")
	}
}

type baseCtxStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *baseCtxStream) Context() context.Context { return s.ctx }

// TestTaskGrantScopedStream_ContextCarriesTheClaimsOnceSeen asserts a
// streaming handler reads the verified claims the way a unary one does: the
// base context before any grant arrived, the scoped one after.
func TestTaskGrantScopedStream_ContextCarriesTheClaimsOnceSeen(t *testing.T) {
	base := context.Background()
	s := &taskGrantScopedStream{ServerStream: &baseCtxStream{ctx: base}}
	if _, ok := TaskGrantClaimsFromContext(s.Context()); ok {
		t.Fatal("no claims before a grant arrived")
	}
	s.scoped = withTaskGrantClaims(base, sdkcg.Claims{MissionID: "bank-1", TaskID: "job-1"})
	claims, ok := TaskGrantClaimsFromContext(s.Context())
	if !ok || claims.TaskID != "job-1" {
		t.Fatalf("claims = %+v, %v", claims, ok)
	}
}
