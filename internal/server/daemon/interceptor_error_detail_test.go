// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errorDetailOf returns the one ErrorDetail in the status of err.
func errorDetailOf(t *testing.T, err error) *commonpb.ErrorDetail {
	t.Helper()
	var found *commonpb.ErrorDetail
	for _, d := range status.Convert(err).Details() {
		if ed, ok := d.(*commonpb.ErrorDetail); ok {
			if found != nil {
				t.Fatal("the status carries two ErrorDetail messages")
			}
			found = ed
		}
	}
	if found == nil {
		t.Fatalf("the status %v carries no ErrorDetail", err)
	}
	return found
}

// An invalid request gets InvalidArgument, and the client reads each field
// error from the status details (gibson#847).
func TestErrorDetail_InvalidRequestNamesTheField(t *testing.T) {
	v, err := buildProtovalidateValidator()
	if err != nil {
		t.Fatalf("buildProtovalidateValidator: %v", err)
	}
	validate := newProtovalidateUnaryInterceptor(v)
	unary, _ := errorDetailInterceptors()
	req := &missionv1.AgentNodeConfig{AgentName: "test", MaxTokensPerCall: ptrInt32(-1)}

	_, err = unary(context.Background(), req, &grpc.UnaryServerInfo{FullMethod: "/test.Method"},
		func(ctx context.Context, r any) (any, error) {
			return validate(ctx, r, &grpc.UnaryServerInfo{FullMethod: "/test.Method"},
				func(context.Context, any) (any, error) { return struct{}{}, nil })
		})

	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
	detail := errorDetailOf(t, err)
	if detail.GetCode() != commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT || detail.GetReason() != "INVALID_ARGUMENT" {
		t.Errorf("detail = %v, want the invalid-argument code and reason", detail)
	}
	if len(detail.GetFieldErrors()) != 1 {
		t.Fatalf("field errors = %v, want one", detail.GetFieldErrors())
	}
	fe := detail.GetFieldErrors()[0]
	if fe.GetField() != "max_tokens_per_call" || fe.GetRule() == "" || fe.GetMessage() == "" {
		t.Errorf("field error = %v, want the field path, a rule id and a message", fe)
	}
}

// Each error status gets a code and a reason, and its message stays the same.
func TestErrorDetail_AddsCodeAndReasonAndKeepsTheMessage(t *testing.T) {
	cases := []struct {
		in     error
		code   commonpb.ErrorCode
		reason string
	}{
		{status.Error(codes.NotFound, "mission not found"), commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, "NOT_FOUND"},
		{status.Error(codes.FailedPrecondition, "not pending"),
			commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "FAILED_PRECONDITION"},
		{status.Error(codes.DeadlineExceeded, "slow"), commonpb.ErrorCode_ERROR_CODE_TIMEOUT, "DEADLINE_EXCEEDED"},
		{status.Error(codes.Unauthenticated, "no token"),
			commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "UNAUTHENTICATED"},
		{status.Error(codes.Internal, "failed"), commonpb.ErrorCode_ERROR_CODE_INTERNAL, "INTERNAL"},
		{status.Error(codes.Aborted, "conflict"), commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "ABORTED"},
	}
	for _, tc := range cases {
		got := withErrorDetail(tc.in)
		if status.Code(got) != status.Code(tc.in) {
			t.Errorf("%v: code changed to %v", tc.in, status.Code(got))
		}
		if status.Convert(got).Message() != status.Convert(tc.in).Message() {
			t.Errorf("%v: message changed to %q", tc.in, status.Convert(got).Message())
		}
		detail := errorDetailOf(t, got)
		if detail.GetCode() != tc.code || detail.GetReason() != tc.reason {
			t.Errorf("%v: detail = %v, want %v and %s", tc.in, detail, tc.code, tc.reason)
		}
		if len(detail.GetFieldErrors()) != 0 {
			t.Errorf("%v: field errors = %v, want none", tc.in, detail.GetFieldErrors())
		}
	}
}

// The interceptor adds no text. A plain error becomes the Unknown status that
// the gRPC server sends for it, with the same text and nothing more.
func TestErrorDetail_AddsNoText(t *testing.T) {
	if withErrorDetail(nil) != nil {
		t.Fatal("a nil error must stay nil")
	}
	got := withErrorDetail(errors.New("boom"))
	if status.Code(got) != codes.Unknown || status.Convert(got).Message() != "boom" {
		t.Fatalf("got %v, want Unknown with the text boom", got)
	}
	if errorDetailOf(t, got).GetReason() != "UNKNOWN" {
		t.Errorf("reason = %q, want UNKNOWN", errorDetailOf(t, got).GetReason())
	}
}

// A status with an ErrorDetail passes unchanged, so the field errors of the
// validation status are not replaced.
func TestErrorDetail_KeepsAnExistingDetail(t *testing.T) {
	st, err := status.New(codes.InvalidArgument, "bad").WithDetails(&commonpb.ErrorDetail{
		Code:        commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
		Reason:      "INVALID_ARGUMENT",
		FieldErrors: []*commonpb.FieldError{{Field: "name", Rule: "string.min_len", Message: "too short"}},
	})
	if err != nil {
		t.Fatalf("WithDetails: %v", err)
	}
	got := withErrorDetail(st.Err())
	if len(errorDetailOf(t, got).GetFieldErrors()) != 1 {
		t.Fatalf("the field errors were replaced: %v", got)
	}
}

// The scrub interceptor rewrites the message and keeps the details.
func TestScrubError_KeepsTheDetails(t *testing.T) {
	st, err := status.New(codes.Internal, "failed to load /home/user/.gibson/config.yaml").
		WithDetails(&commonpb.ErrorDetail{Code: commonpb.ErrorCode_ERROR_CODE_INTERNAL, Reason: "INTERNAL"})
	if err != nil {
		t.Fatalf("WithDetails: %v", err)
	}
	got := scrubError(context.Background(), nil, nil, st.Err(), "/test.Method")
	if status.Convert(got).Message() == st.Message() {
		t.Fatal("the message was not scrubbed")
	}
	if errorDetailOf(t, got).GetReason() != "INTERNAL" {
		t.Errorf("detail lost: %v", got)
	}
}
