// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"strings"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errorDetailInterceptors returns the unary and stream interceptors that
// attach one gibson.common.v1.ErrorDetail to each error status that has none
// (ADR-0028, rule 4, gibson#847).
//
// Position in chain: outermost. The scrub interceptor rewrites the message of
// a status, and the recovery interceptor turns a panic into a status. This
// interceptor runs after both on the way out, so each status that leaves the
// daemon carries a code and a reason.
//
// The interceptor changes no message. It adds the detail only. A status that
// already carries an ErrorDetail, for example from the protovalidate
// interceptor with its field errors, passes unchanged.
func errorDetailInterceptors() (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	unary := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		resp, err := handler(ctx, req)
		return resp, withErrorDetail(err)
	}
	stream := func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return withErrorDetail(handler(srv, ss))
	}
	return unary, stream
}

// withErrorDetail returns err with one ErrorDetail in its status details. A
// nil error stays nil. An error that is not a status becomes the status the
// gRPC server would send for it: Unknown, with the text of the error.
func withErrorDetail(err error) error {
	if err == nil {
		return nil
	}
	st := status.Convert(err)
	if hasErrorDetail(st) {
		return err
	}
	detail := &commonpb.ErrorDetail{
		Code:   errorCodeFor(st.Code()),
		Reason: reasonFor(st.Code()),
	}
	withDetail, derr := st.WithDetails(detail)
	if derr != nil {
		// The detail did not marshal. The status is still correct without it.
		return st.Err()
	}
	return withDetail.Err()
}

// hasErrorDetail reports whether st already carries an ErrorDetail.
func hasErrorDetail(st *status.Status) bool {
	for _, d := range st.Details() {
		if _, ok := d.(*commonpb.ErrorDetail); ok {
			return true
		}
	}
	return false
}

// errorCodeFor maps a gRPC code to the standard error code of the API.
func errorCodeFor(code codes.Code) commonpb.ErrorCode {
	switch code {
	case codes.OK:
		return commonpb.ErrorCode_ERROR_CODE_UNSPECIFIED
	case codes.InvalidArgument, codes.FailedPrecondition, codes.OutOfRange, codes.Aborted:
		return commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT
	case codes.NotFound:
		return commonpb.ErrorCode_ERROR_CODE_NOT_FOUND
	case codes.DeadlineExceeded:
		return commonpb.ErrorCode_ERROR_CODE_TIMEOUT
	case codes.Unavailable:
		return commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE
	case codes.PermissionDenied, codes.Unauthenticated:
		return commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED
	case codes.AlreadyExists:
		return commonpb.ErrorCode_ERROR_CODE_ALREADY_EXISTS
	case codes.ResourceExhausted:
		return commonpb.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED
	case codes.Canceled:
		return commonpb.ErrorCode_ERROR_CODE_CANCELLED
	default:
		// Internal, Unknown, Unimplemented and DataLoss are faults of the
		// daemon, not of the request.
		return commonpb.ErrorCode_ERROR_CODE_INTERNAL
	}
}

// reasonFor returns the stable reason for a status with no reason of its own:
// the name of the gRPC code in upper snake case, for example NOT_FOUND or
// FAILED_PRECONDITION.
func reasonFor(code codes.Code) string {
	name := code.String()
	var b strings.Builder
	b.Grow(len(name) + 4)
	for i, r := range name {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		b.WriteRune(r)
	}
	return strings.ToUpper(b.String())
}
