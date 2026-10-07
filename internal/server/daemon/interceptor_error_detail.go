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

// withErrorDetailInterceptors wraps the outermost interceptors so that each
// error status that they return carries one gibson.common.v1.ErrorDetail
// (ADR-0028, rule 4, gibson#847). panicRecoveryInterceptors applies it, so
// the detail also covers a status that the scrub interceptor rewrote and a
// status that the recovery made from a panic.
//
// It changes no message. It adds the detail only. A status that already
// carries an ErrorDetail, for example from the protovalidate interceptor with
// its field errors, passes unchanged.
func withErrorDetailInterceptors(
	unary grpc.UnaryServerInterceptor, stream grpc.StreamServerInterceptor,
) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	wrappedUnary := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		resp, err := unary(ctx, req, info, handler)
		return resp, withErrorDetail(err)
	}
	wrappedStream := func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return withErrorDetail(stream(srv, ss, info, handler))
	}
	return wrappedUnary, wrappedStream
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
	return attachDetail(err, st, detail)
}

// attachDetail returns st with detail in its details. When the detail cannot
// be attached (st has the code OK, or the detail does not marshal), it
// returns err as it was: the status is still correct without the detail.
func attachDetail(err error, st *status.Status, detail *commonpb.ErrorDetail) error {
	withDetail, derr := st.WithDetails(detail)
	if derr != nil {
		return err
	}
	return status.ErrorProto(withDetail.Proto())
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
	case codes.InvalidArgument, codes.FailedPrecondition, codes.OutOfRange:
		return commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT
	case codes.NotFound:
		return commonpb.ErrorCode_ERROR_CODE_NOT_FOUND
	case codes.DeadlineExceeded:
		return commonpb.ErrorCode_ERROR_CODE_TIMEOUT
	case codes.Unavailable, codes.Aborted:
		// Aborted is a concurrency conflict. The client retries, as it does
		// for Unavailable.
		return commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE
	case codes.PermissionDenied, codes.Unauthenticated:
		// The API has no unauthenticated code. A client tells "sign in
		// again" from "refused" by the reason: UNAUTHENTICATED.
		return commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED
	case codes.AlreadyExists:
		return commonpb.ErrorCode_ERROR_CODE_ALREADY_EXISTS
	case codes.ResourceExhausted:
		return commonpb.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED
	case codes.Canceled:
		return commonpb.ErrorCode_ERROR_CODE_CANCELLED
	case codes.Unknown, codes.Unimplemented, codes.Internal, codes.DataLoss:
		// These are faults of the daemon, not of the request.
		return commonpb.ErrorCode_ERROR_CODE_INTERNAL
	}
	// A code that gRPC does not define is a fault of the daemon too.
	return commonpb.ErrorCode_ERROR_CODE_INTERNAL
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
