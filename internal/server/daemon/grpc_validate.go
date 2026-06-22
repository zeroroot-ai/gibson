package daemon

import (
	"context"
	"errors"
	"fmt"

	"buf.build/go/protovalidate"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// newProtovalidateUnaryInterceptor returns a gRPC unary interceptor
// that runs the configured protovalidate Validator against every
// incoming request message that carries `(buf.validate.field).*`
// annotations. Violations are surfaced as
// `codes.InvalidArgument` with the validation library's formatted
// error.
//
// The validator is allocated once at server construction and
// shared across requests (it is goroutine-safe and caches CEL
// programs internally).
//
// Spec: mission-verb-noun-registry Requirement 10.
func newProtovalidateUnaryInterceptor(v protovalidate.Validator) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Many internal RPC types are not proto.Message (auth probes,
		// debug pings). Skip those cleanly — only proto messages can
		// carry validate annotations.
		msg, ok := req.(proto.Message)
		if !ok {
			return handler(ctx, req)
		}
		if err := v.Validate(msg); err != nil {
			var verr *protovalidate.ValidationError
			if errors.As(err, &verr) {
				return nil, grpcstatus.Error(grpccodes.InvalidArgument, verr.Error())
			}
			// Compilation or other internal errors from the validator
			// are programming bugs — surface as Internal so callers
			// don't mistake them for client-side input errors.
			return nil, grpcstatus.Errorf(grpccodes.Internal, "protovalidate: %v", err)
		}
		return handler(ctx, req)
	}
}

// newProtovalidateStreamInterceptor returns the streaming
// equivalent. Validates the first message of each stream by
// wrapping the ServerStream's RecvMsg.
func newProtovalidateStreamInterceptor(v protovalidate.Validator) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		wrapped := &validatingServerStream{ServerStream: ss, validator: v}
		return handler(srv, wrapped)
	}
}

type validatingServerStream struct {
	grpc.ServerStream
	validator protovalidate.Validator
}

func (s *validatingServerStream) RecvMsg(m any) error {
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	if msg, ok := m.(proto.Message); ok {
		if err := s.validator.Validate(msg); err != nil {
			var verr *protovalidate.ValidationError
			if errors.As(err, &verr) {
				return grpcstatus.Error(grpccodes.InvalidArgument, verr.Error())
			}
			return grpcstatus.Errorf(grpccodes.Internal, "protovalidate: %v", err)
		}
	}
	return nil
}

// buildProtovalidateValidator constructs the singleton validator
// used by the interceptors. Errors here are programming-time
// (proto descriptors are malformed); they fail server startup
// fail-closed.
func buildProtovalidateValidator() (protovalidate.Validator, error) {
	v, err := protovalidate.New()
	if err != nil {
		return nil, fmt.Errorf("protovalidate.New: %w", err)
	}
	return v, nil
}
