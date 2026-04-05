package middleware

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// DeprecatedRPC describes an RPC that has been deprecated and will be removed.
type DeprecatedRPC struct {
	FullMethod     string
	Replacement    string
	RemovalVersion string
}

// DeprecatedRPCInterceptor returns a gRPC unary server interceptor that sets
// an x-deprecated response header for deprecated RPCs.
func DeprecatedRPCInterceptor(deprecated []DeprecatedRPC) grpc.UnaryServerInterceptor {
	lookup := make(map[string]DeprecatedRPC, len(deprecated))
	for _, d := range deprecated {
		lookup[d.FullMethod] = d
	}

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if d, ok := lookup[info.FullMethod]; ok {
			_ = grpc.SetHeader(ctx, metadata.Pairs(
				"x-deprecated",
				fmt.Sprintf("This RPC is deprecated. Use %s instead. Removal planned for %s.", d.Replacement, d.RemovalVersion),
			))
		}
		return handler(ctx, req)
	}
}
