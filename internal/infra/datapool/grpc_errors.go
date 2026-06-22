// Package datapool — grpc_errors.go
//
// MapPoolError translates datapool sentinel errors to gRPC status errors that
// handlers can return directly to callers.
package datapool

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MapPoolError converts a Pool.For error into the appropriate gRPC status error.
//
// Mapping:
//   - *NotProvisionedError → codes.FailedPrecondition (tenant's data-plane is not ready)
//   - *EvictedError        → codes.Unavailable (pool was evicted; caller should retry)
//   - nil                  → nil
//   - anything else        → codes.Internal (unexpected storage error)
//
// Use this helper at every gRPC handler call site that calls pool.For:
//
//	conn, err := s.pool.For(ctx, tenant)
//	if err != nil {
//	    return nil, datapool.MapPoolError(err)
//	}
//	defer conn.Release()
func MapPoolError(err error) error {
	if err == nil {
		return nil
	}
	var notProvisioned *NotProvisionedError
	if errors.As(err, &notProvisioned) {
		return status.Errorf(codes.FailedPrecondition,
			"tenant data-plane not provisioned: %s", notProvisioned.Reason)
	}
	var evicted *EvictedError
	if errors.As(err, &evicted) {
		return status.Errorf(codes.Unavailable,
			"tenant pool was evicted; please retry: %s", evicted.Tenant)
	}
	return status.Errorf(codes.Internal,
		"data-plane connection failed: %v", err)
}
