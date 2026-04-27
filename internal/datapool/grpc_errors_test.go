package datapool_test

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/datapool"
)

func TestMapPoolError_nil(t *testing.T) {
	if got := datapool.MapPoolError(nil); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestMapPoolError_NotProvisioned(t *testing.T) {
	err := datapool.MapPoolError(&datapool.NotProvisionedError{
		Tenant: "acme",
		Reason: "CRD not found",
	})
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status, got %T: %v", err, err)
	}
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %s", st.Code())
	}
}

func TestMapPoolError_Evicted(t *testing.T) {
	err := datapool.MapPoolError(&datapool.EvictedError{Tenant: "acme"})
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status, got %T: %v", err, err)
	}
	if st.Code() != codes.Unavailable {
		t.Errorf("expected Unavailable, got %s", st.Code())
	}
}

func TestMapPoolError_Other(t *testing.T) {
	err := datapool.MapPoolError(errors.New("redis: connection refused"))
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status, got %T: %v", err, err)
	}
	if st.Code() != codes.Internal {
		t.Errorf("expected Internal, got %s", st.Code())
	}
}

func TestMapPoolError_WrappedNotProvisioned(t *testing.T) {
	wrapped := errors.New("outer: " + (&datapool.NotProvisionedError{Tenant: "acme"}).Error())
	// Wrap at a depth
	inner := &datapool.NotProvisionedError{Tenant: "t2", Reason: "no CRD"}
	err := datapool.MapPoolError(inner)
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status, got %v", wrapped)
	}
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %s", st.Code())
	}
}
