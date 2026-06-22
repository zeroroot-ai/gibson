package daemon

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// assertGRPCCode asserts err carries the expected gRPC status code. (Recovered
// from intelligence_service_test.go when the intelligence subsystem was retired,
// gibson#768; still used by graph_service_test.go.)
func assertGRPCCode(t *testing.T, err error, want codes.Code, label string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error with code %s, got nil", label, want)
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("%s: not a gRPC status error: %v", label, err)
	}
	if st.Code() != want {
		t.Errorf("%s: got code %s, want %s (message: %s)", label, st.Code(), want, st.Message())
	}
}
