//go:build audit
// +build audit

// registry_drift_test.go is the spec-21 CI drift gate. It is a stronger
// version of proto_coverage_test.go: rather than walking compiled-in proto
// descriptors via protoregistry.GlobalFiles, it constructs a real
// *grpc.Server, calls every Register*ServiceServer the daemon calls in
// production, and asserts via GetServiceInfo() that:
//
//  1. Every gRPC method on the server has a corresponding entry in the
//     embedded rpc_registry.yaml (default-deny coverage).
//  2. Every entry in the YAML references a method that actually exists on
//     the server (no stale entries after RPC removal).
//
// Behind the `audit` build tag so it does not slow down `make test`.
// Wired into `make check-authz` (see core/gibson/Makefile) and CI.

package api

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/auth"
	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
	daemonpb "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/v1"
	"google.golang.org/grpc"
)

// TestRegistryCoversAllServerRPCs is the spec-21 default-deny invariant guard.
// Adding a new gRPC RPC without a corresponding rpc_registry.yaml entry must
// fail CI; leaving a stale YAML entry after RPC removal must fail CI.
func TestRegistryCoversAllServerRPCs(t *testing.T) {
	srv := grpc.NewServer()

	// Mirror the registrations performed by internal/daemon/grpc.go on the
	// main gRPC server. HarnessCallbackService is intentionally excluded —
	// it runs on a separate callback server with its own trust model and is
	// NOT enforced by FgaAuthzInterceptor (matches the rationale in
	// proto_coverage_test.go's coveredProtoPackages allowlist).
	daemonpb.RegisterDaemonServiceServer(srv, &noopDaemonService{})
	RegisterDaemonAdminServiceServer(srv, &noopDaemonAdminService{})
	componentpb.RegisterComponentServiceServer(srv, &noopComponentService{})

	// Walk the server's registered services to collect the FullMethod paths.
	known := make([]string, 0, 256)
	for svcName, info := range srv.GetServiceInfo() {
		for _, m := range info.Methods {
			known = append(known, "/"+svcName+"/"+m.Name)
		}
	}
	sort.Strings(known)

	// Sanity check — if this fails, the registrations above are broken.
	if len(known) == 0 {
		t.Fatal("no gRPC methods discovered from server.GetServiceInfo() — " +
			"check that the Register*Server calls in this test mirror grpc.go")
	}

	reg, err := auth.LoadRegistry(auth.EmbeddedRpcRegistry, "")
	require.NoError(t, err, "embedded rpc_registry.yaml must load")

	// (1) Every server-registered method must have a YAML entry.
	if covErr := reg.ValidateCoverage(known); covErr != nil {
		t.Errorf("rpc_registry.yaml is missing entries:\n%s\n\n"+
			"Add the missing methods to core/gibson/internal/auth/rpc_registry.yaml; "+
			"see enterprise/docs/AUTH.md \u00a74.5 for the schema.",
			covErr)
	}

	// (2) Every YAML entry must point at a real server method.
	if staleErr := reg.ValidateNoStaleEntries(known); staleErr != nil {
		t.Errorf("rpc_registry.yaml contains stale entries:\n%s\n\n"+
			"Delete the corresponding entries from "+
			"core/gibson/internal/auth/rpc_registry.yaml.",
			staleErr)
	}

	// Diagnostic: log a summary so CI output is easy to scan.
	regMethods := reg.Methods()
	t.Logf("drift gate: server=%d methods, registry=%d methods (overlap=%d)",
		len(known), len(regMethods), countOverlap(known, regMethods))
}

// countOverlap is a small intersection-size helper for the diagnostic log.
func countOverlap(a, b []string) int {
	set := make(map[string]struct{}, len(a))
	for _, s := range a {
		set[s] = struct{}{}
	}
	n := 0
	for _, s := range b {
		if _, ok := set[s]; ok {
			n++
		}
	}
	return n
}

// silenceUnusedImport keeps the strings import alive even though the body
// above doesn't reference it directly today; future failure messages may.
var _ = strings.HasPrefix

// --- noop server impls (embed Unimplemented so adding RPCs doesn't break) ---

type noopDaemonService struct {
	daemonpb.UnimplementedDaemonServiceServer
}

type noopDaemonAdminService struct {
	UnimplementedDaemonAdminServiceServer
}

type noopComponentService struct {
	componentpb.UnimplementedComponentServiceServer
}
