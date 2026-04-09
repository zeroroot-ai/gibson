package api

import (
	"strings"
	"testing"

	"github.com/zero-day-ai/gibson/internal/auth"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	// Blank imports pull the generated Go proto packages into the test
	// binary so their init() funcs register their service/method descriptors
	// with protoregistry.GlobalFiles. The package-level import of this
	// package itself (the one declaring DaemonAdminService) already provides
	// gibson.daemon.admin.v1; these imports cover the other two services.
	_ "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
	_ "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/v1"
)

// TestFgaRegistryCoverAllProtoRPCs is the default-deny CI gate. It walks
// every gRPC method compiled into the daemon (via protoregistry.GlobalFiles)
// and asserts that every one has an entry in the FgaRpcRegistry.
//
// A developer who adds a new RPC without updating fga_rpc_registry.go will
// see this test fail with the unmapped method name.
//
// Lives in internal/daemon/api (not internal/auth) because internal/auth
// cannot import internal/daemon/api without an import cycle — the test
// depends on the proto registrations in the daemon api package.
func TestFgaRegistryCoverAllProtoRPCs(t *testing.T) {
	reg := auth.NewFgaRpcRegistry()

	methods := discoverGibsonRPCs(t)
	if len(methods) == 0 {
		t.Fatal("no gibson.* RPCs discovered — blank imports in proto_coverage_test.go may be wrong")
	}

	var missing []string
	for _, method := range methods {
		if _, ok := reg.Lookup(method); !ok {
			missing = append(missing, method)
		}
	}

	if len(missing) > 0 {
		t.Errorf("FGA registry coverage gap — %d RPC(s) not registered:\n  %s\n\nEvery proto RPC must have an entry in internal/auth/fga_rpc_registry.go NewFgaRpcRegistry().",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// coveredProtoPackages is the allowlist of proto packages whose services
// are actually REGISTERED on the daemon's main gRPC server (see
// internal/daemon/grpc.go). Only these services are enforced by the
// FgaAuthzInterceptor and must therefore be mapped in fga_rpc_registry.go.
//
// Services NOT in this list are excluded from the coverage check:
//
//   - gibson.agent.v1.AgentService: served by agents, not the daemon
//     (daemon is the client)
//   - gibson.tool.v1.ToolService: served by tools
//   - gibson.plugin.v1.PluginService: served by plugins
//   - gibson.harness.v1.HarnessCallbackService: served by the daemon's
//     separate callback server (internal/harness/callback_server.go)
//     which has its own trust model (agents-only) and no
//     FgaAuthzInterceptor
//
// When a new service is added to the main daemon gRPC server, add its
// proto package here to extend the coverage gate.
var coveredProtoPackages = map[string]struct{}{
	"gibson.daemon.v1":       {},
	"gibson.daemon.admin.v1": {},
	"gibson.component.v1":    {},
}

// discoverGibsonRPCs walks protoregistry.GlobalFiles and returns the
// fully-qualified gRPC method paths (/package.Service/Method) for every
// service in coveredProtoPackages.
func discoverGibsonRPCs(t *testing.T) []string {
	t.Helper()

	var methods []string
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		pkg := string(fd.Package())
		if _, covered := coveredProtoPackages[pkg]; !covered {
			return true
		}
		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			svc := services.Get(i)
			svcName := string(svc.FullName())
			rpcs := svc.Methods()
			for j := 0; j < rpcs.Len(); j++ {
				m := rpcs.Get(j)
				methods = append(methods, "/"+svcName+"/"+string(m.Name()))
			}
		}
		return true
	})
	return methods
}

// silenceUnusedImport is a no-op sink; kept because the import is reserved for future use.
var _ = strings.HasPrefix
