package api

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	// Blank imports pull the generated Go proto packages into the test
	// binary so their init() funcs register their service/method descriptors
	// with protoregistry.GlobalFiles.
	_ "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/daemon/operator/v1"
	_ "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	_ "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	_ "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
)

// Note: FGA registry coverage tests have been removed. FGA enforcement has
// moved to Envoy + ext_authz; the daemon no longer runs an FGA interceptor.
// The discoverGibsonRPCs helper below is retained for other test utilities.

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
	"gibson.daemon.v1":          {},
	"gibson.component.v1":       {},
	"gibson.tenant.v1":          {},
	"gibson.daemon.operator.v1": {},
	"gibson.user.v1":            {},
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
