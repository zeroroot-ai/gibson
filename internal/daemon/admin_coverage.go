package daemon

import (
	"fmt"
	"sort"
	"strings"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/authz/registry"
)

// knownUnregisteredAdminServices lists gibson.admin.v1.* services that appear in
// the authz registry but are intentionally NOT (yet) registered on the daemon
// gRPC server. Every entry is an acknowledged gap with a tracking issue;
// registering the service should delete its line here. A NEW admin service must
// be registered in grpc.go — not added here.
var knownUnregisteredAdminServices = map[string]string{
	// PluginsAdminServer is implemented (internal/admin/plugin_admin.go) but not
	// yet wired into grpc.go — same class of gap as SecretsAdminService.
	// Tracked: gibson#565.
	"gibson.admin.v1.PluginsAdminService": "implemented but not yet registered — gibson#565",
}

// assertAdminServicesRegistered is the reverse of assertRegistryCoverage. The
// latter checks registered -> registry (every served method has an authz rule).
// This checks registry -> registered for admin services: every gibson.admin.v1.*
// service declared in the authz registry must actually be registered on the
// daemon gRPC server, or be an acknowledged known gap. It catches a service that
// is fully declared + authz-gated but never served — which boots cleanly and
// only fails (Unimplemented) when a client calls it (see gibson#564, where
// SecretsAdminService had been unregistered since inception).
func assertAdminServicesRegistered(registered map[string]struct{}) error {
	seen := map[string]bool{}
	var missing []string
	for _, e := range registry.Registry {
		svc := e.Service
		if !strings.HasPrefix(svc, "gibson.admin.v1.") || seen[svc] {
			continue
		}
		seen[svc] = true
		if _, ok := knownUnregisteredAdminServices[svc]; ok {
			continue
		}
		if _, ok := registered[svc]; !ok {
			missing = append(missing, svc)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf(
		"admin services declared in the authz registry but not registered on the daemon gRPC server "+
			"(add the Register<Svc>ServiceServer call in grpc.go, or — if intentionally served elsewhere — "+
			"add to knownUnregisteredAdminServices with a tracking issue): %s",
		strings.Join(missing, ", "))
}

// registeredServiceNames returns the set of fully-qualified service names the
// gRPC server is currently serving.
func registeredServiceNames(srv *grpc.Server) map[string]struct{} {
	out := make(map[string]struct{})
	for name := range srv.GetServiceInfo() {
		out[name] = struct{}{}
	}
	return out
}
