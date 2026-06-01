package daemon

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/authz/registry"
)

// requiredAdminServices is every gibson.admin.v1.* service in the registry that
// is NOT a known gap — i.e. the set the daemon must register.
func requiredAdminServices() map[string]struct{} {
	out := make(map[string]struct{})
	for _, e := range registry.Registry {
		if !strings.HasPrefix(e.Service, "gibson.admin.v1.") {
			continue
		}
		if _, gap := knownUnregisteredAdminServices[e.Service]; gap {
			continue
		}
		out[e.Service] = struct{}{}
	}
	return out
}

func TestAssertAdminServicesRegistered_AllPresent(t *testing.T) {
	if err := assertAdminServicesRegistered(requiredAdminServices()); err != nil {
		t.Fatalf("expected ok when all required admin services are registered, got: %v", err)
	}
}

func TestAssertAdminServicesRegistered_MissingFailsLoud(t *testing.T) {
	reg := requiredAdminServices()
	if len(reg) == 0 {
		t.Skip("no required admin services in registry")
	}
	var dropped string
	for k := range reg {
		dropped = k
		delete(reg, k)
		break
	}
	err := assertAdminServicesRegistered(reg)
	if err == nil {
		t.Fatalf("expected failure when %s is unregistered", dropped)
	}
	if !strings.Contains(err.Error(), dropped) {
		t.Fatalf("error must name the missing service %s, got: %v", dropped, err)
	}
}

func TestAssertAdminServicesRegistered_KnownGapTolerated(t *testing.T) {
	// A known gap (e.g. PluginsAdminService) being absent must NOT fail.
	if err := assertAdminServicesRegistered(requiredAdminServices()); err != nil {
		t.Fatalf("known gaps must be tolerated: %v", err)
	}
	if len(knownUnregisteredAdminServices) == 0 {
		t.Skip("no known gaps to assert tolerance for")
	}
}
