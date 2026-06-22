package reconciler

import (
	"context"
	"sort"
	"testing"

	"github.com/zeroroot-ai/sdk/auth"
)

// fgaCatalogFixture wires a recordingAuthorizer (reused from the catalog-fanout
// tests) so that system_tenant:_system#parent lists the given tenants and each
// tenant's tenant_enabled component set is the given map.
func fgaCatalogFixture(tenants []string, enabledByTenant map[string][]string) *recordingAuthorizer {
	a := &recordingAuthorizer{
		listObjects: map[listObjectsKey][]string{},
		listUsers:   map[listUsersKey][]string{},
	}
	refs := make([]string, 0, len(tenants))
	for _, t := range tenants {
		refs = append(refs, "tenant:"+t)
	}
	a.listUsers[listUsersKey{ObjectType: "system_tenant", Object: "system_tenant:_system", Relation: "parent"}] = refs
	for t, comps := range enabledByTenant {
		a.listObjects[listObjectsKey{User: "tenant:" + t, Relation: "tenant_enabled", ObjectType: "component"}] = comps
	}
	return a
}

func desiredKeys(d []ConnectorSandbox) []string {
	out := make([]string, 0, len(d))
	for _, c := range d {
		out = append(out, c.Tenant.String()+"/"+c.Connector)
	}
	sort.Strings(out)
	return out
}

func TestFGACatalogSource_KeepsOnlyManifestBackedConnectors(t *testing.T) {
	// acme has two enabled components: a connector (manifest on record) and a
	// plain tool (no manifest). Only the connector is desired.
	authzr := fgaCatalogFixture(
		[]string{"acme"},
		map[string][]string{"acme": {"component:connector-gitlab", "component:tool-grep"}},
	)
	man := &fakeManifest{manifests: manifestsFor(
		ConnectorSandbox{Tenant: auth.MustNewTenantID("acme"), Connector: "connector-gitlab"},
	)}
	src := &FGACatalogSource{Authorizer: authzr, Manifest: man}

	got, err := src.DesiredConnectors(context.Background())
	if err != nil {
		t.Fatalf("DesiredConnectors: %v", err)
	}
	if want := []string{"acme/connector-gitlab"}; !equalStrs(desiredKeys(got), want) {
		t.Errorf("desired = %v, want %v", desiredKeys(got), want)
	}
}

func TestFGACatalogSource_SkipsSystemBackplaneObject(t *testing.T) {
	// The synthetic component:_system backplane is tenant_enabled on every
	// tenant (ADR-0046) but is never a connector.
	authzr := fgaCatalogFixture(
		[]string{"acme"},
		map[string][]string{"acme": {"component:_system"}},
	)
	src := &FGACatalogSource{Authorizer: authzr, Manifest: &fakeManifest{manifests: map[string][]byte{}}}

	got, err := src.DesiredConnectors(context.Background())
	if err != nil {
		t.Fatalf("DesiredConnectors: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("component:_system must never be desired, got %v", desiredKeys(got))
	}
}

func TestFGACatalogSource_MultipleTenantsIsolated(t *testing.T) {
	// Both tenants enabled the same shared connector; the manifest's _system
	// fallback (modelled here by per-tenant manifests) makes each desired.
	authzr := fgaCatalogFixture(
		[]string{"acme", "globex"},
		map[string][]string{
			"acme":   {"component:connector-gitlab"},
			"globex": {"component:connector-gitlab"},
		},
	)
	man := &fakeManifest{manifests: manifestsFor(
		ConnectorSandbox{Tenant: auth.MustNewTenantID("acme"), Connector: "connector-gitlab"},
		ConnectorSandbox{Tenant: auth.MustNewTenantID("globex"), Connector: "connector-gitlab"},
	)}
	src := &FGACatalogSource{Authorizer: authzr, Manifest: man}

	got, err := src.DesiredConnectors(context.Background())
	if err != nil {
		t.Fatalf("DesiredConnectors: %v", err)
	}
	want := []string{"acme/connector-gitlab", "globex/connector-gitlab"}
	if !equalStrs(desiredKeys(got), want) {
		t.Errorf("desired = %v, want %v", desiredKeys(got), want)
	}
}

func TestFGACatalogSource_NoTenants_NoDesired(t *testing.T) {
	authzr := fgaCatalogFixture(nil, nil)
	src := &FGACatalogSource{Authorizer: authzr, Manifest: &fakeManifest{}}
	got, err := src.DesiredConnectors(context.Background())
	if err != nil {
		t.Fatalf("DesiredConnectors: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("no tenants must yield no desired connectors, got %v", desiredKeys(got))
	}
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
