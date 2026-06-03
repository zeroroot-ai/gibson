package tenant_test

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/pkg/platform/tenant"
)

func TestNames_AllFormats(t *testing.T) {
	type want struct {
		slug, underscore, namespace string
		pgDB, pgRole                string
		neo4jSS, neo4jSecret        string
		neo4jPVCRoot, neo4jBolt     string
		redisField                  string
		qdrant                      string
		vaultPrefix, vaultPolicy    string
		vaultJWT                    string
		fga                         string
		zitadel, langfuse           string
	}
	cases := []struct {
		name     string
		tenantID string
		want     want
	}{
		{
			name:     "single short",
			tenantID: "acme",
			want: want{
				slug: "acme", underscore: "acme", namespace: "tenant-acme",
				pgDB: "tenant_acme", pgRole: "tenant_acme_app",
				neo4jSS: "tenant-acme-neo4j", neo4jSecret: "tenant-acme-neo4j-auth",
				neo4jPVCRoot: "data-tenant-acme-neo4j",
				neo4jBolt:    "bolt://tenant-acme-neo4j.gibson.svc.cluster.local:7687",
				redisField:   "acme",
				qdrant:       "tenant_acme",
				vaultPrefix:  "tenant/acme", vaultPolicy: "tenant-acme-app",
				vaultJWT: "gibson-plugin-acme",
				fga:      "tenant:acme",
				zitadel:  "acme", langfuse: "acme",
			},
		},
		{
			name:     "hyphenated multi-word",
			tenantID: "zeroroot-ai",
			want: want{
				slug: "zeroroot-ai", underscore: "zeroroot_ai", namespace: "tenant-zeroroot-ai",
				pgDB: "tenant_zeroroot_ai", pgRole: "tenant_zeroroot_ai_app",
				neo4jSS: "tenant-zeroroot-ai-neo4j", neo4jSecret: "tenant-zeroroot-ai-neo4j-auth",
				neo4jPVCRoot: "data-tenant-zeroroot-ai-neo4j",
				neo4jBolt:    "bolt://tenant-zeroroot-ai-neo4j.gibson.svc.cluster.local:7687",
				redisField:   "zeroroot-ai",
				qdrant:       "tenant_zeroroot_ai",
				vaultPrefix:  "tenant/zeroroot-ai", vaultPolicy: "tenant-zeroroot-ai-app",
				vaultJWT: "gibson-plugin-zeroroot-ai",
				fga:      "tenant:zeroroot-ai",
				zitadel:  "zeroroot-ai", langfuse: "zeroroot-ai",
			},
		},
		{
			name:     "underscore separator",
			tenantID: "smoke_solo",
			want: want{
				slug: "smoke_solo", underscore: "smoke_solo", namespace: "tenant-smoke_solo",
				pgDB: "tenant_smoke_solo", pgRole: "tenant_smoke_solo_app",
				neo4jSS: "tenant-smoke_solo-neo4j", neo4jSecret: "tenant-smoke_solo-neo4j-auth",
				neo4jPVCRoot: "data-tenant-smoke_solo-neo4j",
				neo4jBolt:    "bolt://tenant-smoke_solo-neo4j.gibson.svc.cluster.local:7687",
				redisField:   "smoke_solo",
				qdrant:       "tenant_smoke_solo",
				vaultPrefix:  "tenant/smoke_solo", vaultPolicy: "tenant-smoke_solo-app",
				vaultJWT: "gibson-plugin-smoke_solo",
				fga:      "tenant:smoke_solo",
				zitadel:  "smoke_solo", langfuse: "smoke_solo",
			},
		},
		{
			name:     "single character",
			tenantID: "a",
			want: want{
				slug: "a", underscore: "a", namespace: "tenant-a",
				pgDB: "tenant_a", pgRole: "tenant_a_app",
				neo4jSS: "tenant-a-neo4j", neo4jSecret: "tenant-a-neo4j-auth",
				neo4jPVCRoot: "data-tenant-a-neo4j",
				neo4jBolt:    "bolt://tenant-a-neo4j.gibson.svc.cluster.local:7687",
				redisField:   "a",
				qdrant:       "tenant_a",
				vaultPrefix:  "tenant/a", vaultPolicy: "tenant-a-app",
				vaultJWT: "gibson-plugin-a",
				fga:      "tenant:a",
				zitadel:  "a", langfuse: "a",
			},
		},
	}

	const operatorNS = "gibson"

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			id, err := auth.NewTenantID(c.tenantID)
			if err != nil {
				t.Fatalf("NewTenantID(%q): %v", c.tenantID, err)
			}
			n := tenant.FromTenantID(id)

			checks := []struct {
				field, got, want string
			}{
				{"Slug", n.Slug(), c.want.slug},
				{"Underscore", n.Underscore(), c.want.underscore},
				{"Namespace", n.Namespace(), c.want.namespace},
				{"PostgresDB", n.PostgresDB(), c.want.pgDB},
				{"PostgresAppRole", n.PostgresAppRole(), c.want.pgRole},
				{"Neo4jStatefulSet", n.Neo4jStatefulSet(), c.want.neo4jSS},
				{"Neo4jService", n.Neo4jService(), c.want.neo4jSS},
				{"Neo4jSecret", n.Neo4jSecret(), c.want.neo4jSecret},
				{"Neo4jPVCRoot", n.Neo4jPVCRoot(), c.want.neo4jPVCRoot},
				{"Neo4jBoltURI", n.Neo4jBoltURI(operatorNS), c.want.neo4jBolt},
				{"RedisIndexField", n.RedisIndexField(), c.want.redisField},
				{"QdrantCollection", n.QdrantCollection(), c.want.qdrant},
				{"VaultPathPrefix", n.VaultPathPrefix(), c.want.vaultPrefix},
				{"VaultPolicyName", n.VaultPolicyName(), c.want.vaultPolicy},
				{"VaultJWTRoleName", n.VaultJWTRoleName(), c.want.vaultJWT},
				{"FGAObject", n.FGAObject(), c.want.fga},
				{"ZitadelOrgSlug", n.ZitadelOrgSlug(), c.want.zitadel},
				{"LangfuseProject", n.LangfuseProject(), c.want.langfuse},
			}
			for _, ck := range checks {
				if ck.got != ck.want {
					t.Errorf("%s = %q, want %q", ck.field, ck.got, ck.want)
				}
			}
		})
	}
}

func TestNames_TenantIDRoundTrip(t *testing.T) {
	id := auth.MustNewTenantID("zeroroot-ai")
	n := tenant.FromTenantID(id)
	if !n.TenantID().Equal(id) {
		t.Errorf("TenantID() round-trip failed: got %v, want %v", n.TenantID(), id)
	}
}

// TestNames_PostgresAppRole_NoLegacyRoleSuffix is a guard: the role suffix
// MUST be "_app", never the legacy "_role". A regression here means the
// daemon and operator are silently disagreeing again. See spec
// tenant-provisioning-unification Requirement 1.3.
func TestNames_PostgresAppRole_NoLegacyRoleSuffix(t *testing.T) {
	id := auth.MustNewTenantID("acme-corp")
	role := tenant.FromTenantID(id).PostgresAppRole()
	if strings.HasSuffix(role, "_role") {
		t.Errorf("PostgresAppRole() returned legacy %q (must end in _app, not _role)", role)
	}
	if !strings.HasSuffix(role, "_app") {
		t.Errorf("PostgresAppRole() returned %q (must end in _app)", role)
	}
}

// TestNames_RedisIndexField_NotHashKey is a guard against the historical
// bug where some callers used "tenant_db_index" or "tenant:index" as the
// _field_ name. The field is the bare slug; the hash key constant lives
// in pkg/platform/dataplane.
func TestNames_RedisIndexField_NotHashKey(t *testing.T) {
	id := auth.MustNewTenantID("acme")
	field := tenant.FromTenantID(id).RedisIndexField()
	for _, forbidden := range []string{"tenant:index", "tenant_db_index"} {
		if field == forbidden {
			t.Errorf("RedisIndexField() returned the master-index hash key %q; field should be the tenant slug", forbidden)
		}
	}
}

// TestNames_NamespaceHasTenantPrefix enforces the contract surfaced
// in tenant-operator#87: the per-tenant K8s namespace name is
// "tenant-" + slug. Every artifact in the platform — the operator's
// ProvisionNamespace path, the chart RoleBindings, the live cluster
// namespaces — uses this form. The previous "Namespace == Slug"
// contract was a draft-spec rule the operator + chart never matched.
func TestNames_NamespaceHasTenantPrefix(t *testing.T) {
	id := auth.MustNewTenantID("zeroroot-ai")
	n := tenant.FromTenantID(id)

	const want = "tenant-zeroroot-ai"
	if got := n.Namespace(); got != want {
		t.Errorf("Namespace() = %q, want %q", got, want)
	}
	if !strings.HasPrefix(n.Namespace(), "tenant-") {
		t.Errorf("Namespace() = %q, must start with %q", n.Namespace(), "tenant-")
	}
	if n.Namespace() == n.Slug() {
		t.Errorf("Namespace() = Slug() = %q — must differ (Namespace must carry tenant- prefix)", n.Slug())
	}
}
