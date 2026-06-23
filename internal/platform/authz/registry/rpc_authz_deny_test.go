package registry_test

// rpc_authz_deny_test.go is the authz-deny dimension of the per-RPC test
// walker (gibson#793, E3 / QUALITY-BARS §4).
//
// gibson does not run a per-RPC FGA interceptor itself — ext-authz enforces,
// driven by the generated authz registry that the daemon serves over mTLS
// (see internal/server/daemon/authz_registry_subsystem.go). The registry IS
// the deny contract: ext-authz reads each entry and denies any call whose
// caller fails the entry's (relation, object_type, object_deriver) FGA Check
// or whose identity class is not in allowed_identities.
//
// Therefore the authz-deny guarantee that gibson owns — and that this test
// proves for EVERY registered RPC — is: each entry is *enforceable*. An entry
// is enforceable iff it is one of:
//
//   1. explicitly Unauthenticated (a vetted public surface; the exact set is
//      frozen by spiffe_required_test.go's allowedUnauthenticated), or
//   2. explicitly Self (self-mode bootstrap read, USER-only; also frozen by
//      spiffe_required_test.go), or
//   3. fully specified: a non-empty Relation, ObjectType, a known
//      ObjectDeriver, and a non-empty AllowedIdentities set.
//
// The failure class this closes: an RPC reaches the registry with NO relation
// and WITHOUT being marked unauthenticated/self — ext-authz would then have no
// FGA Check to run, a silent-allow / fail-open. This test ranges the whole
// registry so the guarantee holds for all 300+ RPCs by construction, and CI
// blocks the moment a new RPC lands without an enforceable rule.

import (
	"regexp"
	"sort"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz/registry"
)

// fieldDeriverRe matches the parameterized deriver families ext-authz resolves
// in resolveObject's default branch: tenant_and_field('Name') and
// from_field('PluginName'). The field name is non-empty and single/double
// quoted, mirroring internal/server/extauthz/fga/check.go.
var fieldDeriverRe = regexp.MustCompile(`^(tenant_and_field|from_field)\(['"][^'"]+['"]\)$`)

// isKnownObjectDeriver reports whether ext-authz can resolve the deriver into
// an FGA object to Check against. Keep in lockstep with resolveObject's switch
// in internal/server/extauthz/fga/check.go.
func isKnownObjectDeriver(d string) bool {
	switch d {
	case "tenant_from_identity", "system_tenant":
		return true
	}
	return fieldDeriverRe.MatchString(d)
}

// TestEveryRegisteredRPCIsAuthzEnforceable is the per-RPC authz-deny gate.
// It proves, for every entry in the generated registry, that ext-authz has a
// concrete rule to deny on — no RPC is left fail-open.
func TestEveryRegisteredRPCIsAuthzEnforceable(t *testing.T) {
	if len(registry.Registry) == 0 {
		t.Fatal("registry.Registry is empty — generated authz registry missing")
	}

	var violations []string
	for method, e := range registry.Registry {
		switch {
		case e.Unauthenticated:
			// Vetted public surface. Its identity/relation fields are
			// intentionally empty; the unauth set itself is frozen by
			// spiffe_required_test.go. Nothing more to enforce here.
			if !e.Self && e.Relation == "" {
				continue
			}
			// An entry must not be BOTH unauthenticated and carry a relation —
			// that is a contradictory rule ext-authz cannot interpret.
			violations = append(violations,
				method+": Unauthenticated entries must have an empty Relation")
		case e.Self:
			// Self-mode read: the daemon authorizes "caller acts on own data"
			// without an FGA Check. spiffe_required_test.go already proves the
			// USER bit is set; here we only require the relation fields stay
			// empty so ext-authz routes it through the self path, not a Check.
			if e.Relation != "" {
				violations = append(violations,
					method+": Self entries must have an empty Relation (self path runs no FGA Check)")
			}
		default:
			// Standard authorized RPC: must be fully specified so ext-authz
			// can build the FGA Check tuple and deny on failure.
			if e.Relation == "" {
				violations = append(violations,
					method+": authorized RPC has empty Relation (would be fail-open at ext-authz)")
			}
			if e.ObjectType == "" {
				violations = append(violations, method+": authorized RPC has empty ObjectType")
			}
			if !isKnownObjectDeriver(e.ObjectDeriver) {
				violations = append(violations,
					method+": ObjectDeriver "+strconvQuote(e.ObjectDeriver)+" is not a known deriver ext-authz can resolve")
			}
			if e.AllowedIdentities == 0 {
				violations = append(violations,
					method+": empty AllowedIdentities (no identity class may call — unreachable RPC, likely a codegen bug)")
			}
		}
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("%d registered RPC(s) are not authz-enforceable (ext-authz would fail open):\n  %s",
			len(violations), joinLines(violations))
	}
}

// strconvQuote is a tiny local helper to avoid importing strconv solely for
// quoting a deriver name in an error string.
func strconvQuote(s string) string { return "\"" + s + "\"" }

func joinLines(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += "\n  "
		}
		out += v
	}
	return out
}
