package auth

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	redisadapter "github.com/casbin/redis-adapter/v3"
)

// casbinModel is the embedded ACL policy model used by the Casbin enforcer.
//
// The model uses a four-tuple request/policy format (sub, dom, obj, act) with
// domain-scoped role inheritance. This supports multi-tenant authorization where
// each tenant (dom) maintains independent policies without cross-tenant leakage.
//
// Request definition: r = sub, dom, obj, act
//
//	sub — the subject (API key ID or identity subject)
//	dom — the domain (tenant ID)
//	obj — the object/resource being accessed (e.g. "graphrag", "plugin:gitlab")
//	act — the action being performed (e.g. "read", "write", "*")
//
// Policy definition: p = sub, dom, obj, act
// Role definition:   g = _, _, _  (subject, role, domain — domain-scoped RBAC)
// Effect:            some(where (p.eft == allow))
// Matcher:           g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
const casbinModel = `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
`

// NewCasbinEnforcer creates a Casbin enforcer backed by Redis for persistent policy storage.
//
// Policies are stored in Redis using the redis-adapter, allowing policy changes to
// persist across daemon restarts and be shared across multiple daemon instances in
// a multi-replica deployment.
//
// The enforcer uses the embedded ACL model with domain-scoped role inheritance,
// suitable for multi-tenant authorization where tenant isolation is required.
//
// Parameters:
//   - redisAddr: Redis server address in "host:port" format (e.g. "localhost:6379")
//   - redisPassword: Redis AUTH password; pass an empty string if auth is not configured
func NewCasbinEnforcer(redisAddr, redisPassword string) (*casbin.Enforcer, error) {
	adapter, err := redisadapter.NewAdapterWithPassword("tcp", redisAddr, redisPassword)
	if err != nil {
		return nil, fmt.Errorf("casbin: failed to create redis adapter: %w", err)
	}

	m, err := model.NewModelFromString(casbinModel)
	if err != nil {
		return nil, fmt.Errorf("casbin: failed to load model: %w", err)
	}

	enforcer, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("casbin: failed to create enforcer: %w", err)
	}

	slog.Info("casbin: enforcer initialized with redis-backed policy store",
		"redis_addr", redisAddr,
	)

	return enforcer, nil
}

// ParseCapability splits a capability string into its resource and action components.
//
// The split is performed on the LAST colon in the string, so compound resource names
// like "plugin:gitlab" are preserved as the resource while only the terminal segment
// becomes the action.
//
// Examples:
//
//	"graphrag:write"     → ("graphrag", "write")
//	"plugin:gitlab:read" → ("plugin:gitlab", "read")
//	"*"                  → ("*", "*")
//	"missions:execute"   → ("missions", "execute")
func ParseCapability(cap string) (resource, action string) {
	if cap == "*" {
		return "*", "*"
	}

	idx := strings.LastIndex(cap, ":")
	if idx < 0 {
		// No colon: treat the entire string as the resource with wildcard action.
		return cap, "*"
	}

	return cap[:idx], cap[idx+1:]
}

// AddPoliciesForKey adds Casbin allow policies for each capability granted to a key.
//
// Each capability string is parsed via ParseCapability to extract (resource, action),
// then a policy rule (keyID, tenantID, resource, action) is added to the enforcer.
// The wildcard capability "*" expands to a single policy with ("*", "*") granting
// unrestricted access within the tenant domain.
//
// Policies are persisted to Redis immediately via the adapter's SavePolicy logic
// embedded in AddPolicy.
func AddPoliciesForKey(enforcer *casbin.Enforcer, keyID, tenantID string, capabilities []string) error {
	for _, cap := range capabilities {
		resource, action := ParseCapability(cap)

		_, err := enforcer.AddPolicy(keyID, tenantID, resource, action)
		if err != nil {
			return fmt.Errorf("casbin: failed to add policy for key %q capability %q: %w", keyID, cap, err)
		}

		slog.Debug("casbin: added policy",
			"key_id", keyID,
			"tenant_id", tenantID,
			"resource", resource,
			"action", action,
		)
	}

	return nil
}

// RemovePoliciesForKey removes all Casbin policies associated with a given key subject.
//
// This performs a filtered removal on field index 0 (the subject/sub field), deleting
// every policy row where the subject matches keyID regardless of domain, object, or action.
// Call this when revoking or rotating an API key to ensure no stale grants remain.
func RemovePoliciesForKey(enforcer *casbin.Enforcer, keyID string) error {
	_, err := enforcer.RemoveFilteredPolicy(0, keyID)
	if err != nil {
		return fmt.Errorf("casbin: failed to remove policies for key %q: %w", keyID, err)
	}

	slog.Info("casbin: removed all policies for key",
		"key_id", keyID,
	)

	return nil
}
