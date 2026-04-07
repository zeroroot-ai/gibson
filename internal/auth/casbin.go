package auth

import (
	"fmt"
	"log/slog"

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

// Note: the per-key and per-identity Casbin policy helpers that used to
// live in this file were removed as part of the declarative-rbac-framework
// spec. Authz policies now come from permissions.yaml loaded once at
// daemon startup. The NewCasbinEnforcer above is retained for the
// membership store's `g` (user -> role -> tenant) rules which still live
// in Redis.
