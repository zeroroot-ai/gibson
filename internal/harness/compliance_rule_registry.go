package harness

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zeroroot-ai/sdk/taxonomy"
)

// Reserved rule id prefixes that tenants cannot extend. Rules whose ID
// starts with any of these prefixes are rejected at overlay load time
// with a WARN log.
var reservedRulePrefixes = []string{
	"PLATFORM.",
	"_system.",
	"SYSTEM.",
}

// ruleOverlayLoader is the narrow interface for loading per-tenant rule
// overlays. Production passes a Redis-backed implementation; tests pass
// an in-memory fake.
type ruleOverlayLoader interface {
	// LoadOverlay returns the overlay rules for the given tenant, or nil
	// if the tenant has not published any.
	LoadOverlay(ctx context.Context, tenantID string) ([]taxonomy.Rule, error)

	// ListTenants returns the set of tenants that currently have an
	// overlay published. Used by the refresh loop.
	ListTenants(ctx context.Context) ([]string, error)
}

// ComplianceRuleRegistry holds the merged system + per-tenant ruleset.
// Reads are cheap (RWMutex); reloads happen on a 60-second timer via
// RefreshLoop.
type ComplianceRuleRegistry struct {
	systemRules []taxonomy.Rule
	overlays    map[string][]taxonomy.Rule
	loader      ruleOverlayLoader
	logger      *slog.Logger
	mu          sync.RWMutex
}

// NewComplianceRuleRegistry constructs a registry with the given system
// rules and overlay loader. The overlay loader may be nil for daemons
// that have not wired Redis yet — the registry will only serve system
// rules in that case.
func NewComplianceRuleRegistry(systemRules []taxonomy.Rule, loader ruleOverlayLoader, logger *slog.Logger) *ComplianceRuleRegistry {
	if logger == nil {
		logger = slog.Default()
	}
	return &ComplianceRuleRegistry{
		systemRules: systemRules,
		overlays:    map[string][]taxonomy.Rule{},
		loader:      loader,
		logger:      logger.With("component", "compliance_rule_registry"),
	}
}

// Get returns the merged ruleset visible to the given tenant. System
// rules are always included; the tenant's overlay is appended after
// filtering out any rules in a reserved namespace.
func (r *ComplianceRuleRegistry) Get(tenantID string) []taxonomy.Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]taxonomy.Rule, 0, len(r.systemRules)+len(r.overlays[tenantID]))
	out = append(out, r.systemRules...)
	out = append(out, r.overlays[tenantID]...)
	return out
}

// RefreshLoop reloads every tenant's overlay from the loader on a 60s
// tick until ctx is canceled. Broken overlays are logged and skipped —
// one misconfigured tenant cannot take down rule evaluation for others.
func (r *ComplianceRuleRegistry) RefreshLoop(ctx context.Context) {
	if r.loader == nil {
		return
	}
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()

	// Initial reload.
	r.reloadOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.reloadOnce(ctx)
		}
	}
}

// reloadOnce pulls the current list of tenants and refreshes each
// overlay. Errors are logged but never propagated — the registry always
// keeps the last-known-good overlays on failure.
func (r *ComplianceRuleRegistry) reloadOnce(ctx context.Context) {
	tenants, err := r.loader.ListTenants(ctx)
	if err != nil {
		r.logger.Warn("failed to list tenant overlays", slog.String("error", err.Error()))
		return
	}
	fresh := map[string][]taxonomy.Rule{}
	for _, tenant := range tenants {
		rules, err := r.loader.LoadOverlay(ctx, tenant)
		if err != nil {
			r.logger.Warn("failed to load tenant overlay — keeping previous",
				slog.String("tenant", tenant),
				slog.String("error", err.Error()),
			)
			r.mu.RLock()
			fresh[tenant] = append([]taxonomy.Rule{}, r.overlays[tenant]...)
			r.mu.RUnlock()
			continue
		}
		filtered := r.filterReserved(tenant, rules)
		fresh[tenant] = filtered
	}
	r.mu.Lock()
	r.overlays = fresh
	r.mu.Unlock()
}

// filterReserved drops any rules whose ID falls into a reserved namespace
// and logs each drop at WARN level.
func (r *ComplianceRuleRegistry) filterReserved(tenant string, rules []taxonomy.Rule) []taxonomy.Rule {
	out := make([]taxonomy.Rule, 0, len(rules))
	for _, rule := range rules {
		if isReservedRuleID(rule.ID) {
			r.logger.Warn("tenant overlay rule in reserved namespace — dropped",
				slog.String("tenant", tenant),
				slog.String("rule_id", rule.ID),
			)
			continue
		}
		out = append(out, rule)
	}
	return out
}

// isReservedRuleID reports whether a rule ID is in a reserved namespace.
func isReservedRuleID(id string) bool {
	for _, prefix := range reservedRulePrefixes {
		if strings.HasPrefix(id, prefix) {
			return true
		}
	}
	return false
}

// SystemRuleCount returns the number of system rules loaded. Used by
// daemon startup logging.
func (r *ComplianceRuleRegistry) SystemRuleCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.systemRules)
}
