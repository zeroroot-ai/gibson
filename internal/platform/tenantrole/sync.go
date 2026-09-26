// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenantrole

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Tenant is the minimum a Sync call needs to know about the tenant it acts
// on: its FGA object id and the Zitadel org that holds its people.
type Tenant struct {
	ID    string // the tenant's FGA/CR name, e.g. "acme"
	OrgID string // the Zitadel org id backing this tenant (status.zitadelOrgID)
}

// Result says what one Sync call changed.
type Result struct {
	Written, Deleted []Tuple
	// Invalid lists every Zitadel grant that gave no role (fail closed):
	// two roles, an unknown role, an inactive grant, or a user from
	// another org.
	Invalid []Grant
}

// ErrOwnerConflict is returned when a Sync would leave the tenant without
// exactly one Owner (a tenant that never had one is the one exception — see
// Sync). The caller changed nothing in FGA.
var ErrOwnerConflict = errors.New("tenantrole: sync would leave the tenant without exactly one Owner")

// Syncer is the one writer of tenant-role tuples (ADR-0093 decision 3).
type Syncer struct {
	grants Grants
	tuples Tuples
	log    *slog.Logger
}

// NewSyncer builds a Syncer. log may be nil, in which case slog.Default is used.
func NewSyncer(g Grants, t Tuples, log *slog.Logger) *Syncer {
	if log == nil {
		log = slog.Default()
	}
	return &Syncer{grants: g, tuples: t, log: log}
}

var (
	metricsOnce    sync.Once
	syncTotal      metric.Int64Counter
	invalidGrants  metric.Int64Counter
	syncDurationMS metric.Float64Histogram
)

func initMetrics() {
	metricsOnce.Do(func() {
		meter := otel.GetMeterProvider().Meter("github.com/zeroroot-ai/gibson/internal/platform/tenantrole")
		syncTotal, _ = meter.Int64Counter(
			"gibson_tenantrole_sync_total",
			metric.WithDescription("Tenant role Sync calls by caller and result."),
		)
		invalidGrants, _ = meter.Int64Counter(
			"gibson_tenantrole_invalid_grants_total",
			metric.WithDescription("Zitadel grants that gave no role on a Sync call (fail closed)."),
		)
		syncDurationMS, _ = meter.Float64Histogram(
			"gibson_tenantrole_sync_duration_ms",
			metric.WithDescription("Duration of a tenant role Sync call, in milliseconds."),
			metric.WithUnit("ms"),
		)
	})
}

// callerFromContext is a low-cardinality label for the sync_total metric.
// It is set by the two callers (the daemon RPC path and the tenant-operator
// timer) via WithCaller; an unset context labels "unknown".
type callerKey struct{}

// WithCaller tags ctx with a caller label ("daemon" or "tenant-operator")
// for the gibson_tenantrole_sync_total metric.
func WithCaller(ctx context.Context, caller string) context.Context {
	return context.WithValue(ctx, callerKey{}, caller)
}

func callerLabel(ctx context.Context) string {
	if v, ok := ctx.Value(callerKey{}).(string); ok && v != "" {
		return v
	}
	return "unknown"
}

// validRole returns the role a single grant confers under t, or ok=false
// when the grant gives no role (owner decision D5, fail closed): inactive,
// wrong org, wrong user org, more than one role key, or an unparseable key.
func validRole(g Grant, t Tenant) (Role, bool) {
	if !g.Active {
		return "", false
	}
	if g.OrgID != t.OrgID || g.UserOrgID != t.OrgID {
		return "", false
	}
	if len(g.RoleKeys) != 1 {
		return "", false
	}
	return Parse(g.RoleKeys[0])
}

// Sync is the ONLY writer of tenant-role tuples (ADR-0093 decision 3). It
// copies the Zitadel grants of the named users (or of every user of the
// tenant, when users is empty) into FGA, in one FGA transaction.
func (s *Syncer) Sync(ctx context.Context, t Tenant, users ...string) (Result, error) {
	initMetrics()
	start := time.Now()
	caller := callerLabel(ctx)
	result, err := s.sync(ctx, t, users)
	syncDurationMS.Record(ctx, float64(time.Since(start).Milliseconds()))
	outcome := "ok"
	switch {
	case errors.Is(err, ErrOwnerConflict):
		outcome = "owner_conflict"
	case err != nil:
		outcome = "error"
	}
	syncTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("caller", caller),
		attribute.String("result", outcome),
	))
	if len(result.Invalid) > 0 {
		invalidGrants.Add(ctx, int64(len(result.Invalid)))
	}
	return result, err
}

func (s *Syncer) sync(ctx context.Context, t Tenant, users []string) (Result, error) {
	if t.ID == "" || t.OrgID == "" {
		return Result{}, fmt.Errorf("tenantrole: Sync requires a tenant id and org id, got %+v", t)
	}

	grants, err := s.grants.List(ctx, t.OrgID, users)
	if err != nil {
		return Result{}, fmt.Errorf("tenantrole: Sync tenant=%s: list grants: %w", t.ID, err)
	}
	byUser := make(map[string][]Grant, len(grants))
	for _, g := range grants {
		byUser[g.UserID] = append(byUser[g.UserID], g)
	}
	desired := make(map[string]Role, len(byUser))
	var invalid []Grant
	for userID, gs := range byUser {
		if len(gs) != 1 {
			invalid = append(invalid, gs...)
			continue
		}
		role, ok := validRole(gs[0], t)
		if !ok {
			invalid = append(invalid, gs[0])
			continue
		}
		desired[userID] = role
	}

	allActual, err := s.tuples.ReadRoles(ctx, t.ID, nil)
	if err != nil {
		return Result{}, fmt.Errorf("tenantrole: Sync tenant=%s: read roles: %w", t.ID, err)
	}
	actualByUser := make(map[string][]Tuple, len(allActual))
	for _, tup := range allActual {
		user := userIDFromSubject(tup.User)
		actualByUser[user] = append(actualByUser[user], tup)
	}

	var scope []string
	if len(users) > 0 {
		scope = users
	} else {
		seen := make(map[string]bool)
		for u := range desired {
			if !seen[u] {
				seen[u] = true
				scope = append(scope, u)
			}
		}
		for u := range actualByUser {
			if !seen[u] {
				seen[u] = true
				scope = append(scope, u)
			}
		}
	}
	scopeSet := make(map[string]bool, len(scope))
	for _, u := range scope {
		scopeSet[u] = true
	}

	// Owner rule check (owner decision D3): count Owners after the change
	// and refuse a change that leaves the tenant with zero or two, unless
	// it already had zero (a tenant that never had an Owner yet).
	ownersBefore := 0
	ownersOutsideScope := 0
	for u, tuples := range actualByUser {
		hasOwner := false
		for _, tup := range tuples {
			if tup.Relation == Owner.Relation() {
				hasOwner = true
				break
			}
		}
		if hasOwner {
			ownersBefore++
			if !scopeSet[u] {
				ownersOutsideScope++
			}
		}
	}
	desiredOwnersInScope := 0
	for _, u := range scope {
		if desired[u] == Owner {
			desiredOwnersInScope++
		}
	}
	newOwnerCount := ownersOutsideScope + desiredOwnersInScope
	if newOwnerCount != 1 && !(newOwnerCount == 0 && ownersBefore == 0) {
		return Result{Invalid: invalid}, ErrOwnerConflict
	}

	var writes, deletes []Tuple
	for _, u := range scope {
		role, hasDesired := desired[u]
		var wanted Tuple
		if hasDesired {
			wanted = Tuple{User: "user:" + u, Relation: role.Relation(), Object: "tenant:" + t.ID}
		}
		found := false
		for _, existing := range actualByUser[u] {
			if hasDesired && existing.Relation == wanted.Relation {
				found = true
				continue
			}
			deletes = append(deletes, existing)
		}
		if hasDesired && !found {
			writes = append(writes, wanted)
		}
	}

	if len(writes) == 0 && len(deletes) == 0 {
		return Result{Invalid: invalid}, nil
	}
	if err := s.tuples.WriteAndDelete(ctx, writes, deletes); err != nil {
		return Result{Invalid: invalid}, fmt.Errorf("tenantrole: Sync tenant=%s: write: %w", t.ID, err)
	}
	for _, w := range writes {
		s.log.Info("tenantrole: wrote tenant role tuple", "tenant", t.ID, "user", w.User, "relation", w.Relation)
	}
	for _, d := range deletes {
		s.log.Info("tenantrole: deleted tenant role tuple", "tenant", t.ID, "user", d.User, "relation", d.Relation)
	}
	return Result{Written: writes, Deleted: deletes, Invalid: invalid}, nil
}

// userIDFromSubject strips the "user:" prefix ReadRoles already filtered on.
func userIDFromSubject(subject string) string {
	const prefix = "user:"
	if len(subject) > len(prefix) && subject[:len(prefix)] == prefix {
		return subject[len(prefix):]
	}
	return subject
}
