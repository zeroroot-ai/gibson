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
	return s.syncMeasured(ctx, t, users, nil)
}

// expectation is what a write just made true in Zitadel for one user: the
// role it wrote, or, with present false, that no grant remains.
//
// WHY THIS EXISTS. Zitadel answers a grant write from its command side and
// answers ListAuthorizations from a projection, and the projection can lag
// the write it just accepted by a moment. The inline sync that follows every
// write read the projection, saw the old role, and left FGA as it was, while
// the call reported success (identity run 36587978263, 2026-09-29: a writer
// demoted to member kept writer until the 60 s timer). The write is the
// truth the caller was promised, so the sync trusts it over a read that
// disagrees. The timer sync carries no expectation and repairs any drift.
type expectation struct {
	user    string
	role    Role
	present bool
}

// syncExpecting is Sync for the users a write just touched, with the
// written state overriding a lagging read.
func (s *Syncer) syncExpecting(ctx context.Context, t Tenant, expects ...expectation) (Result, error) {
	users := make([]string, 0, len(expects))
	for _, e := range expects {
		users = append(users, e.user)
	}
	return s.syncMeasured(ctx, t, users, expects)
}

func (s *Syncer) syncMeasured(ctx context.Context, t Tenant, users []string, expects []expectation) (Result, error) {
	initMetrics()
	start := time.Now()
	caller := callerLabel(ctx)
	result, err := s.sync(ctx, t, users, expects)
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

func (s *Syncer) sync(ctx context.Context, t Tenant, users []string, expects []expectation) (Result, error) {
	if t.ID == "" || t.OrgID == "" {
		return Result{}, fmt.Errorf("tenantrole: Sync requires a tenant id and org id, got %+v", t)
	}

	grants, err := s.grants.List(ctx, t.OrgID, users)
	if err != nil {
		return Result{}, fmt.Errorf("tenantrole: Sync tenant=%s: list grants: %w", t.ID, err)
	}
	desired, invalid := desiredRoles(grants, t)
	for _, e := range expects {
		got, has := desired[e.user]
		switch {
		case e.present && (!has || got != e.role):
			s.log.Info("tenantrole: the grant read lags the write; using the written role",
				"tenant", t.ID, "user", e.user, "read", string(got), "written", string(e.role))
			desired[e.user] = e.role
		case !e.present && has:
			s.log.Info("tenantrole: the grant read lags the delete; using the deletion",
				"tenant", t.ID, "user", e.user, "read", string(got))
			delete(desired, e.user)
		}
	}

	allActual, err := s.tuples.ReadRoles(ctx, t.ID, nil)
	if err != nil {
		return Result{}, fmt.Errorf("tenantrole: Sync tenant=%s: read roles: %w", t.ID, err)
	}
	actualByUser := actualRoles(allActual)

	scope := syncScope(users, desired, actualByUser)
	if err := checkOwnerInvariant(scope, desired, actualByUser); err != nil {
		return Result{Invalid: invalid}, err
	}

	writes, deletes := diffTuples(scope, desired, actualByUser, t.ID)
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

// desiredRoles groups grants by user and resolves each user's single valid
// role (owner decision D5, fail closed): a user with more than one grant, or
// whose one grant gives no role (validRole), lands in invalid instead.
func desiredRoles(grants []Grant, t Tenant) (desired map[string]Role, invalid []Grant) {
	byUser := make(map[string][]Grant, len(grants))
	for _, g := range grants {
		byUser[g.UserID] = append(byUser[g.UserID], g)
	}
	desired = make(map[string]Role, len(byUser))
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
	return desired, invalid
}

// actualRoles groups the stored role tuples by the bare user id.
func actualRoles(allActual []Tuple) map[string][]Tuple {
	actualByUser := make(map[string][]Tuple, len(allActual))
	for _, tup := range allActual {
		user := userIDFromSubject(tup.User)
		actualByUser[user] = append(actualByUser[user], tup)
	}
	return actualByUser
}

// syncScope is the set of users a sync call touches: an explicit list when
// given one, or every user with a desired or actual role when syncing a
// whole tenant.
func syncScope(users []string, desired map[string]Role, actualByUser map[string][]Tuple) []string {
	if len(users) > 0 {
		return users
	}
	var scope []string
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
	return scope
}

// checkOwnerInvariant enforces owner decision D3: after the change the
// tenant must have exactly one Owner, unless it already had zero (a tenant
// that never had one yet). Returns ErrOwnerConflict rather than applying a
// change that would leave zero or two.
func checkOwnerInvariant(scope []string, desired map[string]Role, actualByUser map[string][]Tuple) error {
	scopeSet := make(map[string]bool, len(scope))
	for _, u := range scope {
		scopeSet[u] = true
	}

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
	if newOwnerCount != 1 && (newOwnerCount != 0 || ownersBefore != 0) {
		return ErrOwnerConflict
	}
	return nil
}

// diffTuples computes the FGA writes and deletes that converge actualByUser
// onto desired for every user in scope: one write for a missing or changed
// role, one delete for every other stored role tuple that user held.
func diffTuples(scope []string, desired map[string]Role, actualByUser map[string][]Tuple, tenantID string) (writes, deletes []Tuple) {
	for _, u := range scope {
		role, hasDesired := desired[u]
		var wanted Tuple
		if hasDesired {
			wanted = Tuple{User: "user:" + u, Relation: role.Relation(), Object: "tenant:" + tenantID}
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
	return writes, deletes
}

// userIDFromSubject strips the "user:" prefix ReadRoles already filtered on.
func userIDFromSubject(subject string) string {
	const prefix = "user:"
	if len(subject) > len(prefix) && subject[:len(prefix)] == prefix {
		return subject[len(prefix):]
	}
	return subject
}
