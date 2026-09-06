// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package admin — team_object_migration.go
//
// Backfill for the tenant-namespacing of team FGA object ids
// (team_object_ref.go). Every request path now addresses
// `team:<tenant>/<team_id>`; every tuple written before that change addresses
// the global `team:<team_id>`. Without a backfill the flip would leave real
// teams unreachable and leave squatted ids sitting in the store unaudited —
// the two halves of gibson#1231 that the namespace alone does not answer.
//
// What it does, per tenant, for every legacy (un-namespaced) team the tenant
// parents:
//
//  1. re-writes every STORED tuple whose object is `team:<id>` onto
//     `team:<tenant>/<id>`;
//  2. re-writes every STORED component-access tuple whose subject is the
//     userset `team:<id>#member` onto `team:<tenant>/<id>#member`;
//  3. deletes the originals.
//
// It reads STORED tuples (authz.TupleReader), never effective ones. ListUsers
// would report every tenant admin as a team admin — `admin: [user] or admin
// from parent` derives them — and materialising a derived edge as a direct
// tuple turns "is currently a tenant admin" into "is permanently an admin of
// this team". A migration that over-grants is worse than the defect.
//
// A squatted id — one legacy object parented by two tenants — is reported and
// left completely untouched. It is the one case with no correct automatic
// answer: the roster on a shared object cannot be attributed, so copying it
// into both namespaces would hand the squatter the victim's roster (the very
// leak being fixed) and moving it into one would be a guess about which tenant
// is the victim. Leaving it costs nothing that is not already lost — no request
// path addresses the global object any more, so those tuples are inert — and it
// gives an operator the exact list to resolve by hand.
package admin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// componentAccessRelations are the relations whose SUBJECT is a team userset.
// They are read explicitly because a tuple where the team is the subject is not
// found by reading the team object.
var componentAccessRelations = []string{
	"team_read_disabled",
	"team_write_disabled",
	"team_execute_disabled",
}

// MigrationReport is the audit record of one migration run.
type MigrationReport struct {
	// TenantsScanned is the number of tenants enumerated from FGA.
	TenantsScanned int
	// TeamsMigrated lists "<tenant>/<team_id>" for every team moved.
	TeamsMigrated []string
	// TeamsAlreadyNamespaced counts teams that were already in the new shape,
	// i.e. a re-run.
	TeamsAlreadyNamespaced int
	// SquattedIDs lists legacy team ids parented by more than one tenant.
	// Nothing is written or deleted for these: the roster on a contested object
	// cannot be attributed, and both automatic answers (copy it to everyone,
	// or pick a winner) are wrong. The entry is the hand-off to an operator.
	SquattedIDs []string
	// Skipped lists "<ref>: <reason>" for legacy ids that could not be moved
	// (e.g. an id containing the namespace separator). Nothing is deleted for
	// a skipped team — its tuples are left exactly as they were.
	Skipped []string
	// TuplesWritten / TuplesDeleted are the raw tuple counts.
	TuplesWritten int
	TuplesDeleted int
}

// String renders the report for a CLI run.
func (r MigrationReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "tenants scanned:          %d\n", r.TenantsScanned)
	fmt.Fprintf(&b, "teams migrated:           %d\n", len(r.TeamsMigrated))
	fmt.Fprintf(&b, "teams already namespaced: %d\n", r.TeamsAlreadyNamespaced)
	fmt.Fprintf(&b, "tuples written:           %d\n", r.TuplesWritten)
	fmt.Fprintf(&b, "tuples deleted:           %d\n", r.TuplesDeleted)
	for _, t := range r.TeamsMigrated {
		fmt.Fprintf(&b, "  migrated: %s\n", t)
	}
	for _, s := range r.SquattedIDs {
		fmt.Fprintf(&b, "  SQUATTED (claimed by >1 tenant; left untouched, resolve by hand): %s\n", s)
	}
	for _, s := range r.Skipped {
		fmt.Fprintf(&b, "  SKIPPED: %s\n", s)
	}
	return b.String()
}

// MigrateTeamObjectIDs moves every legacy global team object into its owning
// tenant's namespace.
//
// It is idempotent: a team already in the new shape is counted and left alone,
// so a re-run after a partial failure completes the remainder. dryRun performs
// every read and reports exactly what it would do without writing or deleting.
func MigrateTeamObjectIDs(
	ctx context.Context,
	authorizer authz.Authorizer,
	logger *slog.Logger,
	dryRun bool,
) (MigrationReport, error) {
	var report MigrationReport

	if authorizer == nil {
		return report, errors.New("migrate team object ids: authorizer is nil")
	}
	reader, ok := authorizer.(authz.TupleReader)
	if !ok {
		// Refuse rather than fall back to the effective listings. See the
		// package comment: ListUsers would over-grant.
		return report, errors.New(
			"migrate team object ids: authorizer does not implement authz.TupleReader; " +
				"the migration must read stored tuples, not effective ones")
	}
	if logger == nil {
		logger = slog.Default()
	}

	tenantRefs, err := authorizer.ListUsersOfType(ctx, "system_tenant", "system_tenant:_system", "parent", "tenant")
	if err != nil {
		return report, fmt.Errorf("enumerate tenants: %w", err)
	}
	sort.Strings(tenantRefs)
	report.TenantsScanned = len(tenantRefs)

	// Pass 1: work out who claims what, over the WHOLE store, before moving a
	// single tuple. Contention is a property of the object, not of the tenant
	// that happens to be scanned first, so it cannot be decided inside the
	// per-tenant loop — an earlier version did exactly that and migrated the
	// first claimant's view of a squatted object, carrying the other tenant's
	// roster along with it.
	claimants := map[string][]string{} // legacy team id -> tenant slugs
	for _, tenantRef := range tenantRefs {
		tenantSlug := stripFGATypePrefix(tenantRef, "tenant")

		parents, readErr := reader.ReadTuples(ctx, tenantRef, "parent", "team:")
		if readErr != nil {
			return report, fmt.Errorf("read team parents for %s: %w", tenantRef, readErr)
		}
		for _, parent := range parents {
			// "Already migrated" is not "contains a separator": a legacy id
			// could contain one too. It is "the namespace segment is this
			// tenant", which is the only reading that cannot mistake
			// `team:weird/id` owned by acme for an acme-namespaced object.
			if _, ok := teamIDFromRef(tenantSlug, parent.Object); ok {
				report.TeamsAlreadyNamespaced++
				continue
			}
			legacyID := stripFGATypePrefix(parent.Object, "team")
			claimants[legacyID] = append(claimants[legacyID], tenantSlug)
		}
	}

	legacyIDs := make([]string, 0, len(claimants))
	for id := range claimants {
		legacyIDs = append(legacyIDs, id)
	}
	sort.Strings(legacyIDs)

	// Pass 2: move the unambiguous ones.
	for _, legacyID := range legacyIDs {
		tenants := claimants[legacyID]
		sort.Strings(tenants)
		oldRef := "team:" + legacyID

		if len(tenants) > 1 {
			report.SquattedIDs = append(report.SquattedIDs,
				fmt.Sprintf("%s (claimed by %s)", legacyID, strings.Join(tenants, ", ")))
			logger.WarnContext(ctx, "migrate team object ids: contested team id left untouched for manual resolution",
				slog.String("team_object", oldRef),
				slog.Any("claiming_tenants", tenants))
			continue
		}

		tenantSlug := tenants[0]
		newRef, refErr := teamRef(tenantSlug, legacyID)
		if refErr != nil {
			report.Skipped = append(report.Skipped, fmt.Sprintf("%s (tenant %s): %v", oldRef, tenantSlug, refErr))
			logger.WarnContext(ctx, "migrate team object ids: skipping unmovable legacy team",
				slog.String("team_object", oldRef),
				slog.String("tenant", tenantSlug),
				slog.String("reason", refErr.Error()))
			continue
		}

		moved, moveErr := migrateOneTeam(ctx, authorizer, reader, logger, oldRef, newRef, dryRun)
		if moveErr != nil {
			return report, fmt.Errorf("migrate %s -> %s: %w", oldRef, newRef, moveErr)
		}
		report.TuplesWritten += moved
		report.TuplesDeleted += moved
		report.TeamsMigrated = append(report.TeamsMigrated, tenantSlug+authz.TenantQualifiedSep+legacyID)
	}

	return report, nil
}

// migrateOneTeam rewrites every stored tuple that names oldRef so it names
// newRef instead, and returns the number of tuples moved.
//
// The write happens before the delete. If the process dies between the two the
// store holds both copies, which a re-run resolves — the reverse order would
// lose the roster outright.
func migrateOneTeam(
	ctx context.Context,
	authorizer authz.Authorizer,
	reader authz.TupleReader,
	logger *slog.Logger,
	oldRef, newRef string,
	dryRun bool,
) (int, error) {
	// (a) Everything stored ON the team object: parent, member, admin,
	// can_view_data_from — whatever exists, without enumerating relations, so a
	// relation added to the model later still moves.
	onObject, err := reader.ReadTuples(ctx, "", "", oldRef)
	if err != nil {
		return 0, fmt.Errorf("read tuples on %s: %w", oldRef, err)
	}

	// Every tuple moved is both written under the new ref and deleted under the
	// old one, so the two slices grow in lockstep, and (a) is the bulk of them.
	toWrite := make([]authz.Tuple, 0, len(onObject))
	toDelete := make([]authz.Tuple, 0, len(onObject))

	for _, t := range onObject {
		moved := t
		moved.Object = newRef
		// A team can also be the SUBJECT of a tuple on another team
		// (`can_view_data_from: [team]`). If that subject is the team being
		// moved, it moves with it.
		moved.User = rewriteTeamSubject(t.User, oldRef, newRef)
		toWrite = append(toWrite, moved)
		toDelete = append(toDelete, t)
	}

	// (b) Component-access tuples where the team userset is the SUBJECT. These
	// are invisible to (a) — the team is on the user side, not the object side.
	for _, relation := range componentAccessRelations {
		subject := oldRef + "#member"
		tuples, readErr := reader.ReadTuples(ctx, subject, relation, "component:")
		if readErr != nil {
			return 0, fmt.Errorf("read %s for %s: %w", relation, subject, readErr)
		}
		for _, t := range tuples {
			moved := t
			moved.User = newRef + "#member"
			toWrite = append(toWrite, moved)
			toDelete = append(toDelete, t)
		}
	}

	// (c) can_view_data_from tuples where the moved team is the subject and the
	// object is a DIFFERENT team. (a) catches the ones pointing at this team;
	// this catches the ones pointing away from it.
	outbound, err := reader.ReadTuples(ctx, oldRef, "can_view_data_from", "team:")
	if err != nil {
		return 0, fmt.Errorf("read can_view_data_from for %s: %w", oldRef, err)
	}
	for _, t := range outbound {
		if t.Object == oldRef {
			continue // already handled by (a)
		}
		moved := t
		moved.User = newRef
		toWrite = append(toWrite, moved)
		toDelete = append(toDelete, t)
	}

	if len(toWrite) == 0 {
		return 0, nil
	}

	logger.InfoContext(ctx, "migrate team object ids: moving team",
		slog.String("from", oldRef),
		slog.String("to", newRef),
		slog.Int("tuples", len(toWrite)),
		slog.Bool("dry_run", dryRun),
	)
	if dryRun {
		return len(toWrite), nil
	}

	if err := authorizer.Write(ctx, toWrite); err != nil {
		return 0, fmt.Errorf("write namespaced tuples: %w", err)
	}
	if err := authorizer.Delete(ctx, toDelete); err != nil {
		return 0, fmt.Errorf("delete legacy tuples (namespaced copies are already written; re-run to finish): %w", err)
	}
	return len(toWrite), nil
}

// rewriteTeamSubject swaps oldRef for newRef on the subject side, preserving a
// userset suffix. A subject naming a different object is returned unchanged.
func rewriteTeamSubject(subject, oldRef, newRef string) string {
	switch {
	case subject == oldRef:
		return newRef
	case strings.HasPrefix(subject, oldRef+"#"):
		return newRef + strings.TrimPrefix(subject, oldRef)
	default:
		return subject
	}
}
