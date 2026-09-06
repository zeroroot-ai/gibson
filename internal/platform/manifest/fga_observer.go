// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package manifest

import (
	"context"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// FGAObserver wraps an authz.Authorizer and, after every successful
// Write/Delete, fires ManifestNotifier.Notify for each tenant whose
// manifest may be affected. All other methods pass through verbatim.
//
// This is how the daemon would get manifest invalidation for free on every
// existing FGA write path: wrap the Authorizer once at daemon init and all
// existing call sites (internal/platform/authz/, tenant-operator writes,
// component-grant-crd, …) are covered automatically.
//
// # Deliberately not wired (gibson#1316)
//
// NewFGAObserver has no non-test caller. That is intended, not an
// oversight, for two reasons — check both before wiring it:
//
//  1. The rest of the capability-manifest-rpc subsystem is also
//     deliberately unwired. GetCapabilityManifest and
//     WatchManifestInvalidations both fail closed to codes.Unavailable
//     until a manifest Builder / WatchHub is constructed at daemon init
//     (internal/server/daemon/api/manifest_handler.go). No manifest is
//     ever issued or cached today, so there is nothing yet for this
//     observer to invalidate — wiring it in isolation would fire
//     Redis-pubsub events with zero subscribers.
//
//  2. Wiring it today at its natural call site — replacing
//     `d.authorizer = a` with a wrapped value in
//     internal/server/daemon/authz_init.go — would silently defeat the
//     authz.ConditionalWriter type assertion at
//     internal/server/daemon/api/server_revoke_sessions.go
//     (`s.authorizer.(authz.ConditionalWriter)`, gibson#627 Slice 2's
//     session-revocation instant path). FGAObserver does not implement
//     ConditionalWriter. This is the exact hazard ListUsersOfType's own
//     doc comment below warns about, for a second interface that #1289
//     did not promote onto Authorizer.
//
// When the capability-manifest-rpc daemon-init sequence lands: first
// extend FGAObserver to forward authz.ConditionalWriter
// (WriteConditional / UpdateConditionalTuple), re-check for any other
// type assertions on the concrete authorizer, and only then wrap
// d.authorizer here. Until that day, do not baseline a future
// Authorizer-interface method onto this type without re-reading this
// comment — that per-method baselining is exactly what gibson#1316
// exists to stop.
type FGAObserver struct {
	inner    authz.Authorizer
	notifier ManifestNotifier
	log      *slog.Logger
}

// NewFGAObserver wraps authorizer with notification emissions. Both
// authorizer and notifier are required; nil logger defaults to slog.Default.
func NewFGAObserver(authorizer authz.Authorizer, notifier ManifestNotifier, log *slog.Logger) *FGAObserver {
	if log == nil {
		log = slog.Default()
	}
	return &FGAObserver{inner: authorizer, notifier: notifier, log: log}
}

// Check passes through.
func (o *FGAObserver) Check(ctx context.Context, user, relation, object string) (bool, error) {
	return o.inner.Check(ctx, user, relation, object)
}

// BatchCheck passes through.
func (o *FGAObserver) BatchCheck(ctx context.Context, checks []authz.CheckRequest) ([]bool, error) {
	return o.inner.BatchCheck(ctx, checks)
}

// ListObjects passes through.
func (o *FGAObserver) ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error) {
	return o.inner.ListObjects(ctx, user, relation, objectType)
}

// ListUsers passes through.
func (o *FGAObserver) ListUsers(ctx context.Context, objectType, object, relation string) ([]string, error) {
	return o.inner.ListUsers(ctx, objectType, object, relation)
}

// ListUsersOfType passes through. Forwarding is mandatory, not optional: the
// callers are security gates that used to reach this method by type assertion,
// which any wrapper — this one included — silently defeated.
func (o *FGAObserver) ListUsersOfType(ctx context.Context, objectType, object, relation, userType string) ([]string, error) {
	return o.inner.ListUsersOfType(ctx, objectType, object, relation, userType)
}

// Write forwards to the inner authorizer, then Notify for each
// affected tenant on success. Failed writes do not notify.
func (o *FGAObserver) Write(ctx context.Context, tuples []authz.Tuple) error {
	if err := o.inner.Write(ctx, tuples); err != nil {
		return err
	}
	o.notifyForTuples(ctx, tuples, "fga_tuple_write")
	return nil
}

// Delete forwards to the inner authorizer, then Notify for each
// affected tenant on success.
func (o *FGAObserver) Delete(ctx context.Context, tuples []authz.Tuple) error {
	if err := o.inner.Delete(ctx, tuples); err != nil {
		return err
	}
	o.notifyForTuples(ctx, tuples, "fga_tuple_delete")
	return nil
}

// StoreID / ModelID / Close pass through.
func (o *FGAObserver) StoreID() string { return o.inner.StoreID() }
func (o *FGAObserver) ModelID() string { return o.inner.ModelID() }
func (o *FGAObserver) Close() error    { return o.inner.Close() }

// notifyForTuples dedupes the affected tenant set and fires Notify.
// Tuples that don't encode a tenant (e.g. system_tenant grants) are
// skipped here — those are handled by the registry observer or by
// higher-level code.
func (o *FGAObserver) notifyForTuples(ctx context.Context, tuples []authz.Tuple, reason string) {
	seen := make(map[string]struct{}, len(tuples))
	for _, t := range tuples {
		tenant := extractTenantFromFGATuple(t.User, t.Relation, t.Object)
		if tenant == "" {
			continue
		}
		if _, dup := seen[tenant]; dup {
			continue
		}
		seen[tenant] = struct{}{}
		o.notifier.Notify(ctx, tenant, reason)
	}
}

// Compile-time assertion that FGAObserver satisfies authz.Authorizer.
var _ authz.Authorizer = (*FGAObserver)(nil)
