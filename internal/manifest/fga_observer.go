package manifest

import (
	"context"
	"log/slog"

	"github.com/zero-day-ai/gibson/internal/authz"
)

// FGAObserver wraps an authz.Authorizer and, after every successful
// Write/Delete, fires ManifestNotifier.Notify for each tenant whose
// manifest may be affected. All other methods pass through verbatim.
//
// This is how the daemon gets manifest invalidation for FREE on every
// existing FGA write path — wrap the Authorizer once at daemon init and
// all existing call sites (internal/authz/, tenant-operator writes,
// component-grant-crd, …) are covered automatically.
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
