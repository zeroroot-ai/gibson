// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/outsideagent"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

// Outside agents of a tenant (gibson#1403).
//
// The daemon holds the outside agent records of a tenant and cannot write
// cluster resources (ADR-0023). This loop pulls the records of each ready
// tenant and renders the backend, the route and the credential Secret of each
// record into the namespace of the gateway. It has no custom resource. The
// ModelProvider has one for its status and for a finalizer that removes the
// objects of another namespace. An outside agent has neither need. The record in
// the daemon is the one source of truth, and the label LabelOutsideAgent marks
// each object that this loop owns. The loop deletes the labeled objects whose
// record is gone.

const defaultOutsideAgentSyncInterval = 30 * time.Second

// OutsideAgentRecords reads the outside agent records of a tenant from the
// daemon. The daemon client implements it.
type OutsideAgentRecords interface {
	TenantOutsideAgents(ctx context.Context, tenantID string) ([]provision.DesiredOutsideAgent, error)
}

// OutsideAgentCredentialSource returns the content of the credential Secret of
// an outside agent, by the key names that the gateway reads. It returns
// clients.ErrNotFound when the agent has no credential secret or the tenant
// secret does not exist.
type OutsideAgentCredentialSource interface {
	OutsideAgentCredential(ctx context.Context, tenantID, name string) (map[string][]byte, error)
}

// OutsideAgentSyncRunnable pulls the outside agent records and renders them
// into the gateway namespace. It is a manager.Runnable that needs leader
// election.
type OutsideAgentSyncRunnable struct {
	Client      client.Client
	Daemon      OutsideAgentRecords
	Credentials OutsideAgentCredentialSource
	// Render holds the namespace of the gateway and the name of the Gateway.
	Render outsideagent.Config
	// Interval between passes. Zero uses the default.
	Interval time.Duration
}

// NeedLeaderElection makes only the lead replica run the loop.
func (r *OutsideAgentSyncRunnable) NeedLeaderElection() bool { return true }

// SetupWithManager registers the runnable.
func (r *OutsideAgentSyncRunnable) SetupWithManager(mgr manager.Manager) error {
	if r.Daemon == nil || r.Credentials == nil {
		return errors.New("outsideagent-sync: the daemon client is nil")
	}
	if err := r.Render.Validate(); err != nil {
		return fmt.Errorf("outsideagent-sync: %w", err)
	}
	if r.Client == nil {
		r.Client = mgr.GetClient()
	}
	return mgr.Add(r)
}

// Start runs the loop until the manager context ends.
func (r *OutsideAgentSyncRunnable) Start(ctx context.Context) error {
	interval := r.Interval
	if interval <= 0 {
		interval = defaultOutsideAgentSyncInterval
	}
	logger := log.FromContext(ctx).WithName("outsideagent-sync")
	logger.Info("starting the pull of outside agent records", "interval", interval.String())
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := r.Sync(ctx); err != nil {
				logger.Error(err, "the pull of outside agent records failed, retrying next tick")
			}
		}
	}
}

// tenantState is what one pass knows about a tenant.
type tenantState int

const (
	// tenantKeep means the objects of the tenant stay as they are: the tenant
	// is not ready, or the read of its records failed.
	tenantKeep tenantState = iota
	// tenantRead means the records were read, and an object whose agent is not
	// in the set is deleted.
	tenantRead
)

// Sync does one pass over every tenant. A tenant whose read fails is left as it
// is: nothing is deleted on an error. A tenant that no longer exists, or that is
// deleted, loses all its objects. The pass returns the joined errors.
func (r *OutsideAgentSyncRunnable) Sync(ctx context.Context) error {
	var tenants gibsonv1alpha1.TenantList
	if err := r.Client.List(ctx, &tenants); err != nil {
		return fmt.Errorf("list tenants: %w", err)
	}
	var errs []error
	state := map[string]tenantState{}
	want := map[string]map[string]bool{} // tenant -> agent names that stay
	for i := range tenants.Items {
		t := &tenants.Items[i]
		state[t.Name] = tenantKeep
		if !t.DeletionTimestamp.IsZero() {
			delete(state, t.Name)
			continue
		}
		if t.Status.Phase != gibsonv1alpha1.TenantPhaseReady {
			continue
		}
		names, err := r.syncTenant(ctx, t.Name)
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", t.Name, err))
		}
		if names != nil {
			state[t.Name] = tenantRead
			want[t.Name] = names
		}
	}
	if err := r.deleteGone(ctx, state, want); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// syncTenant renders the records of one tenant. It returns the names that stay
// in the set, or nil when the read of the records failed. A record that fails
// to render or to write is still in the set, so a delete never follows a failed
// write.
func (r *OutsideAgentSyncRunnable) syncTenant(ctx context.Context, tenant string) (map[string]bool, error) {
	logger := log.FromContext(ctx).WithName("outsideagent-sync")
	records, err := r.Daemon.TenantOutsideAgents(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("read the outside agent records: %w", err)
	}
	names := map[string]bool{}
	var errs []error
	for _, rec := range records {
		names[rec.Name] = true
		agent := outsideagent.Agent{
			Tenant: tenant, Name: rec.Name, URL: rec.A2AURL, CredentialSecret: rec.CredentialSecret,
			CABundleSecret: rec.CABundleSecret,
		}
		if err := r.syncAgent(ctx, agent); err != nil {
			if errors.Is(err, clients.ErrNotFound) {
				logger.Info("the credential secret of an outside agent does not exist",
					"tenant", tenant, "name", rec.Name, "secret", rec.CredentialSecret)
				continue
			}
			errs = append(errs, fmt.Errorf("outside agent %s: %w", rec.Name, err))
		}
	}
	return names, errors.Join(errs...)
}

// syncAgent writes the credential Secret, then the backend and the route. The
// Secret goes first, so the backend never names a Secret that is not there.
// The Secret holds the credential under Authorization and the CA bundle under
// ca.crt. With neither in the record, the loop deletes a Secret that an earlier
// version of the record left.
func (r *OutsideAgentSyncRunnable) syncAgent(ctx context.Context, a outsideagent.Agent) error {
	objs, err := outsideagent.Render(a, r.Render)
	if err != nil {
		return fmt.Errorf("render: %w", err)
	}
	secretKey := types.NamespacedName{
		Namespace: r.Render.Namespace, Name: outsideagent.CredentialSecretName(a.Tenant, a.Name),
	}
	if a.CredentialSecret == "" && a.CABundleSecret == "" {
		if err := r.deleteSecret(ctx, secretKey); err != nil {
			return err
		}
	} else {
		data, err := r.Credentials.OutsideAgentCredential(ctx, a.Tenant, a.Name)
		if err != nil {
			return fmt.Errorf("read the credential from the daemon: %w", err)
		}
		if len(data) == 0 {
			return errors.New("the daemon returned an empty credential")
		}
		labels := map[string]string{
			outsideagent.LabelManagedBy: "gibson-tenant-operator", outsideagent.LabelTenant: a.Tenant,
			outsideagent.LabelOutsideAgent: a.Name,
		}
		annotations := map[string]string{outsideagent.AnnotationCredentialSecret: a.CredentialSecret}
		if err := upsertSecret(ctx, r.Client, secretKey, labels, annotations, data); err != nil {
			return err
		}
	}
	for _, obj := range objs {
		if err := applyObject(ctx, r.Client, obj); err != nil {
			return err
		}
	}
	return nil
}

func (r *OutsideAgentSyncRunnable) deleteSecret(ctx context.Context, key types.NamespacedName) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name}}
	if err := r.Client.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete the credential Secret %s: %w", key.Name, err)
	}
	return nil
}

// deleteGone deletes each owned backend and route whose agent is not in the set
// of a tenant that was read, or whose tenant no longer exists. It then deletes
// the credential Secret of that agent by name. The Role of the operator gives no
// list on Secrets, so the loop derives the name from the labels.
func (r *OutsideAgentSyncRunnable) deleteGone(
	ctx context.Context, state map[string]tenantState, want map[string]map[string]bool,
) error {
	var errs []error
	gone := map[[2]string]bool{}
	for _, gvk := range []schema.GroupVersionKind{agentgatewayBackendGVK, httpRouteGVK} {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(gvk.GroupVersion().WithKind(gvk.Kind + "List"))
		if err := r.Client.List(ctx, list, client.InNamespace(r.Render.Namespace), client.MatchingLabels{
			outsideagent.LabelManagedBy: "gibson-tenant-operator",
		}, client.HasLabels{outsideagent.LabelOutsideAgent}); err != nil {
			errs = append(errs, fmt.Errorf("list %s: %w", gvk.Kind, err))
			continue
		}
		for i := range list.Items {
			o := &list.Items[i]
			tenant, name := o.GetLabels()[outsideagent.LabelTenant], o.GetLabels()[outsideagent.LabelOutsideAgent]
			st, known := state[tenant]
			if known && (st == tenantKeep || want[tenant][name]) {
				continue
			}
			if err := r.Client.Delete(ctx, o); err != nil && !apierrors.IsNotFound(err) {
				errs = append(errs, fmt.Errorf("delete %s %s: %w", o.GetKind(), o.GetName(), err))
				continue
			}
			gone[[2]string{tenant, name}] = true
		}
	}
	for k := range gone {
		key := types.NamespacedName{Namespace: r.Render.Namespace, Name: outsideagent.CredentialSecretName(k[0], k[1])}
		if err := r.deleteSecret(ctx, key); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
