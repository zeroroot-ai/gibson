// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

// ModelProvider records of a tenant (gibson#1387).
//
// The daemon holds the provider records of a tenant and cannot write cluster
// resources (ADR-0023). This loop pulls the records of each ready tenant and
// reconciles one ModelProvider in the tenant namespace for each record. It
// removes a ModelProvider that the loop made and whose record is gone. The
// ModelProviderReconciler renders each ModelProvider into the gateway objects.

const (
	defaultModelProviderSyncInterval = 30 * time.Second

	// LabelModelProviderFromRecord marks a ModelProvider that this loop made from
	// a provider record. The loop deletes only ModelProviders with this label.
	LabelModelProviderFromRecord = "gibson.zeroroot.ai/provider-record"
)

// ModelProviderRecords reads the provider records of a tenant from the daemon.
// The daemon client implements it. The skipped strings name each record that has
// no gateway route, with the reason.
type ModelProviderRecords interface {
	TenantModelProviders(ctx context.Context, tenantID string) (providers []provision.DesiredModelProvider, skipped []string, err error)
}

// ModelProviderSyncRunnable pulls the provider records and reconciles the
// ModelProvider resources. It is a manager.Runnable that needs leader election.
type ModelProviderSyncRunnable struct {
	Client client.Client
	Daemon ModelProviderRecords
	// Interval between passes. Zero uses the default.
	Interval time.Duration
}

// NeedLeaderElection makes only the lead replica run the loop.
func (r *ModelProviderSyncRunnable) NeedLeaderElection() bool { return true }

// SetupWithManager registers the runnable.
func (r *ModelProviderSyncRunnable) SetupWithManager(mgr manager.Manager) error {
	if r.Daemon == nil {
		return errors.New("modelprovider-sync: the daemon client is nil")
	}
	if r.Client == nil {
		r.Client = mgr.GetClient()
	}
	if err := mgr.Add(r); err != nil {
		return fmt.Errorf("add the model provider sync: %w", err)
	}
	return nil
}

// Start runs the loop until the manager context ends.
func (r *ModelProviderSyncRunnable) Start(ctx context.Context) error {
	interval := r.Interval
	if interval <= 0 {
		interval = defaultModelProviderSyncInterval
	}
	logger := log.FromContext(ctx).WithName("modelprovider-sync")
	logger.Info("starting the pull of provider records", "interval", interval.String())
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := r.Sync(ctx); err != nil {
				logger.Error(err, "the pull of provider records failed; retrying next tick")
			}
		}
	}
}

// Sync does one pass over every ready tenant. A tenant whose read fails is left
// as it is: nothing is deleted on an error. The pass returns the joined errors.
func (r *ModelProviderSyncRunnable) Sync(ctx context.Context) error {
	var tenants gibsonv1alpha1.TenantList
	if err := r.Client.List(ctx, &tenants); err != nil {
		return fmt.Errorf("list tenants: %w", err)
	}
	var errs []error
	for i := range tenants.Items {
		t := &tenants.Items[i]
		if !t.DeletionTimestamp.IsZero() || t.Status.Phase != gibsonv1alpha1.TenantPhaseReady {
			continue
		}
		if err := r.syncTenant(ctx, t); err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", t.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (r *ModelProviderSyncRunnable) syncTenant(ctx context.Context, t *gibsonv1alpha1.Tenant) error {
	logger := log.FromContext(ctx).WithName("modelprovider-sync")
	ns := TenantNamespaceForBackfill(t)
	desired, skipped, err := r.Daemon.TenantModelProviders(ctx, t.Name)
	if err != nil {
		return fmt.Errorf("read the provider records: %w", err)
	}
	for _, s := range skipped {
		logger.Info("a provider record has no gateway route", "tenant", t.Name, "record", s)
	}
	want := map[string]provision.DesiredModelProvider{}
	for _, d := range desired {
		if msgs := validation.IsDNS1123Label(d.Name); len(msgs) > 0 {
			logger.Info("a provider record has a name that is not a Kubernetes name", "tenant", t.Name, "name", d.Name)
			continue
		}
		want[d.Name] = d
	}
	var existing gibsonv1alpha1.ModelProviderList
	if err := r.Client.List(ctx, &existing, client.InNamespace(ns),
		client.MatchingLabels{LabelModelProviderFromRecord: "true"}); err != nil {
		return fmt.Errorf("list the model providers: %w", err)
	}
	have := map[string]*gibsonv1alpha1.ModelProvider{}
	var errs []error
	for i := range existing.Items {
		mp := &existing.Items[i]
		d, keep := want[mp.Name]
		// The type and the tenant of a ModelProvider cannot change. A changed
		// type is a delete now and a create on the next pass.
		if !keep || mp.Spec.Type != gibsonv1alpha1.ModelProviderType(d.Type) {
			if err := r.Client.Delete(ctx, mp); err != nil && !apierrors.IsNotFound(err) {
				errs = append(errs, fmt.Errorf("delete the model provider %s: %w", mp.Name, err))
			}
			continue
		}
		have[mp.Name] = mp
	}
	for name, d := range want {
		if mp, ok := have[name]; ok {
			if err := r.update(ctx, mp, d); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		mp := &gibsonv1alpha1.ModelProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: ns, Labels: map[string]string{LabelModelProviderFromRecord: "true"},
			},
			Spec: specOf(t.Name, d),
		}
		if err := r.Client.Create(ctx, mp); err != nil && !apierrors.IsAlreadyExists(err) {
			errs = append(errs, fmt.Errorf("create the model provider %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func specOf(tenant string, d provision.DesiredModelProvider) gibsonv1alpha1.ModelProviderSpec {
	return gibsonv1alpha1.ModelProviderSpec{
		TenantID: tenant, Type: gibsonv1alpha1.ModelProviderType(d.Type), BaseURL: d.BaseURL,
		Region: d.Region, ProjectID: d.ProjectID, CredentialSecret: d.CredentialSecret,
		CABundleSecret: d.CABundleSecret,
	}
}

func (r *ModelProviderSyncRunnable) update(ctx context.Context, mp *gibsonv1alpha1.ModelProvider, d provision.DesiredModelProvider) error {
	want := specOf(mp.Spec.TenantID, d)
	// The model filter is not part of a provider record. The loop keeps it.
	want.ModelFilter = mp.Spec.ModelFilter
	if mp.Spec.BaseURL == want.BaseURL && mp.Spec.Region == want.Region && mp.Spec.ProjectID == want.ProjectID &&
		mp.Spec.CredentialSecret == want.CredentialSecret && mp.Spec.CABundleSecret == want.CABundleSecret {
		return nil
	}
	mp.Spec = want
	if err := r.Client.Update(ctx, mp); err != nil {
		return fmt.Errorf("update the model provider %s: %w", mp.Name, err)
	}
	return nil
}
