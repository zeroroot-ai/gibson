// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	zitadel "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// SystemClientFactory constructs a Zitadel SystemClient. Separated from
// the concrete constructor so unit tests can substitute a fake.
type SystemClientFactory func(apiURL, systemUserName, externalDomain, keyPath string) (zitadel.SystemClient, error)

// DefaultSystemClientFactory is the production wiring.
func DefaultSystemClientFactory(apiURL, systemUserName, externalDomain, keyPath string) (zitadel.SystemClient, error) {
	return zitadel.NewSystemClient(apiURL, systemUserName, externalDomain, keyPath)
}

// reconcileTrustedDomain registers the cluster-internal Zitadel Service
// hostname as an additional trusted domain on the Zitadel instance so
// in-cluster consumers can dial it directly without hostAliases.
//
// Called from Reconcile AFTER reconcileOIDCChildren (i.e., after the Zitadel
// instance + system-bot user are guaranteed to exist). This ordering is
// enforced by the call sequence in Reconcile.
//
// Condition managed: ConditionTrustedDomainReady.
//
// If spec.zitadel.systemClient is nil the condition flips True with reason
// "SystemClientDisabled" and no System API calls are made. This allows
// existing clusters to opt-in incrementally without breaking the reconciler.
func (r *PlatformBootstrapReconciler) reconcileTrustedDomain(
	ctx context.Context,
	pb *gibsonv1alpha1.PlatformBootstrap,
	logger logr.Logger,
) (ctrl.Result, error) {
	if pb.Spec.Zitadel.SystemClient == nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionTrustedDomainReady, metav1.ConditionTrue,
			"SystemClientDisabled", "spec.zitadel.systemClient not configured; skipping trusted-domain registration")
		return ctrl.Result{}, nil
	}

	sc := pb.Spec.Zitadel.SystemClient

	// Resolve the target cluster-service domain. If the spec field is empty,
	// derive it from the Helm release name and namespace convention:
	// "<releaseName>-zitadel.<namespace>.svc.cluster.local".
	targetDomain := sc.TrustedClusterDomain
	if targetDomain == "" {
		// Derive from the release name embedded in the CR name. By convention
		// the CR is named after the Helm release (e.g. "gibson"). If no
		// namespace is set on the CR we use the defaultChildNamespace.
		releaseName := pb.Name
		ns := defaultChildNamespace
		targetDomain = fmt.Sprintf("%s-zitadel.%s.svc.cluster.local", releaseName, ns)
	}

	// Build the System API base URL. Use the issuer host but switch to the
	// in-cluster Service URL for the actual call.
	apiURL := pb.Spec.Zitadel.Issuer
	systemUserName := sc.SystemUserName
	if systemUserName == "" {
		systemUserName = "gibson-system-bot"
	}

	// Construct the system client via the factory (real or test-injected).
	factory := r.SystemClientFactory
	if factory == nil {
		factory = DefaultSystemClientFactory
	}
	// externalDomain for Host header forging — same pattern as
	// DefaultZitadelClientFactory reading ZITADEL_EXTERNAL_DOMAIN.
	externalDomain := pb.Spec.Zitadel.ExternalDomain
	sysCli, err := factory(apiURL, systemUserName, externalDomain, sc.KeyPath)
	if err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionTrustedDomainReady, metav1.ConditionFalse,
			"SystemClientInitFailed", err.Error())
		// Construction failure is permanent (bad key path / parse error).
		if zitadel.IsPermanent(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}

	// List current domains to short-circuit if already registered (avoid
	// a write RPC on every reconcile loop).
	domains, err := sysCli.ListInstanceDomains(ctx)
	if err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionTrustedDomainReady, metav1.ConditionUnknown,
			"ListDomainsFailed", err.Error())
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}

	for _, d := range domains {
		if d == targetDomain {
			logger.V(1).Info("trusted domain already registered", "domain", targetDomain)
			setBootstrapCond(pb, gibsonv1alpha1.ConditionTrustedDomainReady, metav1.ConditionTrue,
				"DomainRegistered", fmt.Sprintf("trusted domain %q already registered", targetDomain))
			return ctrl.Result{}, nil
		}
	}

	// Domain not yet present — register it.
	logger.Info("registering trusted cluster domain", "domain", targetDomain)
	if err := sysCli.AddInstanceDomain(ctx, targetDomain); err != nil {
		if zitadel.IsPermanent(err) {
			setBootstrapCond(pb, gibsonv1alpha1.ConditionTrustedDomainReady, metav1.ConditionFalse,
				"PermanentError", err.Error())
			return ctrl.Result{}, nil
		}
		setBootstrapCond(pb, gibsonv1alpha1.ConditionTrustedDomainReady, metav1.ConditionFalse,
			"AddDomainFailed", err.Error())
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}

	logger.Info("trusted cluster domain registered", "domain", targetDomain)
	setBootstrapCond(pb, gibsonv1alpha1.ConditionTrustedDomainReady, metav1.ConditionTrue,
		"DomainRegistered", fmt.Sprintf("trusted domain %q registered", targetDomain))
	return ctrl.Result{}, nil
}
