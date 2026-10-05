// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
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
// The registration call itself goes over the Zitadel System API, which is an
// instance-superuser surface. It is dialled at a cluster-internal address
// (see systemAPIBaseURL) so that traffic never leaves the cluster and no
// ingress route has to publish "/system/v1/". The Host header is still
// claimed with the instance header (see systemAPIClaimedHost) because Zitadel
// selects the instance by Host — dialling in-cluster while presenting the
// public host is what makes both properties hold at once.
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

	// Build the System API base URL. This is ALWAYS a cluster-internal
	// address — see systemAPIBaseURL.
	apiURL := systemAPIBaseURL(sc.APIURL, targetDomain)
	systemUserName := sc.SystemUserName
	if systemUserName == "" {
		systemUserName = "gibson-system-bot"
	}

	// Construct the system client via the factory (real or test-injected).
	factory := r.SystemClientFactory
	if factory == nil {
		factory = DefaultSystemClientFactory
	}
	// The claimed host (ADR-0092). The connection goes to the in-cluster
	// Service, and the x-zitadel-instance-host header names the public
	// domain, so the call lands on the right instance before the
	// cluster-internal hostname is a trusted domain.
	externalDomain := systemAPIClaimedHost(pb.Spec.Zitadel.ExternalDomain)
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

// defaultSystemAPIPort is the Zitadel Service port the chart exposes
// in-cluster. Only used when neither spec.zitadel.systemClient.apiURL nor
// ZITADEL_URL names a full URL.
const defaultSystemAPIPort = "8080"

// systemAPIBaseURL resolves the base URL for Zitadel System API calls.
//
// The System API ("/system/v1/*") is an instance-superuser surface. It must
// be dialled over a cluster-internal address so no ingress route has to
// publish it — publishing it is the exposure this seam exists to remove.
// The public issuer is therefore never a candidate here.
//
// Resolution order:
//  1. specAPIURL — spec.zitadel.systemClient.apiURL, set by the chart.
//  2. ZITADEL_URL — the operator Pod env that names the in-cluster
//     Zitadel Service (ADR-0092).
//  3. "http://<clusterDomain>:8080" — derived from the same cluster Service
//     hostname the reconciler is about to register as a trusted domain.
//
// Step 3 is why an unset apiURL still reconciles on an already-installed
// cluster: this path gates bringup, so it defaults to a working in-cluster
// address rather than failing closed.
func systemAPIBaseURL(specAPIURL, clusterDomain string) string {
	if specAPIURL != "" {
		return specAPIURL
	}
	if env := os.Getenv(zitadelconn.EnvURL); env != "" {
		return env
	}
	return "http://" + net.JoinHostPort(clusterDomain, defaultSystemAPIPort)
}

// systemAPIClaimedHost resolves the public host the System API client claims
// with the x-zitadel-instance-host header: spec.zitadel.externalDomain, and
// ZITADEL_EXTERNAL_DOMAIN when the spec leaves it empty. It is never derived
// from spec.zitadel.issuer, which holds a connect address on every profile.
// An empty or ported result is refused by the client constructor.
func systemAPIClaimedHost(specExternalDomain string) string {
	if specExternalDomain != "" {
		return specExternalDomain
	}
	return os.Getenv(zitadelconn.EnvExternalDomain)
}
