// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"fmt"
	"net"
	"os"

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
//  3. "http://<serviceHost>:8080" — the cluster Service hostname of Zitadel
//     (zitadelServiceHost).
//
// Step 3 is why an unset apiURL still reconciles on an already-installed
// cluster: this path gates bringup, so it defaults to a working in-cluster
// address rather than failing closed.
func systemAPIBaseURL(specAPIURL, serviceHost string) string {
	if specAPIURL != "" {
		return specAPIURL
	}
	if env := os.Getenv(zitadelconn.EnvURL); env != "" {
		return env
	}
	return "http://" + net.JoinHostPort(serviceHost, defaultSystemAPIPort)
}

// systemAPIClaimedHost resolves the public host the System API client claims
// with the x-zitadel-instance-host header: spec.zitadel.externalDomain, and
// ZITADEL_EXTERNAL_DOMAIN when the spec leaves it empty. It is never derived
// from the connect address of the operator (ZITADEL_URL).
// An empty or ported result is refused by the client constructor.
func systemAPIClaimedHost(specExternalDomain string) string {
	if specExternalDomain != "" {
		return specExternalDomain
	}
	return os.Getenv(zitadelconn.EnvExternalDomain)
}

// zitadelServiceHost is the cluster-internal Zitadel Service host: the spec
// value, or "<cr-name>-zitadel.<namespace>.svc.cluster.local". The operator
// dials it. It registers no trusted domain: the x-zitadel-instance-host header
// alone selects the instance (ADR-0092, gibson#990).
func zitadelServiceHost(pb *gibsonv1alpha1.PlatformBootstrap) string {
	if d := pb.Spec.Zitadel.SystemClient.TrustedClusterDomain; d != "" {
		return d
	}
	return fmt.Sprintf("%s-zitadel.%s.svc.cluster.local", pb.Name, defaultChildNamespace)
}

// systemClient builds the Zitadel System API client of the PlatformBootstrap.
// It dials the cluster-internal address and claims the public host
// (ADR-0092). spec.zitadel.systemClient must be set.
func (r *PlatformBootstrapReconciler) systemClient(pb *gibsonv1alpha1.PlatformBootstrap) (zitadel.SystemClient, error) {
	sc := pb.Spec.Zitadel.SystemClient
	apiURL := systemAPIBaseURL(sc.APIURL, zitadelServiceHost(pb))
	systemUserName := sc.SystemUserName
	if systemUserName == "" {
		systemUserName = "gibson-system-bot"
	}
	factory := r.SystemClientFactory
	if factory == nil {
		factory = DefaultSystemClientFactory
	}
	return factory(apiURL, systemUserName, systemAPIClaimedHost(pb.Spec.Zitadel.ExternalDomain), sc.KeyPath)
}
