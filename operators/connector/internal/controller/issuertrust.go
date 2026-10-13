// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/internal/ciliumegress"
	"github.com/zeroroot-ai/gibson/operators/internal/spirebundle"
)

// The ToolHive proxy of a connector checks the JWT-SVID of the daemon. For
// that check it fetches the keys of the SPIRE OIDC provider from the JWKS
// URL, over HTTPS. Two things stopped that fetch, and the proxy refused the
// daemon with 401:
//
//  1. The tenant namespace is default-deny. No policy of the connector let
//     the proxy reach the provider. The proxy issuer policy below permits
//     the proxy pod, and only that pod, to reach the provider pods on their
//     HTTPS port. It names no other pod and no other port of the namespace.
//  2. The provider serves its SPIRE X.509-SVID, which no public root signs.
//     The operator copies the SPIRE trust bundle, as PEM, into a ConfigMap
//     beside each connector, and the oidcConfig of the proxy names it in
//     caBundleRef. The copy follows each change of the bundle, so a SPIRE CA
//     rotation reaches every proxy.
//
// The provider namespace comes from the JWKS URL (ProxyAuth.IssuerNamespace).
// The pod label, the port and the bundle ConfigMap are the ones the gibson
// chart renders for the SPIRE OIDC provider and the SPIRE bundle publisher.

const (
	// issuerPodName is the app.kubernetes.io/name label of the SPIRE OIDC
	// provider pods.
	issuerPodName = "spiffe-oidc-discovery-provider"
	// issuerPort is the HTTPS container port of the provider. The Service
	// port 443 maps to it, and Cilium checks the port of the pod.
	issuerPort = "8443"
	// trustBundleName and trustBundleKey name the ConfigMap that the SPIRE
	// k8s_configmap bundle publisher writes in the provider namespace. Its
	// content is the trust bundle in JWKS form.
	trustBundleName = "spire-bundle"
	trustBundleKey  = "bundle.spiffe"
	// issuerCAKey is the key of the PEM bundle in the ConfigMap of a
	// connector.
	issuerCAKey = "ca.crt"
)

// errEmptyTrustBundle is returned when the SPIRE trust bundle holds no X.509
// root. A proxy with no root refuses each token.
var errEmptyTrustBundle = errors.New("the SPIRE trust bundle holds no X.509 root")

// proxyIssuerPolicyName is the name of the issuer policy of a connector.
func proxyIssuerPolicyName(ci *connectorv1alpha1.ConnectorInstance) string {
	return "connector-" + ci.Name + "-proxy-issuer"
}

// issuerCAName is the name of the ConfigMap that holds the SPIRE trust
// bundle of a connector.
func issuerCAName(ci *connectorv1alpha1.ConnectorInstance) string {
	return "connector-" + ci.Name + "-issuer-ca"
}

// managedLabels are the labels of each object the operator writes for a
// connector.
func managedLabels(ci *connectorv1alpha1.ConnectorInstance) map[string]string {
	return map[string]string{
		"app.kubernetes.io/managed-by": "gibson-connector-operator",
		"gibson.zeroroot.ai/connector": ci.Spec.Connector,
	}
}

// desiredProxyIssuerPolicy is the policy that lets the ToolHive proxy of a
// connector reach the SPIRE OIDC provider in issuerNS on its HTTPS port.
func desiredProxyIssuerPolicy(ci *connectorv1alpha1.ConnectorInstance, issuerNS string) *unstructured.Unstructured {
	u := ciliumegress.NewPolicy()
	u.SetName(proxyIssuerPolicyName(ci))
	u.SetNamespace(ci.Namespace)
	u.SetLabels(managedLabels(ci))
	u.Object["spec"] = map[string]interface{}{
		"endpointSelector": proxyPodSelector(ci),
		"egress": []interface{}{map[string]interface{}{
			"toEndpoints": []interface{}{map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"k8s:io.kubernetes.pod.namespace": issuerNS,
					"app.kubernetes.io/name":          issuerPodName,
				},
			}},
			"toPorts": []interface{}{map[string]interface{}{
				"ports": []interface{}{map[string]interface{}{
					"port":     issuerPort,
					"protocol": "TCP",
				}},
			}},
		}},
	}
	return u
}

// reconcileProxyIssuerPolicy applies the issuer policy of the connector.
func (r *ConnectorInstanceReconciler) reconcileProxyIssuerPolicy(
	ctx context.Context, ci *connectorv1alpha1.ConnectorInstance,
) error {
	issuerNS, err := r.ProxyAuth.IssuerNamespace()
	if err != nil {
		return err
	}
	desired := desiredProxyIssuerPolicy(ci, issuerNS)
	if err := controllerutil.SetControllerReference(ci, desired, r.Scheme); err != nil {
		return fmt.Errorf("proxy issuer policy owner ref: %w", err)
	}
	live := ciliumegress.NewPolicy()
	err = r.Get(ctx, client.ObjectKeyFromObject(desired), live)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("create proxy issuer policy: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get proxy issuer policy: %w", err)
	}
	live.Object["spec"] = desired.Object["spec"]
	live.SetLabels(desired.GetLabels())
	if err := r.Update(ctx, live); err != nil {
		return fmt.Errorf("update proxy issuer policy: %w", err)
	}
	return nil
}

// issuerCAPEM reads the SPIRE trust bundle and returns its X.509 roots as
// PEM.
func (r *ConnectorInstanceReconciler) issuerCAPEM(ctx context.Context) (string, error) {
	issuerNS, err := r.ProxyAuth.IssuerNamespace()
	if err != nil {
		return "", err
	}
	bundle := &corev1.ConfigMap{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: issuerNS, Name: trustBundleName}, bundle); err != nil {
		return "", fmt.Errorf("get the SPIRE trust bundle %s/%s: %w", issuerNS, trustBundleName, err)
	}
	pemBundle, err := spirebundle.ToPEM(bundle.Data[trustBundleKey])
	if err != nil {
		return "", fmt.Errorf("convert the SPIRE trust bundle %s/%s: %w", issuerNS, trustBundleName, err)
	}
	if pemBundle == "" {
		return "", fmt.Errorf("%s/%s: %w", issuerNS, trustBundleName, errEmptyTrustBundle)
	}
	return pemBundle, nil
}

// reconcileIssuerCA applies the ConfigMap that holds the SPIRE trust bundle
// of the connector, as PEM.
func (r *ConnectorInstanceReconciler) reconcileIssuerCA(
	ctx context.Context, ci *connectorv1alpha1.ConnectorInstance,
) error {
	pemBundle, err := r.issuerCAPEM(ctx)
	if err != nil {
		return err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      issuerCAName(ci),
			Namespace: ci.Namespace,
			Labels:    managedLabels(ci),
		},
		Data: map[string]string{issuerCAKey: pemBundle},
	}
	if err := controllerutil.SetControllerReference(ci, cm, r.Scheme); err != nil {
		return fmt.Errorf("issuer CA owner ref: %w", err)
	}
	live := &corev1.ConfigMap{}
	err = r.Get(ctx, client.ObjectKeyFromObject(cm), live)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, cm); err != nil {
			return fmt.Errorf("create issuer CA configmap: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get issuer CA configmap: %w", err)
	}
	live.Data = cm.Data
	live.Labels = cm.Labels
	if err := r.Update(ctx, live); err != nil {
		return fmt.Errorf("update issuer CA configmap: %w", err)
	}
	return nil
}

// trustBundleRequests maps a change of the SPIRE trust bundle to a
// reconcile of each connector, so each copy follows the bundle. A change of
// any other ConfigMap maps to nothing.
func (r *ConnectorInstanceReconciler) trustBundleRequests(ctx context.Context, obj client.Object) []reconcile.Request {
	issuerNS, err := r.ProxyAuth.IssuerNamespace()
	if err != nil || obj.GetNamespace() != issuerNS || obj.GetName() != trustBundleName {
		return nil
	}
	var list connectorv1alpha1.ConnectorInstanceList
	if err := r.List(ctx, &list); err != nil {
		log.FromContext(ctx).Error(err, "list the connectors after a change of the SPIRE trust bundle")
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return reqs
}
