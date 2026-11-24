// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/internal/ciliumegress"
)

// The egress of a connector follows its host list (ADR-0114). A Kubernetes
// NetworkPolicy matches addresses and labels and cannot name a host, so the
// operator writes one CiliumNetworkPolicy for each connector. It permits DNS
// to kube-dns with a DNS rule, because Cilium learns the address of a host
// name only from a lookup that it sees, and then each host of
// spec.egressAllow on its port. Every cluster runs Cilium (ADR-0087), and the
// chart renders the same shape for the platform pods.
//
// The owned NetworkPolicy (networkpolicy.go) has no public egress rule. Allow
// rules union, so an allow-all rule there would win over this list. A
// connector with an empty list therefore reaches no public host. This policy
// is the one layer that limits egress, because ToolHive v0.12.1 reads no
// per-connector host list.
//
// The deny rule of this policy never selects the ToolHive proxy pod of a
// connector (gibson#1694). See desiredCiliumEgressPolicy.

// ciliumEgressPolicyName is the name of the egress policy of a connector.
func ciliumEgressPolicyName(ci *connectorv1alpha1.ConnectorInstance) string {
	return "connector-" + ci.Name + "-egress"
}

// desiredCiliumEgressPolicy is the egress policy of a connector with a
// non-empty host list. The allow rules name each host.
//
// A Cilium deny rule wins over every allow rule. So the deny rule must never
// select a pod that has to reach a private address, and the ToolHive proxy
// pod has to reach three: the kube-apiserver, the SPIRE OIDC provider and the
// MCP server pod (gibson#1694). The shape of the connector decides the
// selector:
//
//   - Hosted: the policy selects the MCP server pod, which runs the
//     third-party code. It carries the allow rules and the deny rule. The deny
//     rule refuses the private, link-local, loopback and CGNAT ranges and the
//     cluster ranges, so a host name that resolves to one of them is refused
//     (review B3).
//   - Remote: no MCP server pod exists, because the runner of ToolHive v0.12.1
//     deploys no workload for a remote URL. The proxy pod itself calls the
//     vendor host. The policy selects the proxy pod and carries the allow
//     rules only. A deny rule here would block the kube-apiserver and the
//     issuer again. The proxy runs the code of ToolHive and not third-party
//     code, and the vendor host comes from the catalog.
func desiredCiliumEgressPolicy(ci *connectorv1alpha1.ConnectorInstance, clusterCIDRs []string) (*unstructured.Unstructured, error) {
	egress, err := ciliumegress.Rules(ci.Spec.EgressAllow)
	if err != nil {
		return nil, fmt.Errorf("connector %s: %w", ci.Name, err)
	}
	spec := map[string]interface{}{"egress": egress}
	if ci.Spec.Shape == connectorv1alpha1.ConnectorShapeRemote {
		spec["endpointSelector"] = proxyPodSelector(ci)
	} else {
		deny, err := ciliumegress.DenyRules(clusterCIDRs)
		if err != nil {
			return nil, fmt.Errorf("connector %s: %w", ci.Name, err)
		}
		spec["endpointSelector"] = serverPodSelector(ci)
		spec["egressDeny"] = deny
	}
	u := ciliumegress.NewPolicy()
	u.SetName(ciliumEgressPolicyName(ci))
	u.SetNamespace(ci.Namespace)
	u.SetLabels(map[string]string{
		"app.kubernetes.io/managed-by": "gibson-connector-operator",
		"gibson.zeroroot.ai/connector": ci.Spec.Connector,
	})
	u.Object["spec"] = spec
	return u, nil
}

// reconcileCiliumEgressPolicy applies the egress policy of the connector. It
// deletes the policy when the host list becomes empty.
func (r *ConnectorInstanceReconciler) reconcileCiliumEgressPolicy(
	ctx context.Context, ci *connectorv1alpha1.ConnectorInstance,
) error {
	live := ciliumegress.NewPolicy()
	getErr := r.Get(ctx, client.ObjectKey{Namespace: ci.Namespace, Name: ciliumEgressPolicyName(ci)}, live)
	if getErr != nil && !apierrors.IsNotFound(getErr) {
		return fmt.Errorf("get connector egress policy: %w", getErr)
	}
	exists := getErr == nil
	if len(ci.Spec.EgressAllow) == 0 {
		if exists {
			if err := r.Delete(ctx, live); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete connector egress policy: %w", err)
			}
		}
		return nil
	}
	desired, err := desiredCiliumEgressPolicy(ci, r.ClusterCIDRs)
	if err != nil {
		return err
	}
	if err := controllerutil.SetControllerReference(ci, desired, r.Scheme); err != nil {
		return fmt.Errorf("egress policy owner ref: %w", err)
	}
	if !exists {
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("create connector egress policy: %w", err)
		}
		return nil
	}
	live.Object["spec"] = desired.Object["spec"]
	live.SetLabels(desired.GetLabels())
	if err := r.Update(ctx, live); err != nil {
		return fmt.Errorf("update connector egress policy: %w", err)
	}
	return nil
}

// The ToolHive proxy of a connector creates the MCP server StatefulSet and
// attaches to it through the Kubernetes API (ToolHive v0.12.1, Kubernetes
// runtime). The tenant namespace is default-deny, and the owned NetworkPolicy
// opens no path to the kube-apiserver, so the first API call of the proxy
// hung and the kubelet killed the proxy at its liveness window (gibson#1119).
//
// This policy selects the proxy pod only. ToolHive labels the proxy pod
// app.kubernetes.io/name=mcpserver (MCPServer) or mcpremoteproxy
// (MCPRemoteProxy). The MCP server pod, which runs the third-party code, has
// neither label, so it gets no API access. The entity kube-apiserver names the
// API server on every cluster, so the operator needs no address of it.

// proxyAPIServerPolicyName is the name of the API server policy of a connector.
func proxyAPIServerPolicyName(ci *connectorv1alpha1.ConnectorInstance) string {
	return "connector-" + ci.Name + "-proxy-apiserver"
}

// toolhiveProxyNames are the app.kubernetes.io/name values ToolHive puts on a
// proxy pod.
var toolhiveProxyNames = []interface{}{"mcpserver", "mcpremoteproxy"}

// desiredProxyAPIServerPolicy is the policy that lets the ToolHive proxy of a
// connector reach the Kubernetes API.
func desiredProxyAPIServerPolicy(ci *connectorv1alpha1.ConnectorInstance) *unstructured.Unstructured {
	u := ciliumegress.NewPolicy()
	u.SetName(proxyAPIServerPolicyName(ci))
	u.SetNamespace(ci.Namespace)
	u.SetLabels(map[string]string{
		"app.kubernetes.io/managed-by": "gibson-connector-operator",
		"gibson.zeroroot.ai/connector": ci.Spec.Connector,
	})
	u.Object["spec"] = map[string]interface{}{
		"endpointSelector": proxyPodSelector(ci),
		"egress": []interface{}{map[string]interface{}{
			"toEntities": []interface{}{"kube-apiserver"},
		}},
	}
	return u
}

// serverPodSelector selects the MCP server pod of a Hosted connector, which
// runs the third-party code, and not the ToolHive proxy pod. The server pod
// has the label toolhive-name and has no app.kubernetes.io/name label
// (ToolHive v0.12.1, pkg/labels and the Kubernetes runtime). The proxy pod
// has that label with a value of toolhiveProxyNames. NotIn also matches a pod
// with no such label.
func serverPodSelector(ci *connectorv1alpha1.ConnectorInstance) map[string]interface{} {
	return map[string]interface{}{
		"matchLabels": map[string]interface{}{"toolhive-name": ci.Name},
		"matchExpressions": []interface{}{map[string]interface{}{
			"key":      "app.kubernetes.io/name",
			"operator": "NotIn",
			"values":   toolhiveProxyNames,
		}},
	}
}

// proxyPodSelector selects the ToolHive proxy pod of a connector, and not its
// MCP server pod.
func proxyPodSelector(ci *connectorv1alpha1.ConnectorInstance) map[string]interface{} {
	return map[string]interface{}{
		"matchLabels": map[string]interface{}{"toolhive-name": ci.Name},
		"matchExpressions": []interface{}{map[string]interface{}{
			"key":      "app.kubernetes.io/name",
			"operator": "In",
			"values":   toolhiveProxyNames,
		}},
	}
}

// reconcileProxyAPIServerPolicy applies the API server policy of the
// connector.
func (r *ConnectorInstanceReconciler) reconcileProxyAPIServerPolicy(
	ctx context.Context, ci *connectorv1alpha1.ConnectorInstance,
) error {
	desired := desiredProxyAPIServerPolicy(ci)
	if err := controllerutil.SetControllerReference(ci, desired, r.Scheme); err != nil {
		return fmt.Errorf("proxy api server policy owner ref: %w", err)
	}
	live := ciliumegress.NewPolicy()
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), live)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("create proxy api server policy: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get proxy api server policy: %w", err)
	}
	live.Object["spec"] = desired.Object["spec"]
	live.SetLabels(desired.GetLabels())
	if err := r.Update(ctx, live); err != nil {
		return fmt.Errorf("update proxy api server policy: %w", err)
	}
	return nil
}
