// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// A tenant namespace runs under the gibson-tenant-default-deny NetworkPolicy.
// That policy severs a ToolHive connector: the proxy cannot reach the server
// pod, and the daemon cannot reach the proxy. This file makes the connector-
// operator emit ONE owned NetworkPolicy per ConnectorInstance that opens
// exactly the paths a connector needs and nothing more.
//
// ToolHive labels every pod of a connector `toolhive-name: <mcpserver-name>`,
// which equals the ConnectorInstance name. The policy selects on that label,
// so it covers both the proxy pod and the server pod.
//
// NetworkPolicies union, so this ADDS to the default-deny baseline; it does not
// replace it. It has no egress rule to a public address: the egress to a
// vendor host is the CiliumNetworkPolicy of the connector, which names each
// host of spec.egressAllow (ciliumpolicy.go). An allow-all rule here would win
// over that list, because allow rules union.

const (
	daemonNamespace = "gibson"
	dnsNamespace    = "kube-system"
	mcpProxyPort    = 8080
)

// toolhivePodSelector selects every ToolHive pod of one connector.
func toolhivePodSelector(ci *connectorv1alpha1.ConnectorInstance) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: map[string]string{"toolhive-name": ci.Name}}
}

func tcp(port int) networkingv1.NetworkPolicyPort {
	p := intstr.FromInt(port)
	proto := corev1.ProtocolTCP
	return networkingv1.NetworkPolicyPort{Protocol: &proto, Port: &p}
}

// desiredNetworkPolicy is the NetworkPolicy a ConnectorInstance owns.
func desiredNetworkPolicy(ci *connectorv1alpha1.ConnectorInstance) *networkingv1.NetworkPolicy {
	udp := corev1.ProtocolUDP
	tcpProto := corev1.ProtocolTCP
	dns := intstr.FromInt(53)
	sameConnector := []networkingv1.NetworkPolicyPeer{{PodSelector: toolhivePodSelector(ci)}}
	daemonPeer := []networkingv1.NetworkPolicyPeer{{
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"kubernetes.io/metadata.name": daemonNamespace},
		},
		PodSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app.kubernetes.io/component": "daemon"},
		},
	}}

	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "connector-" + ci.Name,
			Namespace: ci.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "gibson-connector-operator",
				"gibson.zeroroot.ai/connector": ci.Spec.Connector,
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: *toolhivePodSelector(ci),
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress,
			},
			// Ingress: the daemon reaches the proxy, and the connector's own
			// pods reach each other (proxy -> server).
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From:  append(daemonPeer, sameConnector...),
				Ports: []networkingv1.NetworkPolicyPort{tcp(mcpProxyPort)},
			}},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				// proxy -> server, within the connector.
				{To: sameConnector, Ports: []networkingv1.NetworkPolicyPort{tcp(mcpProxyPort)}},
				// DNS.
				{
					To: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"kubernetes.io/metadata.name": dnsNamespace},
						},
					}},
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &udp, Port: &dns}, {Protocol: &tcpProto, Port: &dns},
					},
				},
				// The daemon, for any gibson callback the runner makes.
				{To: daemonPeer, Ports: []networkingv1.NetworkPolicyPort{
					tcp(mcpProxyPort), tcp(50002), tcp(50100),
				}},
			},
		},
	}
}

// reconcileNetworkPolicy applies the owned NetworkPolicy for the connector.
func (r *ConnectorInstanceReconciler) reconcileNetworkPolicy(
	ctx context.Context, ci *connectorv1alpha1.ConnectorInstance,
) error {
	desired := desiredNetworkPolicy(ci)
	if err := controllerutil.SetControllerReference(ci, desired, r.Scheme); err != nil {
		return fmt.Errorf("networkpolicy owner ref: %w", err)
	}
	live := &networkingv1.NetworkPolicy{}
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), live)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, desired); err != nil {
			return fmt.Errorf("create connector networkpolicy: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get connector networkpolicy: %w", err)
	}
	live.Spec = desired.Spec
	live.Labels = desired.Labels
	if err := r.Update(ctx, live); err != nil {
		return fmt.Errorf("update connector networkpolicy: %w", err)
	}
	return nil
}
