// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
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
// connector with an empty list therefore reaches no public host. The ToolHive
// host list of the connector stays as the second layer (egressprofile.go).

const (
	ciliumAPIVersion        = "cilium.io/v2"
	kindCiliumNetworkPolicy = "CiliumNetworkPolicy"
	defaultEgressPort       = 443
)

// ciliumEgressPolicyName is the name of the egress policy of a connector.
func ciliumEgressPolicyName(ci *connectorv1alpha1.ConnectorInstance) string {
	return "connector-" + ci.Name + "-egress"
}

// newCiliumNetworkPolicy returns an empty CiliumNetworkPolicy object.
func newCiliumNetworkPolicy() *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion(ciliumAPIVersion)
	u.SetKind(kindCiliumNetworkPolicy)
	return u
}

// errBadEgressEntry reports an egressAllow entry that is not host or host:port.
var errBadEgressEntry = errors.New("an egressAllow entry is not host or host:port")

// parseEgressEntry splits an egressAllow entry ("api.github.com:443",
// "*.slack.com:443" or "api.osv.dev") into its host and port. The port is 443
// when the entry names none.
func parseEgressEntry(entry string) (host string, port int, err error) {
	entry = strings.TrimSpace(entry)
	host, portStr, splitErr := net.SplitHostPort(entry)
	if splitErr != nil {
		host, portStr = entry, strconv.Itoa(defaultEgressPort)
	}
	port, convErr := strconv.Atoi(portStr)
	if host == "" || strings.ContainsAny(host, ":/ ") || convErr != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("%w: %q", errBadEgressEntry, entry)
	}
	return host, port, nil
}

// desiredCiliumEgressPolicy is the egress policy of a connector with a
// non-empty host list.
func desiredCiliumEgressPolicy(ci *connectorv1alpha1.ConnectorInstance) (*unstructured.Unstructured, error) {
	egress := []interface{}{map[string]interface{}{
		"toEndpoints": []interface{}{map[string]interface{}{
			"matchLabels": map[string]interface{}{
				"io.kubernetes.pod.namespace": dnsNamespace,
				"k8s-app":                     "kube-dns",
			},
		}},
		"toPorts": []interface{}{map[string]interface{}{
			"ports": []interface{}{map[string]interface{}{"port": "53", "protocol": "ANY"}},
			"rules": map[string]interface{}{
				"dns": []interface{}{map[string]interface{}{"matchPattern": "*"}},
			},
		}},
	}}
	for _, entry := range ci.Spec.EgressAllow {
		host, port, err := parseEgressEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("connector %s: %w", ci.Name, err)
		}
		fqdn := map[string]interface{}{"matchName": host}
		if strings.Contains(host, "*") {
			fqdn = map[string]interface{}{"matchPattern": host}
		}
		egress = append(egress, map[string]interface{}{
			"toFQDNs": []interface{}{fqdn},
			"toPorts": []interface{}{map[string]interface{}{
				"ports": []interface{}{map[string]interface{}{"port": strconv.Itoa(port), "protocol": "TCP"}},
			}},
		})
	}
	u := newCiliumNetworkPolicy()
	u.SetName(ciliumEgressPolicyName(ci))
	u.SetNamespace(ci.Namespace)
	u.SetLabels(map[string]string{
		"app.kubernetes.io/managed-by": "gibson-connector-operator",
		"gibson.zeroroot.ai/connector": ci.Spec.Connector,
	})
	u.Object["spec"] = map[string]interface{}{
		"endpointSelector": map[string]interface{}{
			"matchLabels": map[string]interface{}{"toolhive-name": ci.Name},
		},
		"egress": egress,
	}
	return u, nil
}

// reconcileCiliumEgressPolicy applies the egress policy of the connector. It
// deletes the policy when the host list becomes empty.
func (r *ConnectorInstanceReconciler) reconcileCiliumEgressPolicy(
	ctx context.Context, ci *connectorv1alpha1.ConnectorInstance,
) error {
	live := newCiliumNetworkPolicy()
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
	desired, err := desiredCiliumEgressPolicy(ci)
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
