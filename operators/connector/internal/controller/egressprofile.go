// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// spec.egressAllow confines a connector to its vendor hosts. The operator
// renders it into a ToolHive custom permission profile, held in an owned
// ConfigMap that the MCPServer references (permissionProfile type configmap).
//
// Enforcement needs a NetworkPolicy-capable CNI. kind-vanilla runs one (the
// tenant default-deny is enforced, ADR-0014 Spike 1); a cluster on kindnet's
// default does not enforce it. The owned NetworkPolicy is the coarse fence at
// the IP layer; this profile is the host-level refinement.

const egressProfileKey = "profile.json"

// egressProfileName is the ConfigMap that holds the connector's profile.
func egressProfileName(ci *connectorv1alpha1.ConnectorInstance) string {
	return fmt.Sprintf("connector-%s-egress", ci.Name)
}

// hasEgressProfile reports whether the connector declares an egress allow-list.
func hasEgressProfile(ci *connectorv1alpha1.ConnectorInstance) bool {
	return len(ci.Spec.EgressAllow) > 0
}

// toolhivePermissionProfile is the JSON a ToolHive custom profile carries.
type toolhivePermissionProfile struct {
	Name    string `json:"name"`
	Network struct {
		Outbound struct {
			InsecureAllowAll bool     `json:"insecure_allow_all"`
			AllowHost        []string `json:"allow_host"`
			AllowPort        []int    `json:"allow_port"`
		} `json:"outbound"`
	} `json:"network"`
}

// reconcileEgressProfile applies the owned ConfigMap when the connector
// declares an egress allow-list. It is a no-op otherwise; the MCPServer then
// keeps the builtin network profile.
func (r *ConnectorInstanceReconciler) reconcileEgressProfile(
	ctx context.Context, ci *connectorv1alpha1.ConnectorInstance,
) error {
	if !hasEgressProfile(ci) {
		return nil
	}

	var profile toolhivePermissionProfile
	profile.Name = "connector-" + ci.Name
	profile.Network.Outbound.InsecureAllowAll = false
	profile.Network.Outbound.AllowHost = ci.Spec.EgressAllow
	profile.Network.Outbound.AllowPort = []int{443}
	payload, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("marshal egress profile: %w", err)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      egressProfileName(ci),
			Namespace: ci.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "gibson-connector-operator",
				"gibson.zeroroot.ai/connector": ci.Spec.Connector,
			},
		},
		Data: map[string]string{egressProfileKey: string(payload)},
	}
	if err := controllerutil.SetControllerReference(ci, cm, r.Scheme); err != nil {
		return fmt.Errorf("egress profile owner ref: %w", err)
	}
	live := &corev1.ConfigMap{}
	err = r.Get(ctx, client.ObjectKeyFromObject(cm), live)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, cm); err != nil {
			return fmt.Errorf("create egress profile configmap: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get egress profile configmap: %w", err)
	}
	live.Data = cm.Data
	live.Labels = cm.Labels
	if err := r.Update(ctx, live); err != nil {
		return fmt.Errorf("update egress profile configmap: %w", err)
	}
	return nil
}
