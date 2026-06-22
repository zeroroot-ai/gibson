/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
)

const (
	// saIdentityMapName is the ConfigMap the dashboard's
	// resolve-sa-identity-map init container reads to build
	// ALLOWED_SERVICE_SUBJECTS. The dashboard hard-fails (exit 1) when any
	// entry resolves to "<unset>", so every expected key must be present and
	// numeric before the ConfigMap is considered Ready.
	saIdentityMapName = "gibson-sa-identity-map"

	// iamAdminSecretName is the machine-key Secret the Zitadel setup Job
	// writes once Zitadel is live. Its iam-admin.json entry holds a service
	// account key JSON ({"userId":"...","type":"serviceaccount"}); the numeric
	// userId is the iam-admin Zitadel subject. iamAdminMachineKeyFile is the
	// data-map entry name (a filename, not a credential — named to avoid the
	// gosec G101 hardcoded-credential heuristic that fires on a *Key suffix).
	iamAdminSecretName     = "iam-admin"
	iamAdminMachineKeyFile = "iam-admin.json"

	// saIAMAdminEntry is the gibson-sa-identity-map key for the iam-admin
	// machine user.
	saIAMAdminEntry = "gibson-iam-admin"
)

// reconcileSAIdentityMap populates the gibson-sa-identity-map ConfigMap with
// the numeric Zitadel subject of every platform service account. It runs after
// reconcileOIDCChildren so the MACHINE_USER children have minted their Zitadel
// users and persisted status.clientID (the numeric subject for a MACHINE_USER).
//
// Entries written:
//   - "gibson-iam-admin"     → .userId from secret/iam-admin key iam-admin.json
//   - one key per Ready MACHINE_USER OIDCClient child → child.status.clientID
//     (e.g. "gibson-tenant-operator")
//
// The chart's serviceAccounts.required list selects which of these keys the
// dashboard's resolve-sa-identity-map init container actually consumes for
// ALLOWED_SERVICE_SUBJECTS (kind: gibson-iam-admin + gibson-tenant-operator).
// Reflecting every MACHINE_USER child is a harmless superset — unconsumed keys
// are inert — and keeps the map correct if the required list grows. WEB/SERVICE
// OIDC-app children (e.g. the browser-login gibson-dashboard client) are
// deliberately excluded: their status.clientID is an OAuth client_id, not a
// numeric Zitadel subject.
//
// secret/iam-admin is written by the Zitadel setup Job only after Zitadel is
// live, so a missing Secret is a normal early-bootstrap state: requeue short
// rather than erroring. Idempotent — CreateOrUpdate only writes when the
// computed entries differ from what's stored.
//
// Replaces the gitops sa-identity-map-populator kubectl-exec Sync Job
// (gitops#170): the platform-operator already mints these machine users, so it
// owns reflecting their numeric subjects into the ConfigMap rather than a
// separate Job re-deriving them from CR status.
func (r *PlatformBootstrapReconciler) reconcileSAIdentityMap(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, logger logr.Logger) (ctrl.Result, error) {
	entries := map[string]string{}

	// iam-admin numeric subject from the machine-key Secret.
	var sec corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: defaultChildNamespace, Name: iamAdminSecretName}, &sec)
	switch {
	case apierrors.IsNotFound(err):
		setBootstrapCond(pb, gibsonv1alpha1.ConditionSAIdentityMapReady, metav1.ConditionFalse,
			"WaitingForIAMAdminSecret",
			fmt.Sprintf("Secret %s/%s not yet written by the Zitadel setup Job", defaultChildNamespace, iamAdminSecretName))
		return ctrl.Result{RequeueAfter: requeueShort}, nil
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get secret %s/%s: %w", defaultChildNamespace, iamAdminSecretName, err)
	}
	raw, ok := sec.Data[iamAdminMachineKeyFile]
	if !ok || len(raw) == 0 {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionSAIdentityMapReady, metav1.ConditionFalse,
			"WaitingForIAMAdminSecret",
			fmt.Sprintf("Secret %s/%s missing key %q", defaultChildNamespace, iamAdminSecretName, iamAdminMachineKeyFile))
		return ctrl.Result{RequeueAfter: requeueShort}, nil
	}
	var machineKey struct {
		UserID string `json:"userId"`
	}
	if jerr := json.Unmarshal(raw, &machineKey); jerr != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionSAIdentityMapReady, metav1.ConditionFalse,
			"MalformedIAMAdminSecret",
			fmt.Sprintf("parse %s key %q: %v", iamAdminSecretName, iamAdminMachineKeyFile, jerr))
		return ctrl.Result{}, nil
	}
	if strings.TrimSpace(machineKey.UserID) == "" {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionSAIdentityMapReady, metav1.ConditionFalse,
			"WaitingForIAMAdminSecret",
			fmt.Sprintf("Secret %s/%s key %q has empty userId", defaultChildNamespace, iamAdminSecretName, iamAdminMachineKeyFile))
		return ctrl.Result{RequeueAfter: requeueShort}, nil
	}
	entries[saIAMAdminEntry] = strings.TrimSpace(machineKey.UserID)

	// MACHINE_USER children: collect {name → status.clientID}. For a
	// MACHINE_USER the OIDCClient controller persists the numeric Zitadel
	// user id into status.clientID. Only Ready children with a non-empty
	// clientID are eligible — an in-flight child means we requeue.
	pending := []string{}
	for _, ref := range pb.Spec.OIDCClients {
		if defaultAppType(ref) != gibsonv1alpha1.OIDCAppTypeMachineUser {
			continue
		}
		var child gibsonv1alpha1.OIDCClient
		if gerr := r.Get(ctx, types.NamespacedName{Namespace: defaultChildNamespace, Name: ref.Name}, &child); gerr != nil {
			if apierrors.IsNotFound(gerr) {
				pending = append(pending, ref.Name)
				continue
			}
			return ctrl.Result{}, fmt.Errorf("get OIDCClient %s: %w", ref.Name, gerr)
		}
		ready := isConditionTrue(child.Status.Conditions, gibsonv1alpha1.ConditionReady)
		if !ready || strings.TrimSpace(child.Status.ClientID) == "" {
			pending = append(pending, ref.Name)
			continue
		}
		entries[ref.Name] = strings.TrimSpace(child.Status.ClientID)
	}
	if len(pending) > 0 {
		sort.Strings(pending)
		setBootstrapCond(pb, gibsonv1alpha1.ConditionSAIdentityMapReady, metav1.ConditionFalse,
			"WaitingForMachineUsers",
			fmt.Sprintf("MACHINE_USER OIDCClients not yet Ready with a clientID: %s", strings.Join(pending, ", ")))
		return ctrl.Result{RequeueAfter: requeueMedium}, nil
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      saIdentityMapName,
			Namespace: defaultChildNamespace,
		},
	}
	if _, cerr := controllerutil.CreateOrUpdate(ctx, r.Client, cm, func() error {
		if cm.Labels == nil {
			cm.Labels = map[string]string{}
		}
		cm.Labels["app.kubernetes.io/managed-by"] = "platform-operator"
		cm.Labels["gibson.zeroroot.ai/component"] = "sa-identity-map"
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		// Merge our managed entries onto whatever is present. We never delete
		// keys we don't own — other writers (none today) and chart-seeded
		// defaults stay intact.
		for k, v := range entries {
			cm.Data[k] = v
		}
		return nil
	}); cerr != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionSAIdentityMapReady, metav1.ConditionFalse,
			"WriteFailed", cerr.Error())
		return ctrl.Result{}, fmt.Errorf("CreateOrUpdate ConfigMap %s/%s: %w", defaultChildNamespace, saIdentityMapName, cerr)
	}

	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	logger.Info("gibson-sa-identity-map populated", "entries", keys)
	setBootstrapCond(pb, gibsonv1alpha1.ConditionSAIdentityMapReady, metav1.ConditionTrue,
		"Populated",
		fmt.Sprintf("ConfigMap %s/%s populated with %d service-account subjects: %s",
			defaultChildNamespace, saIdentityMapName, len(keys), strings.Join(keys, ", ")))
	return ctrl.Result{}, nil
}
