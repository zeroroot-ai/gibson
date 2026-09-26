// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	zitadel "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// The keys of the login-branding ConfigMap.
const (
	brandPolicyKey = "label-policy.json"
	brandLogoKey   = "logo.svg"
	brandIconKey   = "icon.svg"
)

// brand is the declared login brand, read from the ConfigMap.
type brand struct {
	policy map[string]any
	logo   []byte
	icon   []byte
}

// mark returns the declared bytes for a slot: the logo for both logo slots,
// the icon for both icon slots. The platform ships one brand, and no slot
// may fall back to Zitadel's stock mark in dark mode.
func (b brand) mark(slot zitadel.LabelSlot) []byte {
	if strings.HasPrefix(slot.Field, "logo") {
		return b.logo
	}
	return b.icon
}

// errBrandNotReady marks a ConfigMap that is missing or incomplete. It is a
// state to wait for, not a Zitadel failure.
var errBrandNotReady = errors.New("login branding not ready")

// reconcileLoginBranding keeps the Zitadel instance's active label policy
// and its four marks equal to the declared brand (spec.zitadel.loginBranding).
//
// It is bootstrap work. Writing the instance label policy needs
// iam.policy.write, and no Zitadel role below IAM_OWNER grants it, so no
// narrower identity than bootstrap can do this (ADR-0093 decisions 7 and 9).
//
// The step never stops the reconcile. The brand is cosmetic, and a Zitadel
// outage here must not hold the master key or the FGA model back. It sets
// LoginBrandingReady, which the Ready rollup reads, and the periodic requeue
// retries it.
func (r *PlatformBootstrapReconciler) reconcileLoginBranding(ctx context.Context, pb *gibsonv1alpha1.PlatformBootstrap, logger logr.Logger) {
	spec := pb.Spec.Zitadel.LoginBranding
	if spec == nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionLoginBrandingReady, metav1.ConditionTrue,
			"NotDeclared", "no login branding is declared; Zitadel's stock brand stays")
		return
	}
	b, err := r.readBrand(ctx, spec)
	if err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionLoginBrandingReady, metav1.ConditionFalse,
			"WaitingForBrand", err.Error())
		return
	}
	pat, ok, err := r.readSecretKey(ctx, defaultChildNamespace, pb.Spec.Zitadel.AdminTokenRef)
	if err != nil || !ok {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionLoginBrandingReady, metav1.ConditionFalse,
			"WaitingForAdminToken", "Zitadel admin token Secret not yet materialised")
		return
	}
	zc := r.ZitadelFactory(pb.Spec.Zitadel.Issuer, pat)
	changed, err := applyLoginBranding(ctx, zc, b)
	if err != nil {
		setBootstrapCond(pb, gibsonv1alpha1.ConditionLoginBrandingReady, metav1.ConditionFalse,
			"ZitadelError", err.Error())
		return
	}
	if changed {
		logger.Info("applied the declared login branding to the Zitadel instance label policy")
		if r.Recorder != nil {
			r.Recorder.Event(pb, corev1.EventTypeNormal, "LoginBrandingApplied",
				"the instance label policy now matches the declared brand")
		}
	}
	setBootstrapCond(pb, gibsonv1alpha1.ConditionLoginBrandingReady, metav1.ConditionTrue,
		"BrandApplied", "the active label policy and its marks match the declared brand")
}

// readBrand reads and checks the declared brand.
func (r *PlatformBootstrapReconciler) readBrand(ctx context.Context, spec *gibsonv1alpha1.LoginBrandingSpec) (brand, error) {
	ns := spec.Namespace
	if ns == "" {
		ns = defaultChildNamespace
	}
	var cm corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: spec.ConfigMap}, &cm); err != nil {
		if apierrors.IsNotFound(err) {
			return brand{}, fmt.Errorf("%w: ConfigMap %s/%s does not exist", errBrandNotReady, ns, spec.ConfigMap)
		}
		return brand{}, fmt.Errorf("read ConfigMap %s/%s: %w", ns, spec.ConfigMap, err)
	}
	var b brand
	if err := json.Unmarshal([]byte(cm.Data[brandPolicyKey]), &b.policy); err != nil || len(b.policy) == 0 {
		return brand{}, fmt.Errorf("%w: ConfigMap %s/%s key %s is not a JSON object", errBrandNotReady, ns, spec.ConfigMap, brandPolicyKey)
	}
	b.logo = []byte(cm.Data[brandLogoKey])
	b.icon = []byte(cm.Data[brandIconKey])
	if len(b.logo) == 0 || len(b.icon) == 0 {
		return brand{}, fmt.Errorf("%w: ConfigMap %s/%s needs non-empty %s and %s", errBrandNotReady, ns, spec.ConfigMap, brandLogoKey, brandIconKey)
	}
	return b, nil
}

// applyLoginBranding makes the active label policy and its marks equal to b,
// compared by content. It returns changed=false and writes nothing when they
// already match, so a steady-state reconcile changes nothing.
//
// When something differs, it writes the policy to the preview, replaces each
// stale mark on the preview, activates the preview, and then reads the
// active policy back. The read-back is the proof: a write that Zitadel
// accepted but did not activate fails here.
func applyLoginBranding(ctx context.Context, zc zitadel.LabelPolicyClient, b brand) (bool, error) {
	active, err := zc.GetLabelPolicy(ctx)
	if err != nil {
		return false, fmt.Errorf("read the active label policy: %w", err)
	}
	policyDiffers := !policyMatches(active, b.policy)
	stale, err := staleMarks(ctx, zc, active, b)
	if err != nil {
		return false, err
	}
	if !policyDiffers && len(stale) == 0 {
		return false, nil
	}

	// A 400 here usually means the preview already holds these values: a
	// previous run wrote it and stopped before activating. The read-back
	// below decides, and quotes this answer if it fails.
	var putErr error
	if policyDiffers {
		putErr = zc.UpdateLabelPolicy(ctx, b.policy)
		if putErr != nil && !errors.Is(putErr, zitadel.ErrInvalidInput) {
			return false, fmt.Errorf("write the label policy: %w", putErr)
		}
	}
	for _, slot := range stale {
		if err := zc.RemoveLabelAsset(ctx, slot); err != nil {
			return false, fmt.Errorf("clear %s: %w", slot.Field, err)
		}
		if err := zc.UploadLabelAsset(ctx, slot, b.mark(slot)); err != nil {
			return false, fmt.Errorf("upload %s: %w", slot.Field, err)
		}
	}
	if err := zc.ActivateLabelPolicy(ctx); err != nil {
		return false, fmt.Errorf("activate the label policy: %w", err)
	}
	if err := verifyBrandActive(ctx, zc, b, putErr); err != nil {
		return false, err
	}
	return true, nil
}

// staleMarks returns the slots whose served bytes differ from the brand.
func staleMarks(ctx context.Context, zc zitadel.LabelPolicyClient, policy map[string]any, b brand) ([]zitadel.LabelSlot, error) {
	stale := make([]zitadel.LabelSlot, 0, len(zitadel.LabelSlots))
	for _, slot := range zitadel.LabelSlots {
		same, err := markServed(ctx, zc, policy, slot, b.mark(slot))
		if err != nil {
			return nil, err
		}
		if !same {
			stale = append(stale, slot)
		}
	}
	return stale, nil
}

// verifyBrandActive reads the active policy back after activation. It is
// the proof that Zitadel serves the brand, not only that it accepted the
// writes. putErr is the policy write's answer, quoted when the fields do
// not match.
func verifyBrandActive(ctx context.Context, zc zitadel.LabelPolicyClient, b brand, putErr error) error {
	after, err := zc.GetLabelPolicy(ctx)
	if err != nil {
		return fmt.Errorf("read the label policy back: %w", err)
	}
	if !policyMatches(after, b.policy) {
		errMismatch := errors.New("the active label policy does not match the declared brand after activation")
		if putErr != nil {
			return fmt.Errorf("%w (policy write: %w)", errMismatch, putErr)
		}
		return errMismatch
	}
	stale, err := staleMarks(ctx, zc, after, b)
	if err != nil {
		return err
	}
	if len(stale) > 0 {
		return fmt.Errorf("the active %s does not serve the declared mark after activation", stale[0].Field)
	}
	return nil
}

// policyMatches reports whether every declared field has the declared value
// in the active policy. Fields the brand does not declare are not compared.
// Strings compare without case, because Zitadel may store a color in either.
func policyMatches(active, want map[string]any) bool {
	for k, w := range want {
		a, ok := active[k]
		if !ok {
			return false
		}
		ws, wok := w.(string)
		as, aok := a.(string)
		switch {
		case wok && aok:
			if !strings.EqualFold(ws, as) {
				return false
			}
		case fmt.Sprint(w) != fmt.Sprint(a):
			return false
		}
	}
	return true
}

// markServed reports whether the slot serves exactly want. An empty slot
// serves nothing.
func markServed(ctx context.Context, zc zitadel.LabelPolicyClient, policy map[string]any, slot zitadel.LabelSlot, want []byte) (bool, error) {
	u, _ := policy[slot.Field].(string)
	if u == "" {
		return false, nil
	}
	have, err := zc.LabelAsset(ctx, u)
	if err != nil {
		if errors.Is(err, zitadel.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("read %s: %w", slot.Field, err)
	}
	return sha256.Sum256(have) == sha256.Sum256(want), nil
}

// mapBrandingConfigMap wakes every PlatformBootstrap whose loginBranding
// names the changed ConfigMap, so a new brand is applied at once instead of
// at the next periodic reconcile.
func (r *PlatformBootstrapReconciler) mapBrandingConfigMap(ctx context.Context, obj client.Object) []reconcile.Request {
	var list gibsonv1alpha1.PlatformBootstrapList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	out := make([]reconcile.Request, 0, 1)
	for i := range list.Items {
		lb := list.Items[i].Spec.Zitadel.LoginBranding
		if lb == nil || lb.ConfigMap != obj.GetName() {
			continue
		}
		ns := lb.Namespace
		if ns == "" {
			ns = defaultChildNamespace
		}
		if ns == obj.GetNamespace() {
			out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: list.Items[i].Name}})
		}
	}
	return out
}
