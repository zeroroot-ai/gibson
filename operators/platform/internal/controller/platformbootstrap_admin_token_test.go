// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/platform/internal/clients/vault"
	"github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// adminTokenReconciler wires a fake OpenBao and a fake Zitadel System API.
func adminTokenReconciler(t *testing.T, vc *fakeVaultClient, sys *fakeSystemClient) *PlatformBootstrapReconciler {
	t.Helper()
	s := mustScheme(t)
	tokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: defaultChildNamespace, Name: "vault-admin-token"},
		Data:       map[string][]byte{"token": []byte("root-token")},
	}
	return &PlatformBootstrapReconciler{
		Audit:  (&audittest.Sink{}).Emitter(t),
		Client: fake.NewClientBuilder().WithScheme(s).WithObjects(tokenSecret).Build(),
		Scheme: s,
		VaultFactory: func(string, vault.TokenFunc) (vault.Client, error) {
			return vc, nil
		},
		SystemClientFactory: func(string, string, string, string) (zitadel.SystemClient, error) {
			return sys, nil
		},
		Now: func() time.Time { return time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC) },
	}
}

func adminTokenBootstrap() *gibsonv1alpha1.PlatformBootstrap {
	pb := newTestBootstrap(&gibsonv1alpha1.SystemClientSpec{}, "")
	pb.Spec.VaultTransit.TokenRef = gibsonv1alpha1.SecretKeyRef{Name: "vault-admin-token", Key: "token"}
	return pb
}

func adminTokenCond(t *testing.T, pb *gibsonv1alpha1.PlatformBootstrap) *metav1.Condition {
	t.Helper()
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionAdminTokenReady)
	if c == nil {
		t.Fatal("no AdminTokenReady condition")
	}
	return c
}

// First start: OpenBao holds no token. The step mints one with the System
// API key and writes it, with the user id.
func TestReconcileAdminToken_FirstStartMints(t *testing.T) {
	vc, sys := &fakeVaultClient{}, &fakeSystemClient{}
	r := adminTokenReconciler(t, vc, sys)
	pb := adminTokenBootstrap()
	res, err := r.reconcileAdminToken(context.Background(), pb, logr.Discard())
	if err != nil || !res.IsZero() {
		t.Fatalf("res=%+v err=%v, want a clean pass", res, err)
	}
	if sys.minted != 1 || vc.writes != 1 {
		t.Fatalf("minted %d, wrote %d; want one each", sys.minted, vc.writes)
	}
	stored := vc.kv[adminTokenKVKey]
	if stored[adminTokenProperty] != "pat-1" || stored[adminUserProperty] != "user-iam-admin" {
		t.Errorf("stored = %v", stored)
	}
	if c := adminTokenCond(t, pb); c.Status != metav1.ConditionTrue || c.Reason != "TokenMinted" {
		t.Errorf("condition = %+v", c)
	}
}

// Restore: the restored OpenBao holds a valid token. The step mints nothing
// and writes nothing.
func TestReconcileAdminToken_RestoreMintsNothing(t *testing.T) {
	vc := &fakeVaultClient{kv: map[string]map[string]string{adminTokenKVKey: {adminTokenProperty: "restored"}}}
	sys := &fakeSystemClient{validTokens: map[string]bool{"restored": true}}
	r := adminTokenReconciler(t, vc, sys)
	pb := adminTokenBootstrap()
	if _, err := r.reconcileAdminToken(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatal(err)
	}
	if sys.minted != 0 || vc.writes != 0 {
		t.Fatalf("minted %d, wrote %d; want none", sys.minted, vc.writes)
	}
	if c := adminTokenCond(t, pb); c.Status != metav1.ConditionTrue || c.Reason != "TokenValid" {
		t.Errorf("condition = %+v", c)
	}
}

// Replace: Zitadel refuses the stored token. The step mints a new one and
// writes it over the old one.
func TestReconcileAdminToken_ReplacesAnInvalidToken(t *testing.T) {
	vc := &fakeVaultClient{kv: map[string]map[string]string{adminTokenKVKey: {adminTokenProperty: "revoked"}}}
	sys := &fakeSystemClient{}
	r := adminTokenReconciler(t, vc, sys)
	pb := adminTokenBootstrap()
	if _, err := r.reconcileAdminToken(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatal(err)
	}
	if sys.minted != 1 || vc.kv[adminTokenKVKey][adminTokenProperty] != "pat-1" {
		t.Fatalf("minted %d, stored %v; want a new token", sys.minted, vc.kv[adminTokenKVKey])
	}
}

// Each failure stops the pass, keeps what is stored, and is not Ready.
func TestReconcileAdminToken_Failures(t *testing.T) {
	cases := map[string]struct {
		vc  *fakeVaultClient
		sys *fakeSystemClient
		pb  func() *gibsonv1alpha1.PlatformBootstrap
	}{
		"no system client": {&fakeVaultClient{}, &fakeSystemClient{}, func() *gibsonv1alpha1.PlatformBootstrap {
			pb := adminTokenBootstrap()
			pb.Spec.Zitadel.SystemClient = nil
			return pb
		}},
		"openbao read fails":  {&fakeVaultClient{readErr: errors.New("sealed")}, &fakeSystemClient{}, adminTokenBootstrap},
		"zitadel unreachable": {&fakeVaultClient{kv: map[string]map[string]string{adminTokenKVKey: {adminTokenProperty: "x"}}}, &fakeSystemClient{validErr: errors.New("dial")}, adminTokenBootstrap},
		"mint refused":        {&fakeVaultClient{}, &fakeSystemClient{mintErr: zitadel.WrapPermanent(errors.New("403"))}, adminTokenBootstrap},
		"openbao write fails": {&fakeVaultClient{writeErr: errors.New("permission denied")}, &fakeSystemClient{}, adminTokenBootstrap},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := adminTokenReconciler(t, c.vc, c.sys)
			pb := c.pb()
			res, err := r.reconcileAdminToken(context.Background(), pb, logr.Discard())
			if err != nil {
				t.Fatalf("err = %v, want a requeue", err)
			}
			if res.RequeueAfter == 0 {
				t.Error("no requeue")
			}
			if cond := adminTokenCond(t, pb); cond.Status == metav1.ConditionTrue {
				t.Errorf("condition = %+v, want not True", cond)
			}
		})
	}
}
