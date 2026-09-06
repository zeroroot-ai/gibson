// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	vault "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/vault"
)

func vaultTransitTestPB() *gibsonv1alpha1.PlatformBootstrap {
	return &gibsonv1alpha1.PlatformBootstrap{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: gibsonv1alpha1.PlatformBootstrapSpec{
			VaultTransit: gibsonv1alpha1.VaultTransitSpec{
				Address: "http://vault.gibson.svc.cluster.local:8200",
				TokenRef: gibsonv1alpha1.SecretKeyRef{
					Name: "vault-admin-token",
					Key:  "token",
				},
			},
		},
	}
}

// TestReconcileVaultTransit_VaultClientInitFailureRequeues covers gibson#1173:
// every failure branch in reconcileVaultTransit must requeue with backoff so
// a condition that resolves out-of-band (address fixed, Vault reachable
// again, token Secret corrected) is re-evaluated without operator
// intervention. The VaultClientInit branch used to return a zero Result —
// no requeue at all — wedging VaultTransitReady=False forever.
func TestReconcileVaultTransit_VaultClientInitFailureRequeues(t *testing.T) {
	s := mustScheme(t)
	tokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: defaultChildNamespace, Name: "vault-admin-token"},
		Data:       map[string][]byte{"token": []byte("root-token")},
	}
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(tokenSecret).Build()

	wantErr := errors.New("boom: invalid apiURL")
	r := &PlatformBootstrapReconciler{
		Client:   cli,
		Scheme:   s,
		Recorder: record.NewFakeRecorder(8),
		VaultFactory: func(_ string, _ vault.TokenFunc) (vault.Client, error) {
			return nil, wantErr
		},
	}
	pb := vaultTransitTestPB()

	result, err := r.reconcileVaultTransit(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsZero() {
		t.Fatal("expected a non-zero Result (RequeueAfter) on VaultClientInit failure, got zero Result — this would wedge VaultTransitReady=False forever")
	}
	if result.RequeueAfter != requeueMedium {
		t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, requeueMedium)
	}
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionVaultTransitReady)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "VaultClientInit" {
		t.Fatalf("expected VaultClientInit/False, got %+v", c)
	}
}

// fakeVaultClient lets tests control EnsureTransitMounted/EnsureTransitKey
// outcomes without a real Vault server.
type fakeVaultClient struct {
	mountErr error
	keyErr   error
}

func (f *fakeVaultClient) EnsureTransitMounted(_ context.Context) error { return f.mountErr }
func (f *fakeVaultClient) EnsureTransitKey(_ context.Context, _ string) error {
	return f.keyErr
}

// TestReconcileVaultTransit_MountFailureRequeuesAndSetsCondition is a
// regression check that the (already-correct) mount-failure path still
// requeues and sets VaultTransitReady=False/VaultMountFailed — the specific
// condition observed wedged in the gibson#1173 staging incident.
func TestReconcileVaultTransit_MountFailureRequeuesAndSetsCondition(t *testing.T) {
	s := mustScheme(t)
	tokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: defaultChildNamespace, Name: "vault-admin-token"},
		Data:       map[string][]byte{"token": []byte("root-token")},
	}
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(tokenSecret).Build()

	r := &PlatformBootstrapReconciler{
		Client:   cli,
		Scheme:   s,
		Recorder: record.NewFakeRecorder(8),
		VaultFactory: func(_ string, tokenFn vault.TokenFunc) (vault.Client, error) {
			// Exercise tokenFn the same way the real HTTP client would, so a
			// broken tokenFn (e.g. a Renewer surfacing renErr) is covered too.
			if _, err := tokenFn(); err != nil {
				return nil, err
			}
			return &fakeVaultClient{mountErr: errors.New("permission denied")}, nil
		},
	}
	pb := vaultTransitTestPB()

	result, err := r.reconcileVaultTransit(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != requeueMedium {
		t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, requeueMedium)
	}
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionVaultTransitReady)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "VaultMountFailed" {
		t.Fatalf("expected VaultMountFailed/False, got %+v", c)
	}
}

// TestReconcileVaultTransit_UsesVaultTokenSourceAndRequeuesOnTokenError
// verifies the production wiring: when r.VaultToken is set (the
// vaulttoken.Renewer path), a Token() error propagates through tokenFn and
// the step requeues rather than silently using a bad/zero-value token.
type staticFailingTokenSource struct{ err error }

func (s staticFailingTokenSource) Token() (string, error) { return "", s.err }

func TestReconcileVaultTransit_UsesVaultTokenSourceAndRequeuesOnTokenError(t *testing.T) {
	s := mustScheme(t)
	cli := fake.NewClientBuilder().WithScheme(s).Build()

	tokenErr := errors.New("vault admin token renewal failed: verify token: permission denied")
	r := &PlatformBootstrapReconciler{
		Client:     cli,
		Scheme:     s,
		Recorder:   record.NewFakeRecorder(8),
		VaultToken: staticFailingTokenSource{err: tokenErr},
		VaultFactory: func(_ string, tokenFn vault.TokenFunc) (vault.Client, error) {
			return &fakeVaultClient{mountErr: mustCallTokenFn(tokenFn)}, nil
		},
	}
	pb := vaultTransitTestPB()

	result, err := r.reconcileVaultTransit(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != requeueMedium {
		t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, requeueMedium)
	}
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionVaultTransitReady)
	if c == nil || c.Status != metav1.ConditionFalse {
		t.Fatalf("expected VaultTransitReady=False, got %+v", c)
	}
}

func mustCallTokenFn(tokenFn vault.TokenFunc) error {
	_, err := tokenFn()
	return err
}
