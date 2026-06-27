// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
)

func mustScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(gibsonv1alpha1.AddToScheme(s))
	return s
}

func TestReconcileMasterKey_MissingSecretGenerated(t *testing.T) {
	s := mustScheme(t)
	cli := fake.NewClientBuilder().WithScheme(s).Build()
	r := &PlatformBootstrapReconciler{Client: cli, Scheme: s, Recorder: record.NewFakeRecorder(8)}
	pb := &gibsonv1alpha1.PlatformBootstrap{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: gibsonv1alpha1.PlatformBootstrapSpec{
			MasterKey: gibsonv1alpha1.MasterKeySpec{
				SecretName: "gibson-master-key",
				Namespace:  "gibson",
			},
		},
	}

	if _, err := r.reconcileMasterKey(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Secret should exist with the default key, non-empty.
	var sec corev1.Secret
	if err := cli.Get(context.Background(), client.ObjectKey{Namespace: "gibson", Name: "gibson-master-key"}, &sec); err != nil {
		t.Fatalf("secret not created: %v", err)
	}
	v, ok := sec.Data["master-key"]
	if !ok || len(v) == 0 {
		t.Fatalf("master-key data empty: %v", sec.Data)
	}
	// Raw 32 bytes (daemon key-provider rejects anything else).
	if len(v) != 32 {
		t.Fatalf("expected 32-byte raw key, got %d bytes", len(v))
	}
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionMasterKeyReady)
	if c == nil || c.Status != metav1.ConditionTrue || c.Reason != "Generated" {
		t.Fatalf("expected Generated/True, got %+v", c)
	}
}

func TestReconcileMasterKey_ExistingSecretPreserved(t *testing.T) {
	s := mustScheme(t)
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gibson", Name: "gibson-master-key"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"master-key": []byte("DO-NOT-OVERWRITE")},
	}
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(existing).Build()
	r := &PlatformBootstrapReconciler{Client: cli, Scheme: s, Recorder: record.NewFakeRecorder(8)}
	pb := &gibsonv1alpha1.PlatformBootstrap{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: gibsonv1alpha1.PlatformBootstrapSpec{
			MasterKey: gibsonv1alpha1.MasterKeySpec{
				SecretName: "gibson-master-key",
				Namespace:  "gibson",
			},
		},
	}

	if _, err := r.reconcileMasterKey(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got corev1.Secret
	if err := cli.Get(context.Background(), client.ObjectKey{Namespace: "gibson", Name: "gibson-master-key"}, &got); err != nil {
		t.Fatalf("secret missing: %v", err)
	}
	if string(got.Data["master-key"]) != "DO-NOT-OVERWRITE" {
		t.Fatalf("master-key overwritten — got %q, want DO-NOT-OVERWRITE", got.Data["master-key"])
	}
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionMasterKeyReady)
	if c == nil || c.Status != metav1.ConditionTrue || c.Reason != "Exists" {
		t.Fatalf("expected Exists/True, got %+v", c)
	}
}

func TestReconcileMasterKey_ExistingSecretMissingKeyMaterialised(t *testing.T) {
	s := mustScheme(t)
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gibson", Name: "gibson-master-key"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"some-other-key": []byte("irrelevant")},
	}
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(existing).Build()
	r := &PlatformBootstrapReconciler{Client: cli, Scheme: s, Recorder: record.NewFakeRecorder(8)}
	pb := &gibsonv1alpha1.PlatformBootstrap{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: gibsonv1alpha1.PlatformBootstrapSpec{
			MasterKey: gibsonv1alpha1.MasterKeySpec{
				SecretName: "gibson-master-key",
				Namespace:  "gibson",
				Key:        "custom-key",
			},
		},
	}

	if _, err := r.reconcileMasterKey(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got corev1.Secret
	if err := cli.Get(context.Background(), client.ObjectKey{Namespace: "gibson", Name: "gibson-master-key"}, &got); err != nil {
		t.Fatalf("secret missing: %v", err)
	}
	if v, ok := got.Data["custom-key"]; !ok || len(v) != 32 {
		t.Fatalf("custom-key not materialised: %v", got.Data)
	}
	// Other key preserved.
	if string(got.Data["some-other-key"]) != "irrelevant" {
		t.Fatalf("other key clobbered: %v", got.Data)
	}
}
