// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
)

// machineUserChild builds a Ready MACHINE_USER OIDCClient child in namespace
// gibson with the given name + numeric clientID.
func machineUserChild(name, clientID string) *gibsonv1alpha1.OIDCClient {
	return &gibsonv1alpha1.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "gibson"},
		Spec:       gibsonv1alpha1.OIDCClientSpec{ApplicationType: gibsonv1alpha1.OIDCAppTypeMachineUser},
		Status: gibsonv1alpha1.OIDCClientStatus{
			ClientID: clientID,
			Conditions: []metav1.Condition{{
				Type:   gibsonv1alpha1.ConditionReady,
				Status: metav1.ConditionTrue,
				Reason: "AllStepsComplete",
			}},
		},
	}
}

func iamAdminSecret(userID string) *corev1.Secret {
	body := []byte(`{"userId":"` + userID + `","type":"serviceaccount"}`)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gibson", Name: iamAdminSecretName},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{iamAdminMachineKeyFile: body},
	}
}

func saIdentityMapBootstrap() *gibsonv1alpha1.PlatformBootstrap {
	return &gibsonv1alpha1.PlatformBootstrap{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: gibsonv1alpha1.PlatformBootstrapSpec{
			OIDCClients: []gibsonv1alpha1.OIDCClientReference{
				{Name: "gibson-tenant-operator", ApplicationType: gibsonv1alpha1.OIDCAppTypeMachineUser},
				// A WEB client must NOT appear in the identity map.
				{Name: "gibson-dashboard", ApplicationType: gibsonv1alpha1.OIDCAppTypeWeb},
			},
		},
	}
}

func TestReconcileSAIdentityMap_WaitsForIAMAdminSecret(t *testing.T) {
	s := mustScheme(t)
	cli := fake.NewClientBuilder().WithScheme(s).Build()
	r := &PlatformBootstrapReconciler{Client: cli, Scheme: s, Recorder: record.NewFakeRecorder(8)}
	pb := saIdentityMapBootstrap()

	res, err := r.reconcileSAIdentityMap(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatalf("expected requeue while waiting for secret/iam-admin, got %+v", res)
	}
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionSAIdentityMapReady)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "WaitingForIAMAdminSecret" {
		t.Fatalf("expected WaitingForIAMAdminSecret/False, got %+v", c)
	}
	// ConfigMap must not be created prematurely.
	var cm corev1.ConfigMap
	if err := cli.Get(context.Background(), client.ObjectKey{Namespace: "gibson", Name: saIdentityMapName}, &cm); err == nil {
		t.Fatalf("ConfigMap should not exist yet")
	}
}

func TestReconcileSAIdentityMap_WaitsForMachineUserChild(t *testing.T) {
	s := mustScheme(t)
	// iam-admin secret present, but the MACHINE_USER child is missing.
	cli := fake.NewClientBuilder().WithScheme(s).
		WithObjects(iamAdminSecret("12345")).Build()
	r := &PlatformBootstrapReconciler{Client: cli, Scheme: s, Recorder: record.NewFakeRecorder(8)}
	pb := saIdentityMapBootstrap()

	res, err := r.reconcileSAIdentityMap(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatalf("expected requeue while waiting for machine-user child, got %+v", res)
	}
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionSAIdentityMapReady)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "WaitingForMachineUsers" {
		t.Fatalf("expected WaitingForMachineUsers/False, got %+v", c)
	}
}

func TestReconcileSAIdentityMap_PopulatesConfigMap(t *testing.T) {
	s := mustScheme(t)
	cli := fake.NewClientBuilder().WithScheme(s).
		WithObjects(
			iamAdminSecret("100200300"),
			machineUserChild("gibson-tenant-operator", "400500600"),
		).Build()
	r := &PlatformBootstrapReconciler{Client: cli, Scheme: s, Recorder: record.NewFakeRecorder(8)}
	pb := saIdentityMapBootstrap()

	res, err := r.reconcileSAIdentityMap(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("expected zero result on success, got %+v", res)
	}

	var cm corev1.ConfigMap
	if err := cli.Get(context.Background(), client.ObjectKey{Namespace: "gibson", Name: saIdentityMapName}, &cm); err != nil {
		t.Fatalf("ConfigMap not created: %v", err)
	}
	if got := cm.Data[saIAMAdminEntry]; got != "100200300" {
		t.Fatalf("gibson-iam-admin = %q, want 100200300", got)
	}
	if got := cm.Data["gibson-tenant-operator"]; got != "400500600" {
		t.Fatalf("gibson-tenant-operator = %q, want 400500600", got)
	}
	// The WEB client must not be reflected into the identity map.
	if _, ok := cm.Data["gibson-dashboard"]; ok {
		t.Fatalf("WEB client gibson-dashboard should not appear in the identity map: %v", cm.Data)
	}
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionSAIdentityMapReady)
	if c == nil || c.Status != metav1.ConditionTrue || c.Reason != "Populated" {
		t.Fatalf("expected Populated/True, got %+v", c)
	}
}

func TestReconcileSAIdentityMap_PreservesForeignKeys(t *testing.T) {
	s := mustScheme(t)
	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gibson", Name: saIdentityMapName},
		Data:       map[string]string{"some-other-sa": "999"},
	}
	cli := fake.NewClientBuilder().WithScheme(s).
		WithObjects(
			existing,
			iamAdminSecret("100200300"),
			machineUserChild("gibson-tenant-operator", "400500600"),
		).Build()
	r := &PlatformBootstrapReconciler{Client: cli, Scheme: s, Recorder: record.NewFakeRecorder(8)}
	pb := saIdentityMapBootstrap()

	if _, err := r.reconcileSAIdentityMap(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var cm corev1.ConfigMap
	if err := cli.Get(context.Background(), client.ObjectKey{Namespace: "gibson", Name: saIdentityMapName}, &cm); err != nil {
		t.Fatalf("ConfigMap missing: %v", err)
	}
	if got := cm.Data["some-other-sa"]; got != "999" {
		t.Fatalf("foreign key clobbered: %v", cm.Data)
	}
	if got := cm.Data[saIAMAdminEntry]; got != "100200300" {
		t.Fatalf("gibson-iam-admin not written: %v", cm.Data)
	}
}
