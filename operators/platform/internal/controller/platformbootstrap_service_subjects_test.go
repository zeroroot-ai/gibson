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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
)

var errAPIDown = errors.New("api server unavailable")

// failGetNamed wraps c so every Get of an object named name fails with
// errAPIDown. Every other call goes through to c.
func failGetNamed(c client.WithWatch, name string) client.WithWatch {
	return interceptor.NewClient(c, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if key.Name == name {
				return errAPIDown
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	})
}

func newSubjectsTestReconciler(t *testing.T, objs ...client.Object) *PlatformBootstrapReconciler {
	t.Helper()
	return &PlatformBootstrapReconciler{
		Client: fake.NewClientBuilder().WithScheme(mustScheme(t)).WithObjects(objs...).Build(),
		Scheme: mustScheme(t),
	}
}

// TestPlatformServiceSubjects_IAMAdminSecretStates pins each broken shape
// of secret/iam-admin: every one is a wait, never a subject list.
func TestPlatformServiceSubjects_IAMAdminSecretStates(t *testing.T) {
	cases := []struct {
		name        string
		data        map[string][]byte
		wantReason  string
		wantRequeue bool
	}{
		{"missing key", map[string][]byte{}, "WaitingForIAMAdminSecret", true},
		{"malformed JSON", map[string][]byte{iamAdminMachineKeyFile: []byte("{not json")}, "MalformedIAMAdminSecret", false},
		{"empty userId", map[string][]byte{iamAdminMachineKeyFile: []byte(`{"userId":"  "}`)}, "WaitingForIAMAdminSecret", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sec := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "gibson", Name: iamAdminSecretName},
				Data:       tc.data,
			}
			r := newSubjectsTestReconciler(t, sec)

			got, wait, err := r.platformServiceSubjects(context.Background(), saIdentityMapBootstrap())
			if err != nil {
				t.Fatalf("platformServiceSubjects: %v", err)
			}
			if got != nil || wait == nil || wait.reason != tc.wantReason {
				t.Fatalf("got %v, wait %+v, want wait %s", got, wait, tc.wantReason)
			}
			if (wait.requeue != 0) != tc.wantRequeue {
				t.Fatalf("requeue = %v, want requeue=%v", wait.requeue, tc.wantRequeue)
			}
		})
	}
}

// TestPlatformServiceSubjects_APIErrors pins that an API error reading
// either the iam-admin Secret or a declared child is returned as an error.
func TestPlatformServiceSubjects_APIErrors(t *testing.T) {
	for _, name := range []string{iamAdminSecretName, "gibson-tenant-operator"} {
		t.Run(name, func(t *testing.T) {
			r := newSubjectsTestReconciler(t, iamAdminSecret("UID-IAMADMIN"), machineUserChild("gibson-tenant-operator", "UID-TENANTOP"))
			r.Client = failGetNamed(r.Client.(client.WithWatch), name)

			if _, _, err := r.platformServiceSubjects(context.Background(), saIdentityMapBootstrap()); !errors.Is(err, errAPIDown) {
				t.Fatalf("err = %v, want errAPIDown", err)
			}
		})
	}
}

func TestReconcileSAIdentityMap_APIErrorReturned(t *testing.T) {
	r := newSubjectsTestReconciler(t, iamAdminSecret("UID-IAMADMIN"))
	r.Client = failGetNamed(r.Client.(client.WithWatch), iamAdminSecretName)

	if _, err := r.reconcileSAIdentityMap(context.Background(), saIdentityMapBootstrap(), logr.Discard()); !errors.Is(err, errAPIDown) {
		t.Fatalf("err = %v, want errAPIDown", err)
	}
}

// TestReconcileSAIdentityMap_WriteFailed pins the ConfigMap write failure:
// the condition says WriteFailed and the error is returned.
func TestReconcileSAIdentityMap_WriteFailed(t *testing.T) {
	r := newSubjectsTestReconciler(t, iamAdminSecret("UID-IAMADMIN"), machineUserChild("gibson-tenant-operator", "UID-TENANTOP"))
	r.Client = interceptor.NewClient(r.Client.(client.WithWatch), interceptor.Funcs{
		Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
			return errAPIDown
		},
	})
	pb := saIdentityMapBootstrap()

	if _, err := r.reconcileSAIdentityMap(context.Background(), pb, logr.Discard()); !errors.Is(err, errAPIDown) {
		t.Fatalf("err = %v, want errAPIDown", err)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionSAIdentityMapReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "WriteFailed" {
		t.Fatalf("condition = %+v, want False/WriteFailed", cond)
	}
}
