// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
)

// TestStatusUpdate_RetriesAConflictWithTheComputedStatus: the first status
// write loses to a concurrent writer; the retry lands this reconcile's
// status, user id included, on a fresh read (hosted#309).
func TestStatusUpdate_RetriesAConflictWithTheComputedStatus(t *testing.T) {
	s := mustScheme(t)
	pb := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{Name: "platform"}}
	base := fake.NewClientBuilder().WithScheme(s).WithObjects(pb).WithStatusSubresource(pb).Build()
	conflicts := 0
	cli := interceptor.NewClient(base, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, _ string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if conflicts == 0 {
				conflicts++
				return apierrors.NewConflict(schema.GroupResource{Group: "gibson.zeroroot.ai", Resource: "platformbootstraps"}, obj.GetName(), nil)
			}
			return c.Status().Update(ctx, obj, opts...)
		},
	})
	r := &PlatformBootstrapReconciler{Audit: (&audittest.Sink{}).Emitter(t), Client: cli, Scheme: s}

	got := &gibsonv1alpha1.PlatformBootstrap{}
	if err := cli.Get(context.Background(), client.ObjectKey{Name: "platform"}, got); err != nil {
		t.Fatal(err)
	}
	got.Status.PlatformOwnerUserID = "UID-1"
	setBootstrapCond(got, gibsonv1alpha1.ConditionPlatformOwnerReady, metav1.ConditionTrue, "Ready", "owner provisioned")

	if err := r.statusUpdate(context.Background(), got); err != nil {
		t.Fatalf("statusUpdate: %v", err)
	}
	if conflicts != 1 {
		t.Fatalf("expected one conflict to be retried, got %d", conflicts)
	}
	after := &gibsonv1alpha1.PlatformBootstrap{}
	if err := cli.Get(context.Background(), client.ObjectKey{Name: "platform"}, after); err != nil {
		t.Fatal(err)
	}
	if after.Status.PlatformOwnerUserID != "UID-1" {
		t.Fatalf("the user id must survive the conflict, got %q", after.Status.PlatformOwnerUserID)
	}
	if len(after.Status.Conditions) != 1 || after.Status.Conditions[0].Reason != "Ready" {
		t.Fatalf("the computed conditions must land, got %+v", after.Status.Conditions)
	}
}
