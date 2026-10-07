// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package audit_test

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"
)

// ObjectEvent names the tenant, the target and the correlation id of the
// object, and copies the fields.
func TestObjectEvent_NamesTheOwnerAndTheTarget(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name:        "github",
		Namespace:   "tenant-acme",
		Annotations: map[string]string{audit.AnnotationCorrelationID: "rec-1"},
	}}
	ev := audit.ObjectEvent("connector.delete", cm, map[string]string{"connector": "github"})
	if ev.Action != "connector.delete" || ev.TenantID != "acme" || ev.TargetID != "tenant-acme/github" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.TargetType != "configmap" {
		t.Errorf("target type = %q, want the Go type name in lower case", ev.TargetType)
	}
	if ev.Fields["connector"] != "github" || ev.Fields[audit.FieldCorrelationID] != "rec-1" {
		t.Errorf("fields = %v", ev.Fields)
	}
	if audit.CorrelationIDOf(cm) != "rec-1" {
		t.Errorf("CorrelationIDOf = %q", audit.CorrelationIDOf(cm))
	}

	// The owner reference names the tenant before the namespace does, and a
	// set kind wins over the Go type name.
	owned := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "s", Namespace: "other",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Tenant", Name: "beta"}},
		},
	}
	ev = audit.ObjectEvent("x", owned, nil)
	if ev.TenantID != "beta" || ev.TargetType != "secret" || ev.TargetID != "other/s" {
		t.Fatalf("owned event = %+v", ev)
	}
	if _, has := ev.Fields[audit.FieldCorrelationID]; has {
		t.Error("an object with no stamp must carry no correlation id")
	}

	// A cluster-scoped object is the tenant itself.
	cluster := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	ev = audit.ObjectEvent("x", cluster, nil)
	if ev.TenantID != "acme" || ev.TargetID != "acme" || ev.TargetType != "namespace" {
		t.Fatalf("cluster event = %+v", ev)
	}
}

// Change records first, runs the change, and records the failure of the
// change. When the first record is refused, the change does not run.
func TestSagaEmitter_Change(t *testing.T) {
	ctx := context.Background()
	ev := audit.Event{Action: "x", TenantID: "acme", TargetType: "tenant", TargetID: "acme"}

	sink := &audittest.Sink{}
	ran := false
	if err := sink.Emitter(t).Change(ctx, ev, func() error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("a change that passes: err = %v, ran = %v", err, ran)
	}
	if got := sink.Events(); len(got) != 1 || got[0].Action != "x" {
		t.Fatalf("records = %+v, want one", got)
	}

	sink = &audittest.Sink{}
	boom := errors.New("boom")
	err := sink.Emitter(t).Change(ctx, ev, func() error { return boom })
	if !errors.Is(err, boom) || errors.Is(err, audit.ErrNotRecorded) {
		t.Fatalf("a change that fails: err = %v", err)
	}
	if got := sink.Events(); len(got) != 2 || got[1].Result != audit.ResultFailure || got[1].Reason != "boom" {
		t.Fatalf("records = %+v, want the failure record", got)
	}

	down := errors.New("daemon down")
	sink = &audittest.Sink{Err: down}
	ran = false
	err = sink.Emitter(t).Change(ctx, ev, func() error { ran = true; return nil })
	if !errors.Is(err, audit.ErrNotRecorded) || !errors.Is(err, down) || ran {
		t.Fatalf("a refused record: err = %v, ran = %v", err, ran)
	}
}
