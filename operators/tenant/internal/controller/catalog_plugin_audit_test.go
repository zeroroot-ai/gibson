// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

// A new instance writes its record before the first object exists. A second
// pass that finds the same state writes none.
func TestCatalogPlugins_AuditRecordComesFirstAndOnlyOnAChange(t *testing.T) {
	sink := &audittest.Sink{}
	d := &fakeCatalogPluginDaemon{desired: []provision.DesiredCatalogPlugin{cpWish(cpTenant, cpPlugin)}}
	r, c := newCatalogPluginLoop(t, d, cpTenantObject(cpTenant))
	r.Audit = sink.Emitter(t)
	sink.OnEmit = func(ev audit.Event) {
		if ev.Action == audit.ActionCatalogPluginApply && cpExists(t, c, client.ObjectKey{Name: cpNamespace}, &corev1.Namespace{}) {
			t.Error("the record came after the namespace")
		}
	}
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if got := len(sink.Events()); got != 1 {
		t.Fatalf("records after the first pass = %d, want 1", got)
	}
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if got := len(sink.Events()); got != 1 {
		t.Fatalf("records after a pass with no change = %d, want 1", got)
	}

	// A wish with a wider egress list is a change.
	wide := cpWish(cpTenant, cpPlugin)
	wide.EgressAllow = append(wide.EgressAllow, "example.com:443")
	d.desired = []provision.DesiredCatalogPlugin{wide}
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if got := len(sink.Events()); got != 2 {
		t.Fatalf("records after a change of the egress list = %d, want 2", got)
	}
}

// With no record the loop makes no object.
func TestCatalogPlugins_NoRecordMeansNoObject(t *testing.T) {
	sink := &audittest.Sink{Err: errors.New("audit down")}
	d := &fakeCatalogPluginDaemon{desired: []provision.DesiredCatalogPlugin{cpWish(cpTenant, cpPlugin)}}
	r, c := newCatalogPluginLoop(t, d, cpTenantObject(cpTenant))
	r.Audit = sink.Emitter(t)
	_ = r.converge(context.Background())
	if cpExists(t, c, client.ObjectKey{Name: cpNamespace}, &corev1.Namespace{}) {
		t.Fatal("a namespace exists with no audit record")
	}
	if cpExists(t, c, client.ObjectKey{Namespace: cpNamespace, Name: "gibson-plugin-" + cpPlugin}, &appsv1.Deployment{}) {
		t.Fatal("a Deployment exists with no audit record")
	}
}

// A delete writes its record before the object goes, and no record means no
// delete.
func TestCatalogPlugins_DeleteWritesItsRecordFirst(t *testing.T) {
	r, c, d := convergedInstance(t)
	sink := &audittest.Sink{Err: errors.New("audit down")}
	r.Audit = sink.Emitter(t)
	d.desired = nil
	_ = r.converge(context.Background())
	if !cpExists(t, c, client.ObjectKey{Name: cpNamespace}, &corev1.Namespace{}) {
		t.Fatal("the namespace went with no audit record")
	}

	sink = &audittest.Sink{}
	r.Audit = sink.Emitter(t)
	sink.OnEmit = func(ev audit.Event) {
		if ev.Action == audit.ActionCatalogPluginDelete && !cpExists(t, c, client.ObjectKey{Name: cpNamespace}, &corev1.Namespace{}) {
			t.Error("the delete record came after the namespace went")
		}
	}
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	deleted := 0
	for _, ev := range sink.Events() {
		if ev.Action == audit.ActionCatalogPluginDelete {
			deleted++
		}
	}
	if deleted == 0 {
		t.Fatal("no delete record")
	}
}

// The loop refuses to start with no audit emitter.
func TestCatalogPluginRunnable_SetupRefusesNoAudit(t *testing.T) {
	r := &CatalogPluginRunnable{Daemon: &fakeCatalogPluginDaemon{}, Config: cpConfig()}
	if err := r.SetupWithManager(nil); err == nil || !strings.Contains(err.Error(), "Audit") {
		t.Fatalf("err = %v, want a refusal that names Audit", err)
	}
}
