// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

var errKube = errors.New("kube is down")

// failingLoop is a loop whose kube client fails the calls in funcs.
func failingLoop(t *testing.T, d *fakeDesiredDaemon, funcs interceptor.Funcs, objs ...client.Object) *DesiredConnectorsRunnable {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := connectorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&connectorv1alpha1.ConnectorInstance{}).WithInterceptorFuncs(funcs).Build()
	return &DesiredConnectorsRunnable{Client: c, Daemon: d}
}

func TestDesiredConnectors_LoopBasics(t *testing.T) {
	r := &DesiredConnectorsRunnable{}
	if !r.NeedLeaderElection() {
		t.Error("the loop must run on one replica")
	}
	if err := r.SetupWithManager(nil); err == nil {
		t.Error("SetupWithManager accepted a nil daemon client")
	}

	// Start runs one pass and returns when the context ends.
	d := &fakeDesiredDaemon{desired: []*daemonoperatorv1.DesiredConnector{gitlabWish("acme")}}
	loop, c := desiredLoop(t, d)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := loop.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, ok := getCI(t, c, "tenant-acme", "gitlab"); !ok {
		t.Error("Start ran no pass")
	}
}

// A kube failure fails the pass, or, for one connector, is reported to the
// daemon as Failed.
func TestDesiredConnectors_KubeFailures(t *testing.T) {
	wish := []*daemonoperatorv1.DesiredConnector{gitlabWish("acme")}
	cases := map[string]struct {
		funcs interceptor.Funcs
		objs  []client.Object
	}{
		"list":   {funcs: interceptor.Funcs{List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error { return errKube }}},
		"create": {funcs: interceptor.Funcs{Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error { return errKube }}},
		"update": {
			funcs: interceptor.Funcs{Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error { return errKube }},
			objs:  []client.Object{managedCI("tenant-acme", "gitlab", connectorOperatorManagedBy)},
		},
		"delete": {
			funcs: interceptor.Funcs{Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error { return errKube }},
			objs:  []client.Object{managedCI("tenant-acme", "slack", connectorOperatorManagedBy)},
		},
		"adopt label": {
			funcs: interceptor.Funcs{Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error { return errKube }},
			objs:  []client.Object{managedCI("tenant-acme", "gitlab", legacyConnectorServiceManagedBy)},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d := &fakeDesiredDaemon{desired: wish}
			if name == "delete" {
				d.desired = nil
			}
			r := failingLoop(t, d, c.funcs, c.objs...)
			err := r.converge(context.Background())
			failedReport := len(d.reports) > 0 && d.reports[len(d.reports)-1].GetPhase() == "Failed"
			if err == nil && !failedReport {
				t.Fatalf("%s failure: no error and no Failed report (reports %v)", name, d.reports)
			}
		})
	}
}
