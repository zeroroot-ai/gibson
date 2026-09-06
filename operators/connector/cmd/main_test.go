// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"testing"
	"time"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/connector/internal/daemonclient"
)

// TestSchemeRegistersConnectorInstance asserts init() wired the ConnectorInstance
// API into the manager scheme, so the operator can watch its own CR.
func TestSchemeRegistersConnectorInstance(t *testing.T) {
	if !scheme.Recognizes(connectorv1alpha1.SchemeGroupVersion.WithKind("ConnectorInstance")) {
		t.Fatal("scheme must recognize ConnectorInstance after init")
	}
}

// TestDaemonSettings pins the finalizer's daemon dial contract: the address is
// required, the SVID defaults to the platform daemon and an explicit one wins.
func TestDaemonSettings(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	if _, _, err := daemonSettings(env(map[string]string{})); err == nil {
		t.Error("a missing GIBSON_DAEMON_GRPC_ADDRESS must be refused")
	}
	addr, svid, err := daemonSettings(env(map[string]string{"GIBSON_DAEMON_GRPC_ADDRESS": "gibson-workloads:50051"}))
	if err != nil || addr != "gibson-workloads:50051" || svid != defaultDaemonSVID {
		t.Errorf("got (%q, %q, %v), want the address and the default SVID", addr, svid, err)
	}
	_, svid, _ = daemonSettings(env(map[string]string{
		"GIBSON_DAEMON_GRPC_ADDRESS": "x:1", "GIBSON_DAEMON_SPIFFE_ID": "spiffe://example.org/daemon",
	}))
	if svid != "spiffe://example.org/daemon" {
		t.Errorf("explicit SVID must win, got %q", svid)
	}
}

// TestWireReconciler registers the controller on a manager built over a dummy
// rest.Config (constructed lazily, no API-server round trip) with a revoker.
func TestWireReconciler(t *testing.T) {
	mgr, err := manager.New(&rest.Config{Host: "https://127.0.0.1:6443"}, manager.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		t.Fatalf("manager.New: %v", err)
	}
	if err := wireReconciler(mgr, daemonclient.NewWithConn(nil)); err != nil {
		t.Fatalf("wireReconciler: %v", err)
	}
}

// TestBuildRevoker_FailsLoud covers both boot failures: no address, and an
// address with no SPIRE Workload API socket to open the X509Source on.
func TestBuildRevoker_FailsLoud(t *testing.T) {
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///nonexistent/spire/api.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	if _, err := buildRevoker(ctx, env(map[string]string{})); err == nil {
		t.Error("a missing address must fail the boot")
	}
	if _, err := buildRevoker(ctx, env(map[string]string{"GIBSON_DAEMON_GRPC_ADDRESS": "gibson-workloads:50051"})); err == nil {
		t.Error("an unreachable SPIRE Workload API must fail the boot")
	}
}
