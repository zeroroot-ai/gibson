// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command connector-operator reconciles ConnectorInstance resources into
// ToolHive resources (ADR-0014).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/connector/internal/controller"
	"github.com/zeroroot-ai/gibson/operators/connector/internal/daemonclient"
)

// defaultDaemonSVID is the platform daemon's SPIFFE ID the operator pins at
// the mTLS handshake (ADR-0002). GIBSON_DAEMON_SPIFFE_ID overrides it.
const defaultDaemonSVID = "spiffe://zeroroot.ai/platform/daemon"

// wireReconciler registers the ConnectorInstance controller on the manager
// with the grant revoker its finalizer needs (ADR-0015 §5).
func wireReconciler(mgr ctrl.Manager, revoker controller.GrantRevoker) error {
	if err := (&controller.ConnectorInstanceReconciler{
		Client:  mgr.GetClient(),
		Scheme:  mgr.GetScheme(),
		Revoker: revoker,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("connectorinstance controller: %w", err)
	}
	return nil
}

// daemonSettings reads the daemon dial settings from the environment. The
// address is required: an operator that cannot reach the daemon cannot revoke
// a grant (ADR-0015 §5), so it fails at boot rather than silently leaving
// grants alive after every delete. The SVID defaults to the platform daemon.
func daemonSettings(getenv func(string) string) (addr, svid string, err error) {
	addr = getenv("GIBSON_DAEMON_GRPC_ADDRESS")
	if addr == "" {
		return "", "", errors.New("GIBSON_DAEMON_GRPC_ADDRESS is required (the ConnectorInstance finalizer revokes grants through the daemon, ADR-0015)")
	}
	svid = getenv("GIBSON_DAEMON_SPIFFE_ID")
	if svid == "" {
		svid = defaultDaemonSVID
	}
	return addr, svid, nil
}

// buildRevoker reads the dial settings and opens the SPIFFE-mTLS daemon
// client the finalizer revokes grants through (ADR-0002, ADR-0015 §5). Both
// failure modes — missing address, unreachable SPIRE Workload API — fail the
// boot, so a misconfigured operator never runs with grants it cannot revoke.
func buildRevoker(ctx context.Context, getenv func(string) string) (*daemonclient.Client, error) {
	addr, svid, err := daemonSettings(getenv)
	if err != nil {
		return nil, err
	}
	revoker, err := daemonclient.New(ctx, addr, svid)
	if err != nil {
		return nil, fmt.Errorf("daemon gRPC client init failed (addr %s): %w", addr, err)
	}
	setupLog.Info("daemon grant revoker: gRPC (SPIFFE mTLS)", "addr", addr, "daemon_svid", svid)
	return revoker, nil
}

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(connectorv1alpha1.AddToScheme(scheme))
}

func main() {
	var metricsAddr, probeAddr string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "Metrics endpoint address; 0 disables it.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe endpoint address.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for HA.")
	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "connector-operator.gibson.zeroroot.ai",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// The ConnectorInstance finalizer revokes the connector's grant through
	// the daemon on delete (ADR-0015 §5). The dial is SPIFFE mTLS over the
	// SPIRE Workload API socket (ADR-0002).
	revoker, err := buildRevoker(context.Background(), os.Getenv)
	if err != nil {
		setupLog.Error(err, "daemon grant revoker")
		os.Exit(1)
	}
	defer func() { _ = revoker.Close() }()

	if err := wireReconciler(mgr, revoker); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ConnectorInstance")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting connector-operator")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
