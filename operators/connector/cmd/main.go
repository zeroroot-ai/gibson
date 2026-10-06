// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command connector-operator reconciles ConnectorInstance resources into
// ToolHive resources (ADR-0114).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/connector/internal/controller"
	"github.com/zeroroot-ai/gibson/operators/connector/internal/daemonclient"
)

// wireReconciler registers the ConnectorInstance controller on the manager
// with the daemon client it needs: the finalizer revokes the grant on delete
// (ADR-0061) and the controller reads the credential state so the CR
// reports Degraded rather than a silent Active (ADR-0061). One
// client serves both, because both are the same SPIFFE-mTLS dial.
func wireReconciler(mgr ctrl.Manager, daemon *daemonclient.Client, proxyAuth controller.ProxyAuth) error {
	if err := (&controller.ConnectorInstanceReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Revoker:    daemon,
		AuthReader: daemon,
		ProxyAuth:  proxyAuth,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("connectorinstance controller: %w", err)
	}
	return nil
}

// daemonSettings reads the daemon dial settings from the environment. The
// address is required: an operator that cannot reach the daemon can neither
// revoke a grant (ADR-0061) nor tell whether a credential is still alive
// (ADR-0061), so it fails at boot rather than silently leaving
// grants alive after every delete. The daemon SVID is required too: it holds
// the trust domain of the install, and no code holds that as a literal
// (ADR-0164).
func daemonSettings(getenv func(string) string) (addr, svid string, err error) {
	addr = getenv("GIBSON_DAEMON_GRPC_ADDRESS")
	if addr == "" {
		return "", "", errors.New("GIBSON_DAEMON_GRPC_ADDRESS is required (the ConnectorInstance finalizer revokes grants through the daemon, ADR-0061)")
	}
	svid = getenv("GIBSON_DAEMON_SPIFFE_ID")
	if svid == "" {
		return "", "", errors.New("GIBSON_DAEMON_SPIFFE_ID is required: it names the daemon in the trust domain of the install (ADR-0164)")
	}
	return addr, svid, nil
}

// buildDaemonClient reads the dial settings and opens the SPIFFE-mTLS daemon
// client the operator revokes grants through and reads credential state from
// (ADR-0002, ADR-0061). Both failure modes — missing address, unreachable
// SPIRE Workload API — fail the boot, so a misconfigured operator never runs
// with grants it cannot revoke.
// proxyAuthSettings reads the caller authentication of each connector proxy
// (ADR-0114, D22). The daemon is the only caller: the proxy validates its
// JWT-SVID against the SPIRE OIDC issuer and permits its SPIFFE ID only.
// Each value is required, so no connector runs without it.
func proxyAuthSettings(getenv func(string) string) (controller.ProxyAuth, error) {
	auth := controller.ProxyAuth{
		Issuer:         getenv("CONNECTOR_PROXY_OIDC_ISSUER"),
		JWKSURL:        getenv("CONNECTOR_PROXY_JWKS_URL"),
		DaemonSPIFFEID: getenv("GIBSON_DAEMON_SPIFFE_ID"),
	}
	switch {
	case auth.Issuer == "":
		return auth, errors.New("CONNECTOR_PROXY_OIDC_ISSUER is required: the connector proxy validates the JWT-SVID of the daemon against this issuer")
	case auth.JWKSURL == "":
		return auth, errors.New("CONNECTOR_PROXY_JWKS_URL is required: the connector proxy reads the keys of the issuer from it")
	case auth.DaemonSPIFFEID == "":
		return auth, errors.New("GIBSON_DAEMON_SPIFFE_ID is required: the connector proxy permits only this caller")
	}
	return auth, nil
}

func buildDaemonClient(ctx context.Context, getenv func(string) string) (*daemonclient.Client, error) {
	addr, svid, err := daemonSettings(getenv)
	if err != nil {
		return nil, err
	}
	daemon, err := daemonclient.New(ctx, addr, svid)
	if err != nil {
		return nil, fmt.Errorf("daemon gRPC client init failed (addr %s): %w", addr, err)
	}
	setupLog.Info("daemon client: gRPC (SPIFFE mTLS)", "addr", addr, "daemon_svid", svid)
	return daemon, nil
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
		// The operator reads and writes Secrets only in tenant namespaces,
		// through a RoleBinding in each one (gibson#663). A cached read would
		// open a watch on every Secret in the cluster, which the operator may
		// not do, so Secrets are read from the API server.
		Client: client.Options{Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}}}},
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// The ConnectorInstance finalizer revokes the connector's grant through
	// the daemon on delete (ADR-0061), and the controller reads the
	// credential state from it every pass (ADR-0061). The dial is
	// SPIFFE mTLS over the SPIRE Workload API socket (ADR-0002).
	daemon, err := buildDaemonClient(context.Background(), os.Getenv)
	if err != nil {
		setupLog.Error(err, "daemon client")
		os.Exit(1)
	}
	defer func() { _ = daemon.Close() }()

	proxyAuth, err := proxyAuthSettings(os.Getenv)
	if err != nil {
		setupLog.Error(err, "connector proxy authentication")
		os.Exit(1)
	}

	if err := wireReconciler(mgr, daemon, proxyAuth); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ConnectorInstance")
		os.Exit(1)
	}

	// The desired connectors loop (gibson#662): the daemon keeps the
	// connectors each tenant enabled, and this loop makes the
	// ConnectorInstances. The daemon makes no Kubernetes call.
	if err := (&controller.DesiredConnectorsRunnable{
		Client: mgr.GetClient(),
		Daemon: daemon,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to add the desired connectors loop")
		os.Exit(1)
	}

	// The retry loop of the grants that the finalizer could not revoke.
	if err := (&controller.UnrevokedGrantsRunnable{
		Client:  mgr.GetClient(),
		Revoker: daemon,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to add the unrevoked grants loop")
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
