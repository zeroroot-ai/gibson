/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Command platform-operator is the gibson platform's cross-component
// reconciler. It owns the imperative external-API handshakes that Helm
// hooks were previously misused for: Zitadel OIDC client minting,
// OpenFGA model load, Vault transit init, plan sync, and any future
// platform-wide bootstrap step.
//
// Spec: .spec-workflow/specs/deploy-architecture-refactor (Phase 2).
//
// Sibling of tenant-operator (enterprise/platform/tenant-operator/);
// same kubebuilder v4 layout, same conventions. CRDs land here in
// Phase 2.2 (PlatformBootstrap) and 2.3 (OIDCClient); reconcilers in
// Phase 3.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/zeroroot-ai/gibson/internal/infra/otelinit"
	"github.com/zeroroot-ai/gibson/internal/infra/readiness"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
	"github.com/zeroroot-ai/gibson/operators/platform/internal/controller"
	"github.com/zeroroot-ai/gibson/operators/platform/internal/probes"
	"github.com/zeroroot-ai/gibson/operators/platform/internal/vaulttoken"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gibsonv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// main parses flags, sets up the logger, and delegates to run. Any error
// returned by run is logged and the process exits with code 1. Separating
// run() from main() ensures all defer statements in run() execute before
// os.Exit is called (os.Exit bypasses defers in the calling function).
func main() {
	var (
		metricsAddr          string
		probeAddr            string
		enableLeaderElection bool
		leaderElectionNS     string
		leaderElectionID     string
		metricsSecure        bool
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080",
		"The address the metric endpoint binds to.")
	flag.BoolVar(&metricsSecure, "metrics-secure", false,
		"If set, the metrics endpoint is served securely.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081",
		"The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager.")
	flag.StringVar(&leaderElectionNS, "leader-election-namespace", "",
		"Namespace the leader election Lease lives in. Empty = same ns as the pod.")
	flag.StringVar(&leaderElectionID, "leader-election-id", "platform-operator.gibson.zeroroot.ai",
		"Resource name of the leader election Lease.")
	_ = metricsSecure // reserved for future TLS termination wiring

	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if err := run(runConfig{
		metricsAddr:          metricsAddr,
		probeAddr:            probeAddr,
		enableLeaderElection: enableLeaderElection,
		leaderElectionNS:     leaderElectionNS,
		leaderElectionID:     leaderElectionID,
	}); err != nil {
		setupLog.Error(err, "fatal startup error")
		os.Exit(1)
	}
}

// runConfig holds the parsed flag values passed from main to run.
type runConfig struct {
	metricsAddr          string
	probeAddr            string
	enableLeaderElection bool
	leaderElectionNS     string
	leaderElectionID     string
}

// run contains all startup and blocking logic. Defers here execute normally
// on both success and error returns, so goroutine cancellation and resource
// cleanup are guaranteed regardless of which exit path fires.
func run(cfg runConfig) error {
	// --- Observability (platform-clients) ---
	// Init OTel + structured slog. Each Init call returns an independent
	// *Observability (no global state mutation). SetGlobal wires the global
	// OTel TracerProvider + MeterProvider + propagator for auto-instrumented
	// libraries. Falls back to a no-op exporter when
	// OTEL_EXPORTER_OTLP_ENDPOINT is not set (e.g. local dev, kind).
	obs, err := otelinit.Init(context.Background(), "platform-operator")
	if err != nil {
		// Non-fatal: telemetry is optional infrastructure. Log and proceed.
		setupLog.Error(err, "observability init failed; telemetry disabled")
	}
	if obs != nil {
		// Wire the global OTel providers so auto-instrumented libraries pick them up.
		obs.SetGlobal()
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if serr := obs.Shutdown(shutCtx); serr != nil {
				setupLog.Error(serr, "observability shutdown error")
			}
		}()
	}

	// --- Vault token renewer (platform-clients) ---
	// The vaulttoken.Renewer wraps platform-clients vault.Provider which
	// calls RenewSelf in the background before the admin token's TTL expires.
	// This fixes the P0 finding where the operator used a static token read
	// once at startup — if Vault rotated or the TTL elapsed, every subsequent
	// reconcileVaultTransit failed with 403 until the pod restarted.
	//
	// Token resolution (first non-empty wins):
	//   1. VAULT_TOKEN env var   (explicit override — set by chart Secret mount)
	//   2. VAULT_TOKEN_PATH file  (K8s projected-secret file mount)
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://gibson-vault:8200" // chart default
	}

	// rootCtx drives the vault renewer's background goroutine; cancelled via
	// defer so the goroutine exits before the process terminates.
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	vaultRenewer, err := vaulttoken.New(rootCtx, vaultAddr,
		os.Getenv("VAULT_TOKEN"), os.Getenv("VAULT_TOKEN_PATH"))
	if err != nil {
		// Fail loud: missing Vault token is a chart misconfiguration.
		return fmt.Errorf("vault token renewer init (check VAULT_TOKEN or VAULT_TOKEN_PATH): %w", err)
	}
	defer func() { _ = vaultRenewer.Close() }()

	// --- controller-runtime manager ---
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: cfg.metricsAddr},
		HealthProbeBindAddress:  cfg.probeAddr,
		LeaderElection:          cfg.enableLeaderElection,
		LeaderElectionID:        cfg.leaderElectionID,
		LeaderElectionNamespace: cfg.leaderElectionNS,
	})
	if err != nil {
		return fmt.Errorf("unable to start manager: %w", err)
	}

	if err := (&controller.OIDCClientReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("oidcclient-controller"),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create OIDCClient controller: %w", err)
	}

	// Resolve the Zitadel System API key path. The chart guarantees the
	// mount at DefaultSystemKeyPath; fail loud at startup if absent so
	// the pod CrashLoopBackOffs visibly rather than silently skipping
	// trusted-domain registration on every reconcile.
	systemKeyPath := os.Getenv("ZITADEL_SYSTEM_KEY_PATH")
	if systemKeyPath == "" {
		systemKeyPath = zitadel.DefaultSystemKeyPath
	}
	if _, err := zitadel.LoadRSAKey(systemKeyPath); err != nil {
		// Fail loud — the chart is required to mount this file. Any operator
		// deployment without it is misconfigured and should not start.
		return fmt.Errorf("ZITADEL_SYSTEM_KEY_PATH key not parseable at %q (chart mount missing?): %w",
			systemKeyPath, err)
	}
	setupLog.Info("zitadel system key loaded", "path", systemKeyPath)

	if err := (&controller.PlatformBootstrapReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Recorder:   mgr.GetEventRecorderFor("platformbootstrap-controller"),
		VaultToken: vaultRenewer,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create PlatformBootstrap controller: %w", err)
	}
	// +kubebuilder:scaffold:builder

	// --- Readiness aggregator (platform-clients) ---
	// /readyz runs all probes concurrently; returns 503 when any probe fails.
	// Probes:
	//   vault      — GET /v1/sys/health?standbyok=true (Vault reachability)
	//   zitadel    — GET <cluster-svc>/debug/ready (Zitadel reachability)
	//   system-key — local file + PEM parse (cheap, no network call)
	//
	// The Zitadel probe MUST use the in-cluster service, not the external OIDC
	// issuer (ZITADEL_ISSUER = app.<domain>): that origin doesn't resolve from
	// inside the pod and Envoy doesn't route /debug/ to Zitadel, so probing it
	// pins the pod at 0/1 forever (platform-operator#76, deploy#630). Derive a
	// cluster-service default from the operator namespace when the chart does
	// not set ZITADEL_INTERNAL_ADDRESS.
	zitadelReadyAddr := os.Getenv("ZITADEL_INTERNAL_ADDRESS")
	if zitadelReadyAddr == "" {
		ns := os.Getenv("OPERATOR_NAMESPACE")
		if ns == "" {
			ns = "gibson"
		}
		zitadelReadyAddr = fmt.Sprintf("http://gibson-zitadel.%s.svc:8080", ns)
	}
	agg := readiness.NewAggregator()
	agg.Register(&probes.VaultProbe{Address: vaultAddr})
	agg.Register(&probes.ZitadelProbe{Address: zitadelReadyAddr})
	agg.Register(&systemKeyProbe{path: systemKeyPath})

	// Liveness: always 200 — process is alive, runtime not deadlocked.
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up health check: %w", err)
	}
	// Readiness: probes Vault + Zitadel reachability + system-key file.
	if err := mgr.AddReadyzCheck("readyz", aggregatorChecker(agg)); err != nil {
		return fmt.Errorf("unable to set up ready check: %w", err)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("problem running manager: %w", err)
	}
	return nil
}

// aggregatorChecker adapts a readiness.Aggregator to the healthz.Checker
// (func(*http.Request) error) interface expected by ctrl.Manager.AddReadyzCheck.
// It executes a probe run via the aggregator's internal logic by issuing a
// synthetic request to the ReadyHandler and inspecting the HTTP status code.
func aggregatorChecker(agg *readiness.Aggregator) healthz.Checker {
	handler := agg.ReadyHandler()
	return func(req *http.Request) error {
		// Create a synthetic request with the real request's context so
		// probe timeouts inherit the caller's deadline.
		ctx := req.Context()
		synReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "/readyz", http.NoBody)
		if err != nil {
			return fmt.Errorf("readyz: build synthetic request: %w", err)
		}
		rw := &statusRecorder{}
		handler.ServeHTTP(rw, synReq)
		if rw.code != 0 && rw.code != http.StatusOK {
			return fmt.Errorf("readyz: one or more probes failed (status %d)", rw.code)
		}
		return nil
	}
}

// statusRecorder is a minimal http.ResponseWriter that captures the status
// code written by ReadyHandler.
type statusRecorder struct {
	code int
}

func (r *statusRecorder) Header() http.Header         { return http.Header{} }
func (r *statusRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (r *statusRecorder) WriteHeader(code int)        { r.code = code }

// systemKeyProbe is a readiness.Probe that verifies the Zitadel System API
// RSA private key file is present and parseable. The check is intentionally
// cheap: a local file read + PEM parse; no network call.
type systemKeyProbe struct{ path string }

func (p *systemKeyProbe) Name() string { return "system-key" }

func (p *systemKeyProbe) Check(_ context.Context) error {
	if _, err := zitadel.LoadRSAKey(p.path); err != nil {
		return fmt.Errorf("zitadel system key not parseable at %q: %w", p.path, err)
	}
	return nil
}
