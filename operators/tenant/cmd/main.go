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

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/go-logr/logr"
	"golang.org/x/oauth2/clientcredentials"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/infra/otelinit"
	"github.com/zeroroot-ai/gibson/internal/infra/pools"
	"github.com/zeroroot-ai/gibson/internal/infra/readiness"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/redisstate"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/signupprogress"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/stripe"
	vaultadmin "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/vault"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/zitadel"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/controller"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane"
	dataplaneclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane/client"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/mail"
	gibsonmetrics "github.com/zeroroot-ai/gibson/operators/tenant/internal/metrics"
	platformmigrations "github.com/zeroroot-ai/gibson/operators/tenant/internal/migrations"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga/flows"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/startup"
	gibsonwebhook "github.com/zeroroot-ai/gibson/operators/tenant/internal/webhook"
	"github.com/zeroroot-ai/gibson/operators/tenant/plans"
	// +kubebuilder:scaffold:imports
)

// envFalse is the canonical "disabled" value for boolean env vars in
// this binary. Extracted as a constant to satisfy goconst when the same
// string literal appears in multiple `os.Getenv(...) != envFalse`
// gates (e.g. ORPHAN_REAPER_ENABLED).
const envFalse = "false"

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(gibsonv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme

	gibsonmetrics.Register()
}

// nolint:gocyclo
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	var leaderElectionNamespace string
	var leaderElectionID string
	var leaseDuration, renewDeadline, retryPeriod time.Duration
	flag.BoolVar(&enableLeaderElection, "leader-elect", true,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&leaderElectionNamespace, "leader-election-namespace", "gibson-platform",
		"Namespace to hold the leader election lease.")
	flag.StringVar(&leaderElectionID, "leader-election-id", "gibson-tenant-operator",
		"Name of the leader election lease resource.")
	flag.DurationVar(&leaseDuration, "lease-duration", 15*time.Second,
		"The duration that non-leader candidates will wait after observing a renewal "+
			"before attempting to acquire leadership.")
	flag.DurationVar(&renewDeadline, "renew-deadline", 10*time.Second,
		"The interval between attempts by the acting leader to renew the leadership slot.")
	flag.DurationVar(&retryPeriod, "retry-period", 2*time.Second,
		"The duration the leader election clients should wait between tries of actions.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	var plansFile string
	flag.StringVar(&plansFile, "plans-file", "/etc/gibson/plans/plans.yaml",
		"Path to the canonical plan registry YAML. Mounted from the Helm ConfigMap gibson-tenant-operator-plans by default.")
	// The --dev-mode flag was deleted as part of the one-code-path epic
	// (deploy#205): the operator binary boots identically in every
	// environment. ValidateAtStartup always fails fast on missing client
	// capabilities — no escape hatch. Per-environment differences live in
	// helm values, which fail-loud at chart-render time.
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Initialise OpenTelemetry (traces + metrics) via platform-clients/otelinit.
	// Each Init call returns an independent *Observability (no global state mutation).
	// SetGlobal wires the global OTel TracerProvider + MeterProvider + propagator so
	// auto-instrumented libraries pick them up. The OTLP endpoint is read from
	// OTEL_EXPORTER_OTLP_ENDPOINT; absent → no-op providers.
	// controller-runtime uses the zap logger set above; non-controller code uses
	// the OTel-wired slog default.
	otelProvider, otelErr := otelinit.Init(context.Background(), "tenant-operator")
	if otelErr != nil {
		// Non-fatal: observability is best-effort; missing OTLP must not block startup.
		setupLog.Error(otelErr, "otelinit.Init failed — telemetry disabled")
	} else {
		slog.SetDefault(otelProvider.Logger)
		// Wire the global OTel providers so auto-instrumented libraries pick them up.
		otelProvider.SetGlobal()
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := otelProvider.Shutdown(shutCtx); err != nil {
				setupLog.Error(err, "observability shutdown error")
			}
		}()
	}

	// one-code-path/198: the platform Postgres is structurally required.
	//
	// Historically a missing DATAPLANE_PG_ADMIN_DSN was treated as a
	// "degraded mode": platform-db migrations were skipped, the postgres
	// provisioner was wired as nil, and saga steps that touch the platform
	// DB (WriteTenantBrokerConfig, ProvisionDataPlane.Postgres, etc.) all
	// quietly no-op'd. --dev-mode further downgraded the startup gate so
	// even the existing capability validator's "missing" verdict only
	// produced a warning instead of crash-looping.
	//
	// That "configured ANY differently from production" path is exactly
	// what the one-code-path epic deletes (deploy#186). Without the
	// platform Postgres the dashboard cannot resolve a tenant's broker
	// config, the operator cannot write tenant rows, and signup races
	// silently. There is no useful "no-Postgres" mode of this operator.
	//
	// Fail FAST and LOUD here so the missing-dependency surfaces at
	// `kubectl get pod` time rather than 6 weeks later when a user clicks
	// a panel. Note: --dev-mode does NOT bypass this gate — only the
	// downstream saga capability validator's hard-fail behaviour. Slice
	// #205 deletes --dev-mode entirely; this slice just ensures the
	// postgres-missing path can never reach steady state regardless of
	// --dev-mode's value.
	if err := requirePlatformPostgres(os.Getenv); err != nil {
		setupLog.Error(err, "platform Postgres precondition failed — refusing to start")
		os.Exit(1)
	}

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("Disabling HTTP/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts
	webhookServerOptions := webhook.Options{
		TLSOpts: webhookTLSOpts,
	}

	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}

	webhookServer := webhook.NewServer(webhookServerOptions)

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.3/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.3/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	//
	// TODO(user): If you enable certManager, uncomment the following lines:
	// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml to generate and use certificates
	// managed by cert-manager for the metrics server.
	// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml for TLS certification.
	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsServerOptions,
		WebhookServer:           webhookServer,
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          enableLeaderElection,
		LeaderElectionID:        leaderElectionID,
		LeaderElectionNamespace: leaderElectionNamespace,
		LeaseDuration:           &leaseDuration,
		RenewDeadline:           &renewDeadline,
		RetryPeriod:             &retryPeriod,
		// Disable the informer cache for ConfigMap + Secret reads. The
		// operator's ClusterRole intentionally omits cluster-scope
		// list/watch on these (per spec secrets-blast-radius-reduction
		// Phase 1.1) — each Get is scoped to a specific namespace where a
		// Role grants the permission. The default controller-runtime
		// client routes Gets through the cache, which tries to LIST
		// cluster-wide to backfill the informer, fails RBAC, and then
		// every subsequent client.Get(ConfigMap) hangs indefinitely until
		// caller context timeout. Most visibly, the tenant validating
		// webhook's reserved-names lookup hits this path and 3-second
		// timeouts every Tenant CR create at admission. Disabling cache
		// for these two kinds routes Gets straight through to apiserver,
		// where the Role-scoped RBAC works.
		Client: client.Options{
			Cache: &client.CacheOptions{
				// Per-namespace Role-scoped resources. Cluster-wide
				// LIST/WATCH fails RBAC, the cache hangs, and the
				// manager's WaitForCacheSync never completes — so
				// controllers register but the Reconcile dispatch
				// never fires. Cache-disabled Gets bypass the
				// informer and hit apiserver direct, where the
				// per-namespace Role grants the read.
				//
				// Source of truth + invariant test:
				// cmd/cache_disable_for.go and cmd/cache_disable_for_test.go
				// (tenant-operator#76 PRD Module 2). Every entry here MUST
				// also appear in the chart's per-tenant ClusterRole at
				// helm/gibson-operators/templates/tenant-operator/
				// tenant-namespace-cluster-role.yaml (deploy repo).
				DisableFor: perTenantNamespaceCacheDisableTypes(),
			},
		},
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}

	// Token source for outbound calls to the dashboard's admin provisioning
	// API. The dashboard validates the incoming Bearer token against Zitadel's
	// JWKS endpoint. We use the OAuth2 client_credentials grant exclusively.
	//
	// Required env vars — operator refuses to start if any are empty:
	//   ZITADEL_TENANT_OPERATOR_CLIENT_ID
	//   ZITADEL_TENANT_OPERATOR_CLIENT_SECRET
	//   ZITADEL_ISSUER
	//
	// The URN scope causes Zitadel to embed aud: ["gibson-platform"] in the
	// issued JWT so Envoy jwt_authn accepts it.
	operatorClientID := os.Getenv("ZITADEL_TENANT_OPERATOR_CLIENT_ID")
	operatorClientSecret := os.Getenv("ZITADEL_TENANT_OPERATOR_CLIENT_SECRET")
	zitadelIssuer := os.Getenv("ZITADEL_ISSUER")
	if operatorClientID == "" || operatorClientSecret == "" || zitadelIssuer == "" {
		setupLog.Error(nil,
			"required env vars missing for operator outbound auth — set "+
				"ZITADEL_TENANT_OPERATOR_CLIENT_ID, ZITADEL_TENANT_OPERATOR_CLIENT_SECRET, "+
				"and ZITADEL_ISSUER")
		os.Exit(1)
	}
	ccCfg := clientcredentials.Config{
		ClientID:     operatorClientID,
		ClientSecret: operatorClientSecret,
		TokenURL:     zitadelIssuer + "/oauth/v2/token",
		Scopes:       []string{"openid", "urn:zitadel:iam:org:project:id:gibson-platform:aud"},
	}
	operatorTokenSource := &provision.OAuth2TokenSource{Source: ccCfg.TokenSource(context.Background())}
	setupLog.Info("Zitadel operator token source initialized (client_credentials)",
		"clientID", operatorClientID, "issuer", zitadelIssuer)

	// Construct subsystem clients from environment config.
	// One-code-path slice deploy#195: FGA is a hard dependency. The operator
	// refuses to start when FGA_URL or FGA_STORE_ID are missing — the previous
	// "degraded mode (FGA-dependent saga steps skip)" branch was a silent
	// authz-bypass surface and has been deleted. The check is in a separate
	// pure function so the contract is unit-testable; see
	// cmd/fga_env_validation_test.go.
	if err := validateFGAEnvKeys(os.Getenv); err != nil {
		setupLog.Error(err, "FGA env validation failed")
		os.Exit(1)
	}
	fgaHTTP, err := fga.NewHTTPClient(fga.Config{
		BaseURL:  os.Getenv("FGA_URL"),
		StoreID:  os.Getenv("FGA_STORE_ID"),
		ModelID:  os.Getenv("FGA_MODEL_ID"),
		APIToken: os.Getenv("FGA_API_TOKEN"),
	})
	if err != nil {
		setupLog.Error(err, "fga client init")
		os.Exit(1)
	}
	var fgaClient fga.Client = fgaHTTP

	// Wrap the FGA client with a Redis pub/sub publisher so the
	// dashboard's R17 membership cache invalidates on every operator
	// FGA mutation. The publisher is best-effort: a publish failure
	// never blocks the FGA write that produced it. When REDIS_ADDR
	// is unset the wrapper is a no-op.
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		pubsubRDB, pubsubErr := pools.NewRedis(pools.RedisOptions{
			Addr:            addr,
			Password:        os.Getenv("REDIS_PASSWORD"),
			PoolSize:        3,
			DialTimeout:     5 * time.Second,
			ReadTimeout:     3 * time.Second,
			WriteTimeout:    3 * time.Second,
			ConnMaxLifetime: 30 * time.Minute,
		})
		if pubsubErr != nil {
			setupLog.Error(pubsubErr, "fga pubsub redis client init failed")
			os.Exit(1)
		}
		pub := fga.NewRedisPublisher(pubsubRDB.Unwrap(), fga.PubsubChannel, 0,
			ctrl.Log.WithName("fga-pubsub"))
		fgaClient = fga.WithEventPublisher(fgaClient, pub)
		setupLog.Info("fga pubsub publisher enabled",
			"channel", fga.PubsubChannel)
	} else {
		setupLog.Info(
			"REDIS_ADDR empty — fga pubsub publisher disabled " +
				"(dashboard membership cache will not invalidate on operator FGA writes)")
	}
	// Stripe is required infrastructure (one-code-path epic / tenant-operator#95).
	// `STRIPE_API_KEY` must be set; missing → exit 1. The provisioning saga no
	// longer touches Stripe (the payment gate was removed in E7/gibson#799); the
	// live client now powers only the BillingReconciler (trial expiry, past-due
	// → entitlements revocation). Both the client and this guard exit OSS when
	// billing moves to the closed Entitlements layer (E7/gibson#798+#800), after
	// which on-prem provisions with no Stripe at all. A nil Stripe client used
	// to mask operator misconfiguration as phantom billing "success".
	stripeKey := os.Getenv("STRIPE_API_KEY")
	if stripeKey == "" {
		setupLog.Error(nil, "STRIPE_API_KEY is required (one-code-path / tenant-operator#95): "+
			"the BillingReconciler cannot run without a Stripe client; "+
			"set STRIPE_API_KEY (removed from OSS once billing moves to the closed layer, gibson#798/#800)")
		os.Exit(1)
	}
	// Card-first-signup mode guard (dashboard#767): staging must run Stripe
	// test mode, prod must run live mode. Fail-closed before constructing the
	// client so a mis-mounted key can never process the wrong cards.
	if err := validateStripeMode(os.Getenv); err != nil {
		setupLog.Error(err, "stripe mode guard")
		os.Exit(1)
	}
	stripeClient, err := stripe.NewAPIClient(stripe.Config{APIKey: stripeKey, APIVersion: "2024-12-18.acacia"})
	if err != nil {
		setupLog.Error(err, "stripe client init")
		os.Exit(1)
	}
	// Redis is required infrastructure (one-code-path epic / deploy#199).
	// `REDIS_ADDR` must be set; missing → exit 1. There is no NoopClient
	// fallback — the saga steps that write the tenant keyspace, publish
	// tenant names, and emit signup-progress events all require a live
	// Redis. A degraded mode here used to surface as the dashboard's
	// ProvisioningPanel hanging on a tenant whose signup events were
	// silently dropped.
	if os.Getenv("REDIS_ADDR") == "" {
		setupLog.Error(
			errors.New("REDIS_ADDR is empty"),
			"Redis is required infrastructure (one-code-path epic / deploy#199); "+
				"set REDIS_ADDR (and REDIS_PASSWORD) on the operator pod",
		)
		os.Exit(1)
	}
	redisClient, err := redisstate.NewRedisClient(redisstate.Config{
		Addr:     os.Getenv("REDIS_ADDR"),
		Password: os.Getenv("REDIS_PASSWORD"),
	})
	if err != nil {
		setupLog.Error(err, "redis client init")
		os.Exit(1)
	}

	// SignupProgress client — writes the operator-owned signup-flow
	// progress events the dashboard's <ProvisioningPanel/> polls. Reuses
	// the same Redis address as the redisstate client by default; can be
	// pointed at a separate Redis via SIGNUP_PROGRESS_REDIS_ADDR when the
	// dashboard's progress store lives in a different Redis instance.
	//
	// Redis is structurally required (one-code-path epic / deploy#199):
	// when neither SIGNUP_PROGRESS_REDIS_ADDR nor REDIS_ADDR is set, the
	// operator exits 1. The previous NoopClient fallback caused the
	// dashboard to poll forever on signup attempts whose events were
	// silently dropped on the operator side.
	signupProgressAddr := os.Getenv("SIGNUP_PROGRESS_REDIS_ADDR")
	if signupProgressAddr == "" {
		signupProgressAddr = os.Getenv("REDIS_ADDR")
	}
	if signupProgressAddr == "" {
		setupLog.Error(
			errors.New("SIGNUP_PROGRESS_REDIS_ADDR and REDIS_ADDR are both empty"),
			"Redis is required infrastructure (one-code-path epic / deploy#199); "+
				"set SIGNUP_PROGRESS_REDIS_ADDR or REDIS_ADDR on the operator pod",
		)
		os.Exit(1)
	}
	signupProgressPassword := os.Getenv("SIGNUP_PROGRESS_REDIS_PASSWORD")
	if signupProgressPassword == "" {
		signupProgressPassword = os.Getenv("REDIS_PASSWORD")
	}
	signupProgressClient, err := signupprogress.NewRedisClient(signupprogress.Config{
		Addr:     signupProgressAddr,
		Password: signupProgressPassword,
	})
	if err != nil {
		setupLog.Error(err, "signup-progress client init")
		os.Exit(1)
	}

	// Zitadel IAM client — authenticates with a Personal Access Token (PAT)
	// mounted from the <release>-zitadel-iam-admin-pat Secret. ZITADEL_PAT_PATH
	// defaults to /etc/zitadel/pat.
	//
	// Per epic one-code-path (deploy#186), slice deploy#196: Zitadel is
	// structurally required. The previous "noop client injected when
	// ZITADEL_URL is empty / PAT unreadable" degradation mode has been
	// deleted — every Tenant CR reconcile calls EnsureZitadelOrg, and a
	// noop client silently no-ops the entire IAM provisioning saga while
	// logging "step success". The operator now exits 1 at startup if Zitadel
	// is not reachable, so the failure surfaces as a CrashLoopBackOff on
	// the tenant-operator pod rather than a "Tenant.Status.Ready=True with
	// missing-org" silent corruption days later.
	var zitadelClient zitadel.Client
	zitadelURL := os.Getenv("ZITADEL_URL")
	zitadelPATPath := os.Getenv("ZITADEL_PAT_PATH")
	// Host-header forge target. Matches the chart's
	// `zitadel.configmapConfig.ExternalDomain`; required when ZITADEL_URL
	// points at the in-cluster Service name (gibson-zitadel:8080), because
	// Zitadel's instance router rejects requests whose Host does not match
	// a registered domain — a 404 that previously looked like a missing
	// endpoint.
	zitadelExternalDomain := os.Getenv("ZITADEL_EXTERNAL_DOMAIN")
	if zitadelPATPath == "" {
		zitadelPATPath = "/etc/zitadel/pat"
	}
	if zitadelURL == "" {
		setupLog.Error(nil, "ZITADEL_URL is required (one-code-path / deploy#196): "+
			"the noop-client degradation surface has been deleted; the operator refuses "+
			"to start until the chart provides a reachable Zitadel URL")
		os.Exit(1)
	}
	patBytes, patErr := os.ReadFile(zitadelPATPath)
	if patErr != nil {
		setupLog.Error(patErr, "ZITADEL_PAT_PATH unreadable (one-code-path / deploy#196): "+
			"the noop-client degradation surface has been deleted; the operator refuses "+
			"to start until the chart mounts a readable Zitadel admin PAT",
			"path", zitadelPATPath)
		os.Exit(1)
	}
	pat := strings.TrimSpace(string(patBytes))
	if pat == "" {
		setupLog.Error(nil, "ZITADEL_PAT_PATH file is empty (one-code-path / deploy#196): "+
			"the chart's Zitadel admin PAT Secret is mounted but contains no token bytes",
			"path", zitadelPATPath)
		os.Exit(1)
	}
	zitadelClient = zitadel.New(zitadelURL, pat, zitadelExternalDomain)
	setupLog.Info("Zitadel client initialized",
		"url", zitadelURL,
		"pat-path", zitadelPATPath,
		"external-domain", zitadelExternalDomain)

	// Email sender: SMTP is required infrastructure (one-code-path / tenant-operator#95).
	// SMTP_HOST must be set; missing → exit 1. The previous NullSender default
	// silently discarded welcome and invitation emails, masking misconfiguration
	// as phantom delivery success. Set SMTP_HOST to require SMTP at startup.
	smtpHost := os.Getenv("SMTP_HOST")
	if smtpHost == "" {
		setupLog.Error(nil, "SMTP_HOST is required (one-code-path / tenant-operator#95): "+
			"the operator sends transactional email (welcome, invitations) via SMTP; "+
			"set SMTP_HOST to enable email delivery")
		os.Exit(1)
	}
	port := 587
	if _, perr := fmt.Sscanf(os.Getenv("SMTP_PORT"), "%d", &port); perr != nil {
		port = 587
	}
	mailer, err := mail.NewSMTPSender(mail.Config{
		Host:     smtpHost,
		Port:     port,
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
		From:     os.Getenv("SMTP_FROM"),
		UseTLS:   os.Getenv("SMTP_TLS") == "true",
	})
	if err != nil {
		setupLog.Error(err, "mail sender init")
		os.Exit(1)
	}

	// Build the Vault admin client used by the ProvisionSecretsBackend saga
	// step (spec secrets-broker R10.3) and the Neo4j credential write step
	// (spec per-tenant-data-plane-completion Task 19a). Vault is non-
	// negotiable (one-code-path: tenant-operator#197): buildVaultAdminClient
	// exits 1 when GIBSON_VAULT_ADDR / GIBSON_VAULT_ADMIN_TOKEN are missing
	// or the client cannot be constructed.
	vaultAdminClient := buildVaultAdminClient(setupLog)

	// tenant-operator#134: fail loud at startup if the chart Vault post-
	// install Job (tenant-operator#133) hasn't mounted the JWT auth backend.
	// Without it, EnsureTenantNamespace's auth/jwt/role/gibson-plugin-<id>
	// write 404s and every signup permanently fails at
	// ProvisionSecretsBackend. The chart Job is the source of truth; this
	// guard makes a regression there visible in operator logs at startup
	// instead of at first-signup time.
	if err := vaultAdminClient.VerifyJWTAuthMounted(context.Background()); err != nil {
		if errors.Is(err, clients.ErrUnauthorized) {
			// 403: token lacks sys/auth read permission. The backend may exist;
			// signup will surface the real error at ProvisionSecretsBackend if
			// not. Do not exit — this is a common least-privilege token config.
			setupLog.Info("vault: cannot verify JWT auth mount (403 — permission denied); "+
				"continuing startup; signup will fail at ProvisionSecretsBackend "+
				"if the backend is genuinely absent (tenant-operator#212)",
				"error", err)
		} else {
			setupLog.Error(err, "vault JWT auth backend not mounted; "+
				"signup will 404 on ProvisionSecretsBackend "+
				"(tenant-operator#132 / #134; chart fix tenant-operator#133)")
			os.Exit(1)
		}
	}

	// Build the per-tenant data-plane pipeline provisioner.
	// Each sub-provisioner is optional; when the required env vars are absent
	// the operator boots in degraded mode (NoopProvisioner behaviour) for that
	// store and logs a warning. In production all four stores must be configured.
	dataPlaneProvisioner, transitClient := buildDataPlaneProvisioner(mgr, setupLog, vaultAdminClient)

	deps := flows.ProvisionDeps{
		K8sClient:               mgr.GetClient(),
		FGA:                     fgaClient,
		Redis:                   redisClient,
		Zitadel:                 zitadelClient,
		DataPlane:               dataPlaneProvisioner,
		Vault:                   vaultAdminClient,
		SignupProgress:          signupProgressClient,
		WriteTenantBrokerConfig: buildWriteTenantBrokerConfigDeps(setupLog),
	}

	// Phase 4 of spec tenant-provisioning-unification-phase2: build the
	// unified psaga.Deps bag so saga.ValidateAtStartup can verify each
	// step's RequiredClients() declarations against the live wiring.
	// Field types in psaga.Deps are interface aliases (any-shaped) — we
	// bind concrete clients here.
	psagaDeps := &saga.Deps{
		K8s:     mgr.GetClient(),
		FGA:     fgaClient,
		Stripe:  stripeClient,
		Redis:   redisClient,
		Zitadel: zitadelClient,
		Vault:   vaultAdminClient,
	}
	if pgDSN := os.Getenv("DATAPLANE_PG_ADMIN_DSN"); pgDSN != "" {
		// Postgres admin client is satisfied by DATAPLANE_PG_ADMIN_DSN;
		// the actual DSN-to-client wiring lives in the data-plane
		// pipeline. The startup gate only cares that the capability is
		// declared — the bound value is opaque.
		psagaDeps.Postgres = pgDSN
	}
	// Vault transit client — real interface impl, lifted from
	// buildKEKDeriver. Nil on the KMS path (KMS satisfies KEK derivation
	// but not the vault-transit saga capability).
	// Spec tenant-operator-saga-capabilities Component 5.
	if transitClient != nil {
		psagaDeps.Transit = transitClient
	}
	if redisClient != nil {
		// CapabilityRedisAdmin is the Redis admin client; flow steps
		// type-assert as needed.
		psagaDeps.Redis = redisClient
	}
	// CapabilityQdrantAdmin previously gated the vector step; Redis VSS
	// reuses the Redis client declared above, so no separate capability
	// binding is needed. psagaDeps.Qdrant is intentionally left nil.

	// Load the canonical plan registry + build the entitlements reconciler.
	// The HTTP client for the dashboard's provisioning routes is built
	// against the operator's existing SPIFFE JWT-SVID workload API source
	// and the DASHBOARD_URL env var.
	planRegistry, err := plans.Load(plansFile)
	if err != nil {
		setupLog.Error(err, "failed to load plans registry; refusing to start", "path", plansFile)
		os.Exit(1)
	}
	// Phase 5.1 of spec tenant-provisioning-unification-phase2 + ADR-0002:
	// prefer the direct SPIFFE-mTLS gRPC path against the daemon when
	// GIBSON_DAEMON_GRPC_ADDRESS is set; fall back to the legacy HTTP-to-
	// dashboard fan-out so a staged rollout (chart shipped before the
	// daemon side is rolled out) does not break entitlements reconciliation.
	// The gRPC client uses workload-API-sourced SVIDs via
	// pkg/transport/daemon; the daemon's expected SVID is read from
	// GIBSON_DAEMON_SPIFFE_ID (defaults to spiffe://zeroroot.ai/platform/daemon).
	dashboardBaseURL := os.Getenv("DASHBOARD_URL")
	var entitlementsProvisioner controller.EntitlementsProvisioner
	if grpcAddr := os.Getenv("GIBSON_DAEMON_GRPC_ADDRESS"); grpcAddr != "" {
		daemonSVID := os.Getenv("GIBSON_DAEMON_SPIFFE_ID")
		if daemonSVID == "" {
			daemonSVID = "spiffe://zeroroot.ai/platform/daemon"
		}
		grpcClient, gerr := provision.NewEntitlementsGRPCClient(
			context.Background(), grpcAddr, daemonSVID, operatorTokenSource)
		if gerr != nil {
			setupLog.Error(gerr, "entitlements gRPC client init failed; falling back to HTTP-to-dashboard", "addr", grpcAddr)
			entitlementsProvisioner = provision.NewEntitlementsHTTPClient(dashboardBaseURL, operatorTokenSource)
		} else {
			setupLog.Info("entitlements provisioner: gRPC (SPIFFE mTLS)", "addr", grpcAddr, "daemon_svid", daemonSVID)
			entitlementsProvisioner = grpcClient
			// Bind the same client into the unified deps bag so
			// saga.ValidateAtStartup sees CapabilityDaemonGRPC as
			// satisfied. Spec tenant-operator-saga-capabilities
			// Requirement 3.1.
			psagaDeps.DaemonGRPC = grpcClient
		}
	} else {
		setupLog.Info("entitlements provisioner: HTTP-to-dashboard", "url", dashboardBaseURL)
		entitlementsProvisioner = provision.NewEntitlementsHTTPClient(dashboardBaseURL, operatorTokenSource)
	}
	entitlementsReconciler := &controller.EntitlementsReconciler{
		Plans:       planRegistry,
		Provisioner: entitlementsProvisioner,
		Logger:      slog.Default(),
	}

	provisionSteps := flows.ProvisionSteps(deps)
	provisionSteps = append(provisionSteps, entitlementsReconciler.AsSagaStep())
	teardownSteps := flows.TeardownSteps(deps)

	// Spec tenant-provisioning-unification-phase2 Requirement 5.3:
	// fail-fast startup gate. ValidateAtStartup walks every step's
	// RequiredClients() declaration and checks the unified psaga.Deps
	// bag for non-nil bindings. The operator crash-loops on missing
	// capabilities so the chart upgrade catches the misconfiguration
	// immediately. The previous --dev-mode escape hatch was deleted in
	// the one-code-path epic (deploy#205): one binary, every environment.
	{
		// Build the foundation namespace step so it participates in
		// validation alongside the rest of the graph.
		nsStep := controller.NewNamespaceProvisioner(mgr.GetClient(), os.Getenv("OPERATOR_NAMESPACE"), nil)
		all := make([]saga.Step, 0, 1+len(provisionSteps)+len(teardownSteps))
		all = append(all, nsStep)
		all = append(all, provisionSteps...)
		all = append(all, teardownSteps...)
		summary, vErr := saga.ValidateAtStartupVerbose(all, psagaDeps)
		if vErr != nil {
			setupLog.Error(vErr, "operator startup gate failed")
			os.Exit(1)
		}
		setupLog.Info(summary)
	}

	migrationEmitter := dataplane.NewMigrationMetricEmitter(
		dataplane.NewProductionVersionReader(os.Getenv("DATAPLANE_PG_ADMIN_DSN"), mgr.GetClient()),
	)

	if err := (&controller.TenantReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		PlatformNamespace: os.Getenv("OPERATOR_NAMESPACE"),
		ProvisionSteps:    provisionSteps,
		TeardownSteps:     teardownSteps,
		Deps:              psagaDeps,
		MigrationEmitter:  migrationEmitter,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "Tenant")
		os.Exit(1)
	}

	if err := (&controller.TenantMemberReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		FGA:           fgaClient,
		Mail:          mailer,
		BaseAcceptURL: os.Getenv("DASHBOARD_URL"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "TenantMember")
		os.Exit(1)
	}

	// EnrollmentDeps: agents now authenticate via Zitadel service-account
	// client_credentials (issued by the dashboard's "Register Agent" UI).
	// The operator no longer mints bootstrap tokens or Postgres host records.
	enrollmentDeps := flows.EnrollmentDeps{
		K8sClient:   mgr.GetClient(),
		FGA:         fgaClient,
		PlatformURL: os.Getenv("GIBSON_PLATFORM_URL"),
	}
	if err := (&controller.AgentEnrollmentReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Deps:            enrollmentDeps,
		IssuanceSteps:   flows.EnrollmentIssuanceSteps(enrollmentDeps),
		RevocationSteps: flows.EnrollmentRevocationSteps(enrollmentDeps),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "AgentEnrollment")
		os.Exit(1)
	}

	// Orphan reaper — safety net for Terminating tenant namespaces with
	// orphan child CRs. Disabled via ORPHAN_REAPER_ENABLED=false.
	reaperEnabled := os.Getenv("ORPHAN_REAPER_ENABLED") != envFalse
	reaperGraceSeconds := 300
	if v := os.Getenv("ORPHAN_REAPER_GRACE_SECONDS"); v != "" {
		if _, perr := fmt.Sscanf(v, "%d", &reaperGraceSeconds); perr != nil || reaperGraceSeconds <= 0 {
			reaperGraceSeconds = 300
		}
	}
	if err := (&controller.OrphanReaperReconciler{
		Client:             mgr.GetClient(),
		Recorder:           mgr.GetEventRecorder("orphan-reaper"),
		GracePeriodSeconds: reaperGraceSeconds,
		Enabled:            reaperEnabled,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "OrphanReaper")
		os.Exit(1)
	}

	// BillingReconciler: polls every 5 minutes and enforces the billing state
	// machine (trial expiry, past-due revocation, teardown-after enforcement).
	// The TeardownQueue is consumed by the goroutine below, which deletes the
	// Tenant CR — setting DeletionTimestamp triggers the TenantReconciler's
	// finalizer-driven teardown saga. tenant-operator#181.
	teardownQueue := make(chan string, 32)
	if err := (&controller.BillingReconciler{
		Client:        mgr.GetClient(),
		StripeClient:  stripeClient,
		Entitlements:  entitlementsReconciler,
		TeardownQueue: teardownQueue,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "Billing")
		os.Exit(1)
	}
	go func() {
		for tenantName := range teardownQueue {
			t := &gibsonv1alpha1.Tenant{}
			if err := mgr.GetClient().Get(context.Background(), types.NamespacedName{Name: tenantName}, t); err != nil {
				setupLog.Error(err, "billing: teardown consumer tenant lookup failed", "tenant", tenantName)
				continue
			}
			if err := mgr.GetClient().Delete(context.Background(), t); err != nil {
				setupLog.Error(err, "billing: teardown consumer tenant delete failed", "tenant", tenantName)
			}
		}
	}()

	// Owner-ref mutating webhook — stamps ownerReferences on CREATE for
	// AgentEnrollment/TenantMember when the namespace has
	// the AnnotationOwnerTenantUID annotation. Failure-open: any error
	// returns Allowed (see webhook.OwnerRefMutator.Handle).
	// Enabled only when a webhook cert was provided (webhook-cert-path
	// flag); otherwise the webhook server cannot serve TLS and we skip
	// registration to keep dev-without-certs scenarios working.
	if len(webhookCertPath) > 0 {
		mgr.GetWebhookServer().Register(gibsonwebhook.MutatePath,
			gibsonwebhook.HandlerWebhook(mgr.GetClient()))
		setupLog.Info("owner-ref mutating webhook registered", "path", gibsonwebhook.MutatePath)
		// Reserved-names provider: chart-managed gibson-reserved-names
		// ConfigMap, read with a 30s in-process cache. The dashboard
		// signup form does the same client-side check via the daemon's
		// DaemonOperatorService.GetReservedNames RPC; this webhook is
		// the authoritative gate.
		// Spec: tenant-provisioning-unification-phase2 Requirement 4.5.
		reservedNames := gibsonwebhook.NewConfigMapReservedNames(
			mgr.GetClient(),
			gibsonwebhook.LookupNamespace(),
			30*time.Second,
		)
		mgr.GetWebhookServer().Register(gibsonwebhook.ValidatePath,
			gibsonwebhook.ValidatorWebhookWithReserved(mgr.GetScheme(), reservedNames))
		setupLog.Info("tenant validating webhook registered", "path", gibsonwebhook.ValidatePath)
	} else {
		setupLog.Info(
			"webhook-cert-path empty — owner-ref mutating webhook NOT registered; " +
				"reconciler backfill remains the convergence path")
		setupLog.Info(
			"webhook-cert-path empty — tenant validating webhook NOT registered; " +
				"kubebuilder CEL rules remain the enforcement path")
	}
	// +kubebuilder:scaffold:builder

	// Phase 5.1: register the per-startup backfill runnable. Walks every
	// Tenant once after leader election and ensures per-tenant RBAC
	// exists. Replaces the chart's tenant-rbac-backfill Helm Job (which
	// Phase 8 deletes).
	if err := startup.Register(mgr, dataPlaneProvisioner); err != nil {
		setupLog.Error(err, "Failed to register startup backfills")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}

	// Readyz check: platform-clients/readiness.Aggregator probes every downstream
	// dependency concurrently. Vault is now included (P1 finding: it was absent from
	// the previous buildReadyzDeps implementation). The aggregator is adapted to
	// controller-runtime's healthz.Checker interface via a response-capture helper.
	readyzAgg := buildReadyzAggregator(
		setupLog,
		fgaClient, redisClient,
		stripeClient, vaultAdminClient, zitadelClient,
	)
	if err := mgr.AddReadyzCheck("readyz", func(req *http.Request) error {
		// Capture the aggregator's HTTP response status to determine readiness.
		rr := &statusCapture{}
		readyzAgg.ReadyHandler().ServeHTTP(rr, req)
		if rr.status == http.StatusServiceUnavailable {
			// Use Info, not Error(nil): zapr's Error path calls zap.NamedError
			// with a nil error, which emits zap.Skip() for the error field and
			// has been observed to drop this line under production log config.
			// The aggregator body (JSON naming each failed probe) is the only
			// signal operators have during a readyz outage, so it must always
			// surface. Individual probes also log their own failure (see
			// pingAdapter.Check) so diagnosis never depends solely on this body.
			setupLog.Info("readyz: downstream probe(s) failed", "detail", string(rr.body))
			return fmt.Errorf("readyz: one or more downstream probes failed")
		}
		return nil
	}); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}

// buildDataPlaneProvisioner constructs the real data-plane pipeline provisioner
// from environment variables. Sub-provisioners whose required env vars are
// absent are wired as nil; the pipeline no-ops that step and logs a warning.
// In production all four stores (DATAPLANE_PG_ADMIN_DSN, Neo4j,
// DATAPLANE_REDIS_ADDR — vector uses the same Redis address) must be set.
// DATAPLANE_NEO4J_URI is retired — Neo4j now provisions per-tenant
// StatefulSets via K8s client (per-tenant-data-plane-completion Task 19).
// vaultClient is always non-nil after buildVaultAdminClient returns
// (one-code-path: tenant-operator#197) — the operator exits 1 at startup
// when Vault wiring is missing, so callers downstream of this point may
// assume the client is constructed.
// buildDataPlaneProvisioner also returns the underlying Vault transit client
// (or nil on the KMS path) so cmd/main.go can bind it to psaga.Deps.Transit.
// Spec tenant-operator-saga-capabilities Component 5/6.
func buildDataPlaneProvisioner(
	mgr ctrl.Manager,
	log logr.Logger,
	vaultClient vaultadmin.AdminClient,
) (dataplane.Provisioner, vaultadmin.TransitClient) {
	cfg := dataplane.PipelineConfig{
		K8sClient: mgr.GetClient(),
		Recorder:  mgr.GetEventRecorder("dataplane-provisioner"),
	}

	// --- Postgres ---
	pgDSN := os.Getenv("DATAPLANE_PG_ADMIN_DSN")
	// DATAPLANE_MIGRATIONS_DIR removed per spec
	// gibson-postgres-migrations Component 5: tenant migrations now
	// ship via gibson/pkg/platform/migrations embed.FS.

	// Platform-side migrations run against the operator's dedicated
	// control-plane DB (PLATFORM_PG_DSN → gibson_platform), NOT the
	// postgres admin connection. Running them against DATAPLANE_PG_ADMIN_DSN
	// caused the tenant_neo4j_endpoints table to be owned by the postgres
	// superuser (via the gitops setup job) while DROP ran as tenant_admin,
	// producing a permanent "must be owner" CrashLoopBackOff. Fix: #258.
	platformPGDSN := os.Getenv("PLATFORM_PG_DSN")
	if platformPGDSN == "" {
		setupLog.Error(nil, "PLATFORM_PG_DSN is required for platform-db migrations — operator will not start")
		os.Exit(1)
	}
	{
		migCtx, migCancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := platformmigrations.Run(migCtx, platformPGDSN); err != nil {
			migCancel()
			setupLog.Error(err, "platform-db migrations failed — operator will not start")
			os.Exit(1)
		}
		migCancel()
		setupLog.Info("platform-db migrations applied")
	}

	// KEKDeriver: Vault transit (master KEK never leaves Vault) or AWS KMS.
	// Neither DATAPLANE_MASTER_KEK nor local HKDF is supported — if neither
	// Vault nor KMS is configured the operator exits 1. Spec
	// tenant-provisioning-unification-phase2 Requirement 2.
	// transitClient is the same client value the deriver consumes,
	// surfaced here so it can be bound to psaga.Deps.Transit (Spec
	// tenant-operator-saga-capabilities Component 6); nil on the KMS path.
	kekDeriver, transitClient, kekDeriverSrc, err := buildKEKDeriver()
	if err != nil {
		log.Error(err, "KEKDeriver init failed — operator will not start")
		os.Exit(1)
	}
	log.Info("KEKDeriver configured", "source", kekDeriverSrc)

	pg, err := dataplane.NewPostgresProvisioner(dataplane.PostgresConfig{
		AdminDSN:               pgDSN,
		KEKDeriver:             kekDeriver,
		DefaultConnectionLimit: 50,
		// VaultClient writes per-tenant Postgres credentials to
		// tenant-<id>/infra/postgres so the daemon's secrets broker
		// resolves them via broker.Get instead of re-deriving the
		// password locally. Without this wiring the daemon's
		// dataplane-readiness check at first authenticated RPC
		// returns FailedPrecondition (tenant-operator#189).
		VaultClient: vaultClient,
		// DevMode is always false after the one-code-path epic
		// (deploy#205): the operator boots identically in every
		// environment. Dirty schema_migrations rows now ALWAYS
		// require human intervention so partial user data isn't
		// silently overwritten. Issue #46.
		DevMode: false,
	})
	if err != nil {
		log.Error(err, "postgres provisioner init failed")
		os.Exit(1)
	}
	cfg.Postgres = pg

	// --- Neo4j ---
	// The Neo4j provisioner creates per-tenant K8s StatefulSets rather than
	// calling CREATE DATABASE on a shared cluster (per-tenant-data-plane-completion
	// Task 19). It requires a K8s client (always available from mgr) and
	// optionally a registry DSN + KEK for endpoint registration.
	// DATAPLANE_NEO4J_URI is retired; Neo4j is now structural — no opt-out gate
	// (closes tenant-operator#244; see one-code-path ADR-0027).
	//
	// The K8s client is wrapped by internal/dataplane/client which rejects
	// per-tenant-kind writes targeted at the operator's release namespace
	// (closes the bug class behind tenant-operator#57; see tenant-operator#86).
	n4j, err := dataplane.NewNeo4jProvisioner(dataplane.Neo4jConfig{
		K8sClient: dataplaneclient.New(mgr.GetClient(), gibsonwebhook.LookupNamespace()),
		// VaultClient writes Neo4j credentials to the per-tenant Vault
		// namespace at "infra/neo4j" so the daemon's secrets broker can
		// resolve them at runtime. Vault is non-negotiable
		// (one-code-path: tenant-operator#197) — buildVaultAdminClient
		// already exited 1 if this were nil, so the field is always set.
		// Spec: per-tenant-data-plane-completion Task 19a (D3 amended).
		VaultClient: vaultClient,
	})
	if err != nil {
		log.Error(err, "neo4j provisioner init failed")
		os.Exit(1)
	}
	cfg.Neo4j = n4j

	// --- Redis ---
	redisAddr := os.Getenv("DATAPLANE_REDIS_ADDR")
	if redisAddr != "" {
		rp, err := dataplane.NewRedisProvisioner(dataplane.RedisProvisionerConfig{
			Addr:     redisAddr,
			Password: os.Getenv("DATAPLANE_REDIS_PASSWORD"),
			// VaultClient writes per-tenant Redis credentials to
			// tenant-<id>/infra/redis. Without this the daemon's
			// secrets broker has no way to discover the per-tenant
			// logical DB index allocated by the operator
			// (tenant-operator#189).
			VaultClient: vaultClient,
		})
		if err != nil {
			log.Error(err, "redis provisioner init failed — Redis step will be skipped")
		} else {
			cfg.Redis = rp
		}
	} else {
		log.Info("DATAPLANE_REDIS_ADDR not configured — Redis data-plane step will be skipped")
	}

	// --- Vector (Redis VSS) ---
	// Provisioned against the same Redis server as the Redis data-plane step.
	// The provisioner creates a per-tenant RediSearch HNSW index and writes
	// the index name to Vault so the daemon can resolve it at runtime via the
	// secrets broker (tenant-operator#238).
	if redisAddr != "" {
		vp, err := dataplane.NewRedisVSSProvisioner(dataplane.RedisVSSConfig{
			Addr:        redisAddr,
			Password:    os.Getenv("DATAPLANE_REDIS_PASSWORD"),
			VaultClient: vaultClient,
		})
		if err != nil {
			log.Error(err, "Redis VSS provisioner init failed — Vector step will be skipped")
		} else {
			cfg.Vector = vp
		}
	} else {
		log.Info("DATAPLANE_REDIS_ADDR not configured — Vector data-plane step will be skipped")
	}

	// --- KEK init ---
	// The KEKInitProvisioner is a marker step that validates derivation
	// works for a fresh tenant ID. With the KEKDeriver abstraction,
	// the marker just exercises the deriver — Phase 2.2 of spec
	// tenant-provisioning-unification-phase2.
	if kekDeriver != nil {
		cfg.KEK = &dataplane.KEKInitProvisioner{KEKDeriver: kekDeriver}
	} else {
		log.Info("KEKDeriver not configured — KEK init step will be skipped")
	}

	return dataplane.New(cfg), transitClient
}

// buildKEKDeriver constructs the per-tenant KEKDeriver. Source order:
//
//  1. If GIBSON_KMS_KEY_ARN is set, build an AWS KMS HMAC deriver —
//     production EKS path. The KMS key MUST be of type HMAC_SHA_256;
//     KMS performs the HMAC server-side so the master KEK never enters
//     the operator process. IRSA grants kms:GenerateMac on the key.
//  2. Else if GIBSON_VAULT_ADDR + GIBSON_VAULT_AUTH_TOKEN are set,
//     build a Vault transit deriver — kind dev and legacy production path.
//  3. Else return an error — the operator cannot start without a KEK source.
//
// Returns the deriver, the underlying *TransitClient (nil on KMS path),
// a string identifying the source ("kms-hmac", "vault-transit") for the
// startup log, and any construction error.
//
// Spec helm-eks-readiness-and-pg-split Phase 5 (T5.2) added the KMS
// branch. DATAPLANE_MASTER_KEK / local HKDF removed per tenant-operator#245.
func buildKEKDeriver() (dataplane.KEKDeriver, vaultadmin.TransitClient, string, error) {
	if kmsKeyID := os.Getenv("GIBSON_KMS_KEY_ARN"); kmsKeyID != "" {
		cfg, err := awsconfig.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, nil, "", fmt.Errorf("buildKEKDeriver: load AWS config: %w", err)
		}
		kmsClient := awskms.NewFromConfig(cfg)
		d, err := dataplane.NewKMSHMACDeriver(kmsClient, kmsKeyID)
		if err != nil {
			return nil, nil, "", err
		}
		return d, nil, "kms-hmac", nil
	}

	vaultAddr := os.Getenv("GIBSON_VAULT_ADDR")
	vaultToken := os.Getenv("GIBSON_VAULT_AUTH_TOKEN")
	transitKey := os.Getenv("GIBSON_VAULT_TRANSIT_KEY")
	if transitKey == "" {
		transitKey = "master-kek"
	}
	if vaultAddr != "" && vaultToken != "" {
		tc, err := vaultadmin.NewTransitClient(vaultadmin.TransitConfig{
			Address:   vaultAddr,
			AuthToken: vaultToken,
			KeyName:   transitKey,
			Namespace: os.Getenv("GIBSON_VAULT_ROOT_NAMESPACE"),
		})
		if err != nil {
			return nil, nil, "", fmt.Errorf("buildKEKDeriver: vault transit: %w", err)
		}
		d, err := dataplane.NewVaultTransitDeriver(tc, transitKey)
		if err != nil {
			return nil, nil, "", err
		}
		return d, tc, "vault-transit", nil
	}
	return nil, nil, "", fmt.Errorf("buildKEKDeriver: no KEK source configured — " +
		"set GIBSON_KMS_KEY_ARN (EKS) or GIBSON_VAULT_ADDR + GIBSON_VAULT_AUTH_TOKEN (kind/Vault)")
}

// pingAdapter wraps a func(context.Context) error as a readiness.Probe.
//
// When a probe fails, the adapter logs the failure with its own name before
// returning the error to the aggregator. This guarantees a per-probe diagnostic
// line in the operator's logs (tenant-operator#274), so identifying which
// downstream is down never depends solely on the aggregated readyz body.
type pingAdapter struct {
	name string
	ping func(ctx context.Context) error
	log  logr.Logger
}

func (p pingAdapter) Name() string { return p.name }
func (p pingAdapter) Check(ctx context.Context) error {
	if err := p.ping(ctx); err != nil {
		p.log.Error(err, "readyz: downstream probe failed", "probe", p.name)
		return err
	}
	return nil
}

// buildReadyzAggregator constructs a platform-clients/readiness.Aggregator
// probing every downstream dependency concurrently. Nil ping functions are
// omitted so the aggregator never fails on unconfigured optional clients.
// Vault is now included (P1 finding: it was absent from the previous
// buildReadyzDeps implementation).
func buildReadyzAggregator(
	log logr.Logger,
	fgaC fga.Client,
	redisC redisstate.Client,
	stripeC stripe.Client,
	vaultC vaultadmin.AdminClient,
	_ zitadel.Client, // reserved for when zitadel.Client grows a Ping method
) *readiness.Aggregator {
	agg := readiness.NewAggregator()

	if fgaC != nil {
		agg.Register(pingAdapter{"fga", fgaC.Ping, log})
	}
	if redisC != nil {
		agg.Register(pingAdapter{"redis", redisC.Ping, log})
	}
	if stripeC != nil {
		agg.Register(pingAdapter{"stripe", stripeC.Ping, log})
	}
	if vaultC != nil {
		agg.Register(pingAdapter{"vault", vaultC.Ping, log})
	}

	return agg
}

// buildVaultAdminClient constructs the Vault admin client used by the
// ProvisionSecretsBackend / DeprovisionSecretsBackend saga steps.
//
// Vault is non-negotiable (one-code-path: deploy#197 / tenant-operator
// #197). The previous "return nil when env unset; saga steps no-op"
// behaviour silently broke every signed-up tenant's per-tenant secrets
// namespace, which the daemon's secrets broker requires to resolve any
// tenant credential at runtime. The operator now exits 1 at startup
// when GIBSON_VAULT_ADDR or GIBSON_VAULT_ADMIN_TOKEN is missing, with a
// structured error naming the missing capability. The chart at
// helm/gibson-operators/templates/tenant-operator/deployment.yaml
// requires dataPlane.vault.addr at render time so the env vars are
// always emitted in a well-formed install.
//
// Configuration env vars:
//   - GIBSON_VAULT_ADDR (required): Vault base URL. Operator exits 1 if missing.
//   - GIBSON_VAULT_ADMIN_TOKEN (required): admin token. Operator exits 1 if missing.
//   - GIBSON_VAULT_ROOT_NAMESPACE (optional, Enterprise): parent namespace
//     for per-tenant namespace creation.
//   - GIBSON_VAULT_JWT_AUTH_PATH (optional): JWT auth method mount path,
//     defaults to "auth/jwt".
//   - GIBSON_VAULT_JWT_BOUND_AUDIENCE (optional): expected `aud` claim
//     written into `bound_audiences` on every per-tenant Vault role
//     (load-bearing per ADR-0009 / tenant-operator#147). The mount-level
//     `bound_issuer` is set by the chart's vault-jwt-auth-init Job — Vault
//     1.18 has a single string-valued `bound_issuer` per mount, not a
//     per-role one. See ADR-0009 amendment "Vault auth/jwt mount is
//     SPIRE-only".
//   - GIBSON_VAULT_EDITION (optional): "enterprise" or "community" to
//     override runtime detection. Empty triggers /sys/health probe.
//
// buildVaultAdminClient constructs the Vault admin client with a
// platform-clients/secrets/vault.Provider token source so the Vault token
// renews before its TTL expires (P1 finding: env-baked admin token, never
// renewed — operator pod restart required after token rotation).
//
// The renewal goroutine runs until the returned AdminClient is no longer
// reachable (provider lifetime is process-scoped). Callers must not call
// provider.Close() independently; the manager's signal-handler shutdown
// already tears down in-flight goroutines via process exit.
func buildVaultAdminClient(log logr.Logger) vaultadmin.AdminClient {
	addr := os.Getenv("GIBSON_VAULT_ADDR")
	if addr == "" {
		log.Error(nil, "GIBSON_VAULT_ADDR is required (one-code-path: tenant-operator#197 "+
			"— Vault is non-negotiable; set dataPlane.vault.addr in the helm values)")
		os.Exit(1)
	}
	token := os.Getenv("GIBSON_VAULT_ADMIN_TOKEN")
	if token == "" {
		log.Error(nil, "GIBSON_VAULT_ADMIN_TOKEN is required (one-code-path: tenant-operator#197 "+
			"— Vault is non-negotiable; set dataPlane.vault.adminTokenSecretRef in the helm values)")
		os.Exit(1)
	}

	// The admin token is a periodic renewable token (per ADR-0032): minted by
	// the openbao-auto-init Job with period=1h, renewed by the sidecar renewal
	// probe. The platform-clients/secrets/vault Provider that previously wrapped
	// it for in-process LiveToken() renewal was removed in platform-clients
	// v0.6.0 (the renewal responsibility moved fully to the ADR-0032 renewal
	// probe). Use the static token directly.
	// JWTBoundIssuer + JWKSURL + JWKSCAPEMPath wire the per-tenant
	// auth/jwt/config writer (ConfigureSecretsJWTAuth step,
	// tenant-operator#189). JWTBoundIssuer is REQUIRED — the step refuses
	// to write a degraded config and fails the saga loud. Empty
	// JWKSCAPEMPath is allowed only when JWKSURL is plain HTTP (kind dev
	// cluster); HTTPS without a CA PEM also fails loud.
	issuer := os.Getenv("GIBSON_VAULT_JWT_BOUND_ISSUER")
	if issuer == "" {
		log.Error(nil, "GIBSON_VAULT_JWT_BOUND_ISSUER is required (tenant-operator#189 "+
			"— the per-tenant auth/jwt/config writer mirrors the root namespace's "+
			"bound_issuer; set vault.jwtAuth.spireOidcIssuer in the helm values)")
		os.Exit(1)
	}
	cfg := vaultadmin.Config{
		Address:          addr,
		AdminToken:       token,
		RootNamespace:    os.Getenv("GIBSON_VAULT_ROOT_NAMESPACE"),
		JWTAuthMountPath: os.Getenv("GIBSON_VAULT_JWT_AUTH_PATH"),
		JWTBoundAudience: os.Getenv("GIBSON_VAULT_JWT_BOUND_AUDIENCE"),
		JWTBoundIssuer:   issuer,
		JWKSURL:          os.Getenv("GIBSON_VAULT_JWKS_URL"),
		JWKSCAPEMPath:    os.Getenv("GIBSON_VAULT_JWKS_CA_PEM_PATH"),
	}
	c, err := vaultadmin.New(cfg)
	if err != nil {
		log.Error(err, "vault admin client init failed (one-code-path: tenant-operator#197 "+
			"— operator exits 1; fix the Vault wiring)")
		os.Exit(1)
	}
	return c
}

// buildWriteTenantBrokerConfigDeps assembles the dependency bundle for
// the WriteTenantBrokerConfig saga step. The step is non-negotiable
// (one-code-path: deploy#194) — every required env var MUST be set or
// the operator exits 1. The previous "return zero deps; let Skip()
// no-op" pattern silently broke every signed-up tenant's dashboard.
//
// Required env vars:
//
//	PLATFORM_PG_DSN              — Postgres DSN to the operator-shared
//	                               (platform) DB holding the
//	                               tenant_secrets_broker_config table.
//	GIBSON_SYSTEM_TENANT_KEK_PATH — File path to the 32-byte system-
//	                               tenant KEK. MUST match the daemon's
//	                               KEK byte-for-byte so rows this step
//	                               writes can be decrypted by the
//	                               daemon's TenantConfigStore. Mounted
//	                               from the same Secret the daemon's
//	                               k8s key_provider reads.
//	GIBSON_VAULT_ADDR            — Vault address (reused from
//	                               buildVaultAdminClient above).
//	GIBSON_VAULT_NAMESPACE_TEMPLATE / GIBSON_VAULT_AUTH_METHOD /
//	GIBSON_VAULT_MOUNT_PATH      — Vault broker config. All required.
//	GIBSON_VAULT_JWT_BOUND_AUDIENCE
//	                             — Required (ADR-0009 / #147). The
//	                               expected `aud` claim on plugin JWTs;
//	                               written into bound_audiences on every
//	                               per-tenant Vault role.
//	GIBSON_VAULT_TRANSIT_KEY     — Optional (daemon falls back to local
//	                               HKDF when empty).
//
// Process exits 1 with a structured error naming any missing env var
// or unreachable platform PG.
func buildWriteTenantBrokerConfigDeps(log logr.Logger) flows.WriteTenantBrokerConfigDeps {
	pgDSN := os.Getenv("PLATFORM_PG_DSN")
	if pgDSN == "" {
		log.Error(nil, "PLATFORM_PG_DSN is required (one-code-path: WriteTenantBrokerConfig is non-negotiable)")
		os.Exit(1)
	}
	pool, err := pgxpool.New(context.Background(), pgDSN)
	if err != nil {
		log.Error(err, "platform PG pool init failed — fix the DSN and restart")
		os.Exit(1)
	}

	// File-mount-only KEK loader (env-injection path deleted in
	// deploy#194 because raw 32-byte values crash env-var injection
	// with nul bytes). Same Secret the daemon's k8s key_provider reads.
	kek := loadSystemTenantKEK(log)
	if len(kek) == 0 {
		log.Error(nil, "system-tenant KEK could not be loaded — confirm "+
			"GIBSON_SYSTEM_TENANT_KEK_PATH points at the mounted Secret file")
		os.Exit(1)
	}

	// GIBSON_VAULT_JWT_BOUND_AUDIENCE is the load-bearing audience claim
	// on plugin JWTs (ADR-0009 / tenant-operator#147). The per-tenant
	// Vault JWT role written by writeJWTRole carries this value in its
	// `bound_audiences`; daemon-side JWT-bearer logins must present the
	// same audience. Empty → operator exits 1 (mirrors STRIPE_API_KEY /
	// SMTP_HOST / PLATFORM_PG_DSN fail-loud). The value is operator-
	// internal: it surfaces on the Vault role, NOT on the broker config
	// JSON the daemon reads.
	jwtBoundAudience := os.Getenv("GIBSON_VAULT_JWT_BOUND_AUDIENCE")
	if jwtBoundAudience == "" {
		log.Error(nil, "GIBSON_VAULT_JWT_BOUND_AUDIENCE is required (one-code-path / "+
			"ADR-0009 / tenant-operator#147): per-tenant Vault JWT roles must carry "+
			"a non-empty bound_audiences; set GIBSON_VAULT_JWT_BOUND_AUDIENCE in the "+
			"helm values (envoy.zitadel.dashboardClientId or the platform aud the "+
			"daemon's JWT-SVID resolves to)")
		os.Exit(1)
	}

	vaultCfg := flows.VaultBrokerConfig{
		Address:           os.Getenv("GIBSON_VAULT_ADDR"),
		NamespaceTemplate: os.Getenv("GIBSON_VAULT_NAMESPACE_TEMPLATE"),
		KVMount:           os.Getenv("GIBSON_VAULT_MOUNT_PATH"),
		Auth: flows.VaultAuthConfig{
			Method:   os.Getenv("GIBSON_VAULT_AUTH_METHOD"),
			Role:     os.Getenv("GIBSON_VAULT_AUTH_ROLE"),
			Audience: jwtBoundAudience,
		},
		TransitKey: os.Getenv("GIBSON_VAULT_TRANSIT_KEY"),
	}
	if vaultCfg.NamespaceTemplate == "" || vaultCfg.Auth.Method == "" || vaultCfg.KVMount == "" {
		log.Error(nil, "GIBSON_VAULT_NAMESPACE_TEMPLATE, GIBSON_VAULT_AUTH_METHOD, "+
			"and GIBSON_VAULT_MOUNT_PATH are all required (one-code-path)")
		os.Exit(1)
	}

	return flows.WriteTenantBrokerConfigDeps{
		PlatformPG:      pool,
		SystemTenantKEK: kek,
		VaultConfig:     vaultCfg,
	}
}

// statusCapture is a minimal http.ResponseWriter that captures the HTTP status
// code and body so the readyz aggregator's result can be adapted to a boolean.
// The body is only stored on failure (503) so it can be logged for debugging.
type statusCapture struct {
	status int
	header http.Header
	body   []byte
}

func (s *statusCapture) Header() http.Header {
	if s.header == nil {
		s.header = make(http.Header)
	}
	return s.header
}
func (s *statusCapture) Write(b []byte) (int, error) {
	s.body = append(s.body, b...)
	return len(b), nil
}
func (s *statusCapture) WriteHeader(code int) { s.status = code }
