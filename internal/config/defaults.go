package config

import (
	"os"
	"path/filepath"
	"time"

	"github.com/zero-day-ai/gibson/internal/memory/embedder"
)

// DefaultConfig returns a Config with sensible default values.
func DefaultConfig() *Config {
	homeDir := getDefaultHomeDir()

	return &Config{
		Core: CoreConfig{
			HomeDir:       homeDir,
			DataDir:       filepath.Join(homeDir, "data"),
			CacheDir:      filepath.Join(homeDir, "cache"),
			ParallelLimit: 10,
			Timeout:       5 * time.Minute,
			Debug:         false,
		},
		Security: SecurityConfig{
			EncryptionAlgorithm: "aes-256-gcm",
			KeyDerivation:       "scrypt",
			SSLValidation:       true,
			AuditLogging:        true,
		},
		LLM: LLMConfig{
			DefaultProvider: "",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		Tracing: TracingConfig{
			Enabled:  false,
			Endpoint: "",
		},
		Metrics: MetricsConfig{
			Enabled:       false,
			Port:          9090,
			ListenAddress: "",
			TLS: MetricsTLSConfig{
				// Defaults match the chart-mounted Secret paths
				// (templates/cert-manager/component-certificates.yaml ->
				// gibson-daemon-metrics-tls). Spec security-hardening R20.
				CertPath:     "/etc/gibson/tls/metrics/tls.crt",
				KeyPath:      "/etc/gibson/tls/metrics/tls.key",
				ClientCAPath: "/etc/gibson/tls/metrics/ca.crt",
			},
		},
		Registration: RegistrationConfig{
			Enabled:          false,
			Port:             50100,
			AuthToken:        "",
			HeartbeatTimeout: 30 * time.Second,
		},
		Registry: RegistryConfig{
			Namespace: "gibson",
			TTL:       "30s",
		},
		Callback: CallbackConfig{
			Enabled:          true,
			ListenAddress:    "0.0.0.0:50001",
			AdvertiseAddress: "",
		},
		Daemon: DaemonConfig{
			GRPCAddress: "localhost:50002",
		},
		Embedder: embedder.DefaultEmbedderConfig(),
		Redis: RedisConfig{
			URL:            "redis://localhost:6379",
			Password:       "",
			Database:       0,
			PoolSize:       10,
			ConnectTimeout: 5 * time.Second,
			ReadTimeout:    3 * time.Second,
			WriteTimeout:   3 * time.Second,
			MaxRetries:     3,
			ClusterMode:    false,
			ClusterAddrs:   []string{},
			SentinelMaster: "",
			SentinelAddrs:  []string{},
			TLSEnabled:     false,
			TLSCertFile:    "",
			TLSKeyFile:     "",
			TLSCAFile:      "",
		},
		ActivityLogging: ActivityLoggingConfig{
			Enabled:             true,
			Level:               "normal",
			MaxContentLength:    500,
			Output:              "stdout",
			FilePath:            "",
			BufferSize:          10000,
			IncludeLangfuseURLs: true,
		},
		Shutdown: ShutdownConfig{
			Timeout:           30 * time.Second,
			DrainTimeout:      10 * time.Second,
			CheckpointTimeout: 5 * time.Second,
			AgentTimeout:      15 * time.Second,
		},
		Observability: ObservabilityConfig{
			Neo4jBrowserURL:      "http://localhost:7474",
			LangfuseDashboardURL: "http://localhost:3000",
		},
		Auth: AuthConfig{
			Enabled:   false, // Deprecated: use Mode instead
			ClockSkew: 30 * time.Second,
		},
		Checkpoint: *DefaultCheckpointConfig(),
		Authz: AuthzConfig{
			Enabled:           false, // Disabled by default — flip in dev/prod values
			Provider:          "openfga",
			RequireReady:      true,
			EnforcementSource: "fga", // Only valid value
			Fga: FgaClientConfig{
				Endpoint:  "gibson-fga:8080",
				StoreID:   "", // resolved from ConfigMap at startup if empty
				ModelID:   "", // resolved from ConfigMap at startup if empty
				TimeoutMs: 500,
				TLS: FgaTLSConfig{
					Enabled: false,
				},
			},
		},
		// GraphRAG.Neo4j.TenantMode defaults to "instance" — one StatefulSet per tenant.
		// Override to "multi-db" when migrating to a shared Enterprise cluster.
		// Spec: per-tenant-data-plane-completion Task 11 / Req 5.5.
		GraphRAG: GraphRAGConfig{
			Neo4j: Neo4jConfig{
				TenantMode: "instance",
			},
		},
	}
}

// getDefaultHomeDir returns the default Gibson home directory.
// It uses ~/.gibson or falls back to a temporary directory if user home cannot be determined.
func getDefaultHomeDir() string {
	userHome, err := os.UserHomeDir()
	if err != nil {
		// Fallback to temporary directory if user home cannot be determined
		return filepath.Join(os.TempDir(), ".gibson")
	}
	return filepath.Join(userHome, ".gibson")
}
