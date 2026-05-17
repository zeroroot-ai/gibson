package config

import (
	"time"

	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/memory/embedder"
	"github.com/zero-day-ai/gibson/internal/prompt"
)

// PlatformPostgresConfig holds connection settings for the shared dashboard
// PostgreSQL instance. The daemon uses this database to read and write the
// tenant_provisioning table. It is the same PostgreSQL instance that the
// dashboard's Better Auth server uses for user/session/organisation data.
//
// This is a separate instance from the Langfuse PostgreSQL instance.
//
// Environment variable overrides (all GIBSON_DASHBOARD_POSTGRES_* prefix):
//
//	GIBSON_DASHBOARD_POSTGRES_HOST       — server hostname (default: dashboard-postgresql)
//	GIBSON_DASHBOARD_POSTGRES_PORT       — TCP port (default: 5432)
//	GIBSON_DASHBOARD_POSTGRES_DATABASE   — database name (default: gibson_dashboard)
//	GIBSON_DASHBOARD_POSTGRES_USERNAME   — user name
//	GIBSON_DASHBOARD_POSTGRES_PASSWORD   — password (keep in K8s Secret)
//	GIBSON_DASHBOARD_POSTGRES_SSL_MODE   — sslmode value (default: disable)
//	GIBSON_DASHBOARD_POSTGRES_MAX_CONNS  — connection pool size (default: 5)
type PlatformPostgresConfig struct {
	// Host is the PostgreSQL server hostname or IP address.
	// Default: "dashboard-postgresql"
	Host string `mapstructure:"host" yaml:"host"`

	// Port is the TCP port PostgreSQL listens on.
	// Default: 5432
	Port int `mapstructure:"port" yaml:"port"`

	// Database is the name of the database to connect to.
	// Default: "gibson_dashboard"
	Database string `mapstructure:"database" yaml:"database"`

	// Username is the PostgreSQL role used to authenticate.
	Username string `mapstructure:"username" yaml:"username"`

	// Password is the PostgreSQL password. Store in a Kubernetes Secret.
	Password string `mapstructure:"password" yaml:"password"`

	// SSLMode controls the SSL/TLS negotiation mode.
	// Valid values: disable, require, verify-ca, verify-full.
	// Default: "disable" (suitable for in-cluster communication).
	SSLMode string `mapstructure:"ssl_mode" yaml:"ssl_mode"`

	// MaxConns is the maximum number of open connections in the pool.
	// Default: 5
	MaxConns int `mapstructure:"max_conns" yaml:"max_conns"`
}

// TenantPostgresConfig holds connection settings for the per-tenant admin
// PostgreSQL instance. The daemon uses this database to bootstrap per-tenant
// databases and roles. It requires a role with CREATEDB privilege.
//
// This is distinct from the dashboard Postgres instance (PlatformPostgresConfig)
// and is used exclusively for tenant data-plane operations (CREATE DATABASE,
// CREATE ROLE, cross-tenant admin queries). See spec per-tenant-data-plane-completion
// Req 1.1–1.4 and design D1.
//
// Environment variable overrides (all GIBSON_TENANT_POSTGRES_* prefix, resolved
// by the loader's env-interpolation block):
//
//	GIBSON_TENANT_POSTGRES_HOST           — server hostname
//	GIBSON_TENANT_POSTGRES_PORT           — TCP port (default: 5432)
//	GIBSON_TENANT_POSTGRES_ADMIN_DATABASE — admin database name (default: postgres)
//	GIBSON_TENANT_POSTGRES_ADMIN_USERNAME — admin role (requires CREATEDB)
//	GIBSON_TENANT_POSTGRES_ADMIN_PASSWORD — password (keep in K8s Secret)
//	GIBSON_TENANT_POSTGRES_SSL_MODE       — sslmode value (default: disable)
//	GIBSON_TENANT_POSTGRES_MAX_CONNS      — admin pool size (default: 5)
type TenantPostgresConfig struct {
	// Host is the PostgreSQL server hostname or IP address.
	Host string `mapstructure:"host" yaml:"host"`

	// Port is the TCP port PostgreSQL listens on.
	// Default: 5432
	Port int `mapstructure:"port" yaml:"port"`

	// AdminDatabase is the name of the admin/maintenance database.
	// Default: "postgres"
	AdminDatabase string `mapstructure:"admin_database" yaml:"admin_database"`

	// AdminUsername is the PostgreSQL role used to authenticate.
	// This role must have CREATEDB privilege for tenant provisioning.
	AdminUsername string `mapstructure:"admin_username" yaml:"admin_username"`

	// AdminPassword is the PostgreSQL password. Store in a Kubernetes Secret.
	// The chart injects this via ${TENANT_POSTGRES_ADMIN_PASSWORD} env var.
	AdminPassword string `mapstructure:"admin_password" yaml:"admin_password"`

	// SSLMode controls the SSL/TLS negotiation mode.
	// Valid values: disable, require, verify-ca, verify-full.
	// Default: "disable" (suitable for in-cluster communication).
	SSLMode string `mapstructure:"ssl_mode" yaml:"ssl_mode"`

	// MaxConns is the maximum number of open connections in the admin pool.
	// Default: 5
	MaxConns int `mapstructure:"max_conns" yaml:"max_conns"`
}

// Config is the root configuration for the Gibson Framework.
type Config struct {
	Core              CoreConfig              `mapstructure:"core" yaml:"core" validate:"required"`
	Security          SecurityConfig          `mapstructure:"security" yaml:"security" validate:"required"`
	LLM               LLMConfig               `mapstructure:"llm" yaml:"llm"`
	Memory            memory.MemoryConfig     `mapstructure:"memory" yaml:"memory"`
	Prompt            prompt.PromptConfig     `mapstructure:"prompt" yaml:"prompt"`
	Logging           LoggingConfig           `mapstructure:"logging" yaml:"logging"`
	Tracing           TracingConfig           `mapstructure:"tracing" yaml:"tracing"`
	Metrics           MetricsConfig           `mapstructure:"metrics" yaml:"metrics"`
	Registration      RegistrationConfig      `mapstructure:"registration" yaml:"registration,omitempty"`
	Registry          RegistryConfig          `mapstructure:"registry" yaml:"registry"`
	Callback          CallbackConfig          `mapstructure:"callback" yaml:"callback,omitempty"`
	Daemon            DaemonConfig            `mapstructure:"daemon" yaml:"daemon,omitempty"`
	Health            HealthConfig            `mapstructure:"health" yaml:"health,omitempty"`
	Embedder          embedder.EmbedderConfig `mapstructure:"embedder" yaml:"embedder"`
	Langfuse          LangfuseConfig          `mapstructure:"langfuse" yaml:"langfuse"`
	GraphRAG          GraphRAGConfig          `mapstructure:"graphrag" yaml:"graphrag"`
	Redis             RedisConfig             `mapstructure:"redis" yaml:"redis" validate:"required"`
	Plugins           PluginsConfig           `mapstructure:"plugins" yaml:"plugins,omitempty"`
	ActivityLogging   ActivityLoggingConfig   `mapstructure:"activity_logging" yaml:"activity_logging"`
	Shutdown          ShutdownConfig          `mapstructure:"shutdown" yaml:"shutdown"`
	Observability     ObservabilityConfig     `mapstructure:"observability" yaml:"observability"`
	OTelObservability OTelObservabilityConfig `mapstructure:"otel_observability" yaml:"otel_observability"`
	Auth              AuthConfig              `mapstructure:"auth" yaml:"auth"`
	Checkpoint        CheckpointConfig        `mapstructure:"checkpoint" yaml:"checkpoint"`
	Authz             AuthzConfig             `mapstructure:"authz" yaml:"authz"`
	PlatformPostgres PlatformPostgresConfig `mapstructure:"dashboard_postgres" yaml:"dashboard_postgres,omitempty"`
	TenantPostgres    TenantPostgresConfig    `mapstructure:"tenant_postgres" yaml:"tenant_postgres,omitempty"`
	Sandbox           SandboxConfig           `mapstructure:"sandbox" yaml:"sandbox,omitempty"`
	ToolRunner        ToolRunnerConfig        `mapstructure:"tool_runner" yaml:"tool_runner,omitempty"`

	// mode is the deployment mode resolved from GIBSON_MODE at config load time.
	// Read via Mode(). Not sourced from YAML — env-var only.
	// Default: ModeSelfhost (preserves current behaviour for self-hosted deployments).
	mode Mode

	// strictTenant controls whether TenantFromContext and related helpers use
	// the fail-closed strict behaviour introduced in Phase 1. Read via
	// StrictTenant(). Not sourced from YAML — env-var only.
	// Default: false in Phase 1; Phase 5 flips this default and removes the flag.
	strictTenant bool
}

// Mode returns the resolved deployment mode (GIBSON_MODE env var).
// Defaults to ModeSelfhost when GIBSON_MODE is unset or empty.
func (c *Config) Mode() Mode {
	return c.mode
}

// StrictTenant returns true when strict tenant-context enforcement is enabled
// (GIBSON_STRICT_TENANT=1/true/yes). False in Phase 1 default.
func (c *Config) StrictTenant() bool {
	return c.strictTenant
}

// ToolRunnerConfig governs the daemon's catalog refresher: which
// gibson-tool-runner images to poll for --list-tools and how often. When
// disabled, the daemon falls back to static sandbox.tools.* config.
//
// Added under the gibson-tool-runner spec as a feature-flagged
// introduction; removal of the static sandbox.tools path (task 16) flips
// this default to enabled.
type ToolRunnerConfig struct {
	// Enabled turns on the dynamic catalog refresh path. Default false.
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// Images is the list of gibson-tool-runner OCI references to poll.
	// Earlier entries win for duplicate tool names (stable-over-experimental).
	Images []string `mapstructure:"images" yaml:"images,omitempty"`
	// RefreshInterval is the cadence between catalog refresh ticks. Zero
	// uses the in-code 10-minute default.
	RefreshInterval time.Duration `mapstructure:"refresh_interval" yaml:"refresh_interval,omitempty"`
}

// PluginsConfig contains configuration for all plugins.
// Keys are plugin names, values are plugin-specific configuration maps.
// Environment variables can be interpolated using ${VAR_NAME} syntax.
type PluginsConfig map[string]map[string]string

// CoreConfig contains core application settings.
type CoreConfig struct {
	HomeDir       string        `mapstructure:"home_dir" yaml:"home_dir"`
	DataDir       string        `mapstructure:"data_dir" yaml:"data_dir"`
	CacheDir      string        `mapstructure:"cache_dir" yaml:"cache_dir"`
	ParallelLimit int           `mapstructure:"parallel_limit" yaml:"parallel_limit" validate:"min=1,max=100"`
	Timeout       time.Duration `mapstructure:"timeout" yaml:"timeout" validate:"min=1s"`
	Debug         bool          `mapstructure:"debug" yaml:"debug"`
}

// SecurityConfig contains security-related settings.
type SecurityConfig struct {
	EncryptionAlgorithm string                    `mapstructure:"encryption_algorithm" yaml:"encryption_algorithm"`
	KeyDerivation       string                    `mapstructure:"key_derivation" yaml:"key_derivation"`
	SSLValidation       bool                      `mapstructure:"ssl_validation" yaml:"ssl_validation"`
	AuditLogging        bool                      `mapstructure:"audit_logging" yaml:"audit_logging"`
	KeyProvider         *crypto.KeyProviderConfig `mapstructure:"key_provider" yaml:"key_provider,omitempty"`
}

// LLMConfig contains LLM provider configuration.
type LLMConfig struct {
	// DefaultProvider is the default LLM provider
	DefaultProvider string `mapstructure:"default_provider" yaml:"default_provider"`

	// Providers contains provider-specific configurations
	Providers map[string]ProviderConfig `mapstructure:"providers" yaml:"providers"`

	// ExecRateLimits configures per-RPC tenant rate limits for the LLM execution
	// handlers (ExecuteLLM, StreamLLM, TestProvider). Keys are RPC names;
	// values are requests-per-minute limits. When a key is absent the default
	// from ratelimit.DefaultLimits() is used.
	ExecRateLimits map[string]int `mapstructure:"rate_limits" yaml:"rate_limits"`
}

// ProviderConfig contains configuration for an LLM provider.
type ProviderConfig struct {
	// Type is the provider type (openai, anthropic, google, ollama)
	Type string `mapstructure:"type" yaml:"type"`

	// APIKey is the API key for the provider
	APIKey string `mapstructure:"api_key" yaml:"api_key"`

	// APIKeyEnv is the environment variable containing the API key
	APIKeyEnv string `mapstructure:"api_key_env" yaml:"api_key_env"`

	// BaseURL overrides the default API endpoint
	BaseURL string `mapstructure:"base_url" yaml:"base_url"`

	// Model is the default model to use
	Model string `mapstructure:"model" yaml:"model"`

	// MaxTokens is the default max tokens
	MaxTokens int `mapstructure:"max_tokens" yaml:"max_tokens"`

	// Temperature is the default temperature
	Temperature float64 `mapstructure:"temperature" yaml:"temperature"`

	// Timeout for API requests
	Timeout time.Duration `mapstructure:"timeout" yaml:"timeout"`

	// RateLimits configures rate limiting
	RateLimits RateLimitConfig `mapstructure:"rate_limits" yaml:"rate_limits"`

	// Available indicates whether this provider passed API key validation at startup.
	// Set by ValidateProviderKeys(). Not persisted to config file.
	Available bool `mapstructure:"-" yaml:"-" json:"-"`
}

// RateLimitConfig contains rate limiting configuration.
type RateLimitConfig struct {
	RequestsPerMinute int `mapstructure:"requests_per_minute" yaml:"requests_per_minute"`
	TokensPerMinute   int `mapstructure:"tokens_per_minute" yaml:"tokens_per_minute"`
}

// LoggingConfig contains logging configuration.
type LoggingConfig struct {
	Level  string `mapstructure:"level" yaml:"level"`
	Format string `mapstructure:"format" yaml:"format"`
}

// TracingConfig contains distributed tracing configuration.
type TracingConfig struct {
	Enabled  bool   `mapstructure:"enabled" yaml:"enabled"`
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint"`
}

// MetricsConfig contains metrics export configuration.
type MetricsConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	Port    int  `mapstructure:"port" yaml:"port"`

	// ListenAddress overrides the host:port the daemon binds the Prometheus
	// metrics handler to. When empty, the daemon falls back to ":<Port>"
	// (i.e. all interfaces). Set explicitly to "0.0.0.0:9090" or "[::]:9090"
	// in chart-managed deployments. Spec: security-hardening R20.
	ListenAddress string `mapstructure:"listen_address" yaml:"listen_address,omitempty"`

	// TLS controls the daemon-owned :9090 mTLS metrics listener (Spec
	// security-hardening R20, week-2-hardening-ha-daemon-internal task 18).
	//
	// Decision (Phase A3, 2026-05-05): TLS termination is OWNED by the daemon
	// — NOT by the SDK healthhttp.Server — so cert rotation, mTLS, and
	// audit are kept inside the daemon binary's contract. The chart provisions
	// `gibson-daemon-metrics-tls` via cert-manager and mounts it at
	// /etc/gibson/tls/metrics/{tls.crt,tls.key,ca.crt}.
	//
	// When the metrics block is enabled, all three paths MUST resolve to
	// readable files at startup. The daemon fails fast on missing material —
	// there is no plaintext fallback.
	TLS MetricsTLSConfig `mapstructure:"tls" yaml:"tls,omitempty"`
}

// MetricsTLSConfig holds the file paths for the daemon's mTLS metrics
// listener. All three paths are required when metrics.enabled=true and TLS
// is configured. Spec security-hardening R20.
type MetricsTLSConfig struct {
	// CertPath is the daemon's server certificate (cert-manager Secret
	// `gibson-daemon-metrics-tls`, key tls.crt). Default mount:
	// /etc/gibson/tls/metrics/tls.crt.
	CertPath string `mapstructure:"cert_path" yaml:"cert_path,omitempty"`

	// KeyPath is the daemon's private key matching CertPath (Secret key
	// tls.key). Default mount: /etc/gibson/tls/metrics/tls.key.
	KeyPath string `mapstructure:"key_path" yaml:"key_path,omitempty"`

	// ClientCAPath is the CA bundle the daemon uses to verify Prometheus
	// scrape clients (Secret key ca.crt). Default mount:
	// /etc/gibson/tls/metrics/ca.crt. Required — clients without a valid
	// cert signed by this CA are rejected at the TLS handshake.
	ClientCAPath string `mapstructure:"client_ca_path" yaml:"client_ca_path,omitempty"`
}

// RegistrationConfig contains configuration for the optional agent self-announcement server.
// When enabled, agents can dynamically register themselves with Gibson by sending heartbeat
// announcements with their capabilities and network addresses.
type RegistrationConfig struct {
	// Enabled controls whether the registration server is started
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// Port is the TCP port for the registration gRPC server (default: 50100)
	// Validation only applies when Enabled is true
	Port int `mapstructure:"port" yaml:"port"`

	// AuthToken is an optional authentication token that agents must provide when registering
	// If empty, no authentication is required (not recommended for production)
	AuthToken string `mapstructure:"auth_token" yaml:"auth_token,omitempty"`

	// HeartbeatTimeout is the duration after which an agent is considered dead if no heartbeat
	// is received (default: 30s)
	HeartbeatTimeout time.Duration `mapstructure:"heartbeat_timeout" yaml:"heartbeat_timeout,omitempty"`
}

// RegistryConfig contains configuration for the component registry.
// The registry now uses Redis exclusively for both runtime service discovery
// and persistent component metadata storage.
type RegistryConfig struct {
	// Namespace is the key prefix for all registry entries (default: "gibson")
	Namespace string `mapstructure:"namespace" yaml:"namespace"`

	// TTL is the time-to-live for runtime service registrations (default: "30s")
	// Persistent component metadata (installed agents/tools/plugins) has no TTL.
	TTL string `mapstructure:"ttl" yaml:"ttl"`
}

// DaemonConfig contains configuration for the Gibson daemon process.
type DaemonConfig struct {
	// GRPCAddress is the address for the daemon's gRPC API server.
	// Clients connect to this address to communicate with the daemon.
	// Default: "localhost:50002"
	// Can be overridden via GIBSON_DAEMON_GRPC_ADDR environment variable.
	GRPCAddress string `mapstructure:"grpc_address" yaml:"grpc_address"`

	// Executor configuration for mission execution
	Executor ExecutorConfig `mapstructure:"executor" yaml:"executor"`
}

// HealthConfig contains HTTP health endpoint configuration.
type HealthConfig struct {
	// Port is the HTTP port for health endpoints (/healthz and /readyz).
	// Default: 8080
	// Can be overridden via GIBSON_HEALTH_PORT environment variable.
	Port int `mapstructure:"port" yaml:"port"`
}

// ExecutorConfig contains configuration for mission execution.
type ExecutorConfig struct {
	// MaxConcurrentMissions limits parallel mission execution
	MaxConcurrentMissions int `mapstructure:"max_concurrent_missions" yaml:"max_concurrent_missions"`

	// DefaultTimeout for mission execution
	DefaultTimeout time.Duration `mapstructure:"default_timeout" yaml:"default_timeout"`

	// RetryPolicy for failed nodes
	RetryPolicy RetryConfig `mapstructure:"retry_policy" yaml:"retry_policy"`

	// ResourceLimits for agent execution
	ResourceLimits ResourceLimitsConfig `mapstructure:"resource_limits" yaml:"resource_limits"`
}

// RetryConfig contains retry policy configuration.
type RetryConfig struct {
	MaxRetries int           `mapstructure:"max_retries" yaml:"max_retries"`
	BackoffMin time.Duration `mapstructure:"backoff_min" yaml:"backoff_min"`
	BackoffMax time.Duration `mapstructure:"backoff_max" yaml:"backoff_max"`
}

// ResourceLimitsConfig contains resource limit configuration for agent execution.
type ResourceLimitsConfig struct {
	MaxMemoryMB int           `mapstructure:"max_memory_mb" yaml:"max_memory_mb"`
	MaxCPUCores float64       `mapstructure:"max_cpu_cores" yaml:"max_cpu_cores"`
	MaxDuration time.Duration `mapstructure:"max_duration" yaml:"max_duration"`
}

// LangfuseConfig contains Langfuse LLM observability configuration.
//
// Deprecated: LangfuseConfig is deprecated. Use OTelObservabilityConfig instead.
// Langfuse will be removed in a future version. See docs/migration/langfuse-to-otel.md
//
// The OTel observability stack provides unified tracing to any OTLP-compatible backend
// (Jaeger, Tempo, Honeycomb, Datadog, etc.) with better standardization and ecosystem support.
type LangfuseConfig struct {
	Enabled   bool   `mapstructure:"enabled" yaml:"enabled"`
	Host      string `mapstructure:"host" yaml:"host"`
	PublicKey string `mapstructure:"public_key" yaml:"public_key"`
	SecretKey string `mapstructure:"secret_key" yaml:"secret_key"`
}

// Neo4jConfig contains Neo4j connection settings for per-tenant GraphRAG.
//
// # TenantMode semantics
//
// Two modes control how the daemon resolves Neo4j endpoints:
//
//   - "instance" (default): one Neo4j StatefulSet per tenant, provisioned by
//     the tenant-operator. Per-tenant URIs come from the endpoint registry
//     (tenant_neo4j_endpoints Postgres table) via instanceResolver. No shared
//     cluster is required; the daemon resolves Neo4j endpoints at request time.
//
//   - "multi-db": a shared Enterprise cluster. SharedClusterURI is the bolt
//     address for the cluster, and each tenant uses the Neo4j database named
//     tenant_<sanitized>. Enabled via multiDBResolver.
//
// There is no startup-time shared Neo4j connection. The daemon connects to
// per-tenant Neo4j instances lazily, at the first request for each tenant.
type Neo4jConfig struct {
	// TenantMode controls per-tenant endpoint resolution.
	// Valid values: "instance" (default), "multi-db".
	// validate:"oneof=instance multi-db" — enforced by config validator.
	TenantMode string `mapstructure:"tenant_mode" yaml:"tenant_mode,omitempty"`

	// SharedClusterURI is the bolt:// URI for the shared Enterprise cluster.
	// Only consulted when TenantMode == "multi-db".
	SharedClusterURI string `mapstructure:"shared_cluster_uri" yaml:"shared_cluster_uri,omitempty"`
}

// GraphRAGConfig contains Neo4j knowledge graph configuration.
type GraphRAGConfig struct {
	Enabled bool        `mapstructure:"enabled" yaml:"enabled"`
	Neo4j   Neo4jConfig `mapstructure:"neo4j" yaml:"neo4j"`
}

// RedisConfig contains Redis connection settings for tool execution and state management.
// Supports standalone, cluster, and sentinel deployment modes with comprehensive
// timeout, pooling, and TLS configuration options.
type RedisConfig struct {
	// Basic connection settings
	URL      string `mapstructure:"url" yaml:"url"`
	Password string `mapstructure:"password" yaml:"password"`
	Database int    `mapstructure:"database" yaml:"database"`

	// Connection pooling
	PoolSize int `mapstructure:"pool_size" yaml:"pool_size"`

	// Timeouts
	ConnectTimeout time.Duration `mapstructure:"connect_timeout" yaml:"connect_timeout"`
	ReadTimeout    time.Duration `mapstructure:"read_timeout" yaml:"read_timeout"`
	WriteTimeout   time.Duration `mapstructure:"write_timeout" yaml:"write_timeout"`

	// Retry settings
	MaxRetries int `mapstructure:"max_retries" yaml:"max_retries"`

	// Cluster mode configuration
	ClusterMode  bool     `mapstructure:"cluster_mode" yaml:"cluster_mode"`
	ClusterAddrs []string `mapstructure:"cluster_addrs" yaml:"cluster_addrs"`

	// Sentinel mode configuration
	SentinelMaster string   `mapstructure:"sentinel_master" yaml:"sentinel_master"`
	SentinelAddrs  []string `mapstructure:"sentinel_addrs" yaml:"sentinel_addrs"`

	// TLS configuration
	TLSEnabled  bool   `mapstructure:"tls_enabled" yaml:"tls_enabled"`
	TLSCertFile string `mapstructure:"tls_cert_file" yaml:"tls_cert_file"`
	TLSKeyFile  string `mapstructure:"tls_key_file" yaml:"tls_key_file"`
	TLSCAFile   string `mapstructure:"tls_ca_file" yaml:"tls_ca_file"`
}

// ShutdownConfig contains configuration for graceful shutdown behavior.
type ShutdownConfig struct {
	// Timeout is the total shutdown timeout (default: 30s)
	Timeout time.Duration `mapstructure:"timeout" yaml:"timeout"`

	// DrainTimeout is the request drain timeout (default: 10s)
	DrainTimeout time.Duration `mapstructure:"drain_timeout" yaml:"drain_timeout"`

	// CheckpointTimeout is the per-mission checkpoint timeout (default: 5s)
	CheckpointTimeout time.Duration `mapstructure:"checkpoint_timeout" yaml:"checkpoint_timeout"`

	// AgentTimeout is the agent disconnect timeout (default: 15s)
	AgentTimeout time.Duration `mapstructure:"agent_timeout" yaml:"agent_timeout"`
}

// ObservabilityConfig contains configuration for observability dashboard integrations.
// This includes URLs for Neo4j Browser and Langfuse dashboard, used for generating
// deep links from traces to knowledge graph visualizations.
type ObservabilityConfig struct {
	// Neo4jBrowserURL is the base URL for Neo4j Browser UI
	// Used to generate deep links from Langfuse traces to graph views
	// Default: http://localhost:7474
	// Environment variable: GIBSON_OBSERVABILITY_NEO4J_BROWSER_URL
	Neo4jBrowserURL string `mapstructure:"neo4j_browser_url" yaml:"neo4j_browser_url"`

	// LangfuseDashboardURL is the URL for the Langfuse UI
	// Used for generating links to Langfuse dashboards
	// Default: http://localhost:3000
	// Environment variable: GIBSON_OBSERVABILITY_LANGFUSE_DASHBOARD_URL
	LangfuseDashboardURL string `mapstructure:"langfuse_dashboard_url" yaml:"langfuse_dashboard_url"`
}

// ApplyDefaults fills in zero-valued fields with sensible defaults.
func (c *ShutdownConfig) ApplyDefaults() {
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}

	if c.DrainTimeout == 0 {
		c.DrainTimeout = 10 * time.Second
	}

	if c.CheckpointTimeout == 0 {
		c.CheckpointTimeout = 5 * time.Second
	}

	if c.AgentTimeout == 0 {
		c.AgentTimeout = 15 * time.Second
	}
}

// ApplyDefaults fills in zero-valued fields with sensible defaults.
func (c *ObservabilityConfig) ApplyDefaults() {
	if c.Neo4jBrowserURL == "" {
		c.Neo4jBrowserURL = "http://localhost:7474"
	}

	if c.LangfuseDashboardURL == "" {
		c.LangfuseDashboardURL = "http://localhost:3000"
	}
}

// OTelObservabilityConfig contains configuration for unified OpenTelemetry observability.
// This replaces the Langfuse-specific configuration for a standard OTel approach that works
// with any OTLP-compatible backend (Jaeger, Tempo, Honeycomb, Datadog, etc.).
//
// OTel observability is optional and gracefully degrades - daemon startup will not fail
// if OTel is misconfigured or unavailable. All trace/metric export errors are logged
// but never block mission execution.
//
// Example configuration:
//
//	otel_observability:
//	  enabled: true
//	  endpoint: "http://localhost:4317"
//	  protocol: "grpc"
//	  service_name: "gibson"
//	  headers:
//	    authorization: "Bearer ${OTEL_API_KEY}"
//	  content_logging:
//	    enabled: true
//	    max_prompt_length: 10000
//	    max_completion_length: 10000
//	    include_tool_io: false
type OTelObservabilityConfig struct {
	// Enabled controls whether OTel observability is active.
	// When false, all OTel components are skipped with zero overhead.
	// Default: false (opt-in model)
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// Endpoint is the OTLP receiver endpoint (e.g., "http://localhost:4317" for gRPC).
	// Supports both gRPC and HTTP/protobuf protocols based on Protocol field.
	// Required when Enabled is true.
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint"`

	// Protocol is the OTLP protocol to use: "grpc" or "http".
	// Default: "grpc" (recommended for production due to better performance)
	Protocol string `mapstructure:"protocol" yaml:"protocol"`

	// Headers are additional headers to send with OTLP requests.
	// Commonly used for authentication tokens or custom metadata.
	// Example: {"Authorization": "Bearer token", "X-Scope-OrgID": "tenant1"}
	Headers map[string]string `mapstructure:"headers" yaml:"headers"`

	// ServiceName identifies this service in traces (appears in trace search/filtering).
	// Default: "gibson"
	ServiceName string `mapstructure:"service_name" yaml:"service_name"`

	// ContentLogging configures prompt/completion capture in traces.
	// When enabled, LLM prompts and completions are recorded as span events
	// with redaction and truncation for security.
	ContentLogging ContentLoggingSubConfig `mapstructure:"content_logging" yaml:"content_logging"`

	// Batching configures export batching to reduce network overhead.
	// Higher batch sizes improve throughput but increase latency and memory usage.
	Batching BatchingConfig `mapstructure:"batching" yaml:"batching"`

	// Retry configures export retry behavior for transient failures.
	// Exponential backoff prevents overwhelming failing backends.
	Retry RetryExportConfig `mapstructure:"retry" yaml:"retry"`

	// Metrics independently controls the metric exporter. Some OTLP backends
	// (notably Langfuse) ingest traces only — sending metrics there yields
	// 404s on every export interval. Disable metrics in those cases; the
	// daemon still runs traces normally.
	Metrics MetricsExportConfig `mapstructure:"metrics" yaml:"metrics"`
}

// MetricsExportConfig controls whether the OTel metric exporter is created.
// When Enabled is false, the daemon installs a no-op MeterProvider — every
// metric instrument keeps working in code but nothing is pushed over the
// wire. Use this when the OTLP endpoint is a trace-only backend (Langfuse,
// some Honeycomb tiers) or when metrics are scraped via Prometheus/pull
// instead of pushed via OTLP.
type MetricsExportConfig struct {
	// Enabled determines whether the OTel metric exporter is active.
	// When nil (unset), defaults to true so existing deployments keep
	// their current behavior. When *false, MeterProvider is a no-op and
	// no /v1/metrics requests are emitted. Pointer type lets us
	// distinguish "field omitted" from "explicitly disabled".
	Enabled *bool `mapstructure:"enabled" yaml:"enabled"`
}

// ContentLoggingSubConfig maps to observability.ContentLoggingConfig.
// It controls whether and how LLM conversation content is logged in traces.
// All fields support security features like redaction and truncation.
type ContentLoggingSubConfig struct {
	// Enabled determines whether content logging is active.
	// Default: false (opt-in for security)
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// MaxPromptLength is the maximum number of characters to log for prompts.
	// Content exceeding this will be truncated with "... [truncated]" suffix.
	// Set to 0 for no limit (not recommended in production).
	// Default: 10000
	MaxPromptLength int `mapstructure:"max_prompt_length" yaml:"max_prompt_length"`

	// MaxCompletionLength is the maximum number of characters to log for completions.
	// Content exceeding this will be truncated with "... [truncated]" suffix.
	// Set to 0 for no limit (not recommended in production).
	// Default: 10000
	MaxCompletionLength int `mapstructure:"max_completion_length" yaml:"max_completion_length"`

	// RedactPatterns contains regex patterns for redacting sensitive information.
	// Matches are replaced with [REDACTED] before logging.
	// Default patterns include: API keys, passwords, secrets, tokens, bearer tokens.
	RedactPatterns []string `mapstructure:"redact_patterns" yaml:"redact_patterns"`

	// IncludeToolIO determines whether tool input and output are logged.
	// Tool I/O can be large and may contain sensitive data.
	// Default: false (to reduce log volume and exposure)
	IncludeToolIO bool `mapstructure:"include_tool_io" yaml:"include_tool_io"`
}

// BatchingConfig configures OTLP export batching behavior.
// Batching reduces network overhead by aggregating multiple spans/metrics
// into fewer network requests at the cost of increased latency.
type BatchingConfig struct {
	// MaxSize is the maximum number of spans/metrics to batch before sending.
	// Higher values reduce network overhead but increase memory usage and latency.
	// Default: 512
	MaxSize int `mapstructure:"max_size" yaml:"max_size"`

	// Timeout is the maximum time to wait before sending a partial batch.
	// Ensures data is sent even if MaxSize isn't reached.
	// Default: 5s
	Timeout time.Duration `mapstructure:"timeout" yaml:"timeout"`
}

// RetryExportConfig configures OTLP export retry behavior with exponential backoff.
// Retry is critical for production resilience to handle transient backend failures.
type RetryExportConfig struct {
	// Enabled determines whether failed exports should be retried.
	// Recommended for production to handle transient failures.
	// Default: true
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// InitialInterval is the initial backoff duration for retry attempts.
	// Subsequent retries use exponential backoff up to MaxInterval.
	// Default: 1s
	InitialInterval time.Duration `mapstructure:"initial_interval" yaml:"initial_interval"`

	// MaxInterval is the maximum backoff duration between retry attempts.
	// Prevents excessive wait times during extended outages.
	// Default: 30s
	MaxInterval time.Duration `mapstructure:"max_interval" yaml:"max_interval"`

	// MaxElapsedTime is the maximum total time to spend retrying.
	// After this time, the export is abandoned and an error is logged.
	// Default: 5m
	MaxElapsedTime time.Duration `mapstructure:"max_elapsed_time" yaml:"max_elapsed_time"`
}

// ApplyDefaults fills in zero-valued fields with production-ready defaults.
// This ensures the configuration is complete even when partially specified in YAML.
func (c *OTelObservabilityConfig) ApplyDefaults() {
	if c.ServiceName == "" {
		c.ServiceName = "gibson"
	}
	if c.Protocol == "" {
		c.Protocol = "grpc"
	}

	// Content logging defaults (conservative for security)
	if c.ContentLogging.MaxPromptLength == 0 {
		c.ContentLogging.MaxPromptLength = 10000
	}
	if c.ContentLogging.MaxCompletionLength == 0 {
		c.ContentLogging.MaxCompletionLength = 10000
	}
	if len(c.ContentLogging.RedactPatterns) == 0 {
		c.ContentLogging.RedactPatterns = []string{
			// Match API keys, passwords, secrets, tokens with various formats
			`(?i)(api[_-]?key|password|secret|token|bearer)[=:\s]+\S+`,
		}
	}

	// Batching defaults (balance throughput and latency)
	if c.Batching.MaxSize == 0 {
		c.Batching.MaxSize = 512
	}
	if c.Batching.Timeout == 0 {
		c.Batching.Timeout = 5 * time.Second
	}

	// Retry defaults (production resilience)
	if c.Retry.InitialInterval == 0 {
		c.Retry.InitialInterval = 1 * time.Second
	}
	if c.Retry.MaxInterval == 0 {
		c.Retry.MaxInterval = 30 * time.Second
	}
	if c.Retry.MaxElapsedTime == 0 {
		c.Retry.MaxElapsedTime = 5 * time.Minute
	}

	// Metrics export defaults to enabled. Operators flip it off via
	// otel_observability.metrics.enabled: false (or env GIBSON_OTEL_OBSERVABILITY_METRICS_ENABLED=false)
	// when the OTLP target is trace-only (e.g. Langfuse).
	if c.Metrics.Enabled == nil {
		t := true
		c.Metrics.Enabled = &t
	}
}

// ApplyDefaults fills in zero-valued fields with sensible defaults.
// This is useful when loading partial configurations from files or environment.
func (c *RedisConfig) ApplyDefaults() {
	if c.URL == "" && !c.ClusterMode && c.SentinelMaster == "" {
		c.URL = "redis://localhost:6379"
	}

	if c.Database < 0 {
		c.Database = 0
	}

	if c.PoolSize == 0 {
		c.PoolSize = 10
	}

	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = 5 * time.Second
	}

	if c.ReadTimeout == 0 {
		c.ReadTimeout = 3 * time.Second
	}

	if c.WriteTimeout == 0 {
		c.WriteTimeout = 3 * time.Second
	}

	if c.MaxRetries == 0 {
		c.MaxRetries = 3
	}
}

// AuthzConfig contains all OpenFGA authorization configuration.
//
// One-code-path epic (slice deploy#195): FGA is a hard dependency. There is no
// `enabled` / `require_ready` toggle anymore — every environment dials a real
// OpenFGA endpoint at startup and the daemon refuses to come up if it is
// unreachable. The legacy fields are silently accepted in the YAML for
// backwards compatibility, but they no longer change behaviour.
//
// Example config:
//
//	authz:
//	  provider: openfga
//	  enforcement_source: fga
//	  fga:
//	    endpoint: gibson-fga:8080
//	    store_id: ""      # resolved from ConfigMap if empty
//	    model_id: ""      # resolved from ConfigMap if empty
//	    timeout_ms: 500
//	    tls:
//	      enabled: false
type AuthzConfig struct {
	// Provider is the authorization provider name. Only "openfga" is supported.
	Provider string `mapstructure:"provider" yaml:"provider"`

	// EnforcementSource is retained for config-file backwards compatibility.
	// The only valid value is "fga"; the daemon ignores any other value and
	// always uses FGA as the sole authorization backend.
	// Override via env: GIBSON_AUTHZ_ENFORCEMENT_SOURCE
	EnforcementSource string `mapstructure:"enforcement_source" yaml:"enforcement_source"`

	// Fga holds OpenFGA-specific settings.
	Fga FgaClientConfig `mapstructure:"fga" yaml:"fga"`
}

// FgaClientConfig holds OpenFGA client connection settings.
type FgaClientConfig struct {
	// Endpoint is the HTTP endpoint for the OpenFGA server.
	// Default: "gibson-fga:8080" (in-cluster)
	// Override via env: GIBSON_AUTHZ_FGA_ENDPOINT
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint"`

	// StoreID is the OpenFGA store identifier (ULID format).
	// If empty, resolved at startup from the gibson-fga-config ConfigMap.
	// Override via env: GIBSON_AUTHZ_FGA_STORE_ID
	StoreID string `mapstructure:"store_id" yaml:"store_id"`

	// ModelID is the OpenFGA authorization model identifier (ULID format).
	// If empty, resolved at startup from the gibson-fga-config ConfigMap.
	// Override via env: GIBSON_AUTHZ_FGA_MODEL_ID
	ModelID string `mapstructure:"model_id" yaml:"model_id"`

	// TimeoutMs is the per-call timeout in milliseconds.
	// Default: 500
	TimeoutMs int `mapstructure:"timeout_ms" yaml:"timeout_ms"`

	// TLS holds TLS configuration for the FGA connection.
	TLS FgaTLSConfig `mapstructure:"tls" yaml:"tls"`
}

// FgaTLSConfig holds TLS settings for the FGA client connection.
type FgaTLSConfig struct {
	// Enabled controls whether TLS is used when connecting to FGA.
	// Default: false (in-cluster pod-to-pod traffic is already protected)
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
}
