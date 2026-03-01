package config

import (
	"time"

	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/memory/embedder"
	"github.com/zero-day-ai/gibson/internal/prompt"
)

// Config is the root configuration for the Gibson Framework.
type Config struct {
	Core         CoreConfig              `mapstructure:"core" yaml:"core" validate:"required"`
	Database     DBConfig                `mapstructure:"database" yaml:"database" validate:"required"`
	Security     SecurityConfig          `mapstructure:"security" yaml:"security" validate:"required"`
	LLM          LLMConfig               `mapstructure:"llm" yaml:"llm"`
	Memory       memory.MemoryConfig     `mapstructure:"memory" yaml:"memory"`
	Prompt       prompt.PromptConfig     `mapstructure:"prompt" yaml:"prompt"`
	Logging      LoggingConfig           `mapstructure:"logging" yaml:"logging"`
	Tracing      TracingConfig           `mapstructure:"tracing" yaml:"tracing"`
	Metrics      MetricsConfig           `mapstructure:"metrics" yaml:"metrics"`
	Registration RegistrationConfig      `mapstructure:"registration" yaml:"registration,omitempty"`
	Registry     RegistryConfig          `mapstructure:"registry" yaml:"registry"`
	Callback     CallbackConfig          `mapstructure:"callback" yaml:"callback,omitempty"`
	Daemon       DaemonConfig            `mapstructure:"daemon" yaml:"daemon,omitempty"`
	Embedder        embedder.EmbedderConfig `mapstructure:"embedder" yaml:"embedder"`
	Langfuse        LangfuseConfig          `mapstructure:"langfuse" yaml:"langfuse"`
	GraphRAG        GraphRAGConfig          `mapstructure:"graphrag" yaml:"graphrag"`
	Redis           RedisConfig             `mapstructure:"redis" yaml:"redis"`
	Plugins         PluginsConfig           `mapstructure:"plugins" yaml:"plugins,omitempty"`
	ActivityLogging ActivityLoggingConfig   `mapstructure:"activity_logging" yaml:"activity_logging"`
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

// DBConfig contains database configuration.
type DBConfig struct {
	Path           string        `mapstructure:"path" yaml:"path"`
	MaxConnections int           `mapstructure:"max_connections" yaml:"max_connections" validate:"min=1,max=100"`
	Timeout        time.Duration `mapstructure:"timeout" yaml:"timeout" validate:"min=1s"`
	WALMode        bool          `mapstructure:"wal_mode" yaml:"wal_mode"`
	AutoVacuum     bool          `mapstructure:"auto_vacuum" yaml:"auto_vacuum"`
}

// SecurityConfig contains security-related settings.
type SecurityConfig struct {
	EncryptionAlgorithm string `mapstructure:"encryption_algorithm" yaml:"encryption_algorithm"`
	KeyDerivation       string `mapstructure:"key_derivation" yaml:"key_derivation"`
	SSLValidation       bool   `mapstructure:"ssl_validation" yaml:"ssl_validation"`
	AuditLogging        bool   `mapstructure:"audit_logging" yaml:"audit_logging"`
}

// LLMConfig contains LLM provider configuration (stub for future stages).
type LLMConfig struct {
	DefaultProvider string `mapstructure:"default_provider" yaml:"default_provider"`
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

// RegistryConfig contains configuration for service discovery via etcd-based registry.
// Supports both embedded etcd (for local development) and external etcd cluster (for production).
type RegistryConfig struct {
	// Type specifies the registry mode: "embedded" (default) or "etcd"
	Type string `mapstructure:"type" yaml:"type"`

	// DataDir is the directory for embedded etcd data storage (default: ~/.gibson/etcd-data)
	DataDir string `mapstructure:"data_dir" yaml:"data_dir"`

	// ListenAddress is the address for embedded etcd to listen on (default: localhost:2379)
	ListenAddress string `mapstructure:"listen_address" yaml:"listen_address"`

	// Endpoints is the list of external etcd endpoints (required when Type="etcd")
	Endpoints []string `mapstructure:"endpoints" yaml:"endpoints"`

	// Namespace is the service prefix for all registry keys (default: "gibson")
	Namespace string `mapstructure:"namespace" yaml:"namespace"`

	// TTL is the lease time-to-live for service registration (default: "30s")
	TTL string `mapstructure:"ttl" yaml:"ttl"`

	// TLS contains TLS configuration for etcd connections
	TLS TLSConfig `mapstructure:"tls" yaml:"tls"`
}

// TLSConfig contains TLS/SSL configuration for secure etcd connections.
type TLSConfig struct {
	// Enabled controls whether TLS is used for etcd connections
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// CertFile is the path to the client certificate file
	CertFile string `mapstructure:"cert_file" yaml:"cert_file"`

	// KeyFile is the path to the client private key file
	KeyFile string `mapstructure:"key_file" yaml:"key_file"`

	// CAFile is the path to the certificate authority file
	CAFile string `mapstructure:"ca_file" yaml:"ca_file"`
}

// DaemonConfig contains configuration for the Gibson daemon process.
type DaemonConfig struct {
	// GRPCAddress is the address for the daemon's gRPC API server.
	// Clients connect to this address to communicate with the daemon.
	// Default: "localhost:50002"
	// Can be overridden via GIBSON_DAEMON_GRPC_ADDR environment variable.
	GRPCAddress string `mapstructure:"grpc_address" yaml:"grpc_address"`
}

// LangfuseConfig contains Langfuse LLM observability configuration.
type LangfuseConfig struct {
	Enabled   bool   `mapstructure:"enabled" yaml:"enabled"`
	Host      string `mapstructure:"host" yaml:"host"`
	PublicKey string `mapstructure:"public_key" yaml:"public_key"`
	SecretKey string `mapstructure:"secret_key" yaml:"secret_key"`
}

// Neo4jConfig contains Neo4j connection settings.
type Neo4jConfig struct {
	URI               string        `mapstructure:"uri" yaml:"uri"`
	Username          string        `mapstructure:"username" yaml:"username"`
	Password          string        `mapstructure:"password" yaml:"password"`
	MaxConnections    int           `mapstructure:"max_connections" yaml:"max_connections"`
	ConnectionTimeout time.Duration `mapstructure:"connection_timeout" yaml:"connection_timeout"`
}

// GraphRAGConfig contains Neo4j knowledge graph configuration.
type GraphRAGConfig struct {
	Enabled bool        `mapstructure:"enabled" yaml:"enabled"`
	Neo4j   Neo4jConfig `mapstructure:"neo4j" yaml:"neo4j"`
}

// RedisConfig contains Redis connection settings for tool execution.
type RedisConfig struct {
	URL            string        `mapstructure:"url" yaml:"url"`
	Database       int           `mapstructure:"database" yaml:"database"`
	ConnectTimeout time.Duration `mapstructure:"connect_timeout" yaml:"connect_timeout"`
	ReadTimeout    time.Duration `mapstructure:"read_timeout" yaml:"read_timeout"`
}
