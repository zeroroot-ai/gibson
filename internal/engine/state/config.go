package state

import (
	"crypto/tls"
	"errors"
	"time"
)

// Config configures the Redis state client.
// It supports multiple deployment modes: standalone, cluster, and sentinel.
type Config struct {
	// URL is the Redis connection string for standalone mode.
	// Format: redis://[:password@]host:port[/database]
	// Example: "redis://localhost:6379/0"
	URL string

	// Password is the Redis authentication password.
	// Optional if Redis doesn't require authentication.
	Password string

	// Database is the Redis database number (0-15).
	// Only applicable in standalone mode. Cluster mode ignores this.
	Database int

	// PoolSize is the maximum number of connections in the pool.
	// Defaults to 10 * runtime.NumCPU().
	PoolSize int

	// DialTimeout is the timeout for establishing new connections.
	// Defaults to 5 seconds.
	DialTimeout time.Duration

	// ReadTimeout is the timeout for read operations.
	// Defaults to 3 seconds.
	ReadTimeout time.Duration

	// WriteTimeout is the timeout for write operations.
	// Defaults to 3 seconds.
	WriteTimeout time.Duration

	// MaxRetries is the maximum number of retries before giving up.
	// Defaults to 3.
	MaxRetries int

	// MinIdleConns is the minimum number of idle connections to maintain.
	// Defaults to 2.
	MinIdleConns int

	// MaxConnAge is the maximum lifetime of a connection.
	// Defaults to 0 (no maximum).
	MaxConnAge time.Duration

	// PoolTimeout is the timeout when waiting for a connection from the pool.
	// Defaults to ReadTimeout + 1 second.
	PoolTimeout time.Duration

	// IdleTimeout is the timeout for idle connections to be closed.
	// Defaults to 5 minutes.
	IdleTimeout time.Duration

	// IdleCheckFrequency is how often to check for idle connections to close.
	// Defaults to 1 minute.
	IdleCheckFrequency time.Duration

	// Cluster mode configuration
	// ClusterMode enables Redis Cluster mode.
	// When true, ClusterAddrs must be provided instead of URL.
	ClusterMode bool

	// ClusterAddrs is the list of cluster node addresses.
	// Only used when ClusterMode is true.
	// Example: []string{"node1:6379", "node2:6379", "node3:6379"}
	ClusterAddrs []string

	// Sentinel mode configuration
	// SentinelMaster is the name of the master instance in Sentinel mode.
	// When set, SentinelAddrs must also be provided.
	SentinelMaster string

	// SentinelAddrs is the list of Sentinel addresses.
	// Only used when SentinelMaster is set.
	// Example: []string{"sentinel1:26379", "sentinel2:26379"}
	SentinelAddrs []string

	// SentinelPassword is the password for Sentinel authentication.
	// Optional if Sentinels don't require authentication.
	SentinelPassword string

	// TLS configuration
	// TLSEnabled enables TLS for Redis connections.
	TLSEnabled bool

	// TLSConfig provides custom TLS configuration.
	// If nil and TLSEnabled is true, default TLS config is used.
	TLSConfig *tls.Config
}

// DefaultConfig returns a Config with sensible defaults for standalone Redis.
// All timeout and pool settings are pre-configured for typical workloads.
func DefaultConfig() *Config {
	return &Config{
		URL:                "redis://localhost:6379/0",
		Database:           0,
		PoolSize:           10,
		DialTimeout:        5 * time.Second,
		ReadTimeout:        3 * time.Second,
		WriteTimeout:       3 * time.Second,
		MaxRetries:         3,
		MinIdleConns:       2,
		MaxConnAge:         0,
		PoolTimeout:        4 * time.Second, // ReadTimeout + 1s
		IdleTimeout:        5 * time.Minute,
		IdleCheckFrequency: 1 * time.Minute,
		ClusterMode:        false,
		TLSEnabled:         false,
	}
}

// ApplyDefaults fills in any zero-valued fields with sensible defaults.
// This is useful when loading partial configurations from files or environment.
func (c *Config) ApplyDefaults() {
	if c.URL == "" && !c.ClusterMode && c.SentinelMaster == "" {
		c.URL = "redis://localhost:6379/0"
	}

	if c.PoolSize == 0 {
		c.PoolSize = 10
	}

	if c.DialTimeout == 0 {
		c.DialTimeout = 5 * time.Second
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

	if c.MinIdleConns == 0 {
		c.MinIdleConns = 2
	}

	if c.PoolTimeout == 0 {
		c.PoolTimeout = c.ReadTimeout + time.Second
	}

	if c.IdleTimeout == 0 {
		c.IdleTimeout = 5 * time.Minute
	}

	if c.IdleCheckFrequency == 0 {
		c.IdleCheckFrequency = 1 * time.Minute
	}
}

// Validate checks the configuration for errors and returns any issues found.
// This should be called before passing the config to NewStateClient.
func (c *Config) Validate() error {
	// Ensure at least one connection method is specified
	if !c.ClusterMode && c.SentinelMaster == "" && c.URL == "" {
		return NewConnectionError("validate", "",
			errors.New("must specify URL, ClusterAddrs, or SentinelMaster"))
	}

	// Cluster mode validation
	if c.ClusterMode {
		if len(c.ClusterAddrs) == 0 {
			return NewConnectionError("validate", "",
				errors.New("ClusterAddrs required when ClusterMode is true"))
		}
		if c.URL != "" && c.URL != "redis://localhost:6379/0" {
			// Allow default URL to be ignored, but warn if custom URL is set
			// This isn't an error, but cluster mode will ignore it
		}
	}

	// Sentinel mode validation
	if c.SentinelMaster != "" {
		if len(c.SentinelAddrs) == 0 {
			return NewConnectionError("validate", "",
				errors.New("SentinelAddrs required when SentinelMaster is set"))
		}
	}

	// Database validation (only applies to standalone)
	if c.Database < 0 || c.Database > 15 {
		return NewConnectionError("validate", "",
			errors.New("database must be between 0 and 15"))
	}

	return nil
}
