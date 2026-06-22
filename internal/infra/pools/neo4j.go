package pools

import (
	"fmt"
	"time"

	neo4j "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	neo4jconfig "github.com/neo4j/neo4j-go-driver/v5/neo4j/config"
)

const (
	// defaultNeo4jIdlePingInterval is the interval at which the driver pings
	// idle connections to keep them alive. 30 s is the production-safe default
	// (Neo4j server-side default idle timeout is typically 5–10 minutes).
	defaultNeo4jIdlePingInterval = 30 * time.Second
)

// Neo4jOptions carries required and optional tuning for NewNeo4j.
// Required fields must be non-zero; NewNeo4j returns an error otherwise.
type Neo4jOptions struct {
	// MaxConnectionLifetime is the maximum duration a pooled connection is
	// kept alive before being closed and replaced.
	//
	// Required: must be > 0. A common production value is 1 hour.
	MaxConnectionLifetime time.Duration

	// ConnectionAcquisitionTimeout is the maximum time NewNeo4j will wait
	// to acquire a connection from the pool before returning an error to
	// the caller.
	//
	// Required: must be > 0. A common production value is 60 s.
	ConnectionAcquisitionTimeout time.Duration

	// MaxConnectionPoolSize caps the total number of connections in the
	// driver pool. Defaults to the neo4j-go-driver default (100) when 0.
	MaxConnectionPoolSize int

	// IdlePingInterval is how often idle connections are pinged to keep
	// them alive. Defaults to defaultNeo4jIdlePingInterval (30 s) when 0.
	IdlePingInterval time.Duration
}

// validate returns a non-nil error if any required field is zero.
func (o Neo4jOptions) validate() error {
	if o.MaxConnectionLifetime == 0 {
		return fmt.Errorf("pools.NewNeo4j: Neo4jOptions.MaxConnectionLifetime is required (must be > 0)")
	}
	if o.ConnectionAcquisitionTimeout == 0 {
		return fmt.Errorf("pools.NewNeo4j: Neo4jOptions.ConnectionAcquisitionTimeout is required (must be > 0)")
	}
	return nil
}

// NewNeo4j constructs a neo4j.DriverWithContext with required-override enforcement.
//
// Required opts fields: MaxConnectionLifetime, ConnectionAcquisitionTimeout.
// Returns an error when either is zero.
//
// The driver is safe for concurrent use. Callers must call driver.Close when
// done to release underlying connections.
//
// Anti-pattern warning: see package doc for the function-scoped defer
// pitfall when creating sessions inside a for-loop.
func NewNeo4j(uri string, auth neo4j.AuthToken, opts Neo4jOptions) (neo4j.DriverWithContext, error) {
	if uri == "" {
		return nil, fmt.Errorf("pools.NewNeo4j: uri must not be empty")
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}

	if opts.IdlePingInterval == 0 {
		opts.IdlePingInterval = defaultNeo4jIdlePingInterval
	}

	configurers := []func(*neo4jconfig.Config){
		func(c *neo4jconfig.Config) {
			c.MaxConnectionLifetime = opts.MaxConnectionLifetime
			c.ConnectionAcquisitionTimeout = opts.ConnectionAcquisitionTimeout
			if opts.MaxConnectionPoolSize > 0 {
				c.MaxConnectionPoolSize = opts.MaxConnectionPoolSize
			}
		},
	}

	driver, err := neo4j.NewDriverWithContext(uri, auth, configurers...)
	if err != nil {
		return nil, fmt.Errorf("pools.NewNeo4j: creating driver: %w", err)
	}

	return driver, nil
}
