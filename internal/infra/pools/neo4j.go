// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pools

import (
	"fmt"
	"time"
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
