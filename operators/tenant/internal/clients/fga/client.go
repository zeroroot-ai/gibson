// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package fga is the operator's client to OpenFGA for writing and deleting
// tuples that project from AgentEnrollment CRDs.
package fga

import (
	"context"
	"time"
)

// Tuple is a single FGA relationship tuple.
type Tuple struct {
	User     string // e.g. "user:alice"
	Relation string // e.g. "can_use"
	Object   string // e.g. "component:tool:nmap"
}

// Client is the FGA admin interface.
type Client interface {
	// Write tuples atomically. Returns ErrAlreadyExists if any tuple
	// already exists (depending on mode — see WriteOpts).
	Write(ctx context.Context, tuples []Tuple) error

	// Delete tuples atomically. Missing tuples are ignored.
	Delete(ctx context.Context, tuples []Tuple) error

	// Read returns tuples matching the given filter (user, relation,
	// or object may be empty wildcards).
	Read(ctx context.Context, filter Tuple) ([]Tuple, error)

	// Check whether a user has a relation on an object (authorization
	// decision).
	Check(ctx context.Context, user, relation, object string) (bool, error)

	// Ping performs a cheap read (empty filter, limit 1) to verify the FGA
	// store is reachable and the configured store ID is valid.
	Ping(ctx context.Context) error
}

// Config holds connection details.
type Config struct {
	BaseURL  string
	StoreID  string
	ModelID  string
	APIToken string
	Timeout  time.Duration
}
