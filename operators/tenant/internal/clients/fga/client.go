// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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

// ConditionalTuple is a relationship tuple that carries an OpenFGA condition.
//
// The condition name must match a condition declared in model.fga; the context
// map values must be JSON-serialisable and type-compatible with the condition's
// parameter declarations (e.g. RFC 3339 strings for timestamp parameters).
//
// Example for the token_not_revoked condition (gibson#627):
//
//	ConditionalTuple{
//	    User:          "user:alice",
//	    Relation:      "active_session",
//	    Object:        "tenant:acme",
//	    ConditionName: "token_not_revoked",
//	    ConditionContext: map[string]any{"revoked_at": "1970-01-01T00:00:00Z"},
//	}
type ConditionalTuple struct {
	User             string
	Relation         string
	Object           string
	ConditionName    string
	ConditionContext map[string]any
}

// Client is the FGA admin interface.
type Client interface {
	// Write tuples atomically. Returns ErrAlreadyExists if any tuple
	// already exists (depending on mode — see WriteOpts).
	Write(ctx context.Context, tuples []Tuple) error

	// WriteConditional writes a single condition-bearing FGA tuple. Idempotent:
	// if an identical (user, relation, object, condition, context) tuple already
	// exists, the call returns nil.
	WriteConditional(ctx context.Context, t ConditionalTuple) error

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
