// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package authz provides the authorization interface and implementations for Gibson.
//
// It wraps OpenFGA (a Google Zanzibar-based relationship-authorization service)
// behind a mockable interface, keeping all FGA-specific code isolated from the
// rest of the daemon.
//
// One-code-path slice deploy#195: the noopAuthorizer was deleted. Every running
// daemon dials a real OpenFGA endpoint at startup; if that endpoint is
// unreachable the daemon exits 1. Tests inject their own fake or stub
// Authorizer implementations (see internal/infra/datapool/admin and internal/admin
// for reference patterns).
package authz

import "context"

// Authorizer is the single authorization contract used across the entire Gibson codebase.
//
// All callers — gRPC interceptors, CLI subcommands, the harness — use this interface.
// The concrete implementation wraps github.com/openfga/go-sdk.
//
// Implementations must be safe for concurrent use.
type Authorizer interface {
	// Check returns true if the given user has the given relation on the given object.
	//
	// user, relation, and object must be non-empty; if any is empty, ErrInvalidArgument
	// is returned without consulting FGA. The FGA tuple format uses colon notation:
	// user = "user:<uuid>", relation = "admin", object = "tenant:<slug>".
	Check(ctx context.Context, user, relation, object string) (bool, error)

	// BatchCheck evaluates multiple authorization checks in a single FGA API call.
	//
	// Results are returned in the same order as the input checks slice.
	// Any individual check failure propagates the error for that check only;
	// the slice is still returned with the other results set to false.
	BatchCheck(ctx context.Context, checks []CheckRequest) ([]bool, error)

	// Write creates or updates one or more relationship tuples in FGA.
	//
	// All tuples in the slice are submitted in a single API call. Write is
	// idempotent per tuple: tuples that already exist are skipped and the
	// rest are written. (OpenFGA itself rejects the whole batch when one
	// tuple exists; the implementation resolves that per tuple.)
	Write(ctx context.Context, tuples []Tuple) error

	// Delete removes one or more relationship tuples from FGA.
	//
	// All tuples in the slice are submitted in a single API call. If a tuple
	// does not exist, FGA treats it as a no-op (idempotent delete).
	Delete(ctx context.Context, tuples []Tuple) error

	// ListObjects returns the IDs of all objects of the given type for which
	// the given user has the given relation.
	//
	// Example: ListObjects(ctx, "user:alice", "admin", "tenant") returns all
	// tenant IDs where alice is an admin.
	ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error)

	// ListUsers returns the user IDs that have the given relation on the given object.
	//
	// objectType and object together identify the FGA object (e.g. objectType="tenant",
	// object="tenant:acme"). The returned strings are FGA user references such as
	// "user:<uuid>".
	//
	// The subject-type filter is hardcoded to "user". A relation model.fga says
	// cannot yield a "user" subject is refused, not answered with an empty list.
	ListUsers(ctx context.Context, objectType, object, relation string) ([]string, error)

	// ListUsersOfType is ListUsers at an explicit subject type — the tenants
	// holding team#parent, say, rather than the users.
	//
	// It is on this interface rather than behind a type assertion because the
	// callers are security gates. A gate that asks `authorizer.(interface{
	// ListUsersOfType(...) })` gets its answer at runtime from whatever wrapper
	// the daemon happens to have composed, and every non-fga implementation —
	// every test double, every decorator that forgets to forward — silently
	// turns the gate off. As a method on Authorizer the same mistake is a
	// compile error.
	ListUsersOfType(ctx context.Context, objectType, object, relation, userType string) ([]string, error)

	// StoreID returns the FGA store ID this authorizer is connected to.
	// Returns an empty string for the no-op implementation.
	StoreID() string

	// ModelID returns the FGA authorization model ID in use.
	// Returns an empty string for the no-op implementation.
	ModelID() string

	// Close releases the underlying gRPC connection.
	// Must be called when the Authorizer is no longer needed.
	Close() error
}

// Tuple is a relationship triple in the FGA data model.
//
// All three fields use OpenFGA's colon-delimited type:id notation:
//   - User:   "user:<uuid>" or "user:_system" or "tenant:<slug>#member"
//   - Object: "tenant:<slug>", "component:<name>", "system_tenant:_system"
type Tuple struct {
	// User is the FGA user reference, e.g. "user:alice" or "tenant:acme#member".
	User string

	// Relation is the relationship name, e.g. "admin", "member", "can_execute".
	Relation string

	// Object is the FGA object reference, e.g. "tenant:zeroroot-ai".
	Object string
}

// CheckRequest is a single authorization check for use in BatchCheck.
type CheckRequest struct {
	// User is the FGA user reference.
	User string

	// Relation is the relationship name.
	Relation string

	// Object is the FGA object reference.
	Object string
}

// ConditionalWriter is the optional interface implemented by Authorizer
// implementations that support condition-bearing tuple writes (gibson#627).
//
// Callers that need WriteConditional / UpdateConditionalTuple should type-assert
// the Authorizer they hold to ConditionalWriter before calling. This keeps the
// base Authorizer interface stable (no breakage of existing test fakes) while
// allowing new callers to opt in to the extended capability.
//
// The concrete fgaAuthorizer returned by NewFgaAuthorizer implements both
// Authorizer and ConditionalWriter.
type ConditionalWriter interface {
	// WriteConditional writes a single condition-bearing relationship tuple.
	//
	// The tuple carries a named condition (e.g. "token_not_revoked") and a
	// context map of parameter values (e.g. {"revoked_at": "1970-01-01T00:00:00Z"}).
	// Idempotent: if an identical tuple+condition+context already exists, the
	// call is a no-op (no error returned).
	WriteConditional(ctx context.Context, t ConditionalTuple) error

	// UpdateConditionalTuple atomically replaces the context of an existing
	// condition-bearing tuple by deleting the old tuple and writing the new one
	// in a single FGA WriteRequest.
	//
	// If no tuple with the given (user, relation, object) exists yet (pre-backfill
	// callers), UpdateConditionalTuple falls back to a plain WriteConditional so
	// the caller never needs to distinguish between "create" and "update".
	UpdateConditionalTuple(ctx context.Context, t ConditionalTuple) error
}

// ConditionalTuple is a relationship tuple carrying an OpenFGA condition.
//
// It extends Tuple with the condition name and a context map of parameter
// values. The context map values must be JSON-serialisable and must match
// the types declared in the condition definition (e.g. RFC 3339 strings for
// timestamp parameters).
//
// Example for token_not_revoked:
//
//	ConditionalTuple{
//	    User:          "user:alice",
//	    Relation:      "active_session",
//	    Object:        "tenant:acme",
//	    ConditionName: "token_not_revoked",
//	    ConditionContext: map[string]any{"revoked_at": "1970-01-01T00:00:00Z"},
//	}
type ConditionalTuple struct {
	// User, Relation, Object follow the same FGA colon-notation as Tuple.
	User     string
	Relation string
	Object   string

	// ConditionName is the name of the OpenFGA condition as declared in model.fga.
	ConditionName string

	// ConditionContext is the map of parameter name → value for the condition.
	// Values must be JSON-serialisable and type-compatible with the condition's
	// parameter declarations (e.g. RFC 3339 strings for timestamp parameters).
	ConditionContext map[string]any
}
