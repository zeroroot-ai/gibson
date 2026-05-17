// Package authz provides the authorization interface and implementations for Gibson.
//
// It wraps OpenFGA (a Google Zanzibar-based relationship-authorization service)
// behind a mockable interface, keeping all FGA-specific code isolated from the
// rest of the daemon.
//
// One-code-path slice deploy#195: the noopAuthorizer was deleted. Every running
// daemon dials a real OpenFGA endpoint at startup; if that endpoint is
// unreachable the daemon exits 1. Tests inject their own fake or stub
// Authorizer implementations (see internal/datapool/admin and internal/admin
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
	// All tuples in the slice are submitted in a single API call. If any tuple
	// already exists, FGA treats it as a no-op (idempotent write).
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
	ListUsers(ctx context.Context, objectType, object, relation string) ([]string, error)

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

	// Object is the FGA object reference, e.g. "tenant:zero-day-ai".
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
