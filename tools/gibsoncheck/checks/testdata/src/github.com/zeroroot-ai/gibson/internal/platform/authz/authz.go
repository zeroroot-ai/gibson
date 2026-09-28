// Package authz is an analyzer-fixture stub of the real
// internal/platform/authz package. It carries only what the guards
// resolve types against: the Authorizer contract and CheckRequest.
package authz

import "context"

// CheckRequest mirrors the real batch-check element.
type CheckRequest struct {
	User     string
	Relation string
	Object   string
}

// Tuple mirrors the real relationship-tuple shape. Added for the
// tenantrolewrite guard (ADR-0093), which matches tuple-literal writes by
// type identity.
type Tuple struct {
	User     string
	Relation string
	Object   string
}

// ConditionalTuple mirrors the real condition-bearing tuple shape.
type ConditionalTuple struct {
	User             string
	Relation         string
	Object           string
	ConditionName    string
	ConditionContext map[string]any
}

// ActiveSessionObject mirrors the real helper the tenantrolewrite guard
// recognizes as a tenant-object constructor.
func ActiveSessionObject(tenantSlug string) string {
	return "tenant:" + tenantSlug
}

// Authorizer is the authorization contract the guards key on.
type Authorizer interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	BatchCheck(ctx context.Context, checks []CheckRequest) ([]bool, error)
	ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error)
	ListUsers(ctx context.Context, objectType, object, relation string) ([]string, error)
	ListUsersOfType(ctx context.Context, objectType, object, relation, subjectType string) ([]string, error)
}
