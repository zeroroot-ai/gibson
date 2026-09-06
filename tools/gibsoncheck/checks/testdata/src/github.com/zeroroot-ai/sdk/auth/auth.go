// Package auth is an analyzer-fixture stub of the OSS SDK auth
// package. It carries the privileged sentinels and the fallible
// security accessors that the privilegedfallback guard derives its
// accessor set from.
package auth

import "context"

// TenantID is the tenant handle carried on the request context.
type TenantID struct {
	Slug string
}

func (t TenantID) String() string { return t.Slug }

// SystemTenant is the platform-operator tenant — a declared privileged
// sentinel.
var SystemTenant = TenantID{Slug: "_system"}

// SystemTenantString is the string form of the platform-operator
// tenant — also a declared privileged sentinel.
const SystemTenantString = "_system"

// Identity is the authenticated caller.
type Identity struct {
	Subject string
}

// TenantFromContext reports the caller's tenant. Absence is the second
// result, never a privileged default.
func TenantFromContext(ctx context.Context) (TenantID, bool) { return TenantID{}, false }

// IdentityFromContext reports the caller's identity.
func IdentityFromContext(ctx context.Context) (Identity, error) { return Identity{}, nil }

// ActingUserFromContext reports the synchronous RPC caller.
func ActingUserFromContext(ctx context.Context) (string, bool) { return "", false }

// TenantStringFromContext encodes absence as the empty string.
func TenantStringFromContext(ctx context.Context) string { return "" }

// NewTenantID parses a tenant slug.
func NewTenantID(s string) (TenantID, error) { return TenantID{Slug: s}, nil }
