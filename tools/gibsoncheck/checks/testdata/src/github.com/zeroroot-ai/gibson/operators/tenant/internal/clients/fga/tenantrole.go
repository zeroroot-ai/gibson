// Package fga is a testdata stand-in for the real
// operators/tenant/internal/clients/fga package. This file's path
// (.../clients/fga/tenantrole.go) is the guard's one file-level exemption
// outside internal/platform/tenantrole: the tenant-operator's adapter that
// translates a tenantrole.Tuple into this client's own Tuple shape. It
// constructs the exact role-tuple-on-a-tenant-object shape the violation
// fixture flags in every OTHER file, and it must NOT be flagged here.
package fga

// Tuple mirrors the real package's Tuple shape: the guard matches this
// type by its full path + name, so it must have that exact shape.
type Tuple struct {
	User, Relation, Object string
}

func adaptOwnerTuple(id, t string) Tuple {
	return Tuple{User: "user:" + id, Relation: "owner", Object: "tenant:" + t}
}
