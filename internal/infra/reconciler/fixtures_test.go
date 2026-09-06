// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package reconciler

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

type listObjectsKey struct {
	User       string
	Relation   string
	ObjectType string
}

type listUsersKey struct {
	ObjectType string
	Object     string
	Relation   string
}

// recordingAuthorizer is a hand-rolled stub for the authz.Authorizer
// interface. It serves canned answers for List* and records Write calls so
// tests can assert on the resulting state-change request. The other methods
// are present to satisfy the interface but return zero values; tests that
// need them should grow the stub.
type recordingAuthorizer struct {
	listObjects map[listObjectsKey][]string
	listUsers   map[listUsersKey][]string
	writes      []authz.Tuple
}

func (a *recordingAuthorizer) ListObjects(_ context.Context, user, relation, objectType string) ([]string, error) {
	return a.listObjects[listObjectsKey{User: user, Relation: relation, ObjectType: objectType}], nil
}

func (a *recordingAuthorizer) ListUsers(_ context.Context, objectType, object, relation string) ([]string, error) {
	return a.listUsers[listUsersKey{ObjectType: objectType, Object: object, Relation: relation}], nil
}

// ListUsersOfType is the typed enumeration the CatalogFanout type-asserts for.
// The canned map is keyed by (objectType, object, relation); userType only
// narrows the FGA user-filter and does not change the fixture lookup.
func (a *recordingAuthorizer) ListUsersOfType(_ context.Context, objectType, object, relation, _ string) ([]string, error) {
	return a.listUsers[listUsersKey{ObjectType: objectType, Object: object, Relation: relation}], nil
}

func (a *recordingAuthorizer) Write(_ context.Context, tuples []authz.Tuple) error {
	a.writes = append(a.writes, tuples...)
	return nil
}

// Interface-completeness stubs — return zero values; tests that exercise
// these paths should grow recordingAuthorizer rather than hand-rolling
// another stub.
func (a *recordingAuthorizer) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (a *recordingAuthorizer) BatchCheck(context.Context, []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (a *recordingAuthorizer) Delete(context.Context, []authz.Tuple) error { return nil }
func (a *recordingAuthorizer) StoreID() string                             { return "" }
func (a *recordingAuthorizer) ModelID() string                             { return "" }
func (a *recordingAuthorizer) Close() error                                { return nil }
