// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — test_fakes_test.go provides deterministic in-memory
// fakes for the authorizer and the audit writer, so handler tests run
// without the production FGA stack.
//
// All fakes are confined to test compilation by living in a *_test.go
// file. They share the api package with the handlers so they can
// reference unexported types.
package api

import (
	"context"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// fakeAuthorizer is a programmable authzIface that scripts Check
// responses by (user, relation, object) tuple. Unscripted tuples return false.
type fakeAuthorizer struct {
	mu           sync.RWMutex
	allowed      map[string]bool     // user|relation|object
	objects      map[string][]string // user|relation|objectType -> object IDs (ListObjects)
	users        map[string][]string // objectType|object|relation -> user refs (ListUsers)
	listUsersErr error
	checks       []checkRecord
	writes       []authz.Tuple // tuples captured by Write
}

type checkRecord struct {
	User, Relation, Object string
}

func newFakeAuthorizer() *fakeAuthorizer {
	return &fakeAuthorizer{allowed: make(map[string]bool), objects: make(map[string][]string), users: make(map[string][]string)}
}

// withObjects scripts the ListObjects(user, relation, objectType) result.
func (a *fakeAuthorizer) withObjects(user, relation, objectType string, objects ...string) *fakeAuthorizer {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.objects[user+"|"+relation+"|"+objectType] = objects
	return a
}

func (a *fakeAuthorizer) allow(user, relation, object string) *fakeAuthorizer {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.allowed[user+"|"+relation+"|"+object] = true
	return a
}

func (a *fakeAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.checks = append(a.checks, checkRecord{User: user, Relation: relation, Object: object})
	return a.allowed[user+"|"+relation+"|"+object], nil
}

func (a *fakeAuthorizer) BatchCheck(ctx context.Context, checks []authz.CheckRequest) ([]bool, error) {
	out := make([]bool, len(checks))
	for i, c := range checks {
		ok, _ := a.Check(ctx, c.User, c.Relation, c.Object)
		out[i] = ok
	}
	return out, nil
}

func (a *fakeAuthorizer) Write(_ context.Context, tuples []authz.Tuple) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.writes = append(a.writes, tuples...)
	return nil
}
func (a *fakeAuthorizer) Delete(_ context.Context, _ []authz.Tuple) error { return nil }

// writtenTuples returns a copy of all tuples captured by Write.
func (a *fakeAuthorizer) writtenTuples() []authz.Tuple {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]authz.Tuple, len(a.writes))
	copy(out, a.writes)
	return out
}
func (a *fakeAuthorizer) ListObjects(_ context.Context, user, relation, objectType string) ([]string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.objects[user+"|"+relation+"|"+objectType], nil
}
func (a *fakeAuthorizer) ListUsers(ctx context.Context, objectType, object, relation string) ([]string, error) {
	return a.ListUsersOfType(ctx, objectType, object, relation, "user")
}

// withUsers scripts the ListUsers(objectType, object, relation) result.
func (a *fakeAuthorizer) withUsers(objectType, object, relation string, users ...string) *fakeAuthorizer {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.users[objectType+"|"+object+"|"+relation] = users
	return a
}

// withListUsersError makes every ListUsers call fail.
func (a *fakeAuthorizer) withListUsersError(err error) *fakeAuthorizer {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.listUsersErr = err
	return a
}

// newFakeAuditWriter returns an instance of the fakeAuditWriter
// defined in tenant_admin_create_test.go (declared once package-wide).
func newFakeAuditWriter() *fakeAuditWriter { return &fakeAuditWriter{} }

// recordedEvents returns a copy of the captured audit events. Wrapper
// around the package-level fakeAuditWriter (no mutex) so tests can
// snapshot without racing with concurrent Log calls.
func (a *fakeAuditWriter) recorded() []audit.Event {
	out := make([]audit.Event, len(a.events))
	copy(out, a.events)
	return out
}

// ListUsersOfType is unused by this package's tests. It exists because the
// method is on authz.Authorizer — a gate reached by type assertion was
// silently skipped by every double that did not implement it.
func (a *fakeAuthorizer) ListUsersOfType(_ context.Context, objectType, object, relation, _ string) ([]string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.listUsersErr != nil {
		return nil, a.listUsersErr
	}
	return a.users[objectType+"|"+object+"|"+relation], nil
}
