/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package grants

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

// recordingFGA is a minimal in-memory fga.Client that records writes/deletes and
// answers Read from the current tuple set. It lets the provisioner tests assert
// write-if-absent (idempotency) and drift-correction without a live OpenFGA.
type recordingFGA struct {
	tuples    map[fga.Tuple]bool
	writes    [][]fga.Tuple
	deletes   [][]fga.Tuple
	reads     []fga.Tuple
	writeErr  error
	readErr   error
	deleteErr error
}

func newRecordingFGA(seed ...fga.Tuple) *recordingFGA {
	f := &recordingFGA{tuples: map[fga.Tuple]bool{}}
	for _, t := range seed {
		f.tuples[t] = true
	}
	return f
}

func (f *recordingFGA) Write(_ context.Context, tuples []fga.Tuple) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.writes = append(f.writes, tuples)
	for _, t := range tuples {
		f.tuples[t] = true
	}
	return nil
}

func (f *recordingFGA) Delete(_ context.Context, tuples []fga.Tuple) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deletes = append(f.deletes, tuples)
	for _, t := range tuples {
		delete(f.tuples, t)
	}
	return nil
}

func (f *recordingFGA) Read(_ context.Context, filter fga.Tuple) ([]fga.Tuple, error) {
	f.reads = append(f.reads, filter)
	if f.readErr != nil {
		return nil, f.readErr
	}
	if f.tuples[filter] {
		return []fga.Tuple{filter}, nil
	}
	return nil, nil
}

func (f *recordingFGA) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}

func (f *recordingFGA) Ping(context.Context) error { return nil }

func TestPlatformRegistrationTupleShape(t *testing.T) {
	tu := PlatformRegistrationTuple("acme")
	if tu.User != "tenant:acme" {
		t.Errorf("user = %q, want tenant:acme", tu.User)
	}
	if tu.Relation != "parent" {
		t.Errorf("relation = %q, want parent", tu.Relation)
	}
	if tu.Object != "system_tenant:_system" {
		t.Errorf("object = %q, want system_tenant:_system", tu.Object)
	}
}

func TestNewPanicsOnNilClient(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatalf("New(nil, ...) must panic (operator misconfigured)")
		}
	}()
	New(nil, nil)
}

// Provision writes a tuple that does not yet exist (write-if-absent).
func TestProvision_WritesAbsentTuple(t *testing.T) {
	fake := newRecordingFGA()
	p := New(fake, isNotFound)
	tu := PlatformRegistrationTuple("acme")

	if err := p.Provision(context.Background(), []fga.Tuple{tu}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if len(fake.writes) != 1 || len(fake.writes[0]) != 1 || fake.writes[0][0] != tu {
		t.Fatalf("want one write of the registration tuple, got %v", fake.writes)
	}
	if !fake.tuples[tu] {
		t.Fatalf("tuple not present after Provision")
	}
}

// Provision is idempotent: a tuple that already exists is NOT re-written
// (OpenFGA rejects duplicate writes; the read-before-write avoids it).
func TestProvision_IdempotentOnExistingTuple(t *testing.T) {
	tu := PlatformRegistrationTuple("acme")
	fake := newRecordingFGA(tu)
	p := New(fake, isNotFound)

	if err := p.Provision(context.Background(), []fga.Tuple{tu}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if len(fake.writes) != 0 {
		t.Fatalf("existing tuple must not be re-written, got writes %v", fake.writes)
	}
}

// Provision drift-corrects: when only some tuples are present, only the missing
// ones are written.
func TestProvision_DriftCorrectsMissingOnly(t *testing.T) {
	present := fga.Tuple{User: "tenant:acme", Relation: "parent", Object: "system_tenant:_system"}
	missing := fga.Tuple{User: "tenant:acme", Relation: "member", Object: "team:acme"}
	fake := newRecordingFGA(present)
	p := New(fake, isNotFound)

	if err := p.Provision(context.Background(), []fga.Tuple{present, missing}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if len(fake.writes) != 1 || len(fake.writes[0]) != 1 || fake.writes[0][0] != missing {
		t.Fatalf("want exactly the missing tuple written, got %v", fake.writes)
	}
}

// A read error (other than not-found) aborts Provision.
func TestProvision_ReadErrorPropagates(t *testing.T) {
	fake := newRecordingFGA()
	fake.readErr = errors.New("fga down")
	p := New(fake, isNotFound)

	if err := p.Provision(context.Background(), []fga.Tuple{PlatformRegistrationTuple("acme")}); err == nil {
		t.Fatalf("want read error to propagate")
	}
}

// Deprovision deletes every tuple.
func TestDeprovision_DeletesTuples(t *testing.T) {
	tu := PlatformRegistrationTuple("acme")
	fake := newRecordingFGA(tu)
	p := New(fake, isNotFound)

	if err := p.Deprovision(context.Background(), []fga.Tuple{tu}); err != nil {
		t.Fatalf("Deprovision: %v", err)
	}
	if len(fake.deletes) != 1 || len(fake.deletes[0]) != 1 || fake.deletes[0][0] != tu {
		t.Fatalf("want one delete of the tuple, got %v", fake.deletes)
	}
	if fake.tuples[tu] {
		t.Fatalf("tuple still present after Deprovision")
	}
}

// Deprovision treats a not-found from Delete as success (idempotent teardown).
func TestDeprovision_NotFoundIsSuccess(t *testing.T) {
	fake := newRecordingFGA()
	fake.deleteErr = errNotFound
	p := New(fake, isNotFound)

	if err := p.Deprovision(context.Background(), []fga.Tuple{PlatformRegistrationTuple("acme")}); err != nil {
		t.Fatalf("NotFound from Delete must be success, got %v", err)
	}
}

// Deprovision with an empty tuple set is a no-op (no Delete call).
func TestDeprovision_EmptyIsNoop(t *testing.T) {
	fake := newRecordingFGA()
	p := New(fake, isNotFound)
	if err := p.Deprovision(context.Background(), nil); err != nil {
		t.Fatalf("Deprovision(nil): %v", err)
	}
	if len(fake.deletes) != 0 {
		t.Fatalf("empty Deprovision must not call Delete, got %v", fake.deletes)
	}
}

var errNotFound = errors.New("tuple to be deleted did not exist")

func isNotFound(err error) bool { return errors.Is(err, errNotFound) }
