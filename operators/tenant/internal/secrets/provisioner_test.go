/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package secrets

import (
	"context"
	"errors"
	"testing"
)

type fakeVault struct {
	ensureErr  error
	jwtErr     error
	deleteErr  error
	ensured    []string
	configured []string
	deleted    []string
}

func (f *fakeVault) EnsureTenantNamespace(_ context.Context, id string) error {
	f.ensured = append(f.ensured, id)
	return f.ensureErr
}

func (f *fakeVault) ConfigureTenantJWTAuth(_ context.Context, id string) error {
	f.configured = append(f.configured, id)
	return f.jwtErr
}

func (f *fakeVault) DeleteTenantNamespace(_ context.Context, id string) error {
	f.deleted = append(f.deleted, id)
	return f.deleteErr
}

type fakeBroker struct {
	writeErr  error
	deleteErr error
	written   []string
	deleted   []string
}

func (f *fakeBroker) WriteBrokerConfig(_ context.Context, id string) error {
	f.written = append(f.written, id)
	return f.writeErr
}

func (f *fakeBroker) DeleteBrokerConfig(_ context.Context, id string) error {
	f.deleted = append(f.deleted, id)
	return f.deleteErr
}

var errGone = errors.New("gone")

func notFound(err error) bool { return errors.Is(err, errGone) }

func TestProvision_RunsAllStepsInOrder(t *testing.T) {
	v := &fakeVault{}
	b := &fakeBroker{}
	p := New(v, b, notFound)

	if err := p.Provision(context.Background(), "acme"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if len(v.ensured) != 1 || v.ensured[0] != "acme" {
		t.Fatalf("want EnsureTenantNamespace(acme), got %v", v.ensured)
	}
	if len(v.configured) != 1 || v.configured[0] != "acme" {
		t.Fatalf("want ConfigureTenantJWTAuth(acme), got %v", v.configured)
	}
	if len(b.written) != 1 || b.written[0] != "acme" {
		t.Fatalf("want WriteBrokerConfig(acme), got %v", b.written)
	}
}

func TestProvision_EnsureNamespaceFailureStopsPipeline(t *testing.T) {
	v := &fakeVault{ensureErr: errors.New("vault down")}
	b := &fakeBroker{}
	p := New(v, b, notFound)

	if err := p.Provision(context.Background(), "acme"); err == nil {
		t.Fatal("want error when EnsureTenantNamespace fails")
	}
	if len(v.configured) != 0 {
		t.Fatalf("jwt config must not run after namespace failure, got %v", v.configured)
	}
	if len(b.written) != 0 {
		t.Fatalf("broker write must not run after namespace failure, got %v", b.written)
	}
}

func TestProvision_BrokerFailureSurfaces(t *testing.T) {
	v := &fakeVault{}
	b := &fakeBroker{writeErr: errors.New("pg down")}
	p := New(v, b, notFound)

	if err := p.Provision(context.Background(), "acme"); err == nil {
		t.Fatal("want error when WriteBrokerConfig fails")
	}
}

func TestProvision_EmptyTenantRejected(t *testing.T) {
	p := New(&fakeVault{}, &fakeBroker{}, notFound)
	if err := p.Provision(context.Background(), ""); err == nil {
		t.Fatal("want error on empty tenant id")
	}
}

func TestDeprovision_DeletesBrokerThenNamespace(t *testing.T) {
	v := &fakeVault{}
	b := &fakeBroker{}
	p := New(v, b, notFound)

	if err := p.Deprovision(context.Background(), "acme"); err != nil {
		t.Fatalf("deprovision: %v", err)
	}
	if len(b.deleted) != 1 || b.deleted[0] != "acme" {
		t.Fatalf("want DeleteBrokerConfig(acme), got %v", b.deleted)
	}
	if len(v.deleted) != 1 || v.deleted[0] != "acme" {
		t.Fatalf("want DeleteTenantNamespace(acme), got %v", v.deleted)
	}
}

func TestDeprovision_NotFoundIsSuccess(t *testing.T) {
	v := &fakeVault{deleteErr: errGone}
	b := &fakeBroker{deleteErr: errGone}
	p := New(v, b, notFound)

	if err := p.Deprovision(context.Background(), "acme"); err != nil {
		t.Fatalf("not-found from both deletes must be success, got %v", err)
	}
}

func TestDeprovision_RealErrorSurfaces(t *testing.T) {
	v := &fakeVault{deleteErr: errors.New("vault down")}
	b := &fakeBroker{}
	p := New(v, b, notFound)

	if err := p.Deprovision(context.Background(), "acme"); err == nil {
		t.Fatal("want error when DeleteTenantNamespace fails with a non-notfound error")
	}
}

func TestNew_NilVaultPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("want panic on nil vault")
		}
	}()
	New(nil, &fakeBroker{}, notFound)
}

func TestNew_NilBrokerPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("want panic on nil broker")
		}
	}()
	New(&fakeVault{}, nil, notFound)
}
