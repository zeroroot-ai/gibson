/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package identity

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/zitadel"
)

// fakeZitadel is a minimal in-memory zitadel.Client for the identity package's
// EnsureOrg / RemoveOrg core. Only the org methods are exercised; the rest
// satisfy the interface.
type fakeZitadel struct {
	orgs       map[string]*zitadel.Organization
	orgsByName map[string]string
	nextID     int

	createErr error
	getErr    error
	deleteErr error

	createCalled int
	getCalled    int
	deleteCalled int
}

func newFakeZitadel() *fakeZitadel {
	return &fakeZitadel{orgs: map[string]*zitadel.Organization{}, orgsByName: map[string]string{}}
}

func (f *fakeZitadel) CreateOrganization(_ context.Context, name, slug string) (string, error) {
	f.createCalled++
	if f.createErr != nil {
		return "", f.createErr
	}
	if id, ok := f.orgsByName[name]; ok {
		return id, nil
	}
	f.nextID++
	id := fmt.Sprintf("org_%d", f.nextID)
	f.orgs[id] = &zitadel.Organization{ID: id, Name: name, Slug: slug}
	f.orgsByName[name] = id
	return id, nil
}

func (f *fakeZitadel) GetOrganization(_ context.Context, orgID string) (*zitadel.Organization, error) {
	f.getCalled++
	if f.getErr != nil {
		return nil, f.getErr
	}
	org, ok := f.orgs[orgID]
	if !ok {
		return nil, fmt.Errorf("fake: org %q: %w", orgID, clients.ErrNotFound)
	}
	return org, nil
}

func (f *fakeZitadel) DeleteOrganization(_ context.Context, orgID string) error {
	f.deleteCalled++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if _, ok := f.orgs[orgID]; !ok {
		return fmt.Errorf("fake: org %q: %w", orgID, clients.ErrNotFound)
	}
	delete(f.orgs, orgID)
	return nil
}

func (f *fakeZitadel) AddMember(_ context.Context, _, _ string, _ []string) (string, error) {
	return "", nil
}
func (f *fakeZitadel) RemoveMember(_ context.Context, _, _ string) error { return nil }
func (f *fakeZitadel) SendInvitation(_ context.Context, _, _ string, _ []string) (string, error) {
	return "", nil
}
func (f *fakeZitadel) CreateServiceAccount(_ context.Context, _, name string) (string, string, string, error) {
	return "svc-" + name, "client-" + name, "secret-" + name, nil
}
func (f *fakeZitadel) DeleteServiceAccount(_ context.Context, _, _ string) error { return nil }

var _ zitadel.Client = (*fakeZitadel)(nil)

// Provision on a fresh tenant creates the org and returns its id/slug.
func TestProvision_CreatesOrg(t *testing.T) {
	fz := newFakeZitadel()
	p := New(fz)

	res, err := p.Provision(context.Background(), Request{TenantID: "acme", DisplayName: "Acme Corp"})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if res.OrgID == "" {
		t.Fatalf("want non-empty org id")
	}
	if res.Slug != "acme" {
		t.Fatalf("want slug=acme, got %q", res.Slug)
	}
	if fz.createCalled != 1 {
		t.Fatalf("want 1 CreateOrganization call, got %d", fz.createCalled)
	}
}

// Provision with a still-valid KnownOrgID is a no-op (fast path): GetOrganization
// confirms it and CreateOrganization is NOT called.
func TestProvision_KnownOrgFastPath(t *testing.T) {
	fz := newFakeZitadel()
	p := New(fz)
	// Seed an existing org.
	first, err := p.Provision(context.Background(), Request{TenantID: "acme", DisplayName: "Acme Corp"})
	if err != nil {
		t.Fatalf("seed provision: %v", err)
	}
	fz.createCalled = 0

	res, err := p.Provision(context.Background(), Request{TenantID: "acme", DisplayName: "Acme Corp", KnownOrgID: first.OrgID})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if res.OrgID != first.OrgID {
		t.Fatalf("want stable org id %q, got %q", first.OrgID, res.OrgID)
	}
	if fz.createCalled != 0 {
		t.Fatalf("CreateOrganization must not run on fast path, got %d", fz.createCalled)
	}
	if fz.getCalled != 1 {
		t.Fatalf("want 1 GetOrganization confirm, got %d", fz.getCalled)
	}
}

// Provision with a KnownOrgID that no longer exists re-creates the org (drift).
func TestProvision_DriftRecreates(t *testing.T) {
	fz := newFakeZitadel()
	p := New(fz)

	res, err := p.Provision(context.Background(), Request{TenantID: "acme", DisplayName: "Acme Corp", KnownOrgID: "org_stale"})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if res.OrgID == "" || res.OrgID == "org_stale" {
		t.Fatalf("want freshly-created org id, got %q", res.OrgID)
	}
	if fz.createCalled != 1 {
		t.Fatalf("want 1 CreateOrganization call after drift, got %d", fz.createCalled)
	}
}

// Empty DisplayName falls back to the tenant id as the org name.
func TestProvision_EmptyDisplayNameFallsBackToTenantID(t *testing.T) {
	fz := newFakeZitadel()
	p := New(fz)
	if _, err := p.Provision(context.Background(), Request{TenantID: "acme"}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, ok := fz.orgsByName["acme"]; !ok {
		t.Fatalf("want org created under name=acme (tenant id fallback), have %v", fz.orgsByName)
	}
}

// Empty tenant id is rejected.
func TestProvision_EmptyTenantRejected(t *testing.T) {
	p := New(newFakeZitadel())
	if _, err := p.Provision(context.Background(), Request{}); err == nil {
		t.Fatal("want error on empty tenant id")
	}
}

// A create error surfaces.
func TestProvision_CreateErrorSurfaces(t *testing.T) {
	fz := newFakeZitadel()
	fz.createErr = errors.New("zitadel down")
	p := New(fz)
	if _, err := p.Provision(context.Background(), Request{TenantID: "acme"}); err == nil {
		t.Fatal("want error when CreateOrganization fails")
	}
}

// Deprovision deletes the org.
func TestDeprovision_DeletesOrg(t *testing.T) {
	fz := newFakeZitadel()
	p := New(fz)
	res, err := p.Provision(context.Background(), Request{TenantID: "acme"})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := p.Deprovision(context.Background(), res.OrgID); err != nil {
		t.Fatalf("deprovision: %v", err)
	}
	if fz.deleteCalled != 1 {
		t.Fatalf("want 1 DeleteOrganization call, got %d", fz.deleteCalled)
	}
	if _, ok := fz.orgs[res.OrgID]; ok {
		t.Fatalf("org should be gone after deprovision")
	}
}

// Deprovision with an empty org id (never provisioned) is a no-op success and
// does NOT call DeleteOrganization.
func TestDeprovision_EmptyOrgIsNoop(t *testing.T) {
	fz := newFakeZitadel()
	p := New(fz)
	if err := p.Deprovision(context.Background(), ""); err != nil {
		t.Fatalf("empty org deprovision must be success, got %v", err)
	}
	if fz.deleteCalled != 0 {
		t.Fatalf("DeleteOrganization must not run for empty org id, got %d", fz.deleteCalled)
	}
}

// Deprovision of an already-gone org (NotFound) is success.
func TestDeprovision_NotFoundIsSuccess(t *testing.T) {
	fz := newFakeZitadel()
	p := New(fz)
	if err := p.Deprovision(context.Background(), "org_missing"); err != nil {
		t.Fatalf("not-found delete must be success, got %v", err)
	}
}

// A real (non-notfound) delete error surfaces.
func TestDeprovision_RealErrorSurfaces(t *testing.T) {
	fz := newFakeZitadel()
	fz.deleteErr = errors.New("zitadel down")
	p := New(fz)
	if err := p.Deprovision(context.Background(), "org_1"); err == nil {
		t.Fatal("want error when DeleteOrganization fails with a non-notfound error")
	}
}

func TestNew_NilClientPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("want panic on nil zitadel client")
		}
	}()
	New(nil)
}
