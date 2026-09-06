// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// config_provider_required_test.go — the missing-quota-row posture.
//
// A tenant with no tenant_quotas row used to resolve to the zero Limits value,
// which every enforcer reads as "unlimited on every dimension". That is the
// correct permissive default for a self-hosted install (ADR-0006), and exactly
// the wrong one for a deployment that has declared entitlements mandatory —
// there, an absent row is indistinguishable from a row that was never written,
// and unlimited is a free grant.
package entitlements

import (
	"context"
	"database/sql"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func TestConfigProvider_MissingRowDeniesWhenEntitlementsRequired(t *testing.T) {
	t.Setenv(RequiredKnob, "true")

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery("FROM tenant_quotas").
		WithArgs("acme").
		WillReturnError(sql.ErrNoRows)

	_, err = NewConfigProvider(db).Limits(context.Background(), "acme")
	if !IsRequired(err) {
		t.Fatalf("a missing quota row must DENY when entitlements are required, got err = %v", err)
	}
}

func TestConfigProvider_MissingRowIsUnlimitedOnPrem(t *testing.T) {
	t.Setenv(RequiredKnob, "")

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery("FROM tenant_quotas").
		WithArgs("acme").
		WillReturnError(sql.ErrNoRows)

	lim, err := NewConfigProvider(db).Limits(context.Background(), "acme")
	if err != nil {
		t.Fatalf("self-hosted must keep the permissive default (ADR-0006), got err = %v", err)
	}
	if lim != (Limits{}) {
		t.Fatalf("expected unlimited Limits on-prem, got %+v", lim)
	}
}

func TestConfigProvider_NilDBDeniesWhenEntitlementsRequired(t *testing.T) {
	t.Setenv(RequiredKnob, "true")

	_, err := NewConfigProvider(nil).Limits(context.Background(), "acme")
	if !IsRequired(err) {
		t.Fatalf("no platform database must DENY when entitlements are required, got err = %v", err)
	}
}

// TestConfigProvider_DenialIsNotCached pins that a denial does not poison the
// cache: once the quota row lands, the very next read must serve it rather than
// replaying a cached deny.
func TestConfigProvider_DenialIsNotCached(t *testing.T) {
	t.Setenv(RequiredKnob, "true")

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	p := NewConfigProvider(db)

	mock.ExpectQuery("FROM tenant_quotas").WithArgs("acme").WillReturnError(sql.ErrNoRows)
	if _, err := p.Limits(context.Background(), "acme"); !IsRequired(err) {
		t.Fatalf("first read must deny, got %v", err)
	}

	mock.ExpectQuery("FROM tenant_quotas").WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"concurrent_missions", "concurrent_agents", "concurrent_connectors"}).
			AddRow(10, 100, 5))
	lim, err := p.Limits(context.Background(), "acme")
	if err != nil {
		t.Fatalf("second read must serve the now-present row, got %v", err)
	}
	if lim.ConcurrentMissions != 10 {
		t.Fatalf("unexpected limits: %+v", lim)
	}
}
