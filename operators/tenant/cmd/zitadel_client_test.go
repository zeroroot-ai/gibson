// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"testing"
)

func TestNewZitadelClient_UsesTheOperatorsOwnCredentials(t *testing.T) {
	c, err := newZitadelClient(context.Background(), "http://gibson-zitadel:8080", "app.example.test", "tenant-operator", "s3cret")
	if err != nil || c == nil {
		t.Fatalf("newZitadelClient = %v, %v; want a client", c, err)
	}
}

// TestNewZitadelClient_RefusesWithoutCredentials: with no client credentials
// there is no token, and the operator must not start (one-code-path).
func TestNewZitadelClient_RefusesWithoutCredentials(t *testing.T) {
	if _, err := newZitadelClient(context.Background(), "http://gibson-zitadel:8080", "app.example.test", "", ""); err == nil {
		t.Fatal("newZitadelClient without client credentials = nil error, want refusal")
	}
}

func TestNewTenantRoleGrants_UsesTheOperatorsOwnCredentials(t *testing.T) {
	g, err := newTenantRoleGrants(context.Background(), "http://gibson-zitadel:8080", "app.example.test", "tenant-operator", "s3cret", "PROJ-1")
	if err != nil || g == nil {
		t.Fatalf("newTenantRoleGrants = %v, %v; want grants", g, err)
	}
}

// TestNewTenantRoleGrants_RefusesABadEndpoint: a claimed host with a port is
// refused (ADR-0092), and the operator must not start.
func TestNewTenantRoleGrants_RefusesABadEndpoint(t *testing.T) {
	if _, err := newTenantRoleGrants(context.Background(), "http://gibson-zitadel:8080", "app.example.test:443", "tenant-operator", "s3cret", "PROJ-1"); err == nil {
		t.Fatal("newTenantRoleGrants with a ported host = nil error, want refusal")
	}
}

func TestNewTenantRoleGrants_RefusesWithoutCredentials(t *testing.T) {
	if _, err := newTenantRoleGrants(context.Background(), "http://gibson-zitadel:8080", "app.example.test", "", "", "PROJ-1"); err == nil {
		t.Fatal("newTenantRoleGrants without client credentials = nil error, want refusal")
	}
}
