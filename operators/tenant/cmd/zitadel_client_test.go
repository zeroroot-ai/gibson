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
