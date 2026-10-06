// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// recordFixture writes the record of the grant of connector in tenant.
func recordFixture(t *testing.T, c client.Client, tenant, connector string) {
	t.Helper()
	ci := secretInstance(connector, "tenant-"+tenant)
	if err := recordUnrevokedGrant(context.Background(), c, ci, tenant, connector, time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatalf("record: %v", err)
	}
}

func recordExists(t *testing.T, c client.Client, tenant, connector string) bool {
	t.Helper()
	var cm corev1.ConfigMap
	err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-" + tenant, Name: unrevokedGrantName(connector)}, &cm)
	if apierrors.IsNotFound(err) {
		return false
	}
	if err != nil {
		t.Fatalf("get record: %v", err)
	}
	return true
}

// TestUnrevokedGrants_RetryRevokesAndDeletesTheRecord: a recorded grant is
// revoked by the next pass, and its record leaves. While the daemon refuses,
// the record stays and the gauge counts it.
func TestUnrevokedGrants_RetryRevokesAndDeletesTheRecord(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	recordFixture(t, c, "primary", "github")

	revoker := &fakeRevoker{err: errors.New("daemon unavailable")}
	loop := &UnrevokedGrantsRunnable{Client: c, Revoker: revoker}
	if err := loop.retry(context.Background()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !recordExists(t, c, "primary", "github") {
		t.Fatal("a grant the daemon did not revoke must keep its record")
	}
	if got := testutil.ToFloat64(UnrevokedGrants); got != 1 {
		t.Errorf("gauge = %v, want 1", got)
	}

	revoker.err = nil
	if err := loop.retry(context.Background()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if recordExists(t, c, "primary", "github") {
		t.Fatal("a revoked grant must lose its record")
	}
	if got := testutil.ToFloat64(UnrevokedGrants); got != 0 {
		t.Errorf("gauge = %v, want 0", got)
	}
	if len(revoker.calls) != 2 || revoker.calls[1] != "primary/github" {
		t.Errorf("revoke calls = %v, want two calls for primary/github", revoker.calls)
	}
}

// TestUnrevokedGrants_ANewInstanceReplacesTheRecord: when the connector
// instance exists again, the old grant was replaced. The record leaves with
// no revoke, so the grant of the new instance stays.
func TestUnrevokedGrants_ANewInstanceReplacesTheRecord(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).
		WithObjects(secretInstance("github", "tenant-primary")).Build()
	recordFixture(t, c, "primary", "github")

	revoker := &fakeRevoker{}
	loop := &UnrevokedGrantsRunnable{Client: c, Revoker: revoker}
	if err := loop.retry(context.Background()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if len(revoker.calls) != 0 {
		t.Errorf("revoke calls = %v, want none", revoker.calls)
	}
	if recordExists(t, c, "primary", "github") {
		t.Fatal("the record of a replaced grant must leave")
	}
}
