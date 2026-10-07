// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// The loop refuses to start with no revoker, runs a pass at each interval,
// and stops with the context.
func TestUnrevokedGrants_StartAndStop(t *testing.T) {
	loop := &UnrevokedGrantsRunnable{Client: fake.NewClientBuilder().WithScheme(testScheme(t)).Build()}
	if err := loop.SetupWithManager(nil); err == nil || !strings.Contains(err.Error(), "Revoker is nil") {
		t.Fatalf("no revoker: %v", err)
	}
	if !loop.NeedLeaderElection() {
		t.Fatal("the loop must run on the leader only")
	}

	c := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	recordFixture(t, c, "primary", "github")
	revoker := &fakeRevoker{}
	loop = &UnrevokedGrantsRunnable{Client: c, Revoker: revoker, Interval: time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- loop.Start(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not stop after the context ended")
	}
	if len(revoker.calls) == 0 || revoker.calls[0] != "primary/github" {
		t.Fatalf("revoke calls = %v, want the recorded grant", revoker.calls)
	}
	if recordExists(t, c, "primary", "github") {
		t.Fatal("a revoked grant must lose its record")
	}
}

// A pass that cannot list the records returns the error.
func TestUnrevokedGrants_ListErrorIsReturned(t *testing.T) {
	loop := &UnrevokedGrantsRunnable{Client: &listRefusingClient{Client: fake.NewClientBuilder().WithScheme(testScheme(t)).Build()}, Revoker: &fakeRevoker{}}
	if err := loop.retry(context.Background()); err == nil {
		t.Fatal("a failed list must return the error")
	}
}

type listRefusingClient struct {
	client.Client
}

func (listRefusingClient) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("api server down")
}

// refusingClient refuses the writes and the lists that name a kind.
type refusingClient struct {
	client.Client
	refuseCreate bool
	refuseDelete bool
	refuseList   string // the type name of the list to refuse, for example "ConnectorInstanceList"
}

func (c *refusingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if c.refuseCreate {
		return errors.New("api server refused the create")
	}
	return c.Client.Create(ctx, obj, opts...) //nolint:wrapcheck // a test double passes the client error through unchanged
}

func (c *refusingClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if c.refuseDelete {
		return errors.New("api server refused the delete")
	}
	return c.Client.Delete(ctx, obj, opts...) //nolint:wrapcheck // a test double passes the client error through unchanged
}

func (c *refusingClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if c.refuseList != "" && strings.HasSuffix(fmt.Sprintf("%T", list), c.refuseList) {
		return errors.New("api server refused the list")
	}
	return c.Client.List(ctx, list, opts...) //nolint:wrapcheck // a test double passes the client error through unchanged
}

// A record that cannot be written, a connector list that cannot be read, and
// a record that cannot be deleted each return their error.
func TestUnrevokedGrants_WriteAndReadErrors(t *testing.T) {
	ctx := context.Background()
	base := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	ci := secretInstance("github", "tenant-primary")
	if err := recordUnrevokedGrant(ctx, &refusingClient{Client: base, refuseCreate: true}, ci, "primary", "github", time.Unix(0, 0)); err == nil {
		t.Fatal("a record that cannot be written must return the error")
	}
	recordFixture(t, base, "primary", "github")
	loop := &UnrevokedGrantsRunnable{Client: &refusingClient{Client: base, refuseList: "ConnectorInstanceList"}, Revoker: &fakeRevoker{}}
	if err := loop.retry(ctx); err == nil {
		t.Fatal("a connector list that cannot be read must return the error")
	}
	loop = &UnrevokedGrantsRunnable{Client: &refusingClient{Client: base, refuseDelete: true}, Revoker: &fakeRevoker{}}
	if err := loop.retry(ctx); err == nil {
		t.Fatal("a record that cannot be deleted must return the error")
	}
}
