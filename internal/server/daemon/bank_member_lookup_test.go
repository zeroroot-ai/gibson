// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/bank"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

// TestBankMemberLookup_MapsNotFoundToNotAMember asserts the contract the
// harness reads: a run that backs no member is harness.ErrNotAMember, a found
// member answers its id and bank, and any other store error stays an error
// that is not "not a member".
func TestBankMemberLookup_MapsNotFoundToNotAMember(t *testing.T) {
	store := newFakeBankStore()
	store.members["bank-1"] = []*bank.Member{{ID: "m-1", BankID: "bank-1", MissionRunID: "run-1"}}
	l := &bankMemberLookup{banks: store}
	ctx := context.Background()

	memberID, bankID, err := l.MemberByRun(ctx, "acme", "run-1")
	if err != nil || memberID != "m-1" || bankID != "bank-1" {
		t.Fatalf("got %q %q %v", memberID, bankID, err)
	}
	if _, _, err := l.MemberByRun(ctx, "acme", "run-9"); !errors.Is(err, harness.ErrNotAMember) {
		t.Fatalf("err = %v, want ErrNotAMember", err)
	}
	store.getErr = errors.New("postgres is down")
	if _, _, err := l.MemberByRun(ctx, "acme", "run-1"); err == nil || errors.Is(err, harness.ErrNotAMember) {
		t.Fatalf("an outage must not read as not-a-member: %v", err)
	}
}

// TestLazySeams_RefuseWhileTheirDependencyIsAbsent asserts that each lazily
// resolved seam answers Unavailable before Start has built the pool or the
// signing key, rather than a nil dereference.
func TestLazySeams_RefuseWhileTheirDependencyIsAbsent(t *testing.T) {
	d := &daemonImpl{}
	ctx := context.Background()

	if _, _, err := (&lazyMemberLookup{daemon: d}).MemberByRun(ctx, "acme", "run-1"); status.Code(err) != codes.Unavailable {
		t.Errorf("member lookup: err = %v, want Unavailable", err)
	}
	if _, err := (&lazyTurnGrantMinter{daemon: d}).Mint(capabilitygrant.MintRequest{}); status.Code(err) != codes.Unavailable {
		t.Errorf("minter: err = %v, want Unavailable", err)
	}
	jobs := &lazyJobSurface{daemon: d}
	checks := map[string]func() error{
		"Claim":         func() error { _, err := jobs.Claim(ctx, "t", "b", "m"); return err },
		"Get":           func() error { _, err := jobs.Get(ctx, "t", "j"); return err },
		"PendingInputs": func() error { _, err := jobs.PendingInputs(ctx, "t", "m", 1); return err },
		"Acknowledge":   func() error { return jobs.Acknowledge(ctx, "t", "i") },
		"SetState":      func() error { _, err := jobs.SetState(ctx, "t", "j", "working", ""); return err },
		"AddDeliverable": func() error {
			_, err := jobs.AddDeliverable(ctx, "t", "j", nil)
			return err
		},
	}
	for name, call := range checks {
		if err := call(); status.Code(err) != codes.Unavailable {
			t.Errorf("jobs.%s: err = %v, want Unavailable", name, err)
		}
	}
}

// TestLazySeams_ReachTheStoreOnceItIsUp asserts each lazily resolved seam
// passes its call through to the store, and wraps a store error rather than
// swallowing it.
func TestLazySeams_ReachTheStoreOnceItIsUp(t *testing.T) {
	ctx := context.Background()
	jobs := newFakeJobStore()
	jobs.jobs["job-1"] = &job.Job{ID: "job-1", BankID: "bank-1", MemberID: "m-1", State: job.StateWorking, Spec: goodSpec()}
	surface := &lazyJobSurface{daemon: &daemonImpl{}, stores: func() (job.Store, error) { return jobs, nil }}

	if _, err := surface.Get(ctx, "acme", "job-1"); err != nil {
		t.Errorf("Get: %v", err)
	}
	if _, err := surface.Get(ctx, "acme", "job-9"); !errors.Is(err, job.ErrNotFound) {
		t.Errorf("Get of a missing job must keep the store's error: %v", err)
	}
	if _, err := surface.SetState(ctx, "acme", "job-1", job.StateWaiting, "sess-1"); err != nil {
		t.Errorf("SetState: %v", err)
	}
	if _, err := surface.AddDeliverable(ctx, "acme", "job-1", &jobpb.Deliverable{Ref: "fix"}); err != nil {
		t.Errorf("AddDeliverable: %v", err)
	}
	if _, err := surface.PendingInputs(ctx, "acme", "m-1", 10); err != nil {
		t.Errorf("PendingInputs: %v", err)
	}
	if err := surface.Acknowledge(ctx, "acme", "in-1"); err != nil {
		t.Errorf("Acknowledge: %v", err)
	}
	if _, err := surface.Claim(ctx, "acme", "bank-1", "m-1"); err != nil {
		t.Errorf("Claim: %v", err)
	}

	banks := newFakeBankStore()
	banks.members["bank-1"] = []*bank.Member{{ID: "m-1", BankID: "bank-1", MissionRunID: "run-1"}}
	lookup := &lazyMemberLookup{daemon: &daemonImpl{}, banks: func() (bank.Store, error) { return banks, nil }}
	memberID, bankID, err := lookup.MemberByRun(ctx, "acme", "run-1")
	if err != nil || memberID != "m-1" || bankID != "bank-1" {
		t.Errorf("MemberByRun = %q %q %v", memberID, bankID, err)
	}
	broken := &lazyMemberLookup{daemon: &daemonImpl{}, banks: func() (bank.Store, error) { return nil, errors.New("postgres is down") }}
	if _, _, err := broken.MemberByRun(ctx, "acme", "run-1"); err == nil {
		t.Error("a store failure must be reported")
	}
}

// TestLazyJobSurface_OpenSendEventsReachTheStore covers the three calls the
// delegation targets use, and their wrapped errors.
func TestLazyJobSurface_OpenSendEventsReachTheStore(t *testing.T) {
	ctx := context.Background()
	jobs := newFakeJobStore()
	surface := &lazyJobSurface{daemon: &daemonImpl{}, stores: func() (job.Store, error) { return jobs, nil }}
	opened, err := surface.Open(ctx, "acme", job.OpenInput{BankID: "bank-1", Spec: goodSpec(), OpenedBy: job.Principal{Kind: job.PrincipalUser, ID: "alice"}})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := surface.Send(ctx, "acme", job.SendInput{JobID: opened.ID, Kind: job.InputTurn, Message: "go", Sender: job.Principal{Kind: job.PrincipalUser, ID: "alice"}}); err != nil {
		t.Errorf("Send: %v", err)
	}
	if _, err := surface.Send(ctx, "acme", job.SendInput{JobID: "job-9", Kind: job.InputTurn, Message: "go", Sender: job.Principal{Kind: job.PrincipalUser, ID: "alice"}}); !errors.Is(err, job.ErrNotFound) {
		t.Errorf("Send to a missing job must keep the store's error: %v", err)
	}
	if evs, err := surface.Events(ctx, "acme", opened.ID, 0, 10); err != nil || len(evs) == 0 {
		t.Errorf("Events = %d, %v", len(evs), err)
	}
	if _, err := surface.Open(ctx, "acme", job.OpenInput{}); err == nil {
		t.Error("an invalid open must be reported")
	}
	down := &lazyJobSurface{daemon: &daemonImpl{}, stores: func() (job.Store, error) { return nil, errors.New("no pool") }}
	if _, err := down.Open(ctx, "acme", job.OpenInput{}); err == nil {
		t.Error("no store must be reported on Open")
	}
	if _, err := down.Send(ctx, "acme", job.SendInput{}); err == nil {
		t.Error("no store must be reported on Send")
	}
	if _, err := down.Events(ctx, "acme", "j", 0, 1); err == nil {
		t.Error("no store must be reported on Events")
	}
}
