// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"github.com/zeroroot-ai/sdk/auth"
	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
	"testing"
	"time"

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

// stubJobDriver answers each job call and counts the calls.
type stubJobDriver struct{ calls int }

func (s *stubJobDriver) OpenJob(context.Context, *jobpb.OpenJobRequest) (*jobpb.OpenJobResponse, error) {
	s.calls++
	return &jobpb.OpenJobResponse{}, nil
}

func (s *stubJobDriver) SendInput(context.Context, *jobpb.SendInputRequest) (*jobpb.SendInputResponse, error) {
	s.calls++
	return &jobpb.SendInputResponse{}, nil
}

func (s *stubJobDriver) CloseJob(context.Context, *jobpb.CloseJobRequest) (*jobpb.CloseJobResponse, error) {
	s.calls++
	return &jobpb.CloseJobResponse{}, nil
}

// TestLazyJobDriver_RefusesUntilTheJobServiceIsUp asserts that the callback
// job calls of a dispatched agent answer Unavailable before the job service
// is registered, and reach the job service after that.
func TestLazyJobDriver_RefusesUntilTheJobServiceIsUp(t *testing.T) {
	d := &daemonImpl{}
	driver := &lazyJobDriver{daemon: d}
	ctx := context.Background()

	calls := map[string]func() error{
		"OpenJob":   func() error { _, err := driver.OpenJob(ctx, &jobpb.OpenJobRequest{}); return err },
		"SendInput": func() error { _, err := driver.SendInput(ctx, &jobpb.SendInputRequest{}); return err },
		"CloseJob":  func() error { _, err := driver.CloseJob(ctx, &jobpb.CloseJobRequest{}); return err },
	}
	for name, call := range calls {
		if err := call(); status.Code(err) != codes.Unavailable {
			t.Errorf("%s with no job service: err = %v, want Unavailable", name, err)
		}
	}

	stub := &stubJobDriver{}
	d.jobService = stub
	for name, call := range calls {
		if err := call(); err != nil {
			t.Errorf("%s with a job service: %v", name, err)
		}
	}
	if stub.calls != 3 {
		t.Errorf("job service calls = %d, want 3", stub.calls)
	}
}

// TestBankMemberLiveness: only the BASE grant of a member that is not dead is
// live. A turn grant of the same member shares its bank and run, but it acts as
// the sender and must not renew, or the sandbox would keep that authority.
func TestBankMemberLiveness(t *testing.T) {
	ctx := context.Background()
	banks := newFakeBankStore()
	banks.banks["bank-1"] = &bank.Bank{ID: "bank-1", AgentName: "claude"}
	banks.members["bank-1"] = []*bank.Member{
		{ID: "m-1", BankID: "bank-1", MissionRunID: "run-1", State: bank.MemberIdle},
		{ID: "m-2", BankID: "bank-1", MissionRunID: "run-2", State: bank.MemberDead},
		{ID: "m-3", BankID: "bank-1", MissionRunID: "run-3", State: bank.MemberNeedsSignIn},
	}
	live := &bankMemberLiveness{banks: func() (bank.Store, error) { return banks, nil }}
	tenant, err := auth.NewTenantID("acme")
	if err != nil {
		t.Fatal(err)
	}
	claims := func(bankID, run, task, subject string) sdkcg.Claims {
		return sdkcg.Claims{Tenant: tenant, MissionID: bankID, MissionRunID: run, TaskID: task, Subject: subject}
	}
	base := memberBaseGrantSubject("claude")
	for name, c := range map[string]struct {
		claims sdkcg.Claims
		want   bool
	}{
		"the base grant of a live member":             {claims("bank-1", "run-1", "m-1", base), true},
		"a member waiting for a sign-in still renews": {claims("bank-1", "run-3", "m-3", base), true},
		"a dead member":                                    {claims("bank-1", "run-2", "m-2", base), false},
		"the run of a member of another bank":              {claims("bank-2", "run-1", "m-1", base), false},
		"a run that backs no member":                       {claims("bank-1", "run-9", "m-9", base), false},
		"a turn grant of a live member (task is a job)":    {claims("bank-1", "run-1", "job-7", "user:alice"), false},
		"a turn grant that borrows the member as its task": {claims("bank-1", "run-1", "m-1", "user:alice"), false},
		"the right task and a subject of another agent":    {claims("bank-1", "run-1", "m-1", memberBaseGrantSubject("opencode")), false},
	} {
		got, err := live.IsMemberBaseGrantLive(ctx, c.claims)
		if err != nil {
			t.Errorf("%s: a clean answer carries no error: %v", name, err)
		}
		if got != c.want {
			t.Errorf("%s: live = %v, want %v", name, got, c.want)
		}
	}
	broken := &bankMemberLiveness{banks: func() (bank.Store, error) { return nil, errors.New("postgres is down") }}
	// A store that is down is an error, not an answer. The renewal then fails.
	if got, err := broken.IsMemberBaseGrantLive(ctx, claims("bank-1", "run-1", "m-1", base)); got || err == nil {
		t.Errorf("a store failure gave live = %v, err = %v, want not live and an error", got, err)
	}
	// The member is found but its bank cannot be read: the subject cannot be
	// checked, so the grant does not renew.
	banks.getErr = errors.New("bank read failed")
	if got, err := live.IsMemberBaseGrantLive(ctx, claims("bank-1", "run-1", "m-1", base)); got || err == nil {
		t.Errorf("a bank that cannot be read gave live = %v, err = %v, want not live and an error", got, err)
	}
	// With a pool the lookup reads the Postgres store.
	store, err := newBankMemberLiveness(&daemonImpl{pool: &mockPool{conn: minimalConn()}}).banks()
	if err != nil || store == nil {
		t.Errorf("with a pool the lookup reads the bank store: %v", err)
	}
	// While the data-plane pool is down no grant is live.
	if got, err := newBankMemberLiveness(&daemonImpl{}).IsMemberBaseGrantLive(ctx, claims("bank-1", "run-1", "m-1", base)); got || err == nil {
		t.Errorf("a daemon with no pool gave live = %v, err = %v, want not live and an error", got, err)
	}
}

// TestBankMemberLiveness_TurnGrant: a turn grant carries the authority of one sender for one
// turn. It renews only for the sender of the current turn of a job that the member holds, while
// the job is open or working. A waiting job never renews. A closed job keeps its wrap-up grant
// for 10 minutes after the close. The base grant of the member is no turn grant.
func TestBankMemberLiveness_TurnGrant(t *testing.T) {
	ctx := context.Background()
	closedAt := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	now := closedAt.Add(time.Minute)
	banks := newFakeBankStore()
	banks.banks["bank-1"] = &bank.Bank{ID: "bank-1", AgentName: "claude"}
	banks.members["bank-1"] = []*bank.Member{
		{ID: "m-1", BankID: "bank-1", MissionRunID: "run-1", State: bank.MemberIdle},
		{ID: "m-2", BankID: "bank-1", MissionRunID: "run-2", State: bank.MemberDead},
	}
	alice := job.Principal{Kind: job.PrincipalUser, ID: "alice"}
	bob := job.Principal{Kind: job.PrincipalUser, ID: "bob"}
	jobs := newFakeJobStore()
	add := func(id, member, bankID string, state job.State, turn job.Principal, closed time.Time) {
		jobs.jobs[id] = &job.Job{
			ID: id, BankID: bankID, MemberID: member, State: state, TurnSender: turn, ClosedAt: closed,
		}
	}
	none := time.Time{}
	add("job-working", "m-1", "bank-1", job.StateWorking, alice, none) // a long coding turn, input acknowledged
	add("job-pulled", "m-1", "bank-1", job.StateOpen, alice, none)     // the first turn of a pulled job
	add("job-bobs-turn", "m-1", "bank-1", job.StateWorking, bob, none) // the turn of another sender started
	add("job-no-turn", "m-1", "bank-1", job.StateWorking, job.Principal{}, none)
	add("job-waiting", "m-1", "bank-1", job.StateWaiting, alice, none)
	add("job-other", "m-9", "bank-1", job.StateWorking, alice, none)
	add("job-bank2", "m-1", "bank-2", job.StateWorking, alice, none)
	add("job-closed", "m-1", "bank-1", job.StateClosed, alice, closedAt)
	add("job-late", "m-1", "bank-1", job.StateClosed, alice, closedAt.Add(-10*time.Minute))
	add("job-noclose", "m-1", "bank-1", job.StateClosed, alice, none)
	live := &bankMemberLiveness{
		banks: func() (bank.Store, error) { return banks, nil },
		jobs:  func() (job.Store, error) { return jobs, nil },
		now:   func() time.Time { return now },
	}
	tenant, err := auth.NewTenantID("acme")
	if err != nil {
		t.Fatal(err)
	}
	claims := func(bankID, run, task string) sdkcg.Claims {
		return sdkcg.Claims{Tenant: tenant, MissionID: bankID, MissionRunID: run, TaskID: task, Subject: "user:alice"}
	}
	for name, c := range map[string]struct {
		claims sdkcg.Claims
		want   bool
	}{
		"a working job in the turn of the sender":               {claims("bank-1", "run-1", "job-working"), true},
		"the first turn of a pulled job (opener is the sender)": {claims("bank-1", "run-1", "job-pulled"), true},
		"a job whose current turn belongs to another sender":    {claims("bank-1", "run-1", "job-bobs-turn"), false},
		"a job with no turn":                                    {claims("bank-1", "run-1", "job-no-turn"), false},
		"a waiting job":                                         {claims("bank-1", "run-1", "job-waiting"), false},
		"a closed job within 10 minutes of the close":           {claims("bank-1", "run-1", "job-closed"), true},
		"a closed job 11 minutes after the close":               {claims("bank-1", "run-1", "job-late"), false},
		"a closed job with no close time":                       {claims("bank-1", "run-1", "job-noclose"), false},
		"a job that another member holds":                       {claims("bank-1", "run-1", "job-other"), false},
		"a job of another bank":                                 {claims("bank-1", "run-1", "job-bank2"), false},
		"a job that does not exist":                             {claims("bank-1", "run-1", "job-9"), false},
		"a dead member":                                         {claims("bank-1", "run-2", "job-working"), false},
		"the run of a member of another bank":                   {claims("bank-2", "run-1", "job-working"), false},
		"a run that backs no member":                            {claims("bank-1", "run-9", "job-working"), false},
		"the base grant of the member (its task is the member)": {claims("bank-1", "run-1", "m-1"), false},
		"a grant with no task":                                  {claims("bank-1", "run-1", ""), false},
	} {
		got, err := live.IsMemberTurnGrantLive(ctx, c.claims)
		if err != nil {
			t.Errorf("%s: a clean answer carries no error: %v", name, err)
		}
		if got != c.want {
			t.Errorf("%s: live = %v, want %v", name, got, c.want)
		}
	}
	// The turn moves from sender A to sender B: the grant of A stops, the grant of B starts.
	jobs.jobs["job-working"].TurnSender = bob
	if got, _ := live.IsMemberTurnGrantLive(ctx, claims("bank-1", "run-1", "job-working")); got {
		t.Error("the grant of sender A must stop when the turn of sender B starts")
	}
	bobClaims := claims("bank-1", "run-1", "job-working")
	bobClaims.Subject = "user:bob"
	if got, _ := live.IsMemberTurnGrantLive(ctx, bobClaims); !got {
		t.Error("the grant of sender B must renew in its own turn")
	}
	// The window ends 10 minutes after the close, to the instant.
	at := func(d time.Duration) bool {
		l := *live
		l.now = func() time.Time { return closedAt.Add(d) }
		got, err := l.IsMemberTurnGrantLive(ctx, claims("bank-1", "run-1", "job-closed"))
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if !at(10*time.Minute) || at(10*time.Minute+time.Second) || at(11*time.Minute) {
		t.Errorf("the wrap-up window must end 10 minutes after the close")
	}

	// A store that is down is an error and never an answer.
	down := errors.New("postgres is down")
	for name, l := range map[string]*bankMemberLiveness{
		"the bank store": {banks: func() (bank.Store, error) { return nil, down }, jobs: live.jobs},
		"the job store":  {banks: live.banks, jobs: func() (job.Store, error) { return nil, down }},
	} {
		task := "job-working"
		if got, err := l.IsMemberTurnGrantLive(ctx, claims("bank-1", "run-1", task)); got || err == nil {
			t.Errorf("%s down gave live = %v, err = %v, want not live and an error", name, got, err)
		}
	}
	// With a pool the lookup reads the Postgres stores.
	pooled := newBankMemberLiveness(&daemonImpl{pool: &mockPool{conn: minimalConn()}})
	if s, err := pooled.jobs(); err != nil || s == nil {
		t.Errorf("a pool must give a job store: %v, %v", s, err)
	}
	if _, err := newBankMemberLiveness(&daemonImpl{}).jobs(); err == nil {
		t.Error("no pool must give an error")
	}
}

// getErrJobStore is a job store whose Get fails with a fixed error.
type getErrJobStore struct {
	*fakeJobStore
	err error
}

func (g getErrJobStore) Get(context.Context, string, string) (*job.Job, error) { return nil, g.err }

// The refusals and errors of the renewal lookup: a store that fails is an error and never an
// answer, a job in a state that the daemon does not know holds no turn, and a job of the member
// in another bank is not held.
func TestBankMemberLiveness_TurnGrantRefusalsAndErrors(t *testing.T) {
	ctx := context.Background()
	tenant, err := auth.NewTenantID("acme")
	if err != nil {
		t.Fatal(err)
	}
	alice := job.Principal{Kind: job.PrincipalUser, ID: "alice"}
	claims := sdkcg.Claims{
		Tenant: tenant, MissionID: "bank-1", MissionRunID: "run-1", TaskID: "job-1", Subject: "user:alice",
	}
	newBanks := func() *fakeBankStore {
		b := newFakeBankStore()
		b.members["bank-1"] = []*bank.Member{{ID: "m-1", BankID: "bank-1", MissionRunID: "run-1", State: bank.MemberIdle}}
		return b
	}
	jobsWith := func(state job.State, bankID string) *fakeJobStore {
		j := newFakeJobStore()
		j.jobs["job-1"] = &job.Job{ID: "job-1", BankID: bankID, MemberID: "m-1", State: state, TurnSender: alice}
		return j
	}
	live := func(b bank.Store, j job.Store) *bankMemberLiveness {
		return &bankMemberLiveness{
			banks: func() (bank.Store, error) { return b, nil },
			jobs:  func() (job.Store, error) { return j, nil },
		}
	}

	t.Run("the member store fails", func(t *testing.T) {
		b := newBanks()
		b.getErr = errors.New("postgres is down")
		got, err := live(b, jobsWith(job.StateWorking, "bank-1")).IsMemberTurnGrantLive(ctx, claims)
		if got || err == nil || !errors.Is(err, b.getErr) {
			t.Fatalf("live = %v, err = %v, want not live and the store error", got, err)
		}
	})
	t.Run("the job store fails", func(t *testing.T) {
		boom := errors.New("job store is down")
		broken := getErrJobStore{fakeJobStore: newFakeJobStore(), err: boom}
		got, err := live(newBanks(), broken).IsMemberTurnGrantLive(ctx, claims)
		if got || !errors.Is(err, boom) {
			t.Fatalf("live = %v, err = %v, want not live and the store error", got, err)
		}
	})
	t.Run("the job does not exist", func(t *testing.T) {
		got, err := live(newBanks(), newFakeJobStore()).IsMemberTurnGrantLive(ctx, claims)
		if got || err != nil {
			t.Fatalf("live = %v, err = %v, want a clean refusal", got, err)
		}
	})
	t.Run("the job belongs to another bank", func(t *testing.T) {
		got, err := live(newBanks(), jobsWith(job.StateWorking, "bank-2")).IsMemberTurnGrantLive(ctx, claims)
		if got || err != nil {
			t.Fatalf("live = %v, err = %v, want a clean refusal", got, err)
		}
	})
	t.Run("a state that the daemon does not know", func(t *testing.T) {
		got, err := live(newBanks(), jobsWith(job.State("paused"), "bank-1")).IsMemberTurnGrantLive(ctx, claims)
		if got || err != nil {
			t.Fatalf("live = %v, err = %v, want a clean refusal", got, err)
		}
	})
	t.Run("the control: the same job is live while it works", func(t *testing.T) {
		got, err := live(newBanks(), jobsWith(job.StateWorking, "bank-1")).IsMemberTurnGrantLive(ctx, claims)
		if !got || err != nil {
			t.Fatalf("live = %v, err = %v, want live", got, err)
		}
	})
}

// The job surface that the harness uses reaches SetTurn of the store, keeps the error of the
// store, and refuses while no store is up.
func TestLazyJobSurface_SetTurnReachesTheStore(t *testing.T) {
	ctx := context.Background()
	jobs := newFakeJobStore()
	jobs.jobs["job-1"] = &job.Job{ID: "job-1"}
	surface := &lazyJobSurface{daemon: &daemonImpl{}, stores: func() (job.Store, error) { return jobs, nil }}
	bob := job.Principal{Kind: job.PrincipalUser, ID: "bob"}

	if err := surface.SetTurn(ctx, "acme", "job-1", bob, "in-1"); err != nil {
		t.Fatalf("SetTurn: %v", err)
	}
	if got := jobs.jobs["job-1"]; got.TurnSender != bob || got.TurnInputID != "in-1" {
		t.Errorf("turn = %+v / %q, want bob / in-1", got.TurnSender, got.TurnInputID)
	}
	if err := surface.SetTurn(ctx, "acme", "job-9", bob, "in-1"); !errors.Is(err, job.ErrNotFound) {
		t.Errorf("a missing job must keep the error of the store: %v", err)
	}
	down := &lazyJobSurface{daemon: &daemonImpl{}, stores: func() (job.Store, error) { return nil, errors.New("no pool") }}
	if err := down.SetTurn(ctx, "acme", "job-1", bob, "in-1"); err == nil {
		t.Error("no store must be reported on SetTurn")
	}
}

// The grant of the first turn of a pulled job renews during that turn. Claim records the opener as
// the sender of the first turn, and PullJob mints the grant for that sender, so the claims of the
// grant (the subject is the opener, the task is the job) match the stored turn. The job is open
// when it is pulled and working when the member reports it, and the grant renews in both states.
func TestBankMemberLiveness_TheFirstTurnGrantOfAPulledJobRenews(t *testing.T) {
	ctx := context.Background()
	opener := job.Principal{Kind: job.PrincipalUser, ID: "alice"}
	banks := newFakeBankStore()
	banks.members["bank-1"] = []*bank.Member{{ID: "m-1", BankID: "bank-1", MissionRunID: "run-1", State: bank.MemberIdle}}
	jobs := newFakeJobStore()
	jobs.jobs["job-1"] = &job.Job{
		ID: "job-1", BankID: "bank-1", MemberID: "m-1", State: job.StateOpen, OpenedBy: opener, TurnSender: opener,
	}
	live := &bankMemberLiveness{
		banks: func() (bank.Store, error) { return banks, nil },
		jobs:  func() (job.Store, error) { return jobs, nil },
	}
	tenant, err := auth.NewTenantID("acme")
	if err != nil {
		t.Fatal(err)
	}
	claims := sdkcg.Claims{
		Tenant: tenant, MissionID: "bank-1", MissionRunID: "run-1", TaskID: "job-1",
		Subject: harness.TurnGrantSubject(opener),
	}
	for _, state := range []job.State{job.StateOpen, job.StateWorking} {
		jobs.jobs["job-1"].State = state
		if got, err := live.IsMemberTurnGrantLive(ctx, claims); err != nil || !got {
			t.Errorf("state %s: live = %v, err = %v, want the first-turn grant to renew", state, got, err)
		}
	}
	// Another member of the same bank does not hold the job, so its run gets no renewal.
	banks.members["bank-1"] = append(banks.members["bank-1"],
		&bank.Member{ID: "m-2", BankID: "bank-1", MissionRunID: "run-2", State: bank.MemberIdle})
	other := claims
	other.MissionRunID = "run-2"
	if got, err := live.IsMemberTurnGrantLive(ctx, other); err != nil || got {
		t.Errorf("a member that does not hold the job: live = %v, err = %v, want a refusal", got, err)
	}
}
