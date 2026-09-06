// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package liveagents_test

import (
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/server/daemon/liveagents"
)

func TestNewRegistry_Options(t *testing.T) {
	// WithLogger(nil) keeps the default; a real logger is accepted. Both paths
	// must build a working registry.
	r := liveagents.NewRegistry(liveagents.WithLogger(nil), liveagents.WithSubscriberBuffer(0))
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	r2 := liveagents.NewRegistry(liveagents.WithLogger(slog.New(slog.DiscardHandler)))
	_, fin := r2.RegisterInstance("t", liveagents.Instance{RunID: "run", AgentName: "a", SandboxID: "sbx", StartedAt: time.Now()})
	fin()
}

// recv reads one chunk from ch within a short deadline, reporting whether the
// channel delivered a value and whether it was closed.
func recv(t *testing.T, ch <-chan liveagents.Event) (data []byte, closed bool) {
	t.Helper()
	select {
	case v, ok := <-ch:
		if !ok {
			return nil, true
		}
		return v.Data, false
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a chunk")
		return nil, false
	}
}

func TestList_EnumeratesEveryRunningInstanceForTenant(t *testing.T) {
	r := liveagents.NewRegistry()
	base := time.Unix(1000, 0)
	_, fin1 := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-1", AgentName: "scanner", SandboxID: "sbx-1", StartedAt: base})
	_, fin2 := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-2", AgentName: "fuzzer", SandboxID: "sbx-2", StartedAt: base.Add(time.Second)})
	_, fin3 := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-3", AgentName: "probe", SandboxID: "sbx-3", StartedAt: base.Add(2 * time.Second)})
	defer fin1()
	defer fin2()
	defer fin3()

	got := r.List("tenant-a")
	if len(got) != 3 {
		t.Fatalf("List returned %d instances, want 3", len(got))
	}
	// Sorted by StartedAt.
	wantOrder := []string{"run-1", "run-2", "run-3"}
	for i, w := range wantOrder {
		if got[i].RunID != w {
			t.Errorf("instance %d = %q, want %q", i, got[i].RunID, w)
		}
	}
	if got[0].AgentName != "scanner" || got[0].SandboxID != "sbx-1" {
		t.Errorf("instance metadata not carried: %+v", got[0])
	}
}

func TestList_OnlyReturnsCallerTenantInstances(t *testing.T) {
	r := liveagents.NewRegistry()
	now := time.Now()
	_, finA := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-a", AgentName: "agent", SandboxID: "sbx-a", StartedAt: now})
	_, finB := r.RegisterInstance("tenant-b", liveagents.Instance{RunID: "run-b", AgentName: "agent", SandboxID: "sbx-b", StartedAt: now})
	defer finA()
	defer finB()

	a := r.List("tenant-a")
	if len(a) != 1 || a[0].RunID != "run-a" {
		t.Fatalf("tenant-a List = %+v, want only run-a", a)
	}
	b := r.List("tenant-b")
	if len(b) != 1 || b[0].RunID != "run-b" {
		t.Fatalf("tenant-b List = %+v, want only run-b", b)
	}
	if got := r.List("tenant-c"); len(got) != 0 {
		t.Fatalf("unknown tenant List = %+v, want empty", got)
	}
}

func TestSubscribe_ForeignRunIDDenied(t *testing.T) {
	r := liveagents.NewRegistry()
	_, fin := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-a", AgentName: "agent", SandboxID: "sbx-a", StartedAt: time.Now()})
	defer fin()

	// tenant-b asks for tenant-a's run id: must be indistinguishable from a
	// run id that never existed.
	if _, _, _, err := r.Subscribe("tenant-b", "run-a", 0); !errors.Is(err, liveagents.ErrInstanceNotFound) {
		t.Fatalf("foreign Subscribe err = %v, want ErrInstanceNotFound", err)
	}
	if _, _, _, err := r.Subscribe("tenant-a", "nope", 0); !errors.Is(err, liveagents.ErrInstanceNotFound) {
		t.Fatalf("unknown Subscribe err = %v, want ErrInstanceNotFound", err)
	}
	// The owner still subscribes fine.
	if _, _, cancel, err := r.Subscribe("tenant-a", "run-a", 0); err != nil {
		t.Fatalf("owner Subscribe err = %v, want nil", err)
	} else {
		cancel()
	}
}

func TestSubscribe_ReceivesPublishedEvents(t *testing.T) {
	r := liveagents.NewRegistry()
	publish, fin := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-a", AgentName: "agent", SandboxID: "sbx-a", StartedAt: time.Now()})
	defer fin()

	_, ch, cancel, err := r.Subscribe("tenant-a", "run-a", 0)
	if err != nil {
		t.Fatalf("Subscribe err = %v", err)
	}
	defer cancel()

	publish([]byte(`{"event":"start"}`))
	got, closed := recv(t, ch)
	if closed {
		t.Fatal("channel closed before event")
	}
	if string(got) != `{"event":"start"}` {
		t.Fatalf("got %q, want start event", got)
	}
}

func TestConcurrentStreams_AreIndependent(t *testing.T) {
	r := liveagents.NewRegistry()
	pub1, fin1 := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-1", AgentName: "agent", SandboxID: "sbx-1", StartedAt: time.Now()})
	pub2, fin2 := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-2", AgentName: "agent", SandboxID: "sbx-2", StartedAt: time.Now()})
	defer fin2()

	_, ch1, cancel1, err := r.Subscribe("tenant-a", "run-1", 0)
	if err != nil {
		t.Fatalf("subscribe run-1: %v", err)
	}
	defer cancel1()
	_, ch2, cancel2, err := r.Subscribe("tenant-a", "run-2", 0)
	if err != nil {
		t.Fatalf("subscribe run-2: %v", err)
	}
	defer cancel2()

	pub1([]byte("one"))
	pub2([]byte("two"))
	if got, _ := recv(t, ch1); string(got) != "one" {
		t.Fatalf("ch1 = %q, want one", got)
	}
	if got, _ := recv(t, ch2); string(got) != "two" {
		t.Fatalf("ch2 = %q, want two", got)
	}

	// Terminate run-1. run-2's stream must be unaffected.
	fin1()
	if _, closed := recv(t, ch1); !closed {
		t.Fatal("ch1 should close on run-1 terminal state")
	}
	pub2([]byte("still-here"))
	if got, closed := recv(t, ch2); closed || string(got) != "still-here" {
		t.Fatalf("ch2 = %q closed=%v, want still-here open", got, closed)
	}
	// run-1 is gone from the enumeration; run-2 remains.
	if got := r.List("tenant-a"); len(got) != 1 || got[0].RunID != "run-2" {
		t.Fatalf("List after fin1 = %+v, want only run-2", got)
	}
}

func TestFinish_ClosesStreamAndDeregisters(t *testing.T) {
	r := liveagents.NewRegistry()
	_, fin := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-a", AgentName: "agent", SandboxID: "sbx-a", StartedAt: time.Now()})
	_, ch, cancel, err := r.Subscribe("tenant-a", "run-a", 0)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer cancel()

	fin()
	if _, closed := recv(t, ch); !closed {
		t.Fatal("subscriber channel must close on terminal state")
	}
	// After terminal, the run is not enumerable and not subscribable.
	if got := r.List("tenant-a"); len(got) != 0 {
		t.Fatalf("List after finish = %+v, want empty", got)
	}
	if _, _, _, err := r.Subscribe("tenant-a", "run-a", 0); !errors.Is(err, liveagents.ErrInstanceNotFound) {
		t.Fatalf("Subscribe after finish err = %v, want ErrInstanceNotFound", err)
	}
	// finish is idempotent.
	fin()
}

func TestPublish_AfterFinishIsNoOp(_ *testing.T) {
	r := liveagents.NewRegistry()
	publish, fin := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-a", AgentName: "agent", SandboxID: "sbx-a", StartedAt: time.Now()})
	fin()
	// Must not panic and must not block.
	publish([]byte("ignored"))
}

func TestPublish_SlowSubscriberDoesNotBlock(t *testing.T) {
	r := liveagents.NewRegistry(liveagents.WithSubscriberBuffer(1))
	publish, fin := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-a", AgentName: "agent", SandboxID: "sbx-a", StartedAt: time.Now()})
	defer fin()
	if _, _, cancel, err := r.Subscribe("tenant-a", "run-a", 0); err != nil {
		t.Fatalf("subscribe: %v", err)
	} else {
		defer cancel()
	}
	// Never read; the buffer fills after one chunk. Further publishes must not
	// block — they drop for this subscriber.
	done := make(chan struct{})
	go func() {
		for range 100 {
			publish([]byte("x"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publish blocked on a slow subscriber")
	}
}

func TestRegisterInstance_EmptyScopeIsNoOp(t *testing.T) {
	r := liveagents.NewRegistry()
	publish, fin := r.RegisterInstance("", liveagents.Instance{RunID: "run-a", AgentName: "agent", SandboxID: "sbx", StartedAt: time.Now()})
	publish([]byte("x")) // must not panic
	fin()
	if got := r.List(""); len(got) != 0 {
		t.Fatalf("empty-tenant List = %+v, want empty", got)
	}
	publish2, fin2 := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: "", AgentName: "agent", SandboxID: "sbx", StartedAt: time.Now()})
	publish2([]byte("x"))
	fin2()
	if got := r.List("tenant-a"); len(got) != 0 {
		t.Fatalf("empty-runID List = %+v, want empty", got)
	}
}

func TestRegisterInstance_DuplicateRunIDReplacesAndClosesOld(t *testing.T) {
	r := liveagents.NewRegistry()
	_, fin1 := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-a", AgentName: "old", SandboxID: "sbx-old", StartedAt: time.Now()})
	_, ch, cancel, err := r.Subscribe("tenant-a", "run-a", 0)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer cancel()

	_, fin2 := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-a", AgentName: "new", SandboxID: "sbx-new", StartedAt: time.Now()})
	defer fin2()
	// The old feed is closed so its subscriber does not hang forever.
	if _, closed := recv(t, ch); !closed {
		t.Fatal("old subscriber must close when run id is re-registered")
	}
	got := r.List("tenant-a")
	if len(got) != 1 || got[0].AgentName != "new" {
		t.Fatalf("List = %+v, want single 'new' instance", got)
	}
	// Deregistering the stale handle must not remove the live re-registration.
	fin1()
	if got := r.List("tenant-a"); len(got) != 1 || got[0].AgentName != "new" {
		t.Fatalf("List after stale finish = %+v, want 'new' still present", got)
	}
}

func TestRegistry_ConcurrentRegisterListSubscribe(t *testing.T) {
	r := liveagents.NewRegistry()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			runID := "run-" + time.Duration(n).String()
			publish, fin := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: runID, AgentName: "agent", SandboxID: "sbx", StartedAt: time.Now()})
			publish([]byte("x"))
			_ = r.List("tenant-a")
			if _, _, cancel, err := r.Subscribe("tenant-a", runID, 0); err == nil {
				cancel()
			}
			fin()
		}(i)
	}
	wg.Wait()
	if got := r.List("tenant-a"); len(got) != 0 {
		t.Fatalf("List after all finish = %d, want 0", len(got))
	}
}

// --- backlog and sequence (dashboard#1148) ---

func seqs(evs []liveagents.Event) []uint64 {
	out := make([]uint64, 0, len(evs))
	for _, ev := range evs {
		out = append(out, ev.Seq)
	}
	return out
}

func TestSubscribe_BacklogAfterSinceSeqThenLive(t *testing.T) {
	r := liveagents.NewRegistry()
	publish, finish := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-a", AgentName: "scanner", SandboxID: "sbx", StartedAt: time.Now()})
	defer finish()
	publish([]byte("one"))
	publish([]byte("two"))
	publish([]byte("three"))

	backlog, ch, cancel, err := r.Subscribe("tenant-a", "run-a", 1)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer cancel()
	if got := seqs(backlog); len(got) != 2 || got[0] != 2 || got[1] != 3 {
		t.Fatalf("backlog seqs = %v; want [2 3]", got)
	}
	if string(backlog[0].Data) != "two" || backlog[0].At.IsZero() {
		t.Fatalf("backlog[0] = %+v; want data two with a timestamp", backlog[0])
	}

	publish([]byte("four"))
	select {
	case ev := <-ch:
		if ev.Seq != 4 || string(ev.Data) != "four" {
			t.Fatalf("live event = %+v; want seq 4 four", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the live event")
	}

	// Zero means the whole backlog; a seq at or past the newest means none.
	all, _, cancelAll, err := r.Subscribe("tenant-a", "run-a", 0)
	if err != nil {
		t.Fatalf("Subscribe(0): %v", err)
	}
	cancelAll()
	if got := seqs(all); len(got) != 4 || got[0] != 1 || got[3] != 4 {
		t.Fatalf("backlog(0) seqs = %v; want [1 2 3 4]", got)
	}
	none, _, cancelNone, err := r.Subscribe("tenant-a", "run-a", 99)
	if err != nil {
		t.Fatalf("Subscribe(99): %v", err)
	}
	cancelNone()
	if len(none) != 0 {
		t.Fatalf("backlog(99) = %v; want empty", seqs(none))
	}
}

func TestPublish_RecordsBacklogWithoutSubscribers(t *testing.T) {
	r := liveagents.NewRegistry()
	publish, finish := r.RegisterInstance("tenant-a", liveagents.Instance{RunID: "run-a", AgentName: "scanner", SandboxID: "sbx", StartedAt: time.Now()})
	defer finish()
	publish([]byte("early"))
	backlog, _, cancel, err := r.Subscribe("tenant-a", "run-a", 0)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	cancel()
	if len(backlog) != 1 || string(backlog[0].Data) != "early" || backlog[0].Seq != 1 {
		t.Fatalf("backlog = %+v; want one event early seq 1", backlog)
	}
}

// TestPublish_ReachesSubscribersAndRefusesAnUnknownRun asserts a line
// published from outside the launcher lands on the feed in sequence, and
// that a run that is not live is ErrInstanceNotFound.
func TestPublish_ReachesSubscribersAndRefusesAnUnknownRun(t *testing.T) {
	r := liveagents.NewRegistry()
	publish, finish := r.RegisterInstance("acme", liveagents.Instance{RunID: "run-1", AgentName: "claude"})
	defer finish()
	publish([]byte("agent line\n"))
	if err := r.Publish("acme", "run-1", []byte(`{"type":"job_opened","job_id":"j-1"}`+"\n")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	backlog, _, cancel, err := r.Subscribe("acme", "run-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if len(backlog) != 2 || backlog[1].Seq != 2 || string(backlog[1].Data) != `{"type":"job_opened","job_id":"j-1"}`+"\n" {
		t.Fatalf("backlog = %+v", backlog)
	}
	if err := r.Publish("acme", "run-9", []byte("x")); !errors.Is(err, liveagents.ErrInstanceNotFound) {
		t.Fatalf("err = %v, want ErrInstanceNotFound", err)
	}
	if err := r.Publish("globex", "run-1", []byte("x")); !errors.Is(err, liveagents.ErrInstanceNotFound) {
		t.Fatalf("another tenant must not reach the run: %v", err)
	}
}
