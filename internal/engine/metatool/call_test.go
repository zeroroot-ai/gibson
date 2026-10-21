// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package metatool

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
)

// seqObserver records the order of the events of a call and can refuse the
// intent.
type seqObserver struct {
	events    []string
	intentErr error
	last      CallRecord
	resultErr error
}

func (o *seqObserver) Intent(_ context.Context, rec CallRecord) error {
	o.events = append(o.events, "intent")
	o.last = rec
	return o.intentErr
}

func (o *seqObserver) Result(_ context.Context, rec CallRecord, _ []byte, err error) {
	o.events = append(o.events, "result")
	o.last, o.resultErr = rec, err
}

type seqQuerier struct {
	obs   *seqObserver
	calls int
}

func (q *seqQuerier) CallConnectorTool(context.Context, string, string, string, map[string]any) (any, error) {
	q.calls++
	q.obs.events = append(q.obs.events, "dispatch")
	return map[string]any{"ok": true}, nil
}

var callerAlice = catalog.Caller{Subject: "user:alice", Tenant: "acme"}

// The intent record comes before the dispatch, and the result record after it.
func TestCall_IntentThenDispatchThenResult(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	h := NewHandler(nil, allowAll("mcp:gitlab:get_project"), q)
	_, err := h.Call(context.Background(), Call{Caller: callerAlice, ID: "mcp:gitlab:get_project", WorkID: "w1", MissionID: "m1", Observer: obs})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got := obs.events; len(got) != 3 || got[0] != "intent" || got[1] != "dispatch" || got[2] != "result" {
		t.Fatalf("events = %v, want intent, dispatch, result", got)
	}
	if obs.last.Connector != "gitlab" || obs.last.Tool != "get_project" || obs.last.MissionID != "m1" || obs.last.WorkID != "w1" {
		t.Errorf("record = %+v", obs.last)
	}
}

// A failed intent write refuses the call: nothing is dispatched.
func TestCall_AFailedIntentRecordRefusesTheCall(t *testing.T) {
	obs := &seqObserver{intentErr: errors.New("audit database down")}
	q := &seqQuerier{obs: obs}
	h := NewHandler(nil, allowAll("mcp:gitlab:get_project"), q)
	_, err := h.Call(context.Background(), Call{Caller: callerAlice, ID: "mcp:gitlab:get_project", Observer: obs})
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("err = %v, want ErrAuditUnavailable", err)
	}
	if q.calls != 0 {
		t.Fatalf("the connector was called %d time(s) with no intent record", q.calls)
	}
}

// A tool on the deny list is refused before the intent record and before the
// dispatch, by the id as given and by its canonical form.
func TestCall_ABlockedToolIsRefusedBeforeAnything(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	h := NewHandler(nil, allowAll("mcp:gitlab:get_project"), q)
	for _, id := range []string{"mcp:gitlab:get_project", "mcp__gitlab__get_project"} {
		_, err := h.Call(context.Background(), Call{
			Caller: callerAlice, ID: id, Observer: obs,
			Policy: MissionPolicy{Blocked: []string{"MCP:gitlab:get_project"}},
		})
		if !errors.Is(err, ErrBlocked) {
			t.Fatalf("%s: err = %v, want ErrBlocked", id, err)
		}
	}
	if len(obs.events) != 0 || q.calls != 0 {
		t.Fatalf("a blocked tool left events %v and %d call(s)", obs.events, q.calls)
	}
}

// A run that is not active may not call a tool.
func TestCall_AnInactiveRunIsRefused(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	h := NewHandler(nil, allowAll("mcp:gitlab:get_project"), q)
	_, err := h.Call(context.Background(), Call{
		Caller: callerAlice, ID: "mcp:gitlab:get_project", Observer: obs,
		Policy: MissionPolicy{RunActive: func(context.Context) error { return ErrRunInactive }},
	})
	if !errors.Is(err, ErrRunInactive) || q.calls != 0 {
		t.Fatalf("err = %v, calls = %d", err, q.calls)
	}
}

// A call that the check denies is recorded as a failure and not dispatched.
func TestCall_ADeniedCallIsRecordedAndNotDispatched(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	h := NewHandler(nil, allowAll(), q)
	_, err := h.Call(context.Background(), Call{Caller: callerAlice, ID: "mcp:gitlab:get_project", Observer: obs})
	if !errors.Is(err, ErrUnauthorized) || q.calls != 0 {
		t.Fatalf("err = %v, calls = %d", err, q.calls)
	}
	if got := obs.events; len(got) != 2 || got[1] != "result" || !errors.Is(obs.resultErr, ErrUnauthorized) {
		t.Fatalf("events = %v, result error = %v", got, obs.resultErr)
	}
}

// A native id is authorized and handed back, because the harness owns its call.
func TestCall_ANativeIDIsHandedBack(t *testing.T) {
	obs := &seqObserver{}
	h := NewHandler(nil, allowAll("native:nmap"), &seqQuerier{obs: obs})
	if _, err := h.Call(context.Background(), Call{Caller: callerAlice, ID: "native:nmap", Observer: obs}); !errors.Is(err, ErrNativeID) {
		t.Fatalf("err = %v, want ErrNativeID", err)
	}
	if len(obs.events) != 0 {
		t.Fatalf("a native id left events %v", obs.events)
	}
}

func TestCall_NeedsAnObserver(t *testing.T) {
	h := NewHandler(nil, allowAll(), nil)
	if _, err := h.Call(context.Background(), Call{Caller: callerAlice, ID: "mcp:gitlab:x"}); err == nil {
		t.Fatal("want an error with no observer")
	}
}
