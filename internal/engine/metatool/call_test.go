// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package metatool

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
)

// seqObserver records the order of the events of a call and can refuse the
// intent.
type seqObserver struct {
	recorded  []string
	codes     []ErrCode
	events    []string
	intentErr error
	last      CallRecord
	resultErr error
}

func (o *seqObserver) record(_ context.Context, rec CallRecord, _ []byte, errText string) string {
	o.recorded = append(o.recorded, rec.Canonical+"|"+errText)
	o.codes = append(o.codes, rec.ErrCode)
	return fmt.Sprintf("rec-%d", len(o.recorded))
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
	_, err := h.Call(context.Background(), Call{Caller: callerAlice, ID: "mcp:gitlab:get_project", WorkID: "w1", MissionID: "m1", Observer: obs, Recorder: obs.record})
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
	_, err := h.Call(context.Background(), Call{Caller: callerAlice, ID: "mcp:gitlab:get_project", Observer: obs, Recorder: obs.record})
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
			Caller: callerAlice, ID: id, Observer: obs, Recorder: obs.record,
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
		Caller: callerAlice, ID: "mcp:gitlab:get_project", Observer: obs, Recorder: obs.record,
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
	_, err := h.Call(context.Background(), Call{Caller: callerAlice, ID: "mcp:gitlab:get_project", Observer: obs, Recorder: obs.record})
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
	if _, err := h.Call(context.Background(), Call{Caller: callerAlice, ID: "native:nmap", Observer: obs, Recorder: obs.record}); !errors.Is(err, ErrNativeID) {
		t.Fatalf("err = %v, want ErrNativeID", err)
	}
	if len(obs.events) != 0 {
		t.Fatalf("a native id left events %v", obs.events)
	}
}

func TestCall_NeedsAnObserver(t *testing.T) {
	h := NewHandler(nil, allowAll(), nil)
	if _, err := h.Call(context.Background(), Call{Caller: callerAlice, ID: "mcp:gitlab:x", Recorder: func(context.Context, CallRecord, []byte, string) string { return "" }}); err == nil {
		t.Fatal("want an error with no observer")
	}
}

// A call is recorded by the flight recorder whatever its outcome: a success, a
// denial and a refused intent. A native id is not, because the harness owns it.
func TestCall_TheFlightRecorderSeesEachOutcome(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	h := NewHandler(nil, allowAll("mcp:gitlab:get_project"), q)
	call := Call{Caller: callerAlice, ID: "mcp:gitlab:get_project", Observer: obs, Recorder: obs.record}

	if _, err := h.Call(context.Background(), call); err != nil {
		t.Fatalf("success: %v", err)
	}
	obs.intentErr = errors.New("down")
	if _, err := h.Call(context.Background(), call); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("refused intent: %v", err)
	}
	obs.intentErr = nil
	denied := NewHandler(nil, allowAll(), q)
	if _, err := denied.Call(context.Background(), call); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("denied: %v", err)
	}
	if len(obs.recorded) != 3 || obs.recorded[0] != "mcp:gitlab:get_project|" {
		t.Fatalf("recorded = %v, want three records, the first with no error", obs.recorded)
	}
	// A native id leaves no record here.
	obs.recorded = nil
	nat := NewHandler(nil, allowAll("native:nmap"), q)
	if _, err := nat.Call(context.Background(), Call{Caller: callerAlice, ID: "native:nmap", Observer: obs, Recorder: obs.record}); !errors.Is(err, ErrNativeID) {
		t.Fatalf("native: %v", err)
	}
	if len(obs.recorded) != 0 {
		t.Fatalf("a native id was recorded: %v", obs.recorded)
	}
}

// Both spellings of an mcp id match in both directions: an entry written as
// mcp__c__t blocks mcp:c:t, and the reverse.
func TestMatchBlocked_BothSpellingsMatchBothWays(t *testing.T) {
	cases := []struct {
		entry, id string
	}{
		{"mcp:gitlab:get_project", "mcp__gitlab__get_project"},
		{"mcp__gitlab__get_project", "mcp:gitlab:get_project"},
		{"MCP__GitLab__Get_Project", "mcp:gitlab:get_project"},
		{"mcp:gitlab:get_project", "mcp:gitlab:get_project"},
	}
	for _, tc := range cases {
		if _, ok := MatchBlocked([]string{tc.entry}, tc.id); !ok {
			t.Errorf("entry %q did not block id %q", tc.entry, tc.id)
		}
	}
	if _, ok := MatchBlocked([]string{"mcp__gitlab__get_project"}, "mcp:gitlab:other"); ok {
		t.Error("another tool must not match")
	}
	if _, ok := MatchBlocked([]string{"nmap"}, "native:nmap", "nmap"); !ok {
		t.Error("a bare native name must still match itself")
	}
}

// A native id that the check denies is recorded as a failure and returned.
func TestCall_ADeniedNativeIDIsRecorded(t *testing.T) {
	obs := &seqObserver{}
	h := NewHandler(nil, allowAll(), &seqQuerier{obs: obs})
	_, err := h.Call(context.Background(), Call{Caller: callerAlice, ID: "native:nmap", Observer: obs, Recorder: obs.record})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if len(obs.recorded) != 1 || len(obs.events) != 1 || obs.events[0] != "result" {
		t.Fatalf("recorded = %v, events = %v", obs.recorded, obs.events)
	}
}

// grantRecorder keeps the grant id of each record.
type grantRecorder struct{ grants []string }

func (g *grantRecorder) record(_ context.Context, rec CallRecord, _ []byte, _ string) string {
	g.grants = append(g.grants, rec.GrantID)
	return "rec"
}

// The record of an allowed connector call names the grant that the lookup
// read. A refused call names none (gibson#1474).
func TestCall_TheRecordNamesTheGrantOfTheCall(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	var asked []string
	h := NewHandler(nil, allowAll("mcp:okta:suspend_user"), q).WithGrantLookup(
		func(_ context.Context, tenant, subject, connector string) (string, error) {
			asked = append(asked, tenant+"/"+subject+"/"+connector)
			return "g-7", nil
		})
	rec := &grantRecorder{}
	call := func(id string) {
		_, _ = h.Call(context.Background(), Call{Caller: callerAlice, ID: id, Observer: obs, Recorder: rec.record})
	}
	call("mcp:okta:suspend_user")
	call("mcp:okta:delete_user") // not allowed
	if len(rec.grants) != 2 || rec.grants[0] != "g-7" || rec.grants[1] != "" {
		t.Fatalf("grants = %q, want [g-7 \"\"]", rec.grants)
	}
	if len(asked) != 1 || asked[0] != "acme/user:alice/okta" {
		t.Fatalf("lookups = %v", asked)
	}
}

// The flight recorder gets the typed code of a refusal, so a reader tells the
// kinds apart by the code and not by the words (gibson#1575).
func TestCall_TheRecordHoldsTheTypedCode(t *testing.T) {
	obs := &seqObserver{}
	h := NewHandler(nil, allowAll(), &seqQuerier{obs: obs})
	_, err := h.Call(context.Background(), Call{Caller: callerAlice, ID: "mcp:gitlab:get_project", Observer: obs, Recorder: obs.record})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if len(obs.codes) != 1 || obs.codes[0] != ErrCodeNotAuthorized {
		t.Fatalf("codes = %v, want [%s]", obs.codes, ErrCodeNotAuthorized)
	}

	ok := &seqObserver{}
	h = NewHandler(nil, allowAll("mcp:gitlab:get_project"), &seqQuerier{obs: ok})
	if _, err := h.Call(context.Background(), Call{Caller: callerAlice, ID: "mcp:gitlab:get_project", Observer: ok, Recorder: ok.record}); err != nil {
		t.Fatal(err)
	}
	if len(ok.codes) != 1 || ok.codes[0] != "" {
		t.Fatalf("a call that succeeded has code %v, want none", ok.codes)
	}
}

func TestCodeOf(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want ErrCode
	}{
		{nil, ""},
		{fmt.Errorf("%w: mcp:a:b", ErrUnauthorized), ErrCodeNotAuthorized},
		{fmt.Errorf("%w: request 1", ErrApprovalPending), ErrCodePendingAuthorization},
		{fmt.Errorf("%w: mr", ErrMergeNotGranted), ErrCodeMergeNotGranted},
		{ErrBlocked, ErrCodeRefused},
		{ErrRunInactive, ErrCodeRefused},
		{ErrApprovalDenied, ErrCodeRefused},
		{errors.New("vendor returned HTTP 500"), ErrCodeFailed},
	} {
		if got := CodeOf(tc.err); got != tc.want {
			t.Errorf("CodeOf(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// A member call passes the loop check first. A covered connector goes on to the
// can_execute check and the dispatch, and the record names the grant, the
// grantor and the member (gibson#1612).
func TestCall_LoopCheckCoveredRecordsGrantAndGrantor(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	h := NewHandler(nil, allowAll("mcp:jira:create_issue"), q)
	_, err := h.Call(context.Background(), Call{
		Caller: callerAlice, ID: "mcp:jira:create_issue", Observer: obs, Recorder: obs.record,
		MemberID: "m-1",
		Loop: func(_ context.Context, connector string) (LoopAllow, error) {
			if connector != "jira" {
				t.Errorf("loop check got connector %q", connector)
			}
			return LoopAllow{GrantID: "lg-1", Grantor: "user:admin"}, nil
		},
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if obs.last.LoopGrantID != "lg-1" || obs.last.Grantor != "user:admin" || obs.last.MemberID != "m-1" {
		t.Errorf("record = %+v, want the grant, the grantor and the member", obs.last)
	}
	d := auditDetails(obs.last, nil)
	if d["loop_grant_id"] != "lg-1" || d["grantor"] != "user:admin" || d["member_id"] != "m-1" {
		t.Errorf("audit details = %v", d)
	}
}

// A refusal by the loop check dispatches nothing, and it is recorded. The
// record names the grant when one exists.
func TestCall_LoopCheckRefusalIsRecordedAndDispatchesNothing(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	h := NewHandler(nil, allowAll("mcp:jira:create_issue"), q)
	_, err := h.Call(context.Background(), Call{
		Caller: callerAlice, ID: "mcp:jira:create_issue", Observer: obs, Recorder: obs.record,
		Loop: func(context.Context, string) (LoopAllow, error) {
			return LoopAllow{GrantID: "lg-1", Grantor: "user:admin"}, fmt.Errorf("%w: class ticket", ErrLoopGrantDenied)
		},
	})
	if !errors.Is(err, ErrLoopGrantDenied) {
		t.Fatalf("err = %v, want ErrLoopGrantDenied", err)
	}
	if q.calls != 0 {
		t.Fatal("a refused call must not reach the connector")
	}
	if len(obs.recorded) != 1 || obs.codes[0] != ErrCodeNotAuthorized {
		t.Errorf("recorded = %v codes = %v, want one record with not_authorized", obs.recorded, obs.codes)
	}
	if got := obs.events; len(got) != 1 || got[0] != "result" {
		t.Errorf("events = %v, want only the result record", got)
	}
	if d := auditDetails(obs.last, obs.resultErr); d["error"] != "no_loop_grant" || d["loop_grant_id"] != "lg-1" {
		t.Errorf("audit details = %v", d)
	}
}

// The loop grant does not replace can_execute: a covered connector that the
// tenant switched off is still refused.
func TestCall_LoopCheckDoesNotReplaceCanExecute(t *testing.T) {
	obs := &seqObserver{}
	q := &seqQuerier{obs: obs}
	h := NewHandler(nil, allowAll("mcp:other:tool"), q)
	_, err := h.Call(context.Background(), Call{
		Caller: callerAlice, ID: "mcp:jira:create_issue", Observer: obs, Recorder: obs.record,
		Loop: func(context.Context, string) (LoopAllow, error) { return LoopAllow{GrantID: "lg-1"}, nil },
	})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized from can_execute", err)
	}
	if q.calls != 0 {
		t.Fatal("the connector must not be called")
	}
}

// A loop grant covers connector tools only.
func TestCall_LoopCheckRefusesANativeTool(t *testing.T) {
	obs := &seqObserver{}
	h := NewHandler(nil, allowAll("native:nmap"), &seqQuerier{obs: obs})
	_, err := h.Call(context.Background(), Call{
		Caller: callerAlice, ID: "native:nmap", Observer: obs, Recorder: obs.record,
		Loop: func(context.Context, string) (LoopAllow, error) { return LoopAllow{}, nil },
	})
	if !errors.Is(err, ErrLoopGrantDenied) {
		t.Fatalf("err = %v, want ErrLoopGrantDenied", err)
	}
}
