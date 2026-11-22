// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package metatool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
)

// ErrBlocked is returned when the mission policy blocks the tool.
var ErrBlocked = errors.New("metatool: the tool is blocked by mission policy")

// ErrRunInactive is returned when the mission run may not call tools.
var ErrRunInactive = errors.New("metatool: the mission run is not active")

// ErrLoopGrantDenied is returned when a bank member calls a tool that its loop
// grant does not cover: no grant exists, the grant has not the class of the
// connector, or the tool is not a connector tool (gibson#1612).
var ErrLoopGrantDenied = errors.New("metatool: the loop grant of the member does not cover the tool")

// ErrLoopGrantUnavailable is returned when the loop grant of a member could not
// be read. The call is refused, because an unread grant is not an empty one.
var ErrLoopGrantUnavailable = errors.New("metatool: the loop grant of the member could not be read")

// ErrAuditUnavailable is returned when the record of a call could not be
// written. The call does not happen.
var ErrAuditUnavailable = errors.New("metatool: the audit record could not be written")

// blockedKey is the form in which a tool id is compared with the deny list. An
// mcp id has two spellings (mcp:<connector>:<tool> and mcp__<connector>__<tool>),
// so both the entry of the list and the requested id go to the canonical form
// first. Any other name, such as a bare native tool name, is compared as it is.
func blockedKey(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if tid, err := decodeID(id); err == nil {
		id = tid.Canonical()
	}
	return id
}

// MatchBlocked reports the first candidate tool id that appears in the
// mission-level deny list. Both sides are canonicalized, so the two spellings
// of an mcp id match in both directions. It is the one place that blocked_tools
// is compared, so each path agrees.
func MatchBlocked(blocked []string, candidates ...string) (string, bool) {
	if len(blocked) == 0 {
		return "", false
	}
	set := make(map[string]struct{}, len(blocked))
	for _, b := range blocked {
		if k := blockedKey(b); k != "" {
			set[k] = struct{}{}
		}
	}
	for _, c := range candidates {
		if _, ok := set[blockedKey(c)]; ok {
			return c, true
		}
	}
	return "", false
}

// MissionPolicy is what a mission lets a call do.
type MissionPolicy struct {
	// Blocked is the mission deny list (MissionConstraints.blocked_tools).
	Blocked []string
	// RunActive returns nil when the run may call tools, and an error that
	// wraps ErrRunInactive when it may not. Nil means there is no run to check.
	RunActive func(ctx context.Context) error
}

// CheckRun applies the run check of the policy.
func (p MissionPolicy) CheckRun(ctx context.Context) error {
	var err error
	if p.RunActive != nil {
		err = p.RunActive(ctx)
	}
	return err
}

// CallRecord names one connector call for the observer.
type CallRecord struct {
	Tenant  string
	Subject string
	// Canonical is the canonical tool id, mcp:<connector>:<tool>.
	Canonical string
	Connector string
	Tool      string
	ArgsJSON  []byte
	// WorkID and MissionID are set only after the caller proved that it claimed
	// the work item. RunID is the mission run of the call.
	WorkID    string
	MissionID string
	RunID     string
	// GrantID is the capability grant that allowed the call. It is empty when
	// the call was refused, when no lookup is wired, or when no grant row
	// exists for the subject.
	GrantID string
	// ErrCode is the typed reason of a call that did not succeed. It is empty
	// for a call that succeeded.
	ErrCode ErrCode
	// MemberID, LoopGrantID and Grantor are set for the call of a bank member.
	// They name the member, the loop grant that the check read, and the admin
	// who gave that grant (gibson#1612). A refusal holds them when a grant
	// exists. They are empty for any other caller.
	MemberID    string
	LoopGrantID string
	Grantor     string
}

// LoopAllow names the loop grant behind the decision of a LoopCheck.
type LoopAllow struct {
	GrantID string
	Grantor string
}

// LoopCheck decides whether the loop grant of a bank member covers a connector.
// It returns the grant that it read, also when it refuses, so the record of the
// refusal names the grant. A refusal wraps ErrLoopGrantDenied. The check reads
// the tool class of the connector from the catalog manifest at call time.
type LoopCheck func(ctx context.Context, connector string) (LoopAllow, error)

// ErrCode is the typed reason of a call that did not succeed. An agent and the
// incident report tell the kinds apart by the code and never by the words of
// the message (gibson#1575). A call that succeeded has no code.
type ErrCode string

const (
	// ErrCodeNotAuthorized means the caller has no grant for the tool.
	ErrCodeNotAuthorized ErrCode = "not_authorized"
	// ErrCodePendingAuthorization means a person has not approved the call yet.
	ErrCodePendingAuthorization ErrCode = "pending_authorization"
	// ErrCodeMergeNotGranted means the merge request has no merge slot yet.
	ErrCodeMergeNotGranted ErrCode = "merge_not_granted"
	// ErrCodeRefused means the daemon refused the call by policy. CodeOf gives
	// it for the mission deny list, an inactive run and the denial of a person.
	// Only the denial of a person reaches the flight recorder and the incident
	// report. A call on the deny list or in an inactive run returns before the
	// record, so it has no record.
	ErrCodeRefused ErrCode = "refused"
	// ErrCodeFailed means the call ran or could not run, and it returned an error.
	ErrCodeFailed ErrCode = "failed"
)

// CodeOf returns the typed code of the error of a call. It returns the empty
// code for a nil error.
func CodeOf(err error) ErrCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrLoopGrantDenied):
		return ErrCodeNotAuthorized
	case errors.Is(err, ErrApprovalPending):
		return ErrCodePendingAuthorization
	case errors.Is(err, ErrMergeNotGranted):
		return ErrCodeMergeNotGranted
	case errors.Is(err, ErrBlocked), errors.Is(err, ErrRunInactive), errors.Is(err, ErrApprovalDenied):
		return ErrCodeRefused
	default:
		return ErrCodeFailed
	}
}

// FlightRecorder receives the record of each call, ADR-0131: a call is recorded
// whatever its outcome, so the agent never gets the result of a tool without an
// independent record of it. It returns the id that the record holds, or an empty
// string when nothing was recorded. The reply of the call carries the id, so a
// finding can cite the call.
type FlightRecorder func(ctx context.Context, rec CallRecord, resultJSON []byte, errText string) string

// CallObserver writes the audit records of a call. Intent runs before the call
// and refuses it when it fails. Result runs after the call, whatever the
// outcome, and also after a refusal that follows the intent.
type CallObserver interface {
	Intent(ctx context.Context, rec CallRecord) error
	Result(ctx context.Context, rec CallRecord, resultJSON []byte, callErr error)
}

// Call is one tool call of an agent.
type Call struct {
	Caller catalog.Caller
	// ID is the tool id as the agent gave it.
	ID   string
	Args map[string]any
	// ArgsJSON is the evidence of the arguments, as the agent sent them. Empty
	// means the marshaled Args.
	ArgsJSON  []byte
	Policy    MissionPolicy
	WorkID    string
	MissionID string
	RunID     string
	// Recorder writes the flight recorder record of the call. It is required.
	Recorder FlightRecorder
	// Observer writes the audit records of the call. It is required.
	Observer CallObserver
	// Loop is set only for the call of a bank member. The check sits beside
	// can_execute and does not replace it: the tenant switch of a connector
	// still stops the member. A call with no Loop is the call of a mission run.
	Loop LoopCheck
	// MemberID names the member behind a call with a Loop.
	MemberID string
	// Daemon is true only for a call that the daemon makes on its own
	// governed path (CallConnectorForTenant). A tool with the role "daemon"
	// runs only then. No agent request sets it.
	Daemon bool
}

// grantOf names the grant of an allowed call. A failed read leaves the record
// with no grant: the call is allowed already, and the report then shows the
// grant as not recorded rather than a wrong one.
func (h *Handler) grantOf(ctx context.Context, caller catalog.Caller, connector string) string {
	if h.grants == nil {
		return ""
	}
	id, err := h.grants(ctx, caller.Tenant, caller.Subject, connector)
	if err != nil {
		return ""
	}
	return id
}

// Call runs one tool call of an agent from start to end: the mission policy,
// the can_execute check, the intent record, the dispatch to the connector, and
// the result record. Each path that lets an agent call a connector tool uses it,
// so there is one policy and one record of a call.
//
// A native id is authorized and then returned as ErrNativeID, because the tool
// call handler of the harness owns a native call and its record.
func (h *Handler) Call(ctx context.Context, c Call) (any, error) {
	if c.Observer == nil || c.Recorder == nil {
		return nil, errors.New("metatool: a call needs an observer and a flight recorder")
	}
	tid, derr := decodeID(c.ID)
	canon := c.ID
	if derr == nil {
		canon = tid.Canonical()
	}
	if blockedID, ok := MatchBlocked(c.Policy.Blocked, c.ID, canon); ok {
		return nil, fmt.Errorf("%w: %s", ErrBlocked, blockedID)
	}
	if err := c.Policy.CheckRun(ctx); err != nil {
		return nil, err
	}

	argsJSON := c.ArgsJSON
	if len(argsJSON) == 0 {
		argsJSON = []byte("{}")
		if len(c.Args) > 0 {
			if b, err := json.Marshal(c.Args); err == nil {
				argsJSON = b
			}
		}
	}
	rec := CallRecord{
		Tenant: c.Caller.Tenant, Subject: c.Caller.Subject, Canonical: canon,
		ArgsJSON: argsJSON, WorkID: c.WorkID, MissionID: c.MissionID, RunID: c.RunID,
	}
	if c.Loop != nil {
		// The record names the member of every refusal, also one before the id
		// is decoded.
		rec.MemberID = c.MemberID
	}

	finish := func(resultJSON []byte, err error) {
		errText := ""
		if err != nil {
			errText = err.Error()
		}
		rec.ErrCode = CodeOf(err)
		_ = c.Recorder(ctx, rec, resultJSON, errText)
		c.Observer.Result(ctx, rec, resultJSON, err)
	}
	if derr != nil {
		finish(nil, derr)
		return nil, derr
	}
	rec.Connector, rec.Tool = tid.Connector, tid.Tool
	if c.Loop != nil {
		// A loop grant covers connector tools. A skill or a native tool is
		// refused, and the refusal is recorded with the grant that the member
		// holds, when it holds one. An empty connector is covered by no class.
		var allow LoopAllow
		var lerr error
		if tid.Source != toolid.SourceMCP {
			allow, _ = c.Loop(ctx, "")
			lerr = fmt.Errorf("%w: only a connector tool is covered", ErrLoopGrantDenied)
		} else {
			allow, lerr = c.Loop(ctx, tid.Connector)
		}
		rec.LoopGrantID, rec.Grantor = allow.GrantID, allow.Grantor
		if lerr != nil {
			finish(nil, lerr)
			return nil, lerr
		}
	}
	if tid.Source == toolid.SourceSkill {
		// A load of an Agent Skill reads the tenant database. It is no connector
		// call, so it has no connector audit record. The flight recorder
		// records it, whatever its outcome.
		result, err := h.loadSkill(ctx, c, tid)
		var resultJSON []byte
		if err == nil {
			resultJSON, _ = json.Marshal(result)
		}
		finish(resultJSON, err)
		if err != nil {
			return nil, err
		}
		return result, nil
	}
	if tid.Source != toolid.SourceMCP {
		if _, err := h.Authorize(ctx, c.Caller, c.ID); err != nil {
			finish(nil, err)
			return nil, err
		}
		return nil, ErrNativeID
	}

	// No call happens without its record.
	if err := c.Observer.Intent(ctx, rec); err != nil {
		refused := fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
		finish(nil, refused)
		return nil, refused
	}

	var result any
	var err error
	if _, err = h.Authorize(ctx, c.Caller, c.ID); err == nil {
		rec.GrantID = h.grantOf(ctx, c.Caller, tid.Connector)
		// The grant is not enough for a tool that the manifest marks. A merge
		// tool needs the merge slot, and a marked tool needs the approval of a
		// person, before the call reaches the connector.
		if err = h.gateCall(ctx, c, tid.Connector, tid.Tool); err == nil {
			result, err = h.Dispatch(ctx, c.Caller, tid, c.Args)
		}
	}
	var resultJSON []byte
	if err == nil {
		// A result that cannot be marshaled is still a completed call. The
		// record then holds no payload.
		resultJSON, _ = json.Marshal(result)
	}
	finish(resultJSON, err)
	if err != nil {
		return nil, err
	}
	return result, nil
}
