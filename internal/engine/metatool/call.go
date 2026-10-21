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
	if p.RunActive == nil {
		return nil
	}
	return p.RunActive(ctx)
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
}

// FlightRecorder receives the record of each call, ADR-0131: a call is recorded
// whatever its outcome, so the agent never gets the result of a tool without an
// independent record of it.
type FlightRecorder func(ctx context.Context, rec CallRecord, resultJSON []byte, errText string)

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

	finish := func(resultJSON []byte, err error) {
		errText := ""
		if err != nil {
			errText = err.Error()
		}
		c.Recorder(ctx, rec, resultJSON, errText)
		c.Observer.Result(ctx, rec, resultJSON, err)
	}
	if derr != nil {
		finish(nil, derr)
		return nil, derr
	}
	rec.Connector, rec.Tool = tid.Connector, tid.Tool
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
		result, err = h.Dispatch(ctx, c.Caller, tid, c.Args)
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
