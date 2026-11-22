// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package metatool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
)

// The approval gate of invoke_tool (gibson#1474, ADR-0180, ADR-0132).
//
// The manifest of a connector marks the tools that need the approval of a
// person (componentcatalog.ToolApproval). Handler.Call checks the mark after
// the can_execute check and before the dispatch. It is the one place that
// dispatches an mcp: id, so an agent cannot skip it.

// ErrApprovalPending means that a person has not decided yet. The call did not
// reach the connector. The agent can call again with the same arguments after
// the approval.
var ErrApprovalPending = errors.New("metatool: pending authorization: a person must approve this call before it runs")

// ErrApprovalDenied means that a person refused the call. The decision is
// final. Callers map it to permission denied.
var ErrApprovalDenied = errors.New("metatool: a person denied this call")

// ErrMergeNotGranted means that the call merges a merge request and the World
// of the tenant holds no merge slot for it yet (gibson#1458, ADR-0179). The
// call did not reach the connector. The agent can call again after the slot is
// granted.
var ErrMergeNotGranted = errors.New("metatool: merge not granted yet: the merge request waits for its merge slot")

// ErrDaemonOnly means that only the daemon calls the tool (the role "daemon"
// of the manifest, review M7). It wraps ErrBlocked, so each caller refuses it
// as a blocked call.
var ErrDaemonOnly = fmt.Errorf("%w: only the daemon calls this tool", ErrBlocked)

// ErrApprovalUnavailable means that the tool needs approval and the daemon has
// no approval queue for it. The call does not run (fail closed).
var ErrApprovalUnavailable = errors.New("metatool: the tool needs approval and the approval queue is not available")

// ApprovalState is the answer of the approval queue.
type ApprovalState int

const (
	// ApprovalStatePending means that a request waits for a decision.
	ApprovalStatePending ApprovalState = iota + 1
	// ApprovalStateDenied means that a person refused.
	ApprovalStateDenied
	// ApprovalStateApproved means that a person approved and the gate spent the
	// approval. The call runs one time.
	ApprovalStateApproved
)

// ApprovalRequest is one call that needs approval.
type ApprovalRequest struct {
	Tenant    string
	MissionID string
	// Agent is the identity of the caller (Caller.Subject). The approval key
	// holds it (review m16).
	Agent     string
	Connector string
	Tool      string
	// ArgsHash is the hash of the canonical arguments (ArgsHash).
	ArgsHash string
	// BlastRadius is the text for the approver: the manifest text and the
	// arguments of the call.
	BlastRadius string
	// Reversible is true only when the manifest names an undo tool.
	Reversible bool
}

// ApprovalGate is the check of the World of the tenant at tool dispatch. The
// daemon implements it over the approval queue of ADR-0132
// (brain.DestructiveAuthorizationQueue) and over the merge slots of
// gibson#1466 (brain.World.MayMerge). No method blocks.
type ApprovalGate interface {
	// Acquire returns the state of the call and the id of its request. For
	// ApprovalStateApproved the approval is spent: the caller must run the
	// call now or lose the approval.
	Acquire(ctx context.Context, req ApprovalRequest) (ApprovalState, string, error)
	// MayMerge reports whether the merge request holds its merge slot in the
	// World of the tenant.
	MayMerge(ctx context.Context, tenant, missionID, mergeRequest string) (bool, error)
}

// MergeAskRecorder is an optional part of an ApprovalGate. The gate records that
// a run asked for a merge and was refused, so the World knows which run waits for
// the slot (gibson#1609). The mission and the run come from the verified grant of
// the call.
type MergeAskRecorder interface {
	AskedForMerge(ctx context.Context, tenant, missionID, runID, mergeRequest string)
}

// MergeRequestArg is the argument of a merge tool that names the merge
// request. Its value is the key that the fix job recorded.
const MergeRequestArg = "merge_request"

// ApprovalMarks returns the approval rule of one tool.
type ApprovalMarks func(connector, tool string) componentcatalog.ToolApproval

// WithApprovalGate wires the approval queue. A call of a marked tool with no
// queue is refused.
func (h *Handler) WithApprovalGate(g ApprovalGate) *Handler {
	h.gate = g
	return h
}

// WithApprovalMarks replaces the source of the marks. The default is the
// catalog of the platform. Tests use it.
func (h *Handler) WithApprovalMarks(m ApprovalMarks) *Handler {
	h.marks = m
	return h
}

func (h *Handler) approvalFor(connector, tool string) componentcatalog.ToolApproval {
	if h.marks != nil {
		return h.marks(connector, tool)
	}
	return componentcatalog.LookupToolApproval(connector, tool)
}

// gateCall applies the approval rule to one call. It returns nil when the call
// may reach the connector.
func (h *Handler) gateCall(ctx context.Context, c Call, connector, tool string) error {
	mark := h.approvalFor(connector, tool)
	if mark.DaemonOnly && !c.Daemon {
		return fmt.Errorf("%w: %s:%s", ErrDaemonOnly, connector, tool)
	}
	// The merge slot comes first, so a call that waits for its slot never
	// spends an approval.
	if mark.Merge {
		if err := h.mergeGranted(ctx, c, connector, tool); err != nil {
			return err
		}
	}
	if !mark.Required {
		return nil
	}
	if h.gate == nil {
		return fmt.Errorf("%w: %s:%s", ErrApprovalUnavailable, connector, tool)
	}
	state, id, err := h.gate.Acquire(ctx, ApprovalRequest{
		Tenant:      c.Caller.Tenant,
		MissionID:   c.MissionID,
		Agent:       c.Caller.Subject,
		Connector:   connector,
		Tool:        tool,
		ArgsHash:    ArgsHash(c.Args),
		BlastRadius: blastRadiusText(mark.BlastRadius, c.Args),
		Reversible:  mark.UndoTool != "",
	})
	if err != nil {
		return fmt.Errorf("metatool: the approval check of %s:%s failed: %w", connector, tool, err)
	}
	switch state {
	case ApprovalStateApproved:
		return nil
	case ApprovalStateDenied:
		return fmt.Errorf("%w: request %s", ErrApprovalDenied, id)
	case ApprovalStatePending:
		return fmt.Errorf("%w: request %s", ErrApprovalPending, id)
	default:
		return fmt.Errorf("%w: unknown state %d", ErrApprovalUnavailable, state)
	}
}

// mergeGranted returns nil when the merge request of the call holds its merge
// slot. The daemon reads the slot from the World. The word of the agent is
// never the source.
func (h *Handler) mergeGranted(ctx context.Context, c Call, connector, tool string) error {
	if h.gate == nil {
		return fmt.Errorf("%w: %s:%s has the merge role and the daemon has no merge gate", ErrApprovalUnavailable, connector, tool)
	}
	mr, _ := c.Args[MergeRequestArg].(string)
	mr = strings.TrimSpace(mr)
	if mr == "" {
		return fmt.Errorf("%w: the call of %s:%s names no %s", ErrMergeNotGranted, connector, tool, MergeRequestArg)
	}
	ok, err := h.gate.MayMerge(ctx, c.Caller.Tenant, c.MissionID, mr)
	if err != nil {
		return fmt.Errorf("metatool: the merge check of %s:%s failed: %w", connector, tool, err)
	}
	if !ok {
		// The run waits for the slot. The World keeps the run, so a slot whose
		// run ended is found.
		if rec, isRec := h.gate.(MergeAskRecorder); isRec && c.RunID != "" {
			rec.AskedForMerge(ctx, c.Caller.Tenant, c.MissionID, c.RunID, mr)
		}
		return fmt.Errorf("%w: %s", ErrMergeNotGranted, mr)
	}
	return nil
}

// ArgsHash returns the hash of the arguments of a call. It hashes the JSON
// form with sorted keys, so two calls with the same arguments in another order
// or with other white space have the same hash. A nil map and an empty map are
// the same.
func ArgsHash(args map[string]any) string {
	if args == nil {
		args = map[string]any{}
	}
	// json.Marshal sorts the keys of a map at each level.
	raw, err := json.Marshal(args)
	if err != nil {
		// A value that cannot be marshaled gets a hash of its printed form. The
		// call still has a stable key and a different value has a different one.
		raw = []byte(fmt.Sprintf("%#v", args))
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

const (
	maxArgValueText = 120
	maxBlastText    = 600
)

// blastRadiusText joins the text of the manifest and the arguments of the call,
// so the approver sees the target. A value is cut short. The text is for a
// person to read: the key of the request does not depend on it.
func blastRadiusText(manifest string, args map[string]any) string {
	parts := []string{}
	if manifest != "" {
		parts = append(parts, manifest)
	}
	if len(args) > 0 {
		keys := make([]string, 0, len(args))
		for k := range args {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		kv := make([]string, 0, len(keys))
		for _, k := range keys {
			v := fmt.Sprint(args[k])
			if len(v) > maxArgValueText {
				v = v[:maxArgValueText] + "..."
			}
			kv = append(kv, k+"="+v)
		}
		parts = append(parts, "Arguments: "+strings.Join(kv, ", "))
	}
	out := strings.Join(parts, ". ")
	if len(out) > maxBlastText {
		out = out[:maxBlastText] + "..."
	}
	return out
}
