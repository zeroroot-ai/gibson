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

// ApprovalGate is the approval queue of one daemon. The daemon implements it
// over the queue of ADR-0132 (brain.DestructiveAuthorizationQueue). Acquire
// never blocks.
type ApprovalGate interface {
	// Acquire returns the state of the call and the id of its request. For
	// ApprovalStateApproved the approval is spent: the caller must run the
	// call now or lose the approval.
	Acquire(ctx context.Context, req ApprovalRequest) (ApprovalState, string, error)
}

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
	if !mark.Required {
		return nil
	}
	if h.gate == nil {
		return fmt.Errorf("%w: %s:%s", ErrApprovalUnavailable, connector, tool)
	}
	state, id, err := h.gate.Acquire(ctx, ApprovalRequest{
		Tenant:      c.Caller.Tenant,
		MissionID:   c.MissionID,
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
		var kv []string
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
