// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fixloop

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
)

// The tools that a connector of the tenant serves for the fix loop. A manifest
// of a Git host, a deploy tool or an observability tool states the tool that
// it serves. Each tool takes the arguments below and returns a JSON object.
const (
	// ToolMergeRequestState takes {merge_request} and returns {state,
	// pipeline_green, reason, at, created_at, source_branch,
	// source_branch_reason}. source_branch_reason says why the host gave no
	// source branch, for example a fork.
	ToolMergeRequestState = "merge_request_state"
	// ToolDeploymentState takes {merge_request} and returns {deployed,
	// deployment, application, at, restart: {needed, started, ended}}.
	ToolDeploymentState = "deployment_state"
	// ToolHealthSignal takes {application, since, hold_seconds} and returns
	// {known, done, held, at}.
	ToolHealthSignal = "health_signal"
	// ToolRevertMergeRequest takes {merge_request}. It opens a revert merge
	// request and merges it.
	ToolRevertMergeRequest = "revert_merge_request"
)

// ErrNoConnector means that the tenant has no connector that serves the tool.
var ErrNoConnector = errors.New("fixloop: the tenant has no connector that serves the tool")

// ToolLister lists the connector tools of a tenant. component.ConnectorMCP
// satisfies it. The fix loop uses it only to find the connector that serves a
// tool. It never calls a tool through it.
type ToolLister interface {
	ListConnectorTools(ctx context.Context, tenant string) ([]catalog.ToolEntry, error)
}

// TenantCaller makes a connector call for a tenant on the one governed path of
// a connector call: the can_execute check of the grant of the tenant on the
// connector, the audit records and the flight recorder (gibson#1465).
// harness.CallbackManager satisfies it.
type TenantCaller interface {
	CallConnectorForTenant(ctx context.Context, tenant, missionID, connector, tool string, args map[string]any) (any, error)
}

// ConnectorReader reads the facts of the fix loop through the connectors of
// the tenant. It implements Reader and Reverter. Each call, a read or the
// revert, goes through the TenantCaller: the can_execute check and the audit
// record of ADR-0065 apply to every connector call of the daemon.
type ConnectorReader struct {
	c ToolLister
	w TenantCaller
}

var (
	_ Reader   = (*ConnectorReader)(nil)
	_ Reverter = (*ConnectorReader)(nil)
)

// NewConnectorReader builds the reader over the tool list of the daemon and
// the governed caller of each connector call.
func NewConnectorReader(c ToolLister, w TenantCaller) *ConnectorReader {
	return &ConnectorReader{c: c, w: w}
}

// connectorFor returns the connector of the tenant that serves the tool. With
// more than one, it takes the first name in order, so the choice is stable.
func (r *ConnectorReader) connectorFor(ctx context.Context, tenant, tool string) (string, error) {
	tools, err := r.c.ListConnectorTools(ctx, tenant)
	if err != nil {
		return "", fmt.Errorf("list connector tools: %w", err)
	}
	var names []string
	for _, t := range tools {
		if t.Tool == tool && t.Connector != "" {
			names = append(names, t.Connector)
		}
	}
	if len(names) == 0 {
		return "", fmt.Errorf("%w: %s", ErrNoConnector, tool)
	}
	sort.Strings(names)
	return names[0], nil
}

// call makes one governed connector call. missionID is the mission of the fix,
// for the audit record and the flight recorder.
func (r *ConnectorReader) call(ctx context.Context, tenant, missionID, tool string, args map[string]any) (map[string]any, error) {
	if r.w == nil {
		return nil, errors.New("fixloop: no governed caller is wired")
	}
	conn, err := r.connectorFor(ctx, tenant, tool)
	if err != nil {
		return nil, err
	}
	res, err := r.w.CallConnectorForTenant(ctx, tenant, missionID, conn, tool, args)
	if err != nil {
		return nil, fmt.Errorf("call %s: %w", tool, err)
	}
	return object(tool, res)
}

func object(tool string, res any) (map[string]any, error) {
	m, ok := res.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("call %s: the result is %T, not an object", tool, res)
	}
	return m, nil
}

// MergeRequest implements Reader.
func (r *ConnectorReader) MergeRequest(ctx context.Context, tenant, missionID, key string) (MergeFact, error) {
	m, err := r.call(ctx, tenant, missionID, ToolMergeRequestState, map[string]any{"merge_request": key})
	if err != nil {
		return MergeFact{}, err
	}
	f := MergeFact{
		State: str(m, "state"), PipelineGreen: boolean(m, "pipeline_green"), Reason: str(m, "reason"), At: when(m, "at"),
		CreatedAt: when(m, "created_at"), SourceBranch: str(m, "source_branch"),
		SourceBranchReason:    str(m, "source_branch_reason"),
		HeadSHA:               str(m, "head_sha"),
		ChangedFilesTruncated: boolean(m, "changed_files_truncated"),
		ChangedFilesError:     str(m, "changed_files_error"),
	}
	if list, ok := m["changed_files"].([]any); ok {
		for _, item := range list {
			if fm, ok := item.(map[string]any); ok {
				f.ChangedFiles = append(f.ChangedFiles, ChangedFile{
					Path: str(fm, "path"), Change: str(fm, "change"), PreviousPath: str(fm, "previous_path"), BlobSHA: str(fm, "blob_sha"),
					Mode: str(fm, "mode"),
				})
			}
		}
	}
	switch f.State {
	case MROpen, MRMerged, MRClosed, MRRefused:
		return f, nil
	}
	return MergeFact{}, fmt.Errorf("merge request state %q is not known", f.State)
}

// Deploy implements Reader.
func (r *ConnectorReader) Deploy(ctx context.Context, tenant, missionID, mergeRequest string) (DeployFact, error) {
	m, err := r.call(ctx, tenant, missionID, ToolDeploymentState, map[string]any{"merge_request": mergeRequest})
	if err != nil {
		return DeployFact{}, err
	}
	d := DeployFact{
		Deployed: boolean(m, "deployed"), DeploymentKey: str(m, "deployment"),
		ApplicationKey: str(m, "application"), At: when(m, "at"),
	}
	if rm, ok := m["restart"].(map[string]any); ok {
		d.Restart = RestartFact{Needed: boolean(rm, "needed"), Started: when(rm, "started"), Ended: when(rm, "ended")}
	}
	return d, nil
}

// Health implements Reader.
func (r *ConnectorReader) Health(
	ctx context.Context, tenant, missionID, application string, since time.Time, hold time.Duration,
) (HealthFact, error) {
	m, err := r.call(ctx, tenant, missionID, ToolHealthSignal, map[string]any{
		"application": application, "since": since.UTC().Format(time.RFC3339), "hold_seconds": int64(hold / time.Second),
	})
	if err != nil {
		return HealthFact{}, err
	}
	return HealthFact{Known: boolean(m, "known"), Done: boolean(m, "done"), Held: boolean(m, "held"), At: when(m, "at")}, nil
}

// Revert implements Reverter. The result of the tool holds merged and
// revert_merge_request (zeroroot-ai/connectors, internal/fixloop RevertResult).
func (r *ConnectorReader) Revert(ctx context.Context, tenant, mergeRequest, missionID string) (RevertFact, error) {
	m, err := r.call(ctx, tenant, missionID, ToolRevertMergeRequest, map[string]any{"merge_request": mergeRequest})
	if err != nil {
		return RevertFact{}, err
	}
	return RevertFact{Merged: boolean(m, "merged"), RevertMergeRequest: str(m, "revert_merge_request")}, nil
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func boolean(m map[string]any, k string) bool { b, _ := m[k].(bool); return b }

func when(m map[string]any, k string) time.Time {
	t, err := time.Parse(time.RFC3339, str(m, k))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
