// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
)

// openMergeRequestTool is the tool that a coding job calls to open its merge
// request. The tool result passes the tool gate of the daemon, so the daemon sees
// the head commit that the tool made.
const openMergeRequestTool = ":open_merge_request"

// openedRecordTimeout bounds the wait for the fold of the record of an open.
const openedRecordTimeout = 10 * time.Second

// openedHead is the head commit that open_merge_request returned, and who asked.
type openedHead struct {
	sha          string
	sourceBranch string
	// jobID is the job whose turn made the call.
	jobID string
}

// openedHeadReader returns the head that open_merge_request returned for a merge
// request of a tenant.
type openedHeadReader interface {
	// OpenedHead returns the head that the tool result named for the merge request
	// key, for the job. ok is false when the Timeline of the tenant holds no result
	// of a turn of that job.
	OpenedHead(tenant, mergeRequest, jobID string) (openedHead, bool)
}

// worldOpenedHeads reads the heads from the World of the tenant. The Timeline is
// the store, so a restart, a link that waits across a restart, and a second
// replica read the same heads. Each tenant has its own World, so a tenant cannot
// evict the heads of another.
type worldOpenedHeads struct{ reg *brain.Registry }

var _ openedHeadReader = worldOpenedHeads{}

func (w worldOpenedHeads) OpenedHead(tenant, mergeRequest, jobID string) (openedHead, bool) {
	if w.reg == nil || jobID == "" {
		return openedHead{}, false
	}
	var rec brain.OpenedMergeRequest
	var ok bool
	w.reg.For(tenant).ReadWorld(func(world *brain.World) { rec, ok = world.OpenedMergeRequest(mergeRequest, jobID) })
	if !ok {
		return openedHead{}, false
	}
	return openedHead{sha: rec.HeadSHA, sourceBranch: rec.SourceBranch, jobID: rec.JobID}, true
}

// openResult is the part of the result of open_merge_request that the daemon reads.
type openResult struct {
	MergeRequest string `json:"merge_request"`
	URL          string `json:"url"`
	SourceBranch string `json:"source_branch"`
	HeadSHA      string `json:"head_sha"`
}

// openedEventOf returns the Timeline event for a successful open_merge_request
// call of a turn of a job. ok is false for any other call, for a call that failed,
// for a call with no verified task grant, and for a result that holds no head or no
// branch. The job is the task of the verified grant, which a caller cannot forge.
func openedEventOf(call harness.ToolCallRecord) (brain.MergeRequestOpened, bool) {
	if call.Err != "" || call.GrantTaskID == "" || !strings.HasPrefix(call.ToolName, "mcp:") ||
		!strings.HasSuffix(call.ToolName, openMergeRequestTool) {
		return brain.MergeRequestOpened{}, false
	}
	var res openResult
	if json.Unmarshal([]byte(call.Result), &res) != nil || res.HeadSHA == "" || res.SourceBranch == "" ||
		(res.MergeRequest == "" && res.URL == "") {
		return brain.MergeRequestOpened{}, false
	}
	return brain.MergeRequestOpened{
		MergeRequest: res.MergeRequest, URL: res.URL, JobID: call.GrantTaskID, SourceBranch: res.SourceBranch,
		HeadSHA: res.HeadSHA, RunID: call.RunID, MissionID: call.MissionID, MissionRunID: call.MissionRunID,
		At: time.Unix(0, call.RecordedAtUnixNano).UTC(),
	}, true
}

// recordOpenedHead submits the event of a successful open_merge_request call to the
// World of the tenant, and it waits for the fold, so the link of the closed job
// finds the head. A failure is logged. The tool call still succeeded, and the link
// then records no head and says why.
func recordOpenedHead(ctx context.Context, reg *brain.Registry, tenant string, call harness.ToolCallRecord) {
	ev, ok := openedEventOf(call)
	if !ok || reg == nil || tenant == "" {
		return
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), openedRecordTimeout)
	defer cancel()
	if err := reg.For(tenant).SubmitAndWait(wctx, ev); err != nil {
		slog.ErrorContext(ctx, "the head of an opened merge request is not in the World, so its fix gets no head",
			"tenant", tenant, "merge_request", ev.MergeRequest, "error", err)
	}
}

// toolCallSink adds the record of the opened merge requests to the sink of tool
// calls.
func (d *daemonImpl) toolCallSink(next harness.ToolCallSink) harness.ToolCallSink {
	return func(ctx context.Context, tenant string, call harness.ToolCallRecord) {
		recordOpenedHead(ctx, d.brainRegistry, tenant, call)
		next(ctx, tenant, call)
	}
}
