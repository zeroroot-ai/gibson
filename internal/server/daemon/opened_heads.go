// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
)

// openMergeRequestTool is the tool that a coding job calls to open its merge
// request. The tool result passes the tool gate of the daemon, so the daemon
// sees the head commit that the tool made.
const openMergeRequestTool = ":open_merge_request"

// openedHeadLimit bounds the heads that the daemon keeps. The oldest head goes
// first. A head that is gone gives a fix with no head, and the agent then makes
// no merge call.
const openedHeadLimit = 4096

// openedHead is the head commit that open_merge_request returned.
type openedHead struct {
	sha          string
	sourceBranch string
}

// openedHeadReader returns the head that open_merge_request returned for a merge
// request of a tenant.
type openedHeadReader interface {
	// OpenedHead returns the head and the source branch that the tool result
	// named for the merge request key. ok is false when the daemon saw no result.
	OpenedHead(tenant, mergeRequest string) (openedHead, bool)
}

// openedHeads remembers the head of each merge request that a tool call opened,
// by tenant and merge request. A head of one tenant is never read for another.
type openedHeads struct {
	mu    sync.Mutex
	heads map[string]openedHead
	order []string
}

var _ openedHeadReader = (*openedHeads)(nil)

func newOpenedHeads() *openedHeads { return &openedHeads{heads: map[string]openedHead{}} }

// openResult is the part of the result of open_merge_request that the daemon reads.
type openResult struct {
	MergeRequest string `json:"merge_request"`
	URL          string `json:"url"`
	SourceBranch string `json:"source_branch"`
	HeadSHA      string `json:"head_sha"`
}

// Record keeps the head of a successful open_merge_request call. Any other call
// is ignored. The head is kept under the reference and under the URL of the
// merge request, because the deliverable of a job names either.
func (o *openedHeads) Record(tenant string, call harness.ToolCallRecord) {
	if tenant == "" || call.Err != "" || !strings.HasPrefix(call.ToolName, "mcp:") ||
		!strings.HasSuffix(call.ToolName, openMergeRequestTool) {
		return
	}
	var res openResult
	if json.Unmarshal([]byte(call.Result), &res) != nil || res.HeadSHA == "" || res.SourceBranch == "" {
		return
	}
	h := openedHead{sha: res.HeadSHA, sourceBranch: res.SourceBranch}
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, key := range []string{res.MergeRequest, res.URL} {
		if key == "" {
			continue
		}
		k := tenant + "\x00" + key
		if _, ok := o.heads[k]; !ok {
			o.order = append(o.order, k)
		}
		o.heads[k] = h
	}
	for len(o.order) > openedHeadLimit {
		delete(o.heads, o.order[0])
		o.order = o.order[1:]
	}
}

// OpenedHead implements openedHeadReader.
func (o *openedHeads) OpenedHead(tenant, mergeRequest string) (openedHead, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	h, ok := o.heads[tenant+"\x00"+mergeRequest]
	return h, ok
}

// openedHeadStore returns the one store of the heads of this daemon.
func (d *daemonImpl) openedHeadStore() *openedHeads {
	d.openedHeadsOnce.Do(func() { d.openedHeads = newOpenedHeads() })
	return d.openedHeads
}

// toolCallSink adds the record of the heads to the sink of tool calls. The first
// sink records the call on the World, and the heads are read from the same call.
func (d *daemonImpl) toolCallSink(next harness.ToolCallSink) harness.ToolCallSink {
	heads := d.openedHeadStore()
	return func(ctx context.Context, tenant string, call harness.ToolCallRecord) {
		heads.Record(tenant, call)
		next(ctx, tenant, call)
	}
}
