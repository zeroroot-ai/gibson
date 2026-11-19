// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// metaToolAdapter serves the meta-tools of ComponentService with the handler
// of the callback service, so an agent in pull mode and an agent in callback
// mode share one implementation.
type metaToolAdapter struct{ svc *harness.CallbackManager }

var _ component.MetaToolCaller = metaToolAdapter{}

// CallMetaTool maps the reply of the callback handler to a MetaToolReply.
func (a metaToolAdapter) CallMetaTool(ctx context.Context, tenant, missionID, runID, name string, input []byte) (component.MetaToolReply, error) {
	resp, err := a.svc.CallMetaTool(ctx, tenant, missionID, runID, name, input)
	if err != nil {
		return component.MetaToolReply{}, fmt.Errorf("meta-tool %s: %w", name, err)
	}
	out := component.MetaToolReply{OutputJSON: string(resp.GetOutputJson()), ToolCallID: resp.GetToolCallId()}
	if e := resp.GetError(); e != nil {
		out.ErrorCode, out.ErrorMessage = e.GetCode().String(), e.GetMessage()
	}
	return out, nil
}
