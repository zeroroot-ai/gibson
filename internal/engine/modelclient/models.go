// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package modelclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// ModelEntry is one model that a provider lists. The route of the list is a
// passthrough, so the reply is the list of the provider. A field that the
// provider does not report stays zero.
type ModelEntry struct {
	// ID is the exact model name.
	ID string
	// ContextWindow is the input window in tokens, or zero when the provider
	// does not report one.
	ContextWindow int
}

// Models sends one GET of /v1/models through the route of the target and returns
// the models that the provider lists. It reads the list shapes of the OpenAI and
// Anthropic APIs (data), the Gemini API (models) and the Bedrock list
// (modelSummaries). The call needs no model name.
func (c *Client) Models(ctx context.Context, caller Caller, target Target) ([]ModelEntry, error) {
	if err := target.validate(false); err != nil {
		return nil, err
	}
	resp, err := c.send(ctx, caller, target, http.MethodGet, modelcall.RouteModels, nil, "application/json")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("modelclient: read the model list: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return nil, errors.New("modelclient: the model list is larger than the gateway buffer")
	}
	return parseModelList(raw)
}

func parseModelList(raw []byte) ([]ModelEntry, error) {
	var list struct {
		Data []struct {
			ID             string `json:"id"`
			MaxInputTokens int    `json:"max_input_tokens"`
			ContextWindow  int    `json:"context_window"`
		} `json:"data"`
		Models []struct {
			Name            string `json:"name"`
			InputTokenLimit int    `json:"inputTokenLimit"`
		} `json:"models"`
		ModelSummaries []struct {
			ModelID string `json:"modelId"`
		} `json:"modelSummaries"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("modelclient: decode the model list: %w", err)
	}
	var out []ModelEntry
	for _, d := range list.Data {
		w := d.MaxInputTokens
		if w == 0 {
			w = d.ContextWindow
		}
		out = append(out, ModelEntry{ID: d.ID, ContextWindow: w})
	}
	for _, m := range list.Models {
		out = append(out, ModelEntry{ID: strings.TrimPrefix(m.Name, "models/"), ContextWindow: m.InputTokenLimit})
	}
	for _, m := range list.ModelSummaries {
		out = append(out, ModelEntry{ID: m.ModelID})
	}
	return out, nil
}
