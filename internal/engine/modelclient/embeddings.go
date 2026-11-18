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

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// EmbeddingsResult is the reply of an embeddings call, in the order of the
// inputs.
type EmbeddingsResult struct {
	Vectors      [][]float64
	PromptTokens int
}

// Embeddings sends one OpenAI Embeddings call through the route of the target.
// model is the exact model name. The vectors come back in the order of the
// inputs. A reply with another count of vectors than inputs is an error.
func (c *Client) Embeddings(
	ctx context.Context, caller Caller, target Target, model string, inputs []string,
) (*EmbeddingsResult, error) {
	if model == "" {
		return nil, errors.New("modelclient: the embeddings call has no exact model name")
	}
	t := target
	t.Model = model
	if err := t.validate(true); err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]any{"model": model, "input": inputs})
	if err != nil {
		return nil, fmt.Errorf("modelclient: encode the request: %w", err)
	}
	resp, err := c.send(ctx, caller, t, http.MethodPost, modelcall.RouteEmbeddings, body, "application/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("modelclient: read the reply: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return nil, errors.New("modelclient: the reply is larger than the gateway buffer")
	}
	var reply struct {
		Data []struct {
			Index     int       `json:"index"`
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
		Usage struct {
			PromptTokens int `json:"prompt_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, fmt.Errorf("modelclient: decode the reply: %w", err)
	}
	if len(reply.Data) != len(inputs) {
		return nil, fmt.Errorf("modelclient: the gateway returned %d vectors for %d inputs", len(reply.Data), len(inputs))
	}
	out := &EmbeddingsResult{Vectors: make([][]float64, len(inputs)), PromptTokens: reply.Usage.PromptTokens}
	for _, d := range reply.Data {
		if d.Index < 0 || d.Index >= len(inputs) || out.Vectors[d.Index] != nil {
			return nil, fmt.Errorf("modelclient: the reply has a bad vector index %d", d.Index)
		}
		out.Vectors[d.Index] = d.Embedding
	}
	return out, nil
}
