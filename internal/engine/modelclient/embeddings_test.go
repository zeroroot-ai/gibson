// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package modelclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

func TestEmbeddings_RoundTripKeepsTheOrder(t *testing.T) {
	var path string
	var sent map[string]any
	c, _ := gateway(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		path = r.URL.Path
		_ = json.Unmarshal(body, &sent)
		// The gateway may answer out of order. The index decides.
		_, _ = io.WriteString(w, `{"data":[{"index":1,"embedding":[0,1]},{"index":0,"embedding":[1,0]}],
"usage":{"prompt_tokens":7}}`)
	})
	res, err := c.Embeddings(context.Background(), Caller{Tenant: "acme", Purpose: modelcall.PurposeEmbedding},
		Target{Tenant: "acme", Provider: "oa"}, "text-embedding-3-small", []string{"a", "b"})
	if err != nil {
		t.Fatalf("Embeddings: %v", err)
	}
	if path != modelcall.RouteEmbeddings || sent["model"] != "text-embedding-3-small" {
		t.Errorf("path = %q, sent = %v", path, sent)
	}
	if res.Vectors[0][0] != 1 || res.Vectors[1][1] != 1 || res.PromptTokens != 7 {
		t.Errorf("result = %+v", res)
	}
}

func TestEmbeddings_Refusals(t *testing.T) {
	c, _ := gateway(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		_, _ = io.WriteString(w, `{"data":[{"index":0,"embedding":[1]}]}`)
	})
	ctx := context.Background()
	caller := Caller{Tenant: "acme", Purpose: modelcall.PurposeEmbedding}
	target := Target{Tenant: "acme", Provider: "oa"}
	if _, err := c.Embeddings(ctx, caller, target, "", []string{"a"}); err == nil {
		t.Error("no model was accepted")
	}
	if _, err := c.Embeddings(ctx, caller, target, "m", []string{"a", "b"}); err == nil {
		t.Error("a short reply was accepted")
	}
	if _, err := c.Embeddings(ctx, Caller{Tenant: "other", Purpose: "embedding"}, target, "m", []string{"a"}); err == nil {
		t.Error("a caller of another tenant was accepted")
	}
}
