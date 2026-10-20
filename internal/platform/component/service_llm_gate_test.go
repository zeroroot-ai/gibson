// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/llm/modelgate"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

// gateAdapter wires a tenant whose slot manager refuses with resolveErr.
func gateAdapter(resolveErr error) *LLMRegistryAdapter {
	prov := &mockLLMProvider{name: "p", models: []llm.ModelInfo{{Name: "m"}}}
	set := newTenantSet("p", prov)
	set.slots.resolveErr = resolveErr
	return NewLLMRegistryAdapter(nil, nil, adapterTestLogger).
		WithTenantResolver(tenantResolverFor(map[string]*tenantSet{adapterTestTenant: set}))
}

// A model gate denial is PermissionDenied on every completion RPC. A gate that
// could not decide stays Unavailable (gibson#1221).
func TestCompletionRPCs_ModelGateCodes(t *testing.T) {
	denied := fmt.Errorf("model_access_denied: not permitted: %w", modelgate.ErrDenied)
	undecided := fmt.Errorf("model_access_denied: check failed: %w", modelgate.ErrUnavailable)
	msgs := []*componentpb.LLMMessage{{Role: "user", Content: "hi"}}

	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"a denial", denied, codes.PermissionDenied},
		{"a gate that could not decide", undecided, codes.Unavailable},
		{"an unrelated slot failure", errors.New("no provider fits"), codes.Unavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adapter := gateAdapter(tc.err)
			svc := NewComponentServiceServer(&noopRegistry{}, &noopWorkQueue{}, testLogger(), adapter, nil, nil, nil).
				WithLLMToolCompleter(adapter)
			ctx := llmSeamContext()

			calls := map[string]func() error{
				"Complete": func() error {
					_, err := svc.Complete(ctx, &componentpb.CompleteRequest{Slot: "p", Messages: msgs})
					return err
				},
				"CompleteStream": func() error {
					//nolint:contextcheck // a server stream carries its context in the stream
					return svc.CompleteStream(&componentpb.CompleteStreamRequest{Slot: "p", Messages: msgs},
						&completeStream{ctx: ctx})
				},
				"CompleteWithTools": func() error {
					_, err := svc.CompleteWithTools(ctx, &componentpb.CompleteWithToolsRequest{Slot: "p", Messages: msgs})
					return err
				},
				"CompleteStructured": func() error {
					_, err := svc.CompleteStructured(ctx, &componentpb.CompleteStructuredRequest{
						Slot: "p", Messages: msgs, SchemaJson: `{"type":"object"}`})
					return err
				},
			}
			for name, call := range calls {
				err := call()
				require.Error(t, err, name)
				s, _ := status.FromError(err)
				assert.Equal(t, tc.want, s.Code(), "%s: %v", name, err)
			}
		})
	}
}
