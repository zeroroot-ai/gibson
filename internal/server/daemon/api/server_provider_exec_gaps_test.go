// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

func TestExecuteLLM_ASettingOfTheRequestReachesTheGateway(t *testing.T) {
	gw := &fakeChatModels{resp: textResponse("ok")}
	maxTokens, temperature := int32(321), 0.25
	_, err := chatServer(chatStore(), gw).ExecuteLLM(userChatCtx("t"), &tenantv1.ExecuteLLMRequest{
		ProviderName: "p", MaxTokens: &maxTokens, Temperature: &temperature,
		Messages: []*tenantv1.LLMMessageContent{
			{Role: "user", Content: "hi"},
			{Role: "assistant", Content: "earlier answer"},
		},
	})
	require.NoError(t, err)
	req := gw.reqs[0]
	assert.Equal(t, 321, req.MaxOutputTokens)
	require.NotNil(t, req.Temperature)
	assert.InDelta(t, 0.25, *req.Temperature, 1e-6)
	require.Len(t, req.Input, 2)
	assert.Equal(t, modelclient.RoleAssistant, req.Input[1].Role, "an assistant message with text is kept")
}

func TestExecuteLLM_AProviderRecordThatCannotBeReadIsInternal(t *testing.T) {
	store := &stubProviderConfigStore{getFunc: func(context.Context, string, string) (*providerconfig.ProviderConfig, error) {
		return nil, errors.New("database is down")
	}}
	_, err := chatServer(store, &fakeChatModels{}).ExecuteLLM(userChatCtx("t"), &tenantv1.ExecuteLLMRequest{
		ProviderName: "p", Messages: []*tenantv1.LLMMessageContent{{Role: "user", Content: "hi"}},
	})
	assert.Equal(t, codes.Internal, grpcCode(err))
	assert.NotContains(t, err.Error(), "database", "the cause stays in the log")
}

func TestExecuteLLM_ACallerWithNoSubjectIsUnauthenticated(t *testing.T) {
	ctx := auth.WithIdentity(auth.ContextWithTenantString(context.Background(), "t"),
		auth.Identity{Tenant: auth.MustNewTenantID("t")})
	gw := &fakeChatModels{resp: textResponse("ok")}
	_, err := chatServer(chatStore(), gw).ExecuteLLM(ctx, &tenantv1.ExecuteLLMRequest{
		ProviderName: "p", Messages: []*tenantv1.LLMMessageContent{{Role: "user", Content: "hi"}},
	})
	assert.Equal(t, codes.Unauthenticated, grpcCode(err))
	assert.Empty(t, gw.reqs, "no call reaches the gateway without an identity")
}
