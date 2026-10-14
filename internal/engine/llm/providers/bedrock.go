// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	bedrockcontrol "github.com/aws/aws-sdk-go-v2/service/bedrock"
	controltypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/document"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/google/uuid"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// defaultBedrockModelID is the model the provider falls back to when neither
// cfg.DefaultModel nor the per-request model is set.
const defaultBedrockModelID = "anthropic.claude-3-sonnet-20240229-v1:0"

// BedrockProvider implements LLMProvider for AWS Bedrock foundation models.
//
// It speaks the unified Bedrock Converse API directly against an
// aws-sdk-go-v2 bedrockruntime.Client. Converse is the single interface for
// every Bedrock foundation model (Claude, Titan/Nova, Llama, Cohere, Mistral,
// AI21), so the provider does not need per-family request shaping.
//
// Credential resolution (in order):
//  1. use_irsa=true: skip static-key validation entirely; rely on the AWS SDK
//     default credential chain (IRSA via OIDC token projection, EC2 instance
//     profile, ECS task role, etc.). No access-key fields required or used.
//  2. Static creds from cfg.Extra["aws_access_key_id"] / ["aws_secret_access_key"]
//     (and optional ["aws_session_token"]). These are treated as a pair — both
//     must be set or both empty.
//  3. The AWS SDK default credential chain (shared config, IAM role, IRSA, etc.).
//
// The daemon's environment is never read for a static key: a config carrying
// no credential of its own must not construct on the daemon's ambient keys and
// then be registered as though the credential belonged to the caller.
//
// Region resolution: cfg.Extra["aws_region"] → AWS_REGION env → us-east-1.
// Region is not a credential, so it is read from the environment unguarded.
type BedrockProvider struct {
	client        *bedrockruntime.Client
	controlClient bedrockModelLister
	config        llm.ProviderConfig
	region        string
	modelID       string
	cache         modelCache
}

// bedrockModelLister is the part of the Bedrock control-plane client that the
// provider uses. *bedrockcontrol.Client satisfies it.
type bedrockModelLister interface {
	ListFoundationModels(ctx context.Context, in *bedrockcontrol.ListFoundationModelsInput, opts ...func(*bedrockcontrol.Options)) (*bedrockcontrol.ListFoundationModelsOutput, error)
}

// NewBedrockProvider constructs a Bedrock-backed LLMProvider.
func NewBedrockProvider(cfg llm.ProviderConfig) (*BedrockProvider, error) {
	region := firstNonEmpty(
		cfg.Extra["aws_region"],
		os.Getenv("AWS_REGION"),
		"us-east-1",
	)

	ctx := context.Background()
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
	}

	// When use_irsa=true the daemon runs inside EKS with a service-account IAM
	// role annotation (or any other ambient credential source). Static key
	// fields are irrelevant — skip both the mismatch guard and the explicit
	// credentials provider so the AWS SDK default chain takes over.
	useIRSA := cfg.Extra["use_irsa"] == "true"

	if !useIRSA {
		ak := cfg.Extra["aws_access_key_id"]
		sk := cfg.Extra["aws_secret_access_key"]
		st := cfg.Extra["aws_session_token"]

		// If only one of ak/sk is set, that's a misconfiguration — fail loudly
		// rather than silently falling through to the default chain.
		if (ak == "") != (sk == "") {
			return nil, llm.NewAuthError("bedrock",
				errors.New("aws_access_key_id and aws_secret_access_key must both be set or both empty"))
		}
		if ak != "" && sk != "" {
			loadOpts = append(loadOpts,
				awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(ak, sk, st)))
		}
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, llm.NewAuthError("bedrock", fmt.Errorf("load AWS config: %w", err))
	}

	// Guard the Bedrock API traffic itself, but NOT awsCfg's HTTP client: the
	// AWS credential chain legitimately reaches the EC2 instance metadata
	// service at 169.254.169.254 when the daemon runs on EC2 without IRSA.
	// Guarding awsCfg would break credential resolution while protecting
	// nothing — Bedrock's endpoint is region-derived, never tenant-supplied.
	guarded := guardedHTTPClient(cfg)
	brClient := bedrockruntime.NewFromConfig(awsCfg, func(o *bedrockruntime.Options) {
		o.HTTPClient = guarded
	})
	controlClient := bedrockcontrol.NewFromConfig(awsCfg, func(o *bedrockcontrol.Options) {
		o.HTTPClient = guarded
	})

	modelID := cfg.DefaultModel
	if modelID == "" {
		modelID = defaultBedrockModelID
	}

	return &BedrockProvider{
		client:        brClient,
		controlClient: controlClient,
		config:        cfg,
		region:        region,
		modelID:       modelID,
	}, nil
}

// Name returns the provider name.
func (p *BedrockProvider) Name() string { return "bedrock" }

// Models asks bedrock:ListFoundationModels for the foundation models of the
// region. It keeps the models that output text (chat) or embeddings. Bedrock
// reports no context window here, so the field stays zero.
func (p *BedrockProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	if p.controlClient == nil {
		return nil, fmt.Errorf("list models: %w", llm.NewProviderError("bedrock", errors.New("bedrock client not initialised")))
	}
	return p.cache.get(func() ([]llm.ModelInfo, error) {
		out, err := p.controlClient.ListFoundationModels(ctx, &bedrockcontrol.ListFoundationModelsInput{})
		if err != nil {
			return nil, translateBedrockError(err)
		}
		models := make([]llm.ModelInfo, 0, len(out.ModelSummaries))
		for _, m := range out.ModelSummaries {
			id := aws.ToString(m.ModelId)
			if id == "" {
				continue
			}
			var features []string
			for _, mod := range m.OutputModalities {
				switch mod {
				case controltypes.ModelModalityText:
					features = append(features, "chat")
				case controltypes.ModelModalityEmbedding:
					features = append(features, "embedding")
				case controltypes.ModelModalityImage:
					// Image output is not a chat or embedding model.
				}
			}
			if len(features) == 0 {
				continue
			}
			if aws.ToBool(m.ResponseStreamingSupported) {
				features = append(features, "streaming")
			}
			if slices.Contains(m.InputModalities, controltypes.ModelModalityImage) {
				features = append(features, "vision")
			}
			models = append(models, llm.ModelInfo{Name: id, Features: features})
		}
		return models, nil
	})
}

// Complete performs a non-tool completion.
func (p *BedrockProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	input, err := buildConverseInput(req, p.modelID, nil)
	if err != nil {
		return nil, translateBedrockError(err)
	}
	out, err := p.client.Converse(ctx, input)
	if err != nil {
		return nil, translateBedrockError(err)
	}
	return fromConverseOutput(out, req.Model), nil
}

// CompleteWithTools performs a completion with tool definitions.
// Only Anthropic Claude (and Amazon Nova) on Bedrock currently support
// tool_use; the daemon's slot resolver is expected to route tool-capable
// requests accordingly.
func (p *BedrockProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	input, err := buildConverseInput(req, p.modelID, tools)
	if err != nil {
		return nil, translateBedrockError(err)
	}
	out, err := p.client.Converse(ctx, input)
	if err != nil {
		return nil, translateBedrockError(err)
	}
	return fromConverseOutput(out, req.Model), nil
}

// Stream emits a streaming completion via the Converse streaming API.
func (p *BedrockProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	input := &bedrockruntime.ConverseStreamInput{
		ModelId:  aws.String(firstNonEmpty(req.Model, p.modelID)),
		Messages: buildConverseMessages(req.Messages),
	}
	if sys := extractSystemPrompt(req.Messages); sys != "" {
		input.System = []bedrocktypes.SystemContentBlock{
			&bedrocktypes.SystemContentBlockMemberText{Value: sys},
		}
	}
	if req.MaxTokens > 0 || req.Temperature != 0 || req.TopP != 0 || len(req.StopSequences) > 0 {
		input.InferenceConfig = buildInferenceConfig(req)
	}

	out, err := p.client.ConverseStream(ctx, input)
	if err != nil {
		return nil, translateBedrockError(err)
	}

	model := firstNonEmpty(req.Model, p.modelID)
	chunkChan := make(chan llm.StreamChunk, 10)
	go func() {
		defer close(chunkChan)
		stream := out.GetStream()
		defer stream.Close()
		var usage *llm.CompletionTokenUsage
		for event := range stream.Events() {
			switch v := event.(type) {
			case *bedrocktypes.ConverseStreamOutputMemberContentBlockDelta:
				if delta, ok := v.Value.Delta.(*bedrocktypes.ContentBlockDeltaMemberText); ok {
					chunkChan <- llm.StreamChunk{Delta: llm.StreamDelta{Content: delta.Value}}
				}
			case *bedrocktypes.ConverseStreamOutputMemberMetadata:
				// Bedrock reports token usage in the trailing metadata event.
				if u := v.Value.Usage; u != nil {
					usage = &llm.CompletionTokenUsage{
						PromptTokens:     int(aws.ToInt32(u.InputTokens)),
						CompletionTokens: int(aws.ToInt32(u.OutputTokens)),
						TotalTokens:      int(aws.ToInt32(u.TotalTokens)),
					}
				}
			case *bedrocktypes.ConverseStreamOutputMemberMessageStop:
				// stream ended normally
			}
		}
		if err := stream.Err(); err != nil {
			chunkChan <- llm.StreamChunk{Error: translateBedrockError(err)}
			return
		}
		// Terminal chunk: aggregated usage + model so the harness World capture
		// path can fold the completed stream (gibson#1085).
		chunkChan <- llm.StreamChunk{FinishReason: llm.FinishReasonStop, Model: model, Usage: usage}
	}()
	return chunkChan, nil
}

// Health probes Bedrock liveness by calling ListFoundationModels. The call is
// read-only, non-billable, and validates that both network reachability and IAM
// credentials (static or IRSA) are functional. A non-nil controlClient is
// required; construction always sets it, so a nil guard here is just a safety net.
func (p *BedrockProvider) Health(ctx context.Context) types.HealthStatus {
	if p.client == nil || p.controlClient == nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, "bedrock client not initialised")
	}
	_, err := p.controlClient.ListFoundationModels(ctx, &bedrockcontrol.ListFoundationModelsInput{})
	if err != nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, translateBedrockError(err).Error())
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

// CredentialSchema returns the credential-field descriptors consumed by
// GetSupportedProviders.
func (p *BedrockProvider) CredentialSchema() []llm.CredentialField { return BedrockCredentialSchema() }

// BedrockCredentialSchema is the exported static schema used by the
// introspection RPC so the handler can build its descriptor table without
// instantiating a provider.
func BedrockCredentialSchema() []llm.CredentialField {
	return []llm.CredentialField{
		{Key: "aws_region", Label: "AWS Region", Placeholder: "us-east-1", Help: "Defaults to AWS_REGION env or us-east-1.", Type: llm.FieldRegion},
		{Key: "use_irsa", Label: "Use IAM role / IRSA", Secret: false, Help: "Select when the daemon runs in EKS with a service-account IAM role annotation. Leave static key fields blank.", Type: llm.FieldBool},
		{Key: "aws_access_key_id", Label: "AWS Access Key ID", Secret: true, Help: "Leave blank to use the AWS SDK default credential chain (IAM role, IRSA, instance profile).", Type: llm.FieldPassword},
		{Key: "aws_secret_access_key", Label: "AWS Secret Access Key", Secret: true, Type: llm.FieldPassword},
		{Key: "aws_session_token", Label: "AWS Session Token", Secret: true, Help: "Only required for temporary credentials.", Type: llm.FieldPassword},
	}
}

// buildConverseInput constructs a ConverseInput from a CompletionRequest.
func buildConverseInput(req llm.CompletionRequest, defaultModelID string, tools []llm.ToolDef) (*bedrockruntime.ConverseInput, error) {
	modelID := firstNonEmpty(req.Model, defaultModelID)
	input := &bedrockruntime.ConverseInput{
		ModelId:  aws.String(modelID),
		Messages: buildConverseMessages(req.Messages),
	}
	if sys := extractSystemPrompt(req.Messages); sys != "" {
		input.System = []bedrocktypes.SystemContentBlock{
			&bedrocktypes.SystemContentBlockMemberText{Value: sys},
		}
	}
	if req.MaxTokens > 0 || req.Temperature != 0 || req.TopP != 0 || len(req.StopSequences) > 0 {
		input.InferenceConfig = buildInferenceConfig(req)
	}
	if len(tools) > 0 {
		toolConfig, err := buildToolConfig(tools)
		if err != nil {
			return nil, err
		}
		input.ToolConfig = toolConfig
	}
	return input, nil
}

// buildConverseMessages converts Gibson messages to Bedrock Converse messages.
// System messages are handled separately (they go in ConverseInput.System).
func buildConverseMessages(msgs []llm.Message) []bedrocktypes.Message {
	var out []bedrocktypes.Message
	for _, m := range msgs {
		switch m.Role {
		case llm.RoleSystem:
			continue // system handled separately
		case llm.RoleAssistant:
			msg := bedrocktypes.Message{Role: bedrocktypes.ConversationRoleAssistant}
			if len(m.ToolCalls) > 0 {
				for _, tc := range m.ToolCalls {
					msg.Content = append(msg.Content, &bedrocktypes.ContentBlockMemberToolUse{
						Value: bedrocktypes.ToolUseBlock{
							ToolUseId: aws.String(tc.ID),
							Name:      aws.String(tc.Name),
							Input:     toolUseInputDocument(tc.Arguments),
						},
					})
				}
			} else {
				msg.Content = []bedrocktypes.ContentBlock{
					&bedrocktypes.ContentBlockMemberText{Value: m.Content},
				}
			}
			out = append(out, msg)
		case llm.RoleTool:
			// tool results map to user messages with toolResult content
			out = append(out, bedrocktypes.Message{
				Role: bedrocktypes.ConversationRoleUser,
				Content: []bedrocktypes.ContentBlock{
					&bedrocktypes.ContentBlockMemberToolResult{
						Value: bedrocktypes.ToolResultBlock{
							ToolUseId: aws.String(m.ToolCallID),
							Content: []bedrocktypes.ToolResultContentBlock{
								&bedrocktypes.ToolResultContentBlockMemberText{Value: m.Content},
							},
						},
					},
				},
			})
		default: // user
			out = append(out, bedrocktypes.Message{
				Role: bedrocktypes.ConversationRoleUser,
				Content: []bedrocktypes.ContentBlock{
					&bedrocktypes.ContentBlockMemberText{Value: m.Content},
				},
			})
		}
	}
	return out
}

// toolUseInputDocument turns a JSON-encoded tool-call argument string into the
// document.Interface the Converse API expects. The arguments are decoded into a
// generic value so the document marshaler re-emits proper JSON; an empty or
// invalid argument string degrades to an empty object.
func toolUseInputDocument(arguments string) document.Interface {
	if strings.TrimSpace(arguments) == "" {
		return document.NewLazyDocument(map[string]any{})
	}
	var v any
	if err := json.Unmarshal([]byte(arguments), &v); err != nil {
		return document.NewLazyDocument(map[string]any{})
	}
	return document.NewLazyDocument(v)
}

// extractSystemPrompt returns the content of the first system message, if any.
func extractSystemPrompt(msgs []llm.Message) string {
	for _, m := range msgs {
		if m.Role == llm.RoleSystem {
			return m.Content
		}
	}
	return ""
}

func buildInferenceConfig(req llm.CompletionRequest) *bedrocktypes.InferenceConfiguration {
	cfg := &bedrocktypes.InferenceConfiguration{}
	if req.MaxTokens > 0 {
		n := int32(req.MaxTokens)
		cfg.MaxTokens = &n
	}
	if req.Temperature != 0 {
		t := float32(req.Temperature)
		cfg.Temperature = &t
	}
	if req.TopP != 0 {
		t := float32(req.TopP)
		cfg.TopP = &t
	}
	if len(req.StopSequences) > 0 {
		cfg.StopSequences = req.StopSequences
	}
	return cfg
}

// buildToolConfig converts Gibson ToolDef slice to Bedrock ToolConfiguration.
func buildToolConfig(tools []llm.ToolDef) (*bedrocktypes.ToolConfiguration, error) {
	bedTools := make([]bedrocktypes.Tool, 0, len(tools))
	for _, t := range tools {
		// Round-trip the JSON schema through encoding/json so the document
		// marshaler receives a plain Go value (map/slice/scalars) rather than
		// the schema.JSON struct, which carries no document serde support.
		schemaBytes, err := json.Marshal(t.Parameters)
		if err != nil {
			return nil, fmt.Errorf("tool %q: marshal schema: %w", t.Name, err)
		}
		var schemaValue any
		if err := json.Unmarshal(schemaBytes, &schemaValue); err != nil {
			return nil, fmt.Errorf("tool %q: decode schema: %w", t.Name, err)
		}
		bedTools = append(bedTools, &bedrocktypes.ToolMemberToolSpec{
			Value: bedrocktypes.ToolSpecification{
				Name:        aws.String(t.Name),
				Description: aws.String(t.Description),
				InputSchema: &bedrocktypes.ToolInputSchemaMemberJson{
					Value: document.NewLazyDocument(schemaValue),
				},
			},
		})
	}
	return &bedrocktypes.ToolConfiguration{Tools: bedTools}, nil
}

// fromConverseOutput converts a Bedrock ConverseOutput to a Gibson CompletionResponse.
func fromConverseOutput(out *bedrockruntime.ConverseOutput, model string) *llm.CompletionResponse {
	resp := &llm.CompletionResponse{
		ID:           uuid.New().String(),
		Model:        model,
		FinishReason: llm.FinishReasonStop,
	}
	if out.Usage != nil {
		resp.Usage = llm.CompletionTokenUsage{
			PromptTokens:     int(aws.ToInt32(out.Usage.InputTokens)),
			CompletionTokens: int(aws.ToInt32(out.Usage.OutputTokens)),
			TotalTokens:      int(aws.ToInt32(out.Usage.TotalTokens)),
		}
	}
	switch out.StopReason {
	case bedrocktypes.StopReasonEndTurn, bedrocktypes.StopReasonStopSequence:
		resp.FinishReason = llm.FinishReasonStop
	case bedrocktypes.StopReasonMaxTokens:
		resp.FinishReason = llm.FinishReasonLength
	case bedrocktypes.StopReasonToolUse:
		resp.FinishReason = llm.FinishReasonToolCalls
	}
	if msgOut, ok := out.Output.(*bedrocktypes.ConverseOutputMemberMessage); ok {
		resp.Message.Role = llm.RoleAssistant
		for _, block := range msgOut.Value.Content {
			switch b := block.(type) {
			case *bedrocktypes.ContentBlockMemberText:
				resp.Message.Content += b.Value
			case *bedrocktypes.ContentBlockMemberToolUse:
				resp.Message.ToolCalls = append(resp.Message.ToolCalls, llm.ToolCall{
					ID:        aws.ToString(b.Value.ToolUseId),
					Type:      "function",
					Name:      aws.ToString(b.Value.Name),
					Arguments: toolUseInputJSON(b.Value.Input),
				})
			}
		}
	}
	return resp
}

// toolUseInputJSON renders a Converse tool-use input document back into the
// JSON string Gibson's ToolCall.Arguments expects.
func toolUseInputJSON(input document.Interface) string {
	if input == nil {
		return ""
	}
	var v any
	if err := input.UnmarshalSmithyDocument(&v); err != nil {
		return ""
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(raw)
}

// translateBedrockError maps AWS service errors into Gibson's error taxonomy.
func translateBedrockError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	lower := strings.ToLower(msg)

	switch {
	case strings.Contains(lower, "throttlingexception"),
		strings.Contains(lower, "too many requests"),
		strings.Contains(lower, "rate exceeded"):
		return llm.NewRateLimitError("bedrock")
	case strings.Contains(lower, "unrecognizedclientexception"),
		strings.Contains(lower, "unauthorizedoperation"),
		strings.Contains(lower, "accessdeniedexception"),
		strings.Contains(lower, "invaliduseridentity"):
		return llm.NewAuthError("bedrock", err)
	case strings.Contains(lower, "validationexception"),
		strings.Contains(lower, "modelnotsupportedexception"):
		return llm.NewInvalidInputError("bedrock", msg)
	default:
		return llm.TranslateError("bedrock", err)
	}
}

// firstNonEmpty returns the first non-empty string in the argument list, or "" if all are empty.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
