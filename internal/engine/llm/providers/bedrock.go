package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	bedrockcontrol "github.com/aws/aws-sdk-go-v2/service/bedrock"
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
//  3. Env vars AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (+ optional AWS_SESSION_TOKEN).
//  4. The AWS SDK default credential chain (shared config, IAM role, IRSA, etc.).
//
// Region resolution: cfg.Extra["aws_region"] → AWS_REGION env → us-east-1.
type BedrockProvider struct {
	client        *bedrockruntime.Client
	controlClient *bedrockcontrol.Client
	config        llm.ProviderConfig
	region        string
	modelID       string
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
		ak := firstNonEmpty(cfg.Extra["aws_access_key_id"], os.Getenv("AWS_ACCESS_KEY_ID"))
		sk := firstNonEmpty(cfg.Extra["aws_secret_access_key"], os.Getenv("AWS_SECRET_ACCESS_KEY"))
		st := firstNonEmpty(cfg.Extra["aws_session_token"], os.Getenv("AWS_SESSION_TOKEN"))

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

	brClient := bedrockruntime.NewFromConfig(awsCfg)
	controlClient := bedrockcontrol.NewFromConfig(awsCfg)

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

// Models returns the curated Bedrock foundation-model catalogue.
func (p *BedrockProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
	return bedrockModelCatalogue(), nil
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

	chunkChan := make(chan llm.StreamChunk, 10)
	go func() {
		defer close(chunkChan)
		stream := out.GetStream()
		defer stream.Close()
		for event := range stream.Events() {
			switch v := event.(type) {
			case *bedrocktypes.ConverseStreamOutputMemberContentBlockDelta:
				if delta, ok := v.Value.Delta.(*bedrocktypes.ContentBlockDeltaMemberText); ok {
					chunkChan <- llm.StreamChunk{Delta: llm.StreamDelta{Content: delta.Value}}
				}
			case *bedrocktypes.ConverseStreamOutputMemberMessageStop:
				// stream ended normally
			}
		}
		if err := stream.Err(); err != nil {
			chunkChan <- llm.StreamChunk{Error: translateBedrockError(err)}
		}
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
		{Key: "aws_region", Label: "AWS Region", Placeholder: "us-east-1", Help: "Defaults to AWS_REGION env or us-east-1."},
		{Key: "use_irsa", Label: "Use IAM role / IRSA", Secret: false, Help: "Select when the daemon runs in EKS with a service-account IAM role annotation. Leave static key fields blank."},
		{Key: "aws_access_key_id", Label: "AWS Access Key ID", Secret: true, Help: "Leave blank to use the AWS SDK default credential chain (IAM role, IRSA, instance profile)."},
		{Key: "aws_secret_access_key", Label: "AWS Secret Access Key", Secret: true},
		{Key: "aws_session_token", Label: "AWS Session Token", Secret: true, Help: "Only required for temporary credentials."},
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

// bedrockModelCatalogue returns the curated set of Bedrock foundation models
// Gibson exposes. Feature flags reflect the *provider-side* model's capability
// so the slot resolver can match agent requirements correctly.
//
// Model IDs are the raw Bedrock model IDs. Newer models (Claude 3 Opus,
// Claude 3.5 Sonnet, Llama 3.1/3.2) work at runtime as long as the operator's
// AWS account has access; the Converse API addresses every family uniformly.
func bedrockModelCatalogue() []llm.ModelInfo {
	chat := []string{"chat", "streaming"}
	claude := []string{"chat", "streaming", "tools"}
	return []llm.ModelInfo{
		// Anthropic Claude family — full tool_use on Bedrock's Anthropic adapter.
		{Name: "anthropic.claude-3-opus-20240229-v1:0", ContextWindow: 200000, MaxOutput: 4096, Features: claude},
		{Name: "anthropic.claude-3-sonnet-20240229-v1:0", ContextWindow: 200000, MaxOutput: 4096, Features: claude},
		{Name: "anthropic.claude-3-haiku-20240307-v1:0", ContextWindow: 200000, MaxOutput: 4096, Features: claude},
		{Name: "anthropic.claude-3-5-sonnet-20241022-v2:0", ContextWindow: 200000, MaxOutput: 8192, Features: claude},
		{Name: "anthropic.claude-3-5-haiku-20241022-v1:0", ContextWindow: 200000, MaxOutput: 8192, Features: claude},
		{Name: "anthropic.claude-v2:1", ContextWindow: 200000, MaxOutput: 4096, Features: chat},

		// Amazon Titan / Nova
		{Name: "amazon.titan-text-lite-v1", ContextWindow: 4096, MaxOutput: 4096, Features: chat},
		{Name: "amazon.titan-text-express-v1", ContextWindow: 8192, MaxOutput: 8192, Features: chat},
		{Name: "us.amazon.nova-micro-v1:0", ContextWindow: 128000, MaxOutput: 5000, Features: chat},
		{Name: "us.amazon.nova-lite-v1:0", ContextWindow: 300000, MaxOutput: 5000, Features: chat},
		{Name: "us.amazon.nova-pro-v1:0", ContextWindow: 300000, MaxOutput: 5000, Features: chat},

		// Meta Llama
		{Name: "meta.llama2-13b-chat-v1", ContextWindow: 4096, MaxOutput: 2048, Features: chat},
		{Name: "meta.llama2-70b-chat-v1", ContextWindow: 4096, MaxOutput: 2048, Features: chat},
		{Name: "meta.llama3-8b-instruct-v1:0", ContextWindow: 8192, MaxOutput: 2048, Features: chat},
		{Name: "meta.llama3-70b-instruct-v1:0", ContextWindow: 8192, MaxOutput: 2048, Features: chat},

		// Cohere Command
		{Name: "cohere.command-text-v14", ContextWindow: 4096, MaxOutput: 4096, Features: chat},
		{Name: "cohere.command-light-text-v14", ContextWindow: 4096, MaxOutput: 4096, Features: chat},

		// AI21 Jurassic-2
		{Name: "ai21.j2-ultra-v1", ContextWindow: 8192, MaxOutput: 8192, Features: chat},
		{Name: "ai21.j2-mid-v1", ContextWindow: 8192, MaxOutput: 8192, Features: chat},

		// Mistral
		{Name: "mistral.mistral-large-2407-v1:0", ContextWindow: 128000, MaxOutput: 8192, Features: chat},
		{Name: "mistral.mistral-7b-instruct-v0:2", ContextWindow: 32768, MaxOutput: 8192, Features: chat},
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
