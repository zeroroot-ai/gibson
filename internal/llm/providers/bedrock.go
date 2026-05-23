package providers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	bedrockcontrol "github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/tmc/langchaingo/llms/bedrock"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// BedrockProvider implements LLMProvider for AWS Bedrock foundation models.
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
//
// Note: langchaingo's bedrock package has no typed options for creds/region.
// Customisation happens by constructing the bedrockruntime.Client yourself
// and passing it with bedrock.WithClient — which is why this file imports
// aws-sdk-go-v2 directly despite Gibson's general langchaingo-only policy.
type BedrockProvider struct {
	client         *bedrock.LLM
	controlClient  *bedrockcontrol.Client
	config         llm.ProviderConfig
	region         string
	modelID        string
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
		modelID = bedrock.ModelAnthropicClaudeV3Sonnet
	}

	lc, err := bedrock.New(
		bedrock.WithClient(brClient),
		bedrock.WithModel(modelID),
	)
	if err != nil {
		return nil, llm.TranslateError("bedrock", err)
	}

	return &BedrockProvider{
		client:        lc,
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
	messages := toSchemaMessages(req.Messages)
	opts := buildCallOptions(req)
	resp, err := p.client.GenerateContent(ctx, messages, opts...)
	if err != nil {
		return nil, translateBedrockError(err)
	}
	return fromLangchainResponse(resp, req.Model), nil
}

// CompleteWithTools performs a completion with tool definitions.
// Only Anthropic Claude on Bedrock currently supports tool_use; the daemon's
// slot resolver is expected to route tool-capable requests accordingly.
func (p *BedrockProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	messages := toSchemaMessages(req.Messages)
	opts := buildCallOptionsWithTools(req, tools)
	resp, err := p.client.GenerateContent(ctx, messages, opts...)
	if err != nil {
		return nil, translateBedrockError(err)
	}
	return fromLangchainResponse(resp, req.Model), nil
}

// Stream emits a streaming completion.
func (p *BedrockProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	chunkChan := make(chan llm.StreamChunk, 10)
	messages := toSchemaMessages(req.Messages)
	opts := buildStreamingCallOptions(req, func(ctx context.Context, chunk []byte) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case chunkChan <- llm.StreamChunk{
			Delta: llm.StreamDelta{Content: string(chunk)},
		}:
			return nil
		}
	})

	go func() {
		defer close(chunkChan)
		_, err := p.client.GenerateContent(ctx, messages, opts...)
		if err != nil {
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
// Model IDs use langchaingo constants where available, and the raw Bedrock
// model IDs for anything langchaingo hadn't pinned as of v0.1.14. Newer models
// (Claude 3 Opus, Claude 3.5 Sonnet, Llama 3.1/3.2) work at runtime as long
// as the operator's AWS account has access.
func bedrockModelCatalogue() []llm.ModelInfo {
	chat := []string{"chat", "streaming"}
	claude := []string{"chat", "streaming", "tools"}
	return []llm.ModelInfo{
		// Anthropic Claude family — full tool_use on Bedrock's Anthropic adapter.
		{Name: "anthropic.claude-3-opus-20240229-v1:0", ContextWindow: 200000, MaxOutput: 4096, Features: claude},
		{Name: bedrock.ModelAnthropicClaudeV3Sonnet, ContextWindow: 200000, MaxOutput: 4096, Features: claude},
		{Name: bedrock.ModelAnthropicClaudeV3Haiku, ContextWindow: 200000, MaxOutput: 4096, Features: claude},
		{Name: "anthropic.claude-3-5-sonnet-20241022-v2:0", ContextWindow: 200000, MaxOutput: 8192, Features: claude},
		{Name: "anthropic.claude-3-5-haiku-20241022-v1:0", ContextWindow: 200000, MaxOutput: 8192, Features: claude},
		{Name: bedrock.ModelAnthropicClaudeV21, ContextWindow: 200000, MaxOutput: 4096, Features: chat},

		// Amazon Titan / Nova
		{Name: bedrock.ModelAmazonTitanTextLiteV1, ContextWindow: 4096, MaxOutput: 4096, Features: chat},
		{Name: bedrock.ModelAmazonTitanTextExpressV1, ContextWindow: 8192, MaxOutput: 8192, Features: chat},
		{Name: bedrock.ModelAmazonNovaMicroV1, ContextWindow: 128000, MaxOutput: 5000, Features: chat},
		{Name: bedrock.ModelAmazonNovaLiteV1, ContextWindow: 300000, MaxOutput: 5000, Features: chat},
		{Name: bedrock.ModelAmazonNovaProV1, ContextWindow: 300000, MaxOutput: 5000, Features: chat},

		// Meta Llama
		{Name: bedrock.ModelMetaLlama213bChatV1, ContextWindow: 4096, MaxOutput: 2048, Features: chat},
		{Name: bedrock.ModelMetaLlama270bChatV1, ContextWindow: 4096, MaxOutput: 2048, Features: chat},
		{Name: bedrock.ModelMetaLlama38bInstructV1, ContextWindow: 8192, MaxOutput: 2048, Features: chat},
		{Name: bedrock.ModelMetaLlama370bInstructV1, ContextWindow: 8192, MaxOutput: 2048, Features: chat},

		// Cohere Command
		{Name: bedrock.ModelCohereCommandTextV14, ContextWindow: 4096, MaxOutput: 4096, Features: chat},
		{Name: bedrock.ModelCohereCommandLightTextV14, ContextWindow: 4096, MaxOutput: 4096, Features: chat},

		// AI21 Jurassic-2
		{Name: bedrock.ModelAi21J2UltraV1, ContextWindow: 8192, MaxOutput: 8192, Features: chat},
		{Name: bedrock.ModelAi21J2MidV1, ContextWindow: 8192, MaxOutput: 8192, Features: chat},

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
