package harness

import (
	"context"
	"log/slog"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// complianceMetadataFieldNumber is the proto field number reserved for
// tool/plugin compliance metadata on response messages. Field 100 is
// already reserved for DiscoveryResult; field 99 is the companion for
// compliance metadata bags.
//
// This convention is documented in docs/sdk/proto-conventions.md.
const complianceMetadataFieldNumber = 99

// ToolMetadataProvider is the precedence-4 MetadataProvider. It extracts
// a `map<string, string> compliance_metadata = 99;` field from tool / plugin
// response protos via reflection and returns it as a TagSet's custom bag.
//
// Tools that do NOT populate field 99 contribute no metadata — that's the
// common case and is silently supported. Malformed fields log a warning
// and return empty.
type ToolMetadataProvider struct {
	logger *slog.Logger
}

// NewToolMetadataProvider constructs a ToolMetadataProvider with the given
// logger. Pass nil to use slog.Default().
func NewToolMetadataProvider(logger *slog.Logger) *ToolMetadataProvider {
	if logger == nil {
		logger = slog.Default()
	}
	return &ToolMetadataProvider{
		logger: logger.With("component", "compliance_tool_provider"),
	}
}

// Precedence returns PrecedenceToolPlugin (4).
func (*ToolMetadataProvider) Precedence() int { return PrecedenceToolPlugin }

// Provide extracts field 99 from the given request/response proto message
// and returns its entries as the custom bag of a TagSet.
//
// Because the ComplianceMiddleware calls Provide at BEGIN time (before the
// inner call), the request proto is what's available — tool responses are
// out of reach. For tool metadata extraction to work end-to-end the
// middleware must also call a post-call variant (ProvideFromResponse) after
// the tool returns. For v1 we support both: if the request carries field
// 99 it's extracted here; if the response carries it, the middleware
// refines on completion.
func (p *ToolMetadataProvider) Provide(ctx context.Context, method HarnessMethod, request any) TagSet {
	msg, ok := request.(ToolCallTarget)
	if !ok {
		return NewTagSet()
	}
	return p.extract(ctx, msg.Request)
}

// ProvideFromResponse extracts field 99 from a tool response proto. The
// middleware calls this after the inner CallToolProto returns so that
// tools can stamp metadata on their responses as well as their requests.
func (p *ToolMetadataProvider) ProvideFromResponse(ctx context.Context, response proto.Message) TagSet {
	return p.extract(ctx, response)
}

// extract walks a proto message for field 99 (compliance_metadata) and
// returns its entries as a TagSet. Empty when absent or malformed.
func (p *ToolMetadataProvider) extract(ctx context.Context, msg proto.Message) TagSet {
	out := NewTagSet()
	if msg == nil {
		return out
	}

	defer func() {
		if r := recover(); r != nil {
			p.logger.WarnContext(ctx, "panic during compliance metadata extraction",
				slog.Any("panic", r),
			)
		}
	}()

	r := msg.ProtoReflect()
	if r == nil || !r.IsValid() {
		return out
	}

	fd := r.Descriptor().Fields().ByNumber(complianceMetadataFieldNumber)
	if fd == nil {
		return out
	}

	// Field must be map<string, string>.
	if !fd.IsMap() {
		p.logger.DebugContext(ctx, "compliance_metadata field is not a map — ignored",
			slog.String("descriptor", string(fd.FullName())),
		)
		return out
	}

	key := fd.MapKey()
	val := fd.MapValue()
	if key.Kind() != protoreflect.StringKind || val.Kind() != protoreflect.StringKind {
		p.logger.DebugContext(ctx, "compliance_metadata must be map<string, string> — ignored",
			slog.String("descriptor", string(fd.FullName())),
		)
		return out
	}

	r.Get(fd).Map().Range(func(k protoreflect.MapKey, v protoreflect.Value) bool {
		out.Custom[k.String()] = v.String()
		return true
	})
	return out
}

// Compile-time assertion.
var _ MetadataProvider = (*ToolMetadataProvider)(nil)
