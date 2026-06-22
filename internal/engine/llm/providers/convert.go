package providers

import (
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/sdk/schema"
)

// convertResponseFormatToTool converts a ResponseFormat to a ToolDef for Anthropic's tool_use pattern.
// This enables structured output by having the model call a "tool" that represents the response schema.
func convertResponseFormatToTool(format *types.ResponseFormat) llm.ToolDef {
	params := convertSDKSchemaToInternal(format.Schema)

	return llm.ToolDef{
		Name:        format.Name,
		Description: "Provide a structured response matching the schema",
		Parameters:  params,
	}
}

// convertSDKSchemaToInternal converts types.JSONSchema to internal/schema.JSON.
func convertSDKSchemaToInternal(sdkSchema *types.JSONSchema) schema.JSON {
	if sdkSchema == nil {
		return schema.JSON{Type: "object"}
	}

	internalSchema := schema.JSON{
		Type:        sdkSchema.Type,
		Description: sdkSchema.Description,
		Required:    sdkSchema.Required,
	}

	if len(sdkSchema.Properties) > 0 {
		internalSchema.Properties = make(map[string]schema.JSON)
		for name, prop := range sdkSchema.Properties {
			internalSchema.Properties[name] = convertSDKSchemaFieldToInternal(prop)
		}
	}

	if sdkSchema.Items != nil {
		field := convertSDKSchemaFieldToInternal(sdkSchema.Items)
		internalSchema.Items = &field
	}

	return internalSchema
}

// convertSDKSchemaFieldToInternal converts types.JSONSchema to internal/schema.JSON recursively.
func convertSDKSchemaFieldToInternal(sdkField *types.JSONSchema) schema.JSON {
	if sdkField == nil {
		return schema.JSON{Type: "object"}
	}

	field := schema.JSON{
		Type:        sdkField.Type,
		Description: sdkField.Description,
		Pattern:     sdkField.Pattern,
		Format:      sdkField.Format,
		Minimum:     sdkField.Minimum,
		Maximum:     sdkField.Maximum,
		MinLength:   sdkField.MinLength,
		MaxLength:   sdkField.MaxLength,
		Required:    sdkField.Required,
	}

	if len(sdkField.Enum) > 0 {
		field.Enum = make([]any, len(sdkField.Enum))
		copy(field.Enum, sdkField.Enum)
	}

	if len(sdkField.Properties) > 0 {
		field.Properties = make(map[string]schema.JSON)
		for name, prop := range sdkField.Properties {
			field.Properties[name] = convertSDKSchemaFieldToInternal(prop)
		}
	}

	if sdkField.Items != nil {
		nestedField := convertSDKSchemaFieldToInternal(sdkField.Items)
		field.Items = &nestedField
	}

	return field
}
