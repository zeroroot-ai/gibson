package harness

import (
	"encoding/json"

	harnesspb "github.com/zero-day-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zero-day-ai/sdk/schema"
)

// SchemaToCallbackProto converts SDK schema.JSON to harness callback proto JSONSchemaNode.
// This preserves taxonomy mappings during gRPC transport to agents.
func SchemaToCallbackProto(s schema.JSON) *harnesspb.JSONSchemaNode {
	// Return nil for empty schemas
	if s.Type == "" && len(s.Properties) == 0 && s.Items == nil {
		return nil
	}

	node := &harnesspb.JSONSchemaNode{
		Type:        s.Type,
		Description: s.Description,
		Required:    s.Required,
		Pattern:     &s.Pattern,
		Format:      s.Format,
	}

	// Convert properties recursively
	if len(s.Properties) > 0 {
		node.Properties = make(map[string]*harnesspb.JSONSchemaNode)
		for name, prop := range s.Properties {
			node.Properties[name] = SchemaToCallbackProto(prop)
		}
	}

	// Convert items recursively
	if s.Items != nil {
		node.Items = SchemaToCallbackProto(*s.Items)
	}

	// Convert enum values
	if len(s.Enum) > 0 {
		for _, v := range s.Enum {
			if str, ok := v.(string); ok {
				node.EnumValues = append(node.EnumValues, str)
			}
		}
	}

	// Convert numeric constraints
	if s.Minimum != nil {
		node.Minimum = s.Minimum
	}
	if s.Maximum != nil {
		node.Maximum = s.Maximum
	}
	if s.MinLength != nil {
		minLen := int32(*s.MinLength)
		node.MinLength = &minLen
	}
	if s.MaxLength != nil {
		maxLen := int32(*s.MaxLength)
		node.MaxLength = &maxLen
	}

	// Convert default value (JSON encode)
	if s.Default != nil {
		if data, err := json.Marshal(s.Default); err == nil {
			defaultVal := string(data)
			node.DefaultValue = &defaultVal
		}
	}

	return node
}

// CallbackProtoToSchema converts harness callback proto JSONSchemaNode to SDK schema.JSON.
// This reconstructs the full SDK schema with taxonomy from the proto representation.
func CallbackProtoToSchema(node *harnesspb.JSONSchemaNode) schema.JSON {
	if node == nil {
		return schema.JSON{}
	}

	s := schema.JSON{
		Type:        node.Type,
		Description: node.Description,
		Required:    node.Required,
		Format:      node.Format,
	}

	if node.Pattern != nil {
		s.Pattern = *node.Pattern
	}

	// Convert properties recursively
	if len(node.Properties) > 0 {
		s.Properties = make(map[string]schema.JSON)
		for name, prop := range node.Properties {
			s.Properties[name] = CallbackProtoToSchema(prop)
		}
	}

	// Convert items recursively
	if node.Items != nil {
		items := CallbackProtoToSchema(node.Items)
		s.Items = &items
	}

	// Convert enum values
	if len(node.EnumValues) > 0 {
		for _, v := range node.EnumValues {
			s.Enum = append(s.Enum, v)
		}
	}

	// Convert numeric constraints
	if node.Minimum != nil {
		s.Minimum = node.Minimum
	}
	if node.Maximum != nil {
		s.Maximum = node.Maximum
	}
	if node.MinLength != nil {
		minLen := int(*node.MinLength)
		s.MinLength = &minLen
	}
	if node.MaxLength != nil {
		maxLen := int(*node.MaxLength)
		s.MaxLength = &maxLen
	}

	// Convert default value (JSON decode)
	if node.DefaultValue != nil && *node.DefaultValue != "" {
		var def any
		if err := json.Unmarshal([]byte(*node.DefaultValue), &def); err == nil {
			s.Default = def
		}
	}

	return s
}
