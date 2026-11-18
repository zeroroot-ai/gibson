// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"encoding/json"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/schema"
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
