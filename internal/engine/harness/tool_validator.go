package harness

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
	"google.golang.org/protobuf/proto"
)

// Prometheus metrics for tool validation
var (
	// toolExtractionSkippedTotal tracks tools that were skipped for entity extraction
	toolExtractionSkippedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_tool_extraction_skipped_total",
			Help: "Total number of tool responses skipped for entity extraction",
		},
		[]string{"tool_name", "reason", "mission_run_id"},
	)

	// toolDiscoveryComplianceTotal tracks tool proto compliance with discovery requirements
	toolDiscoveryComplianceTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_tool_discovery_compliance_total",
			Help: "Total tool response compliance checks by outcome",
		},
		[]string{"tool_name", "compliant", "mission_run_id"},
	)
)

// DiscoveryCategory is the tool category for discovery tools.
// Tools in this category are expected to populate field 100 DiscoveryResult.
const DiscoveryCategory = "discovery"

// knownDiscoveryTools is the set of tools known to be in the discovery category.
// These tools are expected to populate field 100 DiscoveryResult in their response proto.
// If they don't, a warning is logged but execution continues.
var knownDiscoveryTools = map[string]bool{
	"nmap":      true,
	"httpx":     true,
	"nuclei":    true,
	"subfinder": true,
	"dnsx":      true,
	"masscan":   true,
	"amass":     true,
	"ffuf":      true,
	"gobuster":  true,
	"katana":    true,
}

// ToolValidator validates tool response protos for compliance with extraction requirements.
// It checks if discovery-category tools properly populate field 100 DiscoveryResult
// and logs warnings for non-compliant tools. Validation failures do not block tool execution.
//
// Example usage:
//
//	validator := NewToolValidator(logger)
//	result := validator.ValidateDiscoveryCompliance(ctx, "nmap", responseProto)
//	if !result.Compliant {
//	    // Log warning but continue processing
//	}
type ToolValidator struct {
	logger *slog.Logger
}

// ToolValidationResult contains the outcome of a tool response validation.
type ToolValidationResult struct {
	// ToolName is the name of the validated tool
	ToolName string

	// Compliant indicates whether the tool response meets requirements
	Compliant bool

	// IsDiscoveryTool indicates whether this tool is in the discovery category
	IsDiscoveryTool bool

	// HasDiscoveryField indicates whether field 100 DiscoveryResult is present and non-empty
	HasDiscoveryField bool

	// SkipReason is set if the tool was skipped for extraction (only set when !Compliant)
	SkipReason string

	// EntityCount is the number of entities found in the discovery result (if present)
	EntityCount int
}

// NewToolValidator creates a new ToolValidator with the given logger.
func NewToolValidator(logger *slog.Logger) *ToolValidator {
	if logger == nil {
		logger = slog.Default()
	}
	return &ToolValidator{
		logger: logger,
	}
}

// ValidateDiscoveryCompliance checks if a tool response complies with discovery requirements.
// For tools in the discovery category (nmap, httpx, nuclei, etc.), it validates that
// field 100 DiscoveryResult is present and non-empty.
//
// Validation does not fail tool execution - it only logs warnings and records metrics
// for monitoring and debugging purposes.
//
// Parameters:
//   - ctx: Context for logging
//   - toolName: Name of the tool being validated
//   - response: The tool response proto message
//   - missionRunID: Mission run ID for metric labeling
//
// Returns:
//   - ToolValidationResult with compliance details
func (v *ToolValidator) ValidateDiscoveryCompliance(ctx context.Context, toolName string, response proto.Message, missionRunID string) ToolValidationResult {
	result := ToolValidationResult{
		ToolName:        toolName,
		IsDiscoveryTool: v.isDiscoveryTool(toolName),
	}

	// Check if the response has field 100 DiscoveryResult
	discovery := sdkgraphrag.ExtractDiscovery(response)
	if discovery != nil {
		result.HasDiscoveryField = true
		result.EntityCount = v.countEntities(discovery)
	}

	// Determine compliance
	if result.IsDiscoveryTool {
		if result.HasDiscoveryField && result.EntityCount > 0 {
			result.Compliant = true
		} else if result.HasDiscoveryField && result.EntityCount == 0 {
			// Field present but empty - might be legitimate (no findings)
			result.Compliant = true
			result.SkipReason = "empty_discovery"
		} else {
			// Discovery tool without field 100 - non-compliant
			result.Compliant = false
			result.SkipReason = "missing_discovery_field"

			v.logger.WarnContext(ctx, "discovery tool response missing field 100 DiscoveryResult",
				"tool", toolName,
				"mission_run_id", missionRunID,
				"help", "consider adding field 100 DiscoveryResult to the tool's response proto",
			)
		}
	} else {
		// Non-discovery tools are always compliant (no requirement for field 100)
		result.Compliant = true
		if !result.HasDiscoveryField {
			result.SkipReason = "not_discovery_tool"
		}
	}

	// Record metrics
	v.recordMetrics(result, missionRunID)

	return result
}

// isDiscoveryTool checks if a tool is in the discovery category.
func (v *ToolValidator) isDiscoveryTool(toolName string) bool {
	return knownDiscoveryTools[toolName]
}

// countEntities counts the total number of entities in a DiscoveryResult.
func (v *ToolValidator) countEntities(discovery proto.Message) int {
	// Use the SDK's ExtractDiscovery which returns *graphragpb.DiscoveryResult
	pbDiscovery := sdkgraphrag.ExtractDiscovery(discovery)
	if pbDiscovery == nil {
		return 0
	}

	count := len(pbDiscovery.Hosts) +
		len(pbDiscovery.Ports) +
		len(pbDiscovery.Services) +
		len(pbDiscovery.Endpoints) +
		len(pbDiscovery.Domains) +
		len(pbDiscovery.Subdomains) +
		len(pbDiscovery.Technologies) +
		len(pbDiscovery.Certificates) +
		len(pbDiscovery.Findings) +
		len(pbDiscovery.Evidence) +
		len(pbDiscovery.CustomNodes)

	return count
}

// recordMetrics records Prometheus metrics for validation results.
func (v *ToolValidator) recordMetrics(result ToolValidationResult, missionRunID string) {
	// Record compliance metric
	compliant := "false"
	if result.Compliant {
		compliant = "true"
	}
	toolDiscoveryComplianceTotal.WithLabelValues(result.ToolName, compliant, missionRunID).Inc()

	// Record skipped metric if extraction was skipped
	if result.SkipReason != "" {
		toolExtractionSkippedTotal.WithLabelValues(result.ToolName, result.SkipReason, missionRunID).Inc()
	}
}

// RegisterDiscoveryTool adds a tool to the known discovery tools set.
// This is useful for dynamically registering tools that should comply with
// discovery requirements.
func RegisterDiscoveryTool(toolName string) {
	knownDiscoveryTools[toolName] = true
}

// UnregisterDiscoveryTool removes a tool from the known discovery tools set.
func UnregisterDiscoveryTool(toolName string) {
	delete(knownDiscoveryTools, toolName)
}

// IsDiscoveryTool checks if a tool is in the known discovery tools set.
func IsDiscoveryTool(toolName string) bool {
	return knownDiscoveryTools[toolName]
}

// ListDiscoveryTools returns a list of all known discovery tools.
func ListDiscoveryTools() []string {
	tools := make([]string, 0, len(knownDiscoveryTools))
	for tool := range knownDiscoveryTools {
		tools = append(tools, tool)
	}
	return tools
}
