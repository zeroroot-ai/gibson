package extraction

import (
	"context"
	"fmt"
	"sync"

	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/proto"
)

// EntityExtractor defines the interface for tool-specific entity extraction.
// Each tool can implement an extractor that knows how to parse its proto response
// and convert it into a standardized DiscoveryResult containing nodes and relationships.
//
// Example implementation for nmap:
//
//	type NmapExtractor struct{}
//
//	func (e *NmapExtractor) ToolName() string {
//	    return "nmap"
//	}
//
//	func (e *NmapExtractor) CanExtract(msg proto.Message) bool {
//	    _, ok := msg.(*nmappb.NmapResponse)
//	    return ok
//	}
//
//	func (e *NmapExtractor) Extract(ctx context.Context, msg proto.Message) (*ExtractionResult, error) {
//	    resp := msg.(*nmappb.NmapResponse)
//	    // Convert resp.Hosts to DiscoveryResult
//	    return &ExtractionResult{
//	        Discovery: &graphragpb.DiscoveryResult{
//	            Hosts: convertHosts(resp.Hosts),
//	            Ports: convertPorts(resp.Hosts),
//	        },
//	    }, nil
//	}
type EntityExtractor interface {
	// ToolName returns the name of the tool this extractor handles.
	// This must match the tool's Name() method return value.
	// Example: "nmap", "nuclei", "httpx"
	ToolName() string

	// CanExtract checks if this extractor can process the given proto message.
	// Returns true if the message type matches this extractor's expected input.
	// This allows for graceful handling of unknown or unsupported message types.
	CanExtract(msg proto.Message) bool

	// Extract converts a tool-specific proto response into a standardized extraction result.
	// The result contains:
	//   - Discovery: The DiscoveryResult with nodes (hosts, ports, services, findings, etc.)
	//   - RootEntityID: Optional ID of the primary/root entity discovered (e.g., main host ID)
	//
	// Returns an error if extraction fails (parse errors, invalid data, etc.)
	Extract(ctx context.Context, msg proto.Message) (*ExtractionResult, error)
}

// ExtractionResult contains the output of an entity extraction operation.
// It wraps the DiscoveryResult proto and provides metadata about the extraction.
type ExtractionResult struct {
	// Discovery contains all extracted entities (hosts, ports, services, findings, etc.)
	// and their relationships. This is the proto that gets persisted to the graph.
	Discovery *graphragpb.DiscoveryResult

	// RootEntityID is the optional ID of the primary/root entity discovered.
	// For example, in an nmap scan, this might be the ID of the scanned host.
	// This can be used for navigation or to establish a starting point in the graph.
	RootEntityID string

	// Metadata contains additional extraction metadata (tool version, extraction time, etc.)
	// This is optional and tool-specific.
	Metadata map[string]string
}

// ExtractorRegistry manages the registration and lookup of entity extractors.
// It provides a centralized registry where extractors can be registered by tool name
// and retrieved for processing tool responses.
//
// The registry is thread-safe and supports concurrent registration and extraction operations.
//
// Example usage:
//
//	registry := NewExtractorRegistry()
//	registry.Register(&NmapExtractor{})
//	registry.Register(&NucleiExtractor{})
//
//	result, err := registry.ExtractFromResponse(ctx, "nmap", nmapResponse)
//	if err != nil {
//	    log.Printf("extraction failed: %v", err)
//	}
type ExtractorRegistry interface {
	// Register adds an extractor to the registry for its tool.
	// Returns an error if an extractor for this tool is already registered.
	Register(extractor EntityExtractor) error

	// Unregister removes an extractor from the registry by tool name.
	// Returns an error if no extractor is registered for the tool.
	Unregister(toolName string) error

	// Get retrieves an extractor by tool name.
	// Returns an error if no extractor is registered for the tool.
	Get(toolName string) (EntityExtractor, error)

	// Has checks if an extractor is registered for the given tool.
	Has(toolName string) bool

	// ListTools returns the names of all tools with registered extractors.
	ListTools() []string

	// ExtractFromResponse extracts entities from a tool response using the appropriate extractor.
	// This is a convenience method that:
	//   1. Looks up the extractor for the tool
	//   2. Validates the extractor can process the message
	//   3. Executes the extraction
	//
	// Returns an error if:
	//   - No extractor is registered for the tool
	//   - The extractor cannot process the message type
	//   - Extraction fails
	ExtractFromResponse(ctx context.Context, toolName string, msg proto.Message) (*ExtractionResult, error)
}

// defaultExtractorRegistry is the default thread-safe implementation of ExtractorRegistry.
type defaultExtractorRegistry struct {
	mu         sync.RWMutex
	extractors map[string]EntityExtractor
}

// NewExtractorRegistry creates a new ExtractorRegistry with no extractors registered.
// Extractors must be registered via Register() before they can be used.
func NewExtractorRegistry() ExtractorRegistry {
	return &defaultExtractorRegistry{
		extractors: make(map[string]EntityExtractor),
	}
}

// Register implements ExtractorRegistry.Register.
// It adds an extractor to the registry, indexed by the tool name returned by ToolName().
//
// Returns an error if:
//   - The extractor is nil
//   - The tool name is empty
//   - An extractor for this tool is already registered
func (r *defaultExtractorRegistry) Register(extractor EntityExtractor) error {
	if extractor == nil {
		return fmt.Errorf("extractor cannot be nil")
	}

	toolName := extractor.ToolName()
	if toolName == "" {
		return fmt.Errorf("extractor tool name cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.extractors[toolName]; exists {
		return fmt.Errorf("extractor for tool %q already registered", toolName)
	}

	r.extractors[toolName] = extractor
	return nil
}

// Unregister implements ExtractorRegistry.Unregister.
// It removes an extractor from the registry by tool name.
//
// Returns an error if no extractor is registered for the tool.
func (r *defaultExtractorRegistry) Unregister(toolName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.extractors[toolName]; !exists {
		return fmt.Errorf("no extractor registered for tool %q", toolName)
	}

	delete(r.extractors, toolName)
	return nil
}

// Get implements ExtractorRegistry.Get.
// It retrieves an extractor by tool name.
//
// Returns an error if no extractor is registered for the tool.
func (r *defaultExtractorRegistry) Get(toolName string) (EntityExtractor, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	extractor, exists := r.extractors[toolName]
	if !exists {
		return nil, fmt.Errorf("no extractor registered for tool %q", toolName)
	}

	return extractor, nil
}

// Has implements ExtractorRegistry.Has.
// It checks if an extractor is registered for the given tool.
func (r *defaultExtractorRegistry) Has(toolName string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.extractors[toolName]
	return exists
}

// ListTools implements ExtractorRegistry.ListTools.
// It returns the names of all tools with registered extractors.
// The returned slice is not sorted.
func (r *defaultExtractorRegistry) ListTools() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tools := make([]string, 0, len(r.extractors))
	for toolName := range r.extractors {
		tools = append(tools, toolName)
	}

	return tools
}

// ExtractFromResponse implements ExtractorRegistry.ExtractFromResponse.
// It extracts entities from a tool response using the appropriate extractor.
//
// The extraction process:
//  1. Look up the extractor for the tool
//  2. Validate the extractor can process this message type (via CanExtract)
//  3. Execute the extraction (via Extract)
//  4. Return the extraction result
//
// Returns an error if:
//   - No extractor is registered for the tool
//   - The extractor cannot process the message type
//   - Extraction fails
func (r *defaultExtractorRegistry) ExtractFromResponse(ctx context.Context, toolName string, msg proto.Message) (*ExtractionResult, error) {
	// Get the extractor for this tool
	extractor, err := r.Get(toolName)
	if err != nil {
		return nil, err
	}

	// Check if the extractor can process this message
	if !extractor.CanExtract(msg) {
		return nil, fmt.Errorf("extractor for tool %q cannot process message type %T", toolName, msg)
	}

	// Execute the extraction
	result, err := extractor.Extract(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("extraction failed for tool %q: %w", toolName, err)
	}

	return result, nil
}
