// Package extraction provides a framework for extracting entities from tool-specific
// proto responses and converting them into standardized DiscoveryResult structures
// for graph storage.
//
// # Overview
//
// Tools in Gibson return proto messages with tool-specific schemas (e.g., NmapResponse,
// NucleiResponse). To populate the knowledge graph, these responses must be converted
// into the standardized DiscoveryResult proto containing nodes (hosts, ports, services,
// findings) and their relationships.
//
// The extraction package provides:
//   - EntityExtractor interface for implementing tool-specific extraction logic
//   - ExtractorRegistry for thread-safe registration and management of extractors
//   - ExtractionResult type containing DiscoveryResult plus metadata
//
// # EntityExtractor Interface
//
// Each tool implements an EntityExtractor that knows how to parse its proto response
// and convert it to a standardized DiscoveryResult:
//
//	type EntityExtractor interface {
//	    ToolName() string
//	    CanExtract(msg proto.Message) bool
//	    Extract(ctx context.Context, msg proto.Message) (*ExtractionResult, error)
//	}
//
// # ExtractorRegistry
//
// The registry manages extractors with thread-safe operations:
//
//	registry := extraction.NewExtractorRegistry()
//	registry.Register(&nmap.NmapExtractor{})
//	registry.Register(&nuclei.NucleiExtractor{})
//
//	result, err := registry.ExtractFromResponse(ctx, "nmap", toolResp)
//	if err != nil {
//	    log.Printf("extraction failed: %v", err)
//	}
//
// # Example Implementation
//
// Here's a minimal extractor for a hypothetical network scanning tool:
//
//	type ScannerExtractor struct{}
//
//	func (e *ScannerExtractor) ToolName() string {
//	    return "scanner"
//	}
//
//	func (e *ScannerExtractor) CanExtract(msg proto.Message) bool {
//	    _, ok := msg.(*scannerpb.ScanResponse)
//	    return ok
//	}
//
//	func (e *ScannerExtractor) Extract(ctx context.Context, msg proto.Message) (*ExtractionResult, error) {
//	    resp := msg.(*scannerpb.ScanResponse)
//
//	    discovery := &graphragpb.DiscoveryResult{
//	        Hosts: convertHosts(resp.Hosts),
//	        Ports: convertPorts(resp.Hosts),
//	    }
//
//	    return &ExtractionResult{
//	        Discovery: discovery,
//	        RootEntityID: discovery.Hosts[0].GetId(),
//	    }, nil
//	}
//
// # Thread Safety
//
// ExtractorRegistry is fully thread-safe and supports concurrent registration,
// extraction, and lookup operations. All methods use appropriate read/write locks
// to prevent race conditions.
//
// # Integration
//
// The extraction framework integrates with Gibson's existing components:
//   - Uses graphragpb.DiscoveryResult (same type as discovery processor)
//   - Compatible with tool.Execute() proto.Message responses
//   - Follows registry patterns established by LLMRegistry
//
// For more details, see the README.md file and example_extractor.go.example.
package extraction
