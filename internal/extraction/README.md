# Entity Extraction Package

The `extraction` package provides a framework for extracting entities from tool-specific proto responses and converting them into standardized `DiscoveryResult` structures for graph storage.

## Overview

Tools in Gibson return proto messages with tool-specific schemas (e.g., `NmapResponse`, `NucleiResponse`). To populate the knowledge graph, these responses must be converted into the standardized `DiscoveryResult` proto containing nodes (hosts, ports, services, findings) and their relationships.

The extraction package provides:
- **EntityExtractor interface**: For implementing tool-specific extraction logic
- **ExtractorRegistry**: Thread-safe registry for managing extractors
- **ExtractionResult**: Standardized result containing DiscoveryResult + metadata

## Key Concepts

### EntityExtractor

Each tool implements an `EntityExtractor` that knows how to:
1. Identify if it can process a proto message (`CanExtract`)
2. Parse the tool-specific response
3. Convert it to a standardized `DiscoveryResult` (`Extract`)

```go
type EntityExtractor interface {
    ToolName() string
    CanExtract(msg proto.Message) bool
    Extract(ctx context.Context, msg proto.Message) (*ExtractionResult, error)
}
```

### ExtractorRegistry

The registry manages extractors and provides:
- Thread-safe registration/unregistration
- Tool lookup by name
- Convenience method for extraction (`ExtractFromResponse`)

```go
type ExtractorRegistry interface {
    Register(extractor EntityExtractor) error
    Unregister(toolName string) error
    Get(toolName string) (EntityExtractor, error)
    Has(toolName string) bool
    ListTools() []string
    ExtractFromResponse(ctx context.Context, toolName string, msg proto.Message) (*ExtractionResult, error)
}
```

### ExtractionResult

The extraction result wraps the DiscoveryResult and provides metadata:

```go
type ExtractionResult struct {
    Discovery    *graphragpb.DiscoveryResult  // Entities and relationships
    RootEntityID string                       // Optional root entity ID
    Metadata     map[string]string            // Tool-specific metadata
}
```

## Usage Examples

### Implementing an Extractor

Here's an example nmap extractor:

```go
package nmap

import (
    "context"

    "github.com/zero-day-ai/gibson/internal/extraction"
    nmappb "github.com/zero-day-ai/tools/discovery/nmap/gen"
    "github.com/zero-day-ai/sdk/api/gen/graphragpb"
    "google.golang.org/protobuf/proto"
)

type NmapExtractor struct{}

func (e *NmapExtractor) ToolName() string {
    return "nmap"
}

func (e *NmapExtractor) CanExtract(msg proto.Message) bool {
    _, ok := msg.(*nmappb.NmapResponse)
    return ok
}

func (e *NmapExtractor) Extract(ctx context.Context, msg proto.Message) (*extraction.ExtractionResult, error) {
    resp := msg.(*nmappb.NmapResponse)

    discovery := &graphragpb.DiscoveryResult{}
    var rootHostID string

    // Convert nmap hosts to DiscoveryResult
    for _, nmapHost := range resp.Hosts {
        // Create host
        host := &graphragpb.Host{
            Id:       generateHostID(nmapHost.Ip),
            Ip:       nmapHost.Ip,
            Hostname: nmapHost.Hostname,
            State:    nmapHost.State,
        }
        discovery.Hosts = append(discovery.Hosts, host)

        if rootHostID == "" {
            rootHostID = host.Id
        }

        // Convert ports
        for _, nmapPort := range nmapHost.Ports {
            port := &graphragpb.Port{
                Id:       generatePortID(host.Id, nmapPort.Number),
                HostId:   host.Id,
                Number:   nmapPort.Number,
                Protocol: nmapPort.Protocol,
                State:    nmapPort.State,
            }
            discovery.Ports = append(discovery.Ports, port)

            // Convert service if present
            if nmapPort.Service != nil {
                service := &graphragpb.Service{
                    Id:      generateServiceID(port.Id),
                    PortId:  port.Id,
                    Name:    nmapPort.Service.Name,
                    Product: nmapPort.Service.Product,
                    Version: nmapPort.Service.Version,
                }
                discovery.Services = append(discovery.Services, service)
            }
        }
    }

    return &extraction.ExtractionResult{
        Discovery:    discovery,
        RootEntityID: rootHostID,
        Metadata: map[string]string{
            "tool_version": resp.NmapVersion,
            "scan_type":    "network",
        },
    }, nil
}
```

### Registering Extractors

Create a global registry and register extractors during initialization:

```go
package extraction

import "github.com/zero-day-ai/gibson/internal/extraction"

var GlobalRegistry extraction.ExtractorRegistry

func init() {
    GlobalRegistry = extraction.NewExtractorRegistry()
}

// Register during application startup
func RegisterStandardExtractors() error {
    if err := GlobalRegistry.Register(&nmap.NmapExtractor{}); err != nil {
        return err
    }
    if err := GlobalRegistry.Register(&nuclei.NucleiExtractor{}); err != nil {
        return err
    }
    if err := GlobalRegistry.Register(&httpx.HttpxExtractor{}); err != nil {
        return err
    }
    return nil
}
```

### Using Extractors

After tool execution, extract entities:

```go
// Execute tool
toolResp, err := toolClient.Execute(ctx, toolReq)
if err != nil {
    return err
}

// Extract entities
result, err := GlobalRegistry.ExtractFromResponse(ctx, "nmap", toolResp)
if err != nil {
    return fmt.Errorf("extraction failed: %w", err)
}

// Store in graph
if result.Discovery != nil {
    if err := graphClient.StoreDiscovery(ctx, result.Discovery); err != nil {
        return fmt.Errorf("graph storage failed: %w", err)
    }
}
```

## Thread Safety

The `ExtractorRegistry` is fully thread-safe and supports concurrent:
- Registration/unregistration
- Extraction operations
- Lookups and queries

All operations use appropriate read/write locks to prevent race conditions.

## Integration with GraphRAG

The `DiscoveryResult` produced by extractors follows the standard taxonomy defined in `sdk/api/proto/graphrag.proto`:

**Entity Types:**
- `Host` - Network hosts/systems
- `Port` - Open ports on hosts
- `Service` - Services running on ports
- `Endpoint` - HTTP/API endpoints
- `Domain` - DNS domains
- `Subdomain` - Subdomains under domains
- `Technology` - Detected technologies/frameworks
- `Certificate` - TLS/SSL certificates
- `Finding` - Security findings/vulnerabilities
- `Evidence` - Supporting evidence for findings

**Relationships:**
- Parent-child relationships are established via ID references
  - `Port.HostId` links port to host
  - `Service.PortId` links service to port
  - `Endpoint.ServiceId` links endpoint to service
- Explicit relationships can be added via `ExplicitRelationship`

## Design Patterns

### UUID Generation

Tools should generate deterministic UUIDs based on entity natural keys:

```go
import "github.com/google/uuid"

func generateHostID(ip string) string {
    return uuid.NewSHA1(uuid.NameSpaceOID, []byte("host:"+ip)).String()
}

func generatePortID(hostID string, portNum int32) string {
    key := fmt.Sprintf("port:%s:%d", hostID, portNum)
    return uuid.NewSHA1(uuid.NameSpaceOID, []byte(key)).String()
}
```

This ensures:
- Idempotency: Re-scanning the same target produces the same IDs
- Deduplication: Multiple tools discovering the same entity use the same ID
- Consistency: Related entities can be linked via stable references

### Error Handling

Extractors should handle errors gracefully:

```go
func (e *NmapExtractor) Extract(ctx context.Context, msg proto.Message) (*ExtractionResult, error) {
    resp, ok := msg.(*nmappb.NmapResponse)
    if !ok {
        return nil, fmt.Errorf("expected *nmappb.NmapResponse, got %T", msg)
    }

    // Validate response
    if len(resp.Hosts) == 0 {
        return &ExtractionResult{
            Discovery: &graphragpb.DiscoveryResult{},
        }, nil
    }

    // Extract with error handling
    discovery, err := extractHosts(resp.Hosts)
    if err != nil {
        return nil, fmt.Errorf("host extraction failed: %w", err)
    }

    return &ExtractionResult{Discovery: discovery}, nil
}
```

### Partial Results

For large responses, extractors can return partial results:

```go
// Extract in batches to avoid memory spikes
const batchSize = 100

for i := 0; i < len(resp.Hosts); i += batchSize {
    end := i + batchSize
    if end > len(resp.Hosts) {
        end = len(resp.Hosts)
    }

    batch := resp.Hosts[i:end]
    extractBatch(discovery, batch)
}
```

## Testing

The package includes comprehensive tests:

- **Unit tests**: Test each method in isolation
- **Concurrency tests**: Verify thread-safety
- **Integration tests**: Test full extraction flow

Run tests:

```bash
cd core/gibson
go test -v ./internal/extraction/...
go test -race ./internal/extraction/...
```

## Future Enhancements

Potential improvements:

1. **Validation**: Validate DiscoveryResult before returning
2. **Transformation**: Apply transformations (enrichment, normalization)
3. **Hooks**: Pre/post-extraction hooks for plugins
4. **Caching**: Cache extraction results for identical inputs
5. **Metrics**: Track extraction performance and success rates
6. **Schema Evolution**: Support versioned extractors for schema changes

## Related Documentation

- [GraphRAG Taxonomy](../../../sdk/api/proto/graphrag.proto)
- [Tool Development Guide](../../../tools/CLAUDE.md)
- [Discovery Processing](../graphrag/processor/discovery_processor.go)
