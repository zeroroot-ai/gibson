# HttpxExtractor Implementation Summary

## Overview

Implemented `HttpxExtractor` for extracting entities from httpx tool scan results. The extractor converts `HttpxResponse` proto messages into standardized `DiscoveryResult` containing endpoints, technologies, and certificates.

## Files Created

- `/home/anthony/Code/zero-day.ai/core/gibson/internal/extraction/httpx_extractor.go` - Main extractor implementation
- `/home/anthony/Code/zero-day.ai/core/gibson/internal/extraction/httpx_extractor_test.go` - Comprehensive test suite

## Files Modified

- `/home/anthony/Code/zero-day.ai/core/go.work` - Added httpx tool to workspace

## Implementation Details

### Extracted Entities

1. **Endpoints**
   - URL, method, status code
   - Content type, content length
   - HTML page title
   - All fields properly mapped to `graphragpb.Endpoint`

2. **Technologies**
   - Name, version, category
   - Confidence score (converted from 0.0-1.0 to 0-100)
   - Parent reference to endpoint
   - Mapped to `graphragpb.Technology`

3. **Certificates**
   - Subject DN, Issuer DN
   - Serial number
   - Validity dates (not_before, not_after)
   - Subject Alternative Names (SANs)
   - Parent reference to endpoint
   - Mapped to `graphragpb.Certificate`

### Key Features

1. **Deterministic UUID Generation**
   - Endpoints: Based on normalized URL
   - Technologies: Based on parent ID + name + version
   - Certificates: Based on parent ID + serial number
   - Ensures idempotent re-scans produce consistent IDs

2. **URL Normalization**
   - Parses URLs to normalize format
   - Handles invalid URLs gracefully
   - Ensures deterministic IDs for same targets

3. **Timestamp Parsing**
   - Supports multiple timestamp formats (RFC3339, date-only, Unix epoch)
   - Gracefully handles parsing failures
   - Converts to Unix epoch for storage

4. **Parent-Child Relationships**
   - Technologies reference endpoint via parent_id/parent_type
   - Certificates reference endpoint via parent_id/parent_type
   - Enables graph traversal and relationship building

5. **Error Handling**
   - Skips failed HTTP requests
   - Returns empty results (not errors) for no-results scenarios
   - Validates message types before extraction
   - Provides detailed metadata about extraction

### Interface Implementation

```go
type HttpxExtractor struct{}

func (e *HttpxExtractor) ToolName() string
func (e *HttpxExtractor) CanExtract(msg proto.Message) bool
func (e *HttpxExtractor) Extract(ctx context.Context, msg proto.Message) (*ExtractionResult, error)
```

Implements the `EntityExtractor` interface defined in `extractor.go`.

## Testing

### Test Coverage

- **Overall package coverage**: 97.6%
- **HttpxExtractor coverage**: 100%

### Test Cases

1. **Basic Functionality**
   - ToolName returns "httpx"
   - CanExtract validates message types
   - Extract rejects invalid message types

2. **Empty/Error Cases**
   - Empty results handling
   - Failed requests skipped
   - No-results scenario

3. **Entity Extraction**
   - Basic endpoint extraction
   - Endpoint with all fields
   - Endpoint with minimal fields
   - Technology extraction
   - Certificate extraction

4. **Complex Scenarios**
   - Multiple endpoints with technologies
   - Endpoints with certificates
   - Mixed success/failure results
   - Complete end-to-end scenario

5. **Edge Cases**
   - Deterministic UUID generation
   - URL normalization
   - Invalid URL handling
   - Timestamp parsing (multiple formats)

6. **Integration**
   - Registry integration test
   - ExtractFromResponse workflow

7. **Performance**
   - Single endpoint benchmark: ~3,032 ns/op
   - 100 endpoints benchmark: ~332,252 ns/op

### Example Test

```go
func TestHttpxExtractor_Extract_WithTechnologies(t *testing.T) {
    extractor := NewHttpxExtractor()
    resp := &httpxpb.HttpxResponse{
        Results: []*httpxpb.HttpxResult{
            {
                Url:        "https://example.com",
                StatusCode: 200,
                Technologies: []*httpxpb.Technology{
                    {Name: "nginx", Version: "1.21.0", Confidence: 0.95},
                },
            },
        },
    }

    result, err := extractor.Extract(ctx, resp)
    require.NoError(t, err)
    assert.Len(t, result.Discovery.Endpoints, 1)
    assert.Len(t, result.Discovery.Technologies, 1)
    assert.Equal(t, "nginx", result.Discovery.Technologies[0].Name)
}
```

## Usage

### Registration

```go
registry := extraction.NewExtractorRegistry()
registry.Register(extraction.NewHttpxExtractor())
```

### Extraction

```go
resp := &httpxpb.HttpxResponse{...}
result, err := registry.ExtractFromResponse(ctx, "httpx", resp)
if err != nil {
    return err
}

// Access extracted entities
endpoints := result.Discovery.Endpoints
technologies := result.Discovery.Technologies
certificates := result.Discovery.Certificates
```

### Metadata

The extractor provides rich metadata:

```go
result.Metadata["tool_name"]          // "httpx"
result.Metadata["endpoint_count"]     // Number of endpoints
result.Metadata["technology_count"]   // Number of technologies
result.Metadata["certificate_count"]  // Number of certificates
result.Metadata["total_scanned"]      // Total targets scanned
result.Metadata["total_success"]      // Successful responses
result.Metadata["total_failed"]       // Failed requests
result.Metadata["scan_duration"]      // Scan duration in seconds
```

## Proto Structure

### Input: HttpxResponse

```protobuf
message HttpxResponse {
    repeated HttpxResult results = 1;
    int32 total_scanned = 2;
    int32 total_success = 3;
    int32 total_failed = 4;
    double duration = 5;
}

message HttpxResult {
    string url = 1;
    int32 status_code = 2;
    int64 content_length = 3;
    string title = 4;
    repeated Technology technologies = 5;
    TLSInfo tls = 7;
    string content_type = 9;
    string method = 11;
    bool failed = 19;
}
```

### Output: DiscoveryResult

```protobuf
message DiscoveryResult {
    repeated Endpoint endpoints = 4;
    repeated Technology technologies = 7;
    repeated Certificate certificates = 8;
}
```

## Design Patterns

### Deterministic UUID Generation

Uses UUID v5 (SHA1-based) with namespace `uuid.NameSpaceOID`:

```go
func (e *HttpxExtractor) generateEndpointID(url string) string {
    namespace := uuid.NameSpaceOID
    normalizedURL := parseAndNormalizeURL(url)
    name := fmt.Sprintf("endpoint:%s", normalizedURL)
    return uuid.NewSHA1(namespace, []byte(name)).String()
}
```

### Parent References

Technologies and certificates reference their parent endpoint:

```go
technology := &graphragpb.Technology{
    Id:         &techID,
    Name:       tech.Name,
    ParentId:   stringPtr(endpointID),
    ParentType: stringPtr("endpoint"),
}
```

### Graceful Degradation

- Failed requests are skipped, not treated as errors
- Invalid URLs still produce valid UUIDs
- Missing optional fields use nil pointers
- Empty results return success with metadata

## Dependencies

- `github.com/google/uuid` - Deterministic UUID generation
- `github.com/zero-day-ai/sdk/api/gen/graphragpb` - GraphRAG entity types
- `github.com/zero-day-ai/tools/discovery/httpx/gen` - Httpx proto types
- `google.golang.org/protobuf/proto` - Proto message handling

## Future Enhancements

1. **Service Extraction**: Extract service entities for discovered web servers
2. **Port Extraction**: Map endpoint ports to port entities
3. **Host Extraction**: Extract host entities from resolved IPs
4. **Technology Fingerprinting**: Enhanced technology detection from headers
5. **Certificate Validation**: Validate certificate chains and expiry
6. **Relationship Building**: Build explicit relationships between entities
7. **Content Analysis**: Extract additional metadata from response content

## Compliance

- Follows Gibson extractor patterns (consistent with NmapExtractor)
- Implements EntityExtractor interface
- Uses deterministic UUID generation
- Provides comprehensive test coverage
- Thread-safe (no shared state)
- Context-aware (respects cancellation)
