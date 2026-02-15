# Schema Validation Implementation Guide

## Overview

This document describes the optional FileDescriptor-based schema validation feature for the Gibson daemon. This feature enables schema introspection and optional validation of tool inputs at runtime.

**Status**: Partially implemented (SDK side complete, daemon side pending)
**Task**: Task 12 from self-contained-tool-protos spec
**Priority**: Low (Optional Enhancement)

## What's Implemented

### 1. SDK FileDescriptor Extraction (`sdk/serve/schema.go`)

The SDK now includes `ExtractFileDescriptorSet()` which:
- Extracts FileDescriptorSet from a tool's input/output message types
- Uses the protobuf global registry to find message descriptors
- Recursively includes dependencies to create a complete FileDescriptorSet
- Returns nil on error (extraction is optional and won't break tools)

```go
fds := ExtractFileDescriptorSet(myTool)
if fds != nil {
    fdsBytes, _ := proto.Marshal(fds)
    // Include in registration metadata
}
```

### 2. Automatic Registration (`sdk/serve/tool.go`)

Tools automatically extract and register their schemas when starting:

```go
// Extract FileDescriptorSet for schema introspection (optional)
if fds := ExtractFileDescriptorSet(t); fds != nil {
    if fdsBytes, err := protolib.Marshal(fds); err == nil {
        // Encode as base64 string for safe storage in metadata
        metadata["file_descriptor_set"] = base64.StdEncoding.EncodeToString(fdsBytes)
        slog.Debug("extracted tool schema", "tool", t.Name(), "files", len(fds.File))
    }
}
```

The FileDescriptorSet is serialized, base64-encoded, and stored in the `file_descriptor_set` metadata field during tool registration with the etcd registry.

## What's Pending

### 1. Daemon Schema Storage

The daemon needs to:
1. Parse the `file_descriptor_set` metadata during tool discovery
2. Store FileDescriptorSets in memory keyed by tool name
3. Expose schemas via a new API endpoint

#### Recommended Implementation

Create a new schema manager in the daemon:

```go
// daemon/schema/manager.go
package schema

import (
    "encoding/base64"
    "fmt"
    "sync"

    "google.golang.org/protobuf/proto"
    "google.golang.org/protobuf/types/descriptorpb"
)

// Manager stores and manages tool schemas
type Manager struct {
    mu      sync.RWMutex
    schemas map[string]*descriptorpb.FileDescriptorSet
}

// NewManager creates a new schema manager
func NewManager() *Manager {
    return &Manager{
        schemas: make(map[string]*descriptorpb.FileDescriptorSet),
    }
}

// StoreFromMetadata extracts and stores a FileDescriptorSet from tool metadata
func (m *Manager) StoreFromMetadata(toolName string, metadata map[string]string) error {
    fdsB64, ok := metadata["file_descriptor_set"]
    if !ok {
        // No schema available - this is fine, schema is optional
        return nil
    }

    // Decode base64
    fdsBytes, err := base64.StdEncoding.DecodeString(fdsB64)
    if err != nil {
        return fmt.Errorf("invalid base64 in file_descriptor_set: %w", err)
    }

    // Unmarshal FileDescriptorSet
    fds := &descriptorpb.FileDescriptorSet{}
    if err := proto.Unmarshal(fdsBytes, fds); err != nil {
        return fmt.Errorf("invalid FileDescriptorSet: %w", err)
    }

    // Store in memory
    m.mu.Lock()
    defer m.mu.Unlock()
    m.schemas[toolName] = fds

    return nil
}

// GetSchema retrieves the FileDescriptorSet for a tool
func (m *Manager) GetSchema(toolName string) (*descriptorpb.FileDescriptorSet, bool) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    fds, ok := m.schemas[toolName]
    return fds, ok
}

// RemoveSchema removes a tool's schema (called when tool unregisters)
func (m *Manager) RemoveSchema(toolName string) {
    m.mu.Lock()
    defer m.mu.Unlock()
    delete(m.schemas, toolName)
}
```

### 2. Integration with Daemon

Modify `daemon/grpc.go` to use the schema manager:

```go
// In daemonImpl struct
type daemonImpl struct {
    // ... existing fields ...
    schemaManager *schema.Manager
}

// In NewDaemon or daemon initialization
d.schemaManager = schema.NewManager()

// In ListTools method, when processing running tools from registry
for _, r := range running {
    runningTools[r.Name] = true
    // ... existing code ...

    // Store schema if available
    if err := d.schemaManager.StoreFromMetadata(r.Name, r.Metadata); err != nil {
        d.logger.Warn("failed to parse tool schema", "tool", r.Name, "error", err)
    }
}
```

### 3. Add GetToolSchema API Endpoint

Add to `daemon/api/daemon.proto`:

```protobuf
service DaemonService {
    // ... existing methods ...

    // GetToolSchema returns the FileDescriptorSet for a tool
    rpc GetToolSchema(GetToolSchemaRequest) returns (GetToolSchemaResponse);
}

message GetToolSchemaRequest {
    string tool_name = 1;
}

message GetToolSchemaResponse {
    // Base64-encoded FileDescriptorSet
    string file_descriptor_set = 1;

    // Human-readable schema info
    string input_message_type = 2;
    string output_message_type = 3;
    repeated string file_names = 4;
}
```

### 4. Implement gRPC Handler

Add to `daemon/api/server.go`:

```go
// GetToolSchema returns the schema (FileDescriptorSet) for a specific tool
func (s *DaemonServer) GetToolSchema(ctx context.Context, req *GetToolSchemaRequest) (*GetToolSchemaResponse, error) {
    s.logger.Debug("GetToolSchema request received", "tool", req.ToolName)

    if req.ToolName == "" {
        return nil, status.Errorf(codes.InvalidArgument, "tool name is required")
    }

    // Retrieve schema from daemon
    fds, ok := s.daemon.GetToolSchema(ctx, req.ToolName)
    if !ok {
        return nil, status.Errorf(codes.NotFound, "schema not found for tool: %s", req.ToolName)
    }

    // Serialize FileDescriptorSet
    fdsBytes, err := proto.Marshal(fds)
    if err != nil {
        s.logger.Error("failed to serialize FileDescriptorSet", "error", err)
        return nil, status.Errorf(codes.Internal, "failed to serialize schema")
    }

    // Extract file names for informational purposes
    fileNames := make([]string, len(fds.File))
    for i, fd := range fds.File {
        if fd.Name != nil {
            fileNames[i] = *fd.Name
        }
    }

    return &GetToolSchemaResponse{
        FileDescriptorSet: base64.StdEncoding.EncodeToString(fdsBytes),
        FileNames:         fileNames,
    }, nil
}
```

## Usage Examples

### Client-Side Schema Retrieval

```go
// Get tool schema
resp, err := client.GetToolSchema(ctx, &api.GetToolSchemaRequest{
    ToolName: "nmap",
})
if err != nil {
    log.Printf("Schema not available: %v", err)
    return
}

// Decode FileDescriptorSet
fdsBytes, _ := base64.StdEncoding.DecodeString(resp.FileDescriptorSet)
fds := &descriptorpb.FileDescriptorSet{}
proto.Unmarshal(fdsBytes, fds)

// Use schema for validation or introspection
fmt.Printf("Tool has %d proto files:\n", len(fds.File))
for _, f := range fds.File {
    fmt.Printf("  - %s\n", f.GetName())
}
```

### Optional Request Validation (Future Enhancement)

```go
// Validate tool input against schema before execution
func ValidateToolInput(toolName string, inputJSON string) error {
    fds, ok := schemaManager.GetSchema(toolName)
    if !ok {
        // Schema not available, skip validation
        return nil
    }

    // Build FileDescriptorSet into a registry
    files := &protoregistry.Files{}
    for _, fdProto := range fds.File {
        fd, err := protodesc.NewFile(fdProto, files)
        if err != nil {
            return err
        }
        files.RegisterFile(fd)
    }

    // Find the input message type
    msgDesc, err := files.FindDescriptorByName(protoreflect.FullName(inputMessageType))
    if err != nil {
        return err
    }

    // Create new message instance and unmarshal JSON
    msg := dynamicpb.NewMessage(msgDesc.(protoreflect.MessageDescriptor))
    if err := protojson.Unmarshal([]byte(inputJSON), msg); err != nil {
        return fmt.Errorf("validation failed: %w", err)
    }

    return nil
}
```

## Configuration

Schema validation should be configurable:

```yaml
# config.yaml
daemon:
  schema_validation:
    enabled: false  # Default: disabled for backward compatibility
    fail_on_invalid: false  # If true, reject invalid inputs
    log_validation_errors: true  # Log validation failures
```

## Testing

### Unit Tests

```go
func TestSchemaManager_StoreAndRetrieve(t *testing.T) {
    manager := schema.NewManager()

    // Create a test FileDescriptorSet
    fds := &descriptorpb.FileDescriptorSet{
        File: []*descriptorpb.FileDescriptorProto{
            {
                Name: proto.String("test.proto"),
            },
        },
    }

    // Serialize and encode
    fdsBytes, _ := proto.Marshal(fds)
    metadata := map[string]string{
        "file_descriptor_set": base64.StdEncoding.EncodeToString(fdsBytes),
    }

    // Store
    err := manager.StoreFromMetadata("test-tool", metadata)
    require.NoError(t, err)

    // Retrieve
    retrieved, ok := manager.GetSchema("test-tool")
    require.True(t, ok)
    require.NotNil(t, retrieved)
    assert.Equal(t, "test.proto", *retrieved.File[0].Name)
}
```

### Integration Tests

Test the full flow:
1. Start a tool with proto message types
2. Tool registers with FileDescriptorSet in metadata
3. Daemon parses and stores schema
4. Client retrieves schema via GetToolSchema API
5. Schema matches original proto definition

## Benefits

1. **Schema Introspection**: Clients can discover tool schemas dynamically
2. **Documentation Generation**: Auto-generate tool documentation from schemas
3. **Validation**: Optional runtime validation of tool inputs
4. **Debugging**: Better error messages when schema mismatches occur
5. **Type Safety**: Ensure inputs match expected proto message types

## Considerations

1. **Backward Compatibility**: All schema features are optional - tools without schemas work normally
2. **Performance**: Schema extraction is only done once at tool startup
3. **Memory Usage**: FileDescriptorSets are stored in daemon memory (minimal overhead)
4. **Versioning**: Schema is tied to tool version, updated on tool restart
5. **Error Handling**: All schema errors are logged as warnings, never fail tool operations

## Next Steps

To complete this feature:

1. ✅ Implement FileDescriptor extraction in SDK (`schema.go`)
2. ✅ Add schema to tool registration metadata (`tool.go`)
3. ⏳ Create schema manager in daemon (`daemon/schema/manager.go`)
4. ⏳ Integrate with daemon's ListTools method (`daemon/grpc.go`)
5. ⏳ Add GetToolSchema proto definition (`daemon/api/daemon.proto`)
6. ⏳ Implement GetToolSchema gRPC handler (`daemon/api/server.go`)
7. ⏳ Add configuration for schema validation (`config/config.go`)
8. ⏳ Write comprehensive tests
9. ⏳ Document usage in TOOLS.md

## Files Modified

### Completed
- `/home/anthony/Code/zero-day.ai/opensource/sdk/serve/schema.go` (new file)
- `/home/anthony/Code/zero-day.ai/opensource/sdk/serve/schema_extraction_test.go` (new file)
- `/home/anthony/Code/zero-day.ai/opensource/sdk/serve/tool.go` (modified imports and registration)

### Pending
- `opensource/gibson/internal/daemon/schema/manager.go` (to be created)
- `opensource/gibson/internal/daemon/grpc.go` (add schema manager integration)
- `opensource/gibson/internal/daemon/api/daemon.proto` (add GetToolSchema RPC)
- `opensource/gibson/internal/daemon/api/server.go` (add GetToolSchema handler)
- `opensource/gibson/internal/config/config.go` (add schema validation config)

## Conclusion

The SDK portion of the schema validation feature is complete. Tools now automatically extract and register their proto schemas. The daemon-side implementation (storage, API endpoint, optional validation) is documented here and ready to be implemented when needed.

Since this is an optional enhancement (Task 12, Low Priority), it can be completed at any time without blocking other work.
