// Package sandboxed implements the Gibson harness's sandboxed tool execution
// backend: per-call Setec microVM dispatch via gRPC with mTLS.
//
// Scope:
//   - No Setec-specific gRPC client type leaks out of this package.
//   - All public types are plain structs that the daemon's startup wiring
//     populates from configuration.
//   - The Executor consumes a minimal SandboxClient interface so unit tests
//     can mock the gRPC surface without importing the Setec module.
//
// Dispatch is driven by the daemon's catalog refresher: tool metadata is
// written to ComponentRegistry entries under the _system tenant, and
// harness.CallToolProto resolves ToolSpec per-call from those entries
// before handing off to Executor.ExecuteWithSpec. The static per-image
// Registry + NewRegistryFromConfig constructor that lived here pre-
// gibson-tool-runner spec was removed in task 16.
package sandboxed

// ToolSpec is the resolved launch spec for one sandboxed tool call. Fields
// are populated per-call from ComponentRegistry entry metadata and passed
// to Executor.ExecuteWithSpec.
type ToolSpec struct {
	Image   string
	Command []string
	Env     map[string]string
	VCPU    int32
	Memory  string
}
