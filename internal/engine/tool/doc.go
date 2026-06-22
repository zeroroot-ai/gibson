// Package tool defines the Gibson daemon's internal Tool interface and
// associated metadata types.
//
// Tools are atomic, stateless operations that serve as building blocks for
// agent capabilities. Every tool runs out-of-process — the daemon has no
// in-process tool registry; tool execution is dispatched to remote components
// via the component registry (grpc endpoint or Redis work queue) or into a
// Setec microVM sandbox. See core/gibson/internal/harness for dispatch
// implementation.
//
// # Types
//
//   - Tool — the interface every Gibson tool implements (proto in, proto
//     out, plus Name/Version/Description/Tags/Health).
//   - ToolDescriptor — metadata describing a registered tool.
//   - ToolMetrics — execution statistics.
//
// # Invariants (architecture rules)
//
// The Gibson daemon never compile-time-imports any specific tool's Go
// bindings. Tool message types are resolved at runtime via FileDescriptorSet
// metadata flowing through sdk/protoresolver (the two-tier resolver: global
// proto registry first, then dynamic descriptors from the wire). Any future
// change that would introduce an in-process tool registry or statically
// linked tool code violates the decouple-sdk-from-tool-protos spec and the
// remove-local-tool-registry spec that followed it.
package tool
