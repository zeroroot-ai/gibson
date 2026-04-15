package auth

import _ "embed"

// EmbeddedRpcRegistry is the YAML source of truth for daemon gRPC
// authorization, baked into the binary at build time. The daemon loads it
// via LoadRegistry on startup; operators may override it by setting
// GIBSON_AUTHZ_RPC_REGISTRY_PATH (override is fail-closed — see loader).
//
// This file deliberately does nothing else so the //go:embed directive sits
// adjacent to its target file and cannot drift.

//go:embed rpc_registry.yaml
var EmbeddedRpcRegistry []byte
