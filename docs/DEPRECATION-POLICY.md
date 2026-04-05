# Gibson Deprecation Policy

Last Updated: 2026-04-04 | Policy Version: 1.0

## Scope

This policy covers: proto fields, SDK Go interfaces, gRPC RPCs, and configuration keys.

All deprecations follow a structured lifecycle: announce, support for a minimum window, then remove. Every deprecation MUST appear in the CHANGELOG under "Deprecations" when introduced and under "Breaking Changes" when removed.

---

## 1. Proto Fields

**Minimum support window:** 2 minor versions after the deprecation announcement.

### Rules

- The field MUST be annotated with `[deprecated = true]` in the proto definition.
- A version comment MUST appear on the line immediately above the field stating:
  - The version in which the field was deprecated.
  - The replacement field (if any).
  - The version in which the field will be removed.
- On removal, the field number MUST be added to a `reserved` declaration in the message to prevent accidental reuse.
- The deprecation and removal MUST both be documented in the CHANGELOG.

### Example

```protobuf
message ScanConfig {
  string id = 1;

  // Deprecated: v0.8.0. Use target_schemas (field 5) instead. Will be removed in v0.10.0.
  repeated string target_types = 7 [deprecated = true];

  repeated TargetSchema target_schemas = 5;
}
```

After removal in v0.10.0 the message becomes:

```protobuf
message ScanConfig {
  reserved 7;
  reserved "target_types";

  string id = 1;
  repeated TargetSchema target_schemas = 5;
}
```

---

## 2. SDK Interfaces

**Minimum support window:** 1 minor version after the deprecation announcement.

### Rules

- New methods added to an interface MUST have a default implementation provided through the `BaseHarness` (or equivalent base struct) so that existing consumers continue to compile without changes.
- The deprecated method MUST carry a Go doc comment following the convention: `// Deprecated: use X instead. Will be removed in vY.Z.`
- The deprecated method MUST log a warning exactly once per process lifetime using `sync.Once`. The log message must include the deprecated symbol name and the replacement.
- The deprecated method MUST delegate to the replacement internally so behavior stays consistent during the support window.

### Example

```go
// Deprecated: use QueryGraphNodes instead. Will be removed in v0.12.0.
func (h *BaseHarness) QueryNodes(ctx context.Context, label string) ([]*Node, error) {
	deprecateQueryNodes.Do(func() {
		slog.Warn("QueryNodes is deprecated, use QueryGraphNodes instead",
			"removal_version", "v0.12.0",
		)
	})
	return h.QueryGraphNodes(ctx, label)
}

var deprecateQueryNodes sync.Once
```

---

## 3. gRPC RPCs

**Minimum support window:** 2 minor versions after the deprecation announcement.

### Rules

- The RPC MUST be annotated with `option deprecated = true` in the proto service definition.
- A version comment MUST appear above the RPC stating the deprecation version, replacement RPC, and planned removal version.
- The server interceptor MUST inject an `X-Deprecated` response header (gRPC metadata trailer) on every call to the deprecated RPC. The header value MUST include the replacement RPC name and the removal version.
- After removal, the RPC method MUST remain in the service definition for one additional minor version, returning `codes.Unimplemented` with a status message directing callers to the replacement RPC.

### Example

```protobuf
service DaemonService {
  // Deprecated: v0.9.0. Use ListMissionsV2 instead. Will be removed in v0.11.0.
  rpc ListMissions(ListMissionsRequest) returns (ListMissionsResponse) {
    option deprecated = true;
  }

  rpc ListMissionsV2(ListMissionsV2Request) returns (ListMissionsV2Response) {}
}
```

Server-side interceptor behavior (Go):

```go
func DeprecationInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if meta, ok := deprecatedRPCs[info.FullMethod]; ok {
			header := metadata.Pairs(
				"x-deprecated", fmt.Sprintf("Use %s instead. Removal in %s.", meta.Replacement, meta.RemovalVersion),
			)
			grpc.SetTrailer(ctx, header)
		}
		return handler(ctx, req)
	}
}
```

---

## 4. Configuration Keys

**Minimum support window:** 2 minor versions after the deprecation announcement.

### Rules

- The old configuration key MUST be aliased to the new key using Viper's `RegisterAlias` so that existing configs continue to work without modification.
- A WARN-level log MUST be emitted at startup if the old key is present in the loaded configuration. The message must name both the old and new keys.
- If both the old key and the new key are explicitly set, the new key takes precedence.
- The old key MUST be documented as deprecated in the CHANGELOG and in any configuration reference documentation.

### Example

YAML configuration showing migration from `llm.api_key` to `llm.credentials.api_key`:

```yaml
# Before (deprecated in v0.9.0, removal in v0.11.0):
llm:
  api_key: "sk-..."

# After:
llm:
  credentials:
    api_key: "sk-..."
```

Registration in Go:

```go
func registerDeprecatedAliases(v *viper.Viper) {
	v.RegisterAlias("llm.api_key", "llm.credentials.api_key")

	if v.IsSet("llm.api_key") && !v.IsSet("llm.credentials.api_key") {
		slog.Warn("config key 'llm.api_key' is deprecated, use 'llm.credentials.api_key' instead",
			"removal_version", "v0.11.0",
		)
	}
}
```

---

## Enforcement

Proto deprecation and removal hygiene is enforced automatically in CI:

- **`buf breaking`** runs against the previous release tag on every pull request. It detects removed fields that were not yet past their support window, missing `reserved` declarations for removed field numbers, and removed RPCs that have not transitioned through `codes.Unimplemented`.
- **`buf lint`** validates that all deprecated annotations follow the required comment conventions and that `reserved` ranges do not conflict with active fields.

These checks are required to pass before a pull request can merge into `main`.
