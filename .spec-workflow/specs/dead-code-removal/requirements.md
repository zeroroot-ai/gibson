# Dead Code Removal - Requirements Specification

## Overview

**Spec Name:** dead-code-removal
**Version:** 1.0.0
**Created:** 2026-03-05
**Status:** Draft

### Problem Statement

The Gibson SDK and Gibson CLI codebases have accumulated significant amounts of dead code over time:

- **Deprecated protocol buffer files** that were superseded but never removed
- **Unused packages** that were created but never integrated
- **Deprecated functions** that only return errors
- **Test-only exported symbols** that could be unexported
- **Orphaned code paths** that are never executed

This dead code:
1. **Increases maintenance burden** - developers must understand and work around unused code
2. **Inflates binary size** - dead code is still compiled into binaries
3. **Creates confusion** - developers may accidentally use deprecated APIs
4. **Clutters IDE autocomplete** - unused symbols appear in suggestions
5. **Adds cognitive load** - more code to read and understand

### Analysis Summary

Comprehensive dead code analysis was performed on 2026-03-05 covering:
- **SDK**: 157 non-test Go files analyzed
- **Gibson**: 872 Go files analyzed
- **Total dead code identified**: ~5,000+ lines across both codebases

### Goals

1. **Remove all identified dead code** from SDK and Gibson
2. **Maintain backward compatibility** (no breaking changes to used APIs)
3. **Improve codebase clarity** and developer experience
4. **Reduce binary size** and compilation time
5. **Document removal decisions** for future reference

---

## Dead Code Inventory

### SDK Dead Code (4,500+ lines)

#### 1. Deprecated Proto Files (162 KB - CRITICAL)

| File | Lines | Size | Reason |
|------|-------|------|--------|
| `sdk/api/proto/graphrag.pb.go` | 2,039 | 79.8 KB | Superseded by `api/gen/graphragpb/` |
| `sdk/api/proto/taxonomy.pb.go` | 2,328 | 82.3 KB | Superseded by `api/gen/taxonomypb/` |
| `sdk/api/gen/tools/nmap.pb.go` | ~1,000 | 28.1 KB | Deprecated per README |

**Usage**: 0 imports in SDK or Gibson

#### 2. Deprecated Proto Source Files (49 KB)

| File | Size | Status |
|------|------|--------|
| `sdk/api/proto/tools/builtins.proto` | 6.8 KB | Deprecated |
| `sdk/api/proto/tools/httpx.proto` | 5.1 KB | Deprecated |
| `sdk/api/proto/tools/nmap.proto` | 5.4 KB | Deprecated |
| `sdk/api/proto/tools/nuclei.proto` | 6.0 KB | Deprecated |
| `sdk/api/proto/tools/sslyze.proto` | 10.8 KB | Deprecated |
| `sdk/api/proto/tools/testssl.proto` | 7.5 KB | Deprecated |
| `sdk/api/proto/tools/wappalyzer.proto` | 3.3 KB | Deprecated |
| `sdk/api/proto/tools/whatweb.proto` | 4.0 KB | Deprecated |

**Note**: Per README.md: "SDK Tool Protos Deprecated: All tool proto definitions in `sdk/api/proto/tools/` are deprecated as of v1.x and will be removed in SDK v2.0"

#### 3. Unused Result Package (260 lines)

| File | Exports | Usage |
|------|---------|-------|
| `sdk/result/validator.go` | `ResultQuality`, `ValidatedResult`, `Validator`, `NewValidator()`, `WithRules()`, `Validate()` | 0 (only test file) |
| `sdk/result/validator_test.go` | N/A | Test only |

**Recommendation**: DELETE entire `sdk/result/` directory

#### 4. Deprecated Functions

| File | Function | Line | Reason |
|------|----------|------|--------|
| `sdk/serve/subprocess.go` | `RunSubprocess()` | 62-68 | Returns error "subprocess mode is deprecated" |
| `sdk/serve/callback_harness.go` | `StoreNode()` (DEPRECATED comment) | 1133 | Deprecated, use `StoreSemantic()` or `StoreStructured()` |
| `sdk/serve/callback_client.go` | `SetTaskContext()` | 152 | Deprecated, use `SetFullContext()` |

#### 5. Unused Health Functions

| File | Function | Line | Usage |
|------|----------|------|-------|
| `sdk/health/health.go` | `BinaryVersionCheck()` | ~15 | 0 |
| `sdk/health/health.go` | `NetworkCheck()` | ~35 | 0 |
| `sdk/health/health.go` | `FileCheck()` | ~55 | 0 |
| `sdk/health/health.go` | `Combine()` | ~70 | 0 |

---

### Gibson Dead Code (750+ items)

#### 1. Completely Unused Exported Functions (240)

Key examples:
| File | Function | Line |
|------|----------|------|
| `cmd/gibson/attack.go` | `Debugf()` | 1005 |
| `cmd/gibson/attack.go` | `Infof()` | 993 |
| `cmd/gibson/component/context.go` | `GetCallbackManager()` | 29 |
| `cmd/gibson/component/context.go` | `WithCallbackManager()` | 34 |
| `cmd/gibson/component/errors.go` | `PrintComponentError()` | 54 |
| `cmd/gibson/flags.go` | `GetOutputFormat()` | 60 |
| `cmd/gibson/internal/completion.go` | 25+ completion functions | 26-306 |
| `cmd/gibson/mission_progress.go` | `NewProgressReporter()` | 22 |
| `internal/harness/callback_server.go` | `NewCallbackServer()` | 31 |
| `internal/harness/callback_service.go` | 20+ LLM/Memory functions | Various |
| `internal/graphrag/errors.go` | `NewIndexError()` | 227 |
| `internal/graphrag/merge.go` | `DefaultMergeOptions()` | 260 |
| `internal/mission/run_linker.go` | Entire `MissionRunLinker` interface | 15-45 |
| `internal/mission/state.go` | 10+ state management functions | Various |
| `internal/orchestrator/prompts.go` | 6+ Format*Example functions | 884-968 |
| `internal/payload/` | 15+ payload functions | Various |
| `internal/report/` | 15+ report functions | Various |

**Full list**: See `/tmp/gibson_dead_code_full_report.txt`

#### 2. Completely Unused Exported Types (278)

Key examples:
| File | Type | Line |
|------|------|------|
| `cmd/gibson/component/commands.go` | `ComponentCommands` | 60 |
| `cmd/gibson/component/context.go` | `CallbackManagerKey` | 25 |
| `cmd/gibson/component/status.go` | `AllStatusOutput`, `ComponentSummary`, etc. | 18-41 |
| `cmd/gibson/internal/completion.go` | `CompletionContext`, `CompletionFunc` | 15-18 |
| `cmd/gibson/mission_progress.go` | `ProgressReporter` | 13 |
| `internal/agent/delegation.go` | `AgentDelegator`, `DelegationHarness` | 11-18 |
| `internal/attack/` | 5+ types | Various |
| `internal/events/types.go` | 20+ payload types | 290-655 |
| `internal/finding/` | 15+ types | Various |
| `internal/graphrag/` | 10+ types | Various |

#### 3. Test-Only Exported Functions (638)

These are exported but only used in tests - candidates for unexporting:
| File | Function | Test Usage |
|------|----------|------------|
| `cmd/gibson/core/component.go` | `ComponentBuild()`, `ComponentInstall()`, etc. | 2-3 uses |
| `internal/agent/config.go` | `NewAgentConfig()`, `WithSetting()`, etc. | 2-4 uses |
| `internal/agent/delegation.go` | `NewDelegationHarness()` | 3 uses |

#### 4. Rarely Used Functions (416)

Functions with only 2-3 usages that may be candidates for consolidation.

#### 5. Deprecated Code with Comments

| File | Symbol | Line | Deprecation Note |
|------|--------|------|------------------|
| `internal/mission/run_linker.go` | `MissionRunLinker` interface | 15 | "Deprecated: Use MissionRunStore directly" |
| `internal/mission/run_linker.go` | `MissionRunInfo` struct | 34 | "Deprecated: Use MissionRun from run.go" |
| `internal/harness/callback_manager.go` | `RegisterHarness()` | 264 | "Deprecated: Use RegisterHarnessForMission" |
| `internal/harness/context.go` | `URL`, `Headers` fields | 89-91 | "Deprecated: Use Connection[\"url\"]" |
| `internal/harness/callback_service.go` | `exportSpan()` | 2298 | "Deprecated: Use exportSpanData" |
| `internal/registry/adapter.go` | `RegisterHarness()` | 30 | "DEPRECATED: Use RegisterHarnessForMission" |

---

## Functional Requirements

### FR-1: SDK Dead Code Removal

#### FR-1.1: Remove Deprecated Proto Files
**As a** SDK maintainer
**I want** all deprecated proto files removed
**So that** the codebase only contains current implementations

**Files to Delete:**
- `sdk/api/proto/graphrag.pb.go`
- `sdk/api/proto/taxonomy.pb.go`
- `sdk/api/gen/tools/nmap.pb.go`
- `sdk/api/proto/tools/*.proto` (8 files)

**Acceptance Criteria:**
- [ ] All listed files deleted
- [ ] No compilation errors after deletion
- [ ] No import errors in SDK or Gibson
- [ ] Tests still pass

#### FR-1.2: Remove Unused Result Package
**As a** SDK maintainer
**I want** the unused result package removed
**So that** developers don't accidentally use unfinished code

**Actions:**
- Delete `sdk/result/` directory entirely

**Acceptance Criteria:**
- [ ] Directory deleted
- [ ] No references in go.mod
- [ ] No import errors

#### FR-1.3: Remove Deprecated Functions
**As a** SDK maintainer
**I want** deprecated functions removed
**So that** the API surface is clean

**Functions to Delete:**
- `RunSubprocess()` in `sdk/serve/subprocess.go`

**Acceptance Criteria:**
- [ ] Function deleted
- [ ] No callers exist (verified by analysis)
- [ ] Tests still pass

#### FR-1.4: Remove Unused Health Functions
**As a** SDK maintainer
**I want** unused health check functions removed
**So that** the health package contains only used code

**Functions to Delete:**
- `BinaryVersionCheck()`
- `NetworkCheck()`
- `FileCheck()`
- `Combine()`

**Acceptance Criteria:**
- [ ] Functions deleted
- [ ] No compilation errors
- [ ] Tests still pass

---

### FR-2: Gibson Dead Code Removal

#### FR-2.1: Remove Unused Exported Functions (Phase 1 - High Impact)
**As a** Gibson maintainer
**I want** completely unused exported functions removed
**So that** the codebase is leaner

**Priority Functions to Remove (First 50):**
1. `cmd/gibson/attack.go:Debugf()`, `Infof()` - Debug functions never used
2. `cmd/gibson/component/context.go:GetCallbackManager()`, `WithCallbackManager()` - Context helpers unused
3. `cmd/gibson/component/errors.go:PrintComponentError()` - Never called
4. `cmd/gibson/flags.go:GetOutputFormat()` - Never called
5. `cmd/gibson/internal/completion.go:*` - 25+ completion functions never used
6. `cmd/gibson/mission_progress.go:NewProgressReporter()` - Never called

**Acceptance Criteria:**
- [ ] Listed functions removed
- [ ] No compilation errors
- [ ] Tests still pass

#### FR-2.2: Remove Unused Exported Types (Phase 1)
**As a** Gibson maintainer
**I want** unused exported types removed
**So that** the type system is cleaner

**Priority Types to Remove (First 30):**
1. `cmd/gibson/component/commands.go:ComponentCommands`
2. `cmd/gibson/component/context.go:CallbackManagerKey`, `DaemonClientKey`
3. `cmd/gibson/component/status.go:AllStatusOutput`, `ComponentSummary`, etc.
4. `cmd/gibson/internal/completion.go:CompletionContext`, `CompletionFunc`
5. `cmd/gibson/mission_progress.go:ProgressReporter`

**Acceptance Criteria:**
- [ ] Listed types removed
- [ ] No compilation errors
- [ ] Tests still pass

#### FR-2.3: Remove Deprecated Code with Comments
**As a** Gibson maintainer
**I want** code marked as deprecated removed
**So that** we follow through on deprecation promises

**Items to Remove:**
1. `internal/mission/run_linker.go` - Entire file if `MissionRunLinker` and `MissionRunInfo` are unused
2. Deprecated methods in `internal/harness/callback_manager.go`
3. Deprecated fields in `internal/harness/context.go`

**Acceptance Criteria:**
- [ ] Deprecated code removed
- [ ] Replacement code is being used
- [ ] No breaking changes

---

### FR-3: Verification and Testing

#### FR-3.1: Pre-Removal Verification
**As a** developer
**I want** each removal verified before execution
**So that** we don't accidentally break functionality

**Verification Steps:**
1. Run `grep -r "SYMBOL" .` to confirm zero usage
2. Run `go build ./...` to check compilation
3. Run `go test ./...` to check tests

**Acceptance Criteria:**
- [ ] Each symbol verified before removal
- [ ] Verification documented in commit message

#### FR-3.2: Post-Removal Testing
**As a** developer
**I want** comprehensive tests run after removal
**So that** we catch any regressions

**Test Commands:**
```bash
cd sdk && go build ./... && go test ./...
cd gibson && go build ./... && go test ./...
```

**Acceptance Criteria:**
- [ ] All builds pass
- [ ] All tests pass
- [ ] No new warnings introduced

---

## Non-Functional Requirements

### NFR-1: Safety

#### NFR-1.1: No Breaking Changes
- All removed code must have ZERO production usage
- Removal must not break SDK or Gibson compilation
- Removal must not break any tests

#### NFR-1.2: Git History Preservation
- Use standard `git rm` for deletions
- Include comprehensive commit messages explaining what was removed and why
- One logical commit per category of dead code

### NFR-2: Documentation

#### NFR-2.1: Commit Messages
Each commit should include:
- What was removed
- Why it was removed (e.g., "0 usages found", "superseded by X")
- Analysis date and methodology

#### NFR-2.2: Changelog Updates
- Update CHANGELOG.md with removed items
- Note SDK version where deprecations were completed

---

## Phased Removal Plan

### Phase 1: SDK High-Impact (Estimated: 4,500 lines)
1. Delete deprecated proto files (3 files, ~5,400 lines)
2. Delete deprecated proto source files (8 files, ~49 KB)
3. Delete result package (2 files, ~260 lines)
4. Delete deprecated functions (1 function)
5. Delete unused health functions (4 functions)

### Phase 2: Gibson CLI Dead Code (Estimated: 500 lines)
1. Remove unused cmd/gibson functions
2. Remove unused cmd/gibson types
3. Clean up internal/completion.go

### Phase 3: Gibson Internal Dead Code (Estimated: 1,000 lines)
1. Remove unused internal/harness functions
2. Remove unused internal/graphrag functions
3. Remove unused internal/mission functions
4. Remove unused internal/orchestrator functions

### Phase 4: Deprecated Code Cleanup (Estimated: 200 lines)
1. Remove deprecated interfaces
2. Remove deprecated structs
3. Remove deprecated methods

### Phase 5: Test-Only Export Review (Optional)
1. Review 638 test-only exported functions
2. Unexport those that can be made private
3. Move test helpers to _test.go files

---

## Success Criteria

1. **SDK builds** without errors after all removals
2. **Gibson builds** without errors after all removals
3. **All tests pass** in both codebases
4. **~5,000 lines of dead code removed** across both codebases
5. **Zero breaking changes** to used APIs
6. **Clear commit history** documenting each removal

---

## Dependencies

### Internal Dependencies
- SDK go.mod structure
- Gibson go.mod with SDK replace directive
- Existing test suites

### External Dependencies
- None (pure deletion operation)

---

## Out of Scope

- Refactoring working code
- Adding new functionality
- Changing API signatures of used code
- Removing test-only code (Phase 5 is optional)
- Performance optimizations

---

## Glossary

| Term | Definition |
|------|------------|
| **Dead Code** | Code that is never executed in production |
| **Deprecated** | Code marked for removal in a future version |
| **Unused Export** | Exported symbol with zero usage outside its defining package |
| **Test-Only Export** | Exported symbol used only in test files |
| **Orphaned Code** | Code with no callers or references |

---

## Related Documents

- `/tmp/gibson_dead_code_full_report.txt` - Full Gibson analysis output
- `/tmp/sdk_dead_code_comprehensive_report.md` - Full SDK analysis output
- `sdk/README.md` - SDK deprecation notices
