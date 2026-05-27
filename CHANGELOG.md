# Changelog

All notable changes to the gibson daemon are documented here.

---

## Unreleased — working-memory-persistence

### Breaking change: checkpoint schema version 2

The checkpoint schema has been bumped from version 1 to version 2. The new
schema persists working memory and mission memory across daemon crashes and
records per-child execution status for parallel groups.

**Before upgrading:** Run `gibson mission drain --all` to complete or cancel
all in-flight missions. The new daemon refuses to resume version-1 checkpoints
with a clear error message:

```
unsupported checkpoint schema version 1 (this daemon requires version 2):
drain in-flight missions before upgrading
```

Completed or cancelled missions are unaffected.

**No SDK changes required.** All changes are confined to `core/gibson/`. No
`go.mod` bump is needed in any consumer repo (`core/ext-authz/`,
`opensource/adk/`, `opensource/gibson-tool-runner/`).

### Added

- `WorkingMemory.GetAll()` — point-in-time snapshot of the agent's ephemeral
  key-value scratchpad. Non-JSON-serializable values are skipped with a
  `level=warn` log. Snapshots larger than 1 MB are truncated lexicographically.
- `MissionMemory.GetAll(ctx)` — SMEMBERS + pipelined JSON.GET snapshot of the
  mission's Redis-backed shared context. Used as a recovery aid in checkpoints;
  Redis remains the authoritative source of truth on resume.
- `ParallelGroupState` checkpoint struct — records per-child `ChildStatus`
  (`pending`, `in_flight`, `completed`, `failed`) and child outputs for every
  active parallel group. Replaces the former `ParallelState map[string][]string`
  which only recorded completed-node IDs.
- `CheckpointIntegration.MarkChildDispatched` — transitions a child to
  `ChildStatusInFlight` when the scheduler dispatches it.
- `CheckpointIntegration.SetParallelGroupFailFast` — registers fail-fast
  semantics for a parallel group.
- `StateRestorer.RestoreFromCheckpoint` — now accepts optional
  `memory.WorkingMemory` and `memory.MissionMemory` parameters. When provided,
  working-memory entries are re-hydrated via `Set`, and mission-memory Redis
  availability is probed before resume (fail-fast on connection error).
- `ErrMissionMemoryUnavailable` sentinel — returned when Redis is unreachable
  at resume time.

### Changed

- `checkpoint.NewCheckpoint` — `Version` field now set to `CurrentCheckpoint
  Version` (2) instead of hard-coded 1.
- `checkpoint.FromCheckpoint` — fail-fast version guard at the top of the
  function; rejects any checkpoint whose `Version` field does not equal 2.
- `checkpoint.ValidateCheckpointVersion` — updated to accept only version 2.
- `DAGTraversalState.ParallelState` — retagged `json:"-" msgpack:"-"`
  (deprecated, excluded from wire in schema version 2).

---

## [0.120.0](https://github.com/zeroroot-ai/gibson/compare/v0.119.1...v0.120.0) (2026-05-27)


### Features

* **daemon:** implement UpdateMissionDefinition RPC and expose missionDefinitionId in GetMissionDefinitionResponse ([#437](https://github.com/zeroroot-ai/gibson/issues/437), [#438](https://github.com/zeroroot-ai/gibson/issues/438)) ([#442](https://github.com/zeroroot-ai/gibson/issues/442)) ([20ace5d](https://github.com/zeroroot-ai/gibson/commit/20ace5d4b1e44f2687b072db6d7da3a0aecc1950))
* **llm:** add buildEinoOptions / streamToChannel helpers to eino adapter ([#474](https://github.com/zeroroot-ai/gibson/issues/474)) ([5c7c5a7](https://github.com/zeroroot-ai/gibson/commit/5c7c5a7fe40ad4adac816c79cdca15ffc02f80e1))
* **llm:** add Eino deps and Eino-to-internal type adapter (S1) ([#473](https://github.com/zeroroot-ai/gibson/issues/473)) ([48a25c5](https://github.com/zeroroot-ai/gibson/commit/48a25c56d6f956bfecf1d53f52ef3a5e1c1fc042)), closes [#460](https://github.com/zeroroot-ai/gibson/issues/460)
* **llm:** delete langchaingo shim layer (S12) ([#486](https://github.com/zeroroot-ai/gibson/issues/486)) ([48f5fd3](https://github.com/zeroroot-ai/gibson/commit/48f5fd398baded029262024fb3010ff0933bfa21))
* **llm:** remove langchaingo dependency entirely (S13) ([#487](https://github.com/zeroroot-ai/gibson/issues/487)) ([17f9a95](https://github.com/zeroroot-ai/gibson/commit/17f9a9516feb238a3faa723b1c3897f1762989d8))
* **llm:** rewrite Anthropic provider to use Eino (S2) ([#477](https://github.com/zeroroot-ai/gibson/issues/477)) ([ee47f4f](https://github.com/zeroroot-ai/gibson/commit/ee47f4f4898a3c935c82f89075d059dabb4588ba))
* **llm:** rewrite Bedrock provider to use AWS Converse API directly (S10) ([#480](https://github.com/zeroroot-ai/gibson/issues/480)) ([973dac1](https://github.com/zeroroot-ai/gibson/commit/973dac1c1add64003b31777605ce7d06cec150ee))
* **llm:** rewrite Cloudflare provider to use Eino (S7) ([#479](https://github.com/zeroroot-ai/gibson/issues/479)) ([aa510cb](https://github.com/zeroroot-ai/gibson/commit/aa510cb8844bfaba3a1c41f425f31b7558162a92))
* **llm:** rewrite Cohere provider to use Eino (S11) ([#484](https://github.com/zeroroot-ai/gibson/issues/484)) ([ac85186](https://github.com/zeroroot-ai/gibson/commit/ac851864843075aa89e282b6da47ee2da8207934))
* **llm:** rewrite Google provider to use Eino (S4) ([#485](https://github.com/zeroroot-ai/gibson/issues/485)) ([01ca42b](https://github.com/zeroroot-ai/gibson/commit/01ca42b4c9149fbfeab19e79c78d6dc7789c86c2))
* **llm:** rewrite HuggingFace provider to use Eino (S8) ([#482](https://github.com/zeroroot-ai/gibson/issues/482)) ([27ee02c](https://github.com/zeroroot-ai/gibson/commit/27ee02ce873e96280bc7592d134846784b08a969))
* **llm:** rewrite Llamafile provider to use Eino (S9) ([#483](https://github.com/zeroroot-ai/gibson/issues/483)) ([5a04d71](https://github.com/zeroroot-ai/gibson/commit/5a04d714f9b190e110894a1ec7a776fde9bd197b))
* **llm:** rewrite Mistral provider to use Eino (S6) ([#476](https://github.com/zeroroot-ai/gibson/issues/476)) ([cdd28a7](https://github.com/zeroroot-ai/gibson/commit/cdd28a740639db1ea72ff42ca98fef8c7b514910))
* **llm:** rewrite Ollama provider to use Eino (S5) ([#478](https://github.com/zeroroot-ai/gibson/issues/478)) ([d3f118b](https://github.com/zeroroot-ai/gibson/commit/d3f118b7d5b5d2236faa15f6310a28c4e62622a0))
* **llm:** rewrite OpenAI provider to use Eino (S3) ([#481](https://github.com/zeroroot-ai/gibson/issues/481)) ([820c88d](https://github.com/zeroroot-ai/gibson/commit/820c88d4b694f698b09ff824afd82ea7c9f10ebc))
* **missions:** populate MissionDefinitionId in daemon responses ([#448](https://github.com/zeroroot-ai/gibson/issues/448)) ([a358309](https://github.com/zeroroot-ai/gibson/commit/a3583090eecc5799eb503ad40677b0429b19c48c))


### Bug Fixes

* **authz:** fix in_tenant_catalog + deny expansion so user types satisfy component access checks ([#457](https://github.com/zeroroot-ai/gibson/issues/457)) ([31246f9](https://github.com/zeroroot-ai/gibson/commit/31246f9faf446d8b0212b72704a2753c05ded63f))
* **ci:** upgrade Go to 1.26 and fix BSR authz-registry build ([#449](https://github.com/zeroroot-ai/gibson/issues/449)) ([51ad0a6](https://github.com/zeroroot-ai/gibson/commit/51ad0a60f42ec9bd3f1733df44a3e6770e8b4539))
* **cue:** bump sdk to v0.124.1 to fix CUE module path after rebrand ([#451](https://github.com/zeroroot-ai/gibson/issues/451)) ([a648fb2](https://github.com/zeroroot-ai/gibson/commit/a648fb2f732ac330d1f4c2c4ba7fa9bd54eb13dc))
* **state:** correct inverted NoAck doc comment in StreamReadGroup ([#458](https://github.com/zeroroot-ai/gibson/issues/458)) ([841fd0b](https://github.com/zeroroot-ai/gibson/commit/841fd0bf9646dcf4c6b4d237fade9e269145a154))
* **test:** rename gibsoncheck testdata fixtures from zero-day-ai → zeroroot-ai ([#456](https://github.com/zeroroot-ai/gibson/issues/456)) ([0dad4e7](https://github.com/zeroroot-ai/gibson/commit/0dad4e7de869934c53657811a2852575a6547c5a))
* **test:** update no_graceful_nil allowlist grpc.go:2573 → :2574 ([#455](https://github.com/zeroroot-ai/gibson/issues/455)) ([fd3f02a](https://github.com/zeroroot-ai/gibson/commit/fd3f02a4a7063a5cc55db159ce141c97d7d4b064))

## [0.119.1](https://github.com/zeroroot-ai/gibson/compare/v0.119.0...v0.119.1) (2026-05-26)


### Bug Fixes

* **authz:** realign IdentityClass const block in generated registry ([#436](https://github.com/zeroroot-ai/gibson/issues/436)) ([32a7566](https://github.com/zeroroot-ai/gibson/commit/32a7566ad595cf4d3d0632f5ca41767bba39950d))
* **idp:** guard parseZitadelError against nil Details slice + fix GetUserProfile error mapping ([#433](https://github.com/zeroroot-ai/gibson/issues/433)) ([06dbca0](https://github.com/zeroroot-ai/gibson/commit/06dbca07a8a434d4c1c35fbd172c9ace260ab5ec))
* **state:** guard XRead against infinite hang when Block &gt; 0 ([#391](https://github.com/zeroroot-ai/gibson/issues/391)) ([804ccd9](https://github.com/zeroroot-ai/gibson/commit/804ccd91636944b8bb259ab598c59db73c5e8530))

## [0.119.0](https://github.com/zeroroot-ai/gibson/compare/v0.118.0...v0.119.0) (2026-05-26)


### ⚠ BREAKING CHANGES

* remove DaemonOperatorService handlers for superseded RPCs ([#409](https://github.com/zeroroot-ai/gibson/issues/409))

### Features

* **admin:** add 12 TenantAdminService handlers for team/component/grant ops ([#402](https://github.com/zeroroot-ai/gibson/issues/402)) ([66f48ec](https://github.com/zeroroot-ai/gibson/commit/66f48ecb404834fc0a701da57a160ff4e5ee2472))
* **cue:** populate CompiledDefinition in ValidateMissionCUE response ([#393](https://github.com/zeroroot-ai/gibson/issues/393)) ([7428c01](https://github.com/zeroroot-ai/gibson/commit/7428c011be76bea234a1df0f9f067fd306ce7d16))
* **providerconfig:** broker-backed store — metadata in Postgres, credentials in secrets broker ([#431](https://github.com/zeroroot-ai/gibson/issues/431)) ([dfb7b07](https://github.com/zeroroot-ai/gibson/commit/dfb7b07c34cea2105831cbdf721c9e552b025ead)), closes [#423](https://github.com/zeroroot-ai/gibson/issues/423) [#425](https://github.com/zeroroot-ai/gibson/issues/425) [#426](https://github.com/zeroroot-ai/gibson/issues/426)
* **secrets:** namespace all user secrets under user/ prefix in Vault ([#406](https://github.com/zeroroot-ai/gibson/issues/406)) ([d81b172](https://github.com/zeroroot-ai/gibson/commit/d81b172652dd64d5bc03bb1ea1e58f9c1e9c3bfd)), closes [#404](https://github.com/zeroroot-ai/gibson/issues/404)
* **secrets:** remove Postgres broker from factory map, registry, and admin RPC ([#407](https://github.com/zeroroot-ai/gibson/issues/407)) ([7789d00](https://github.com/zeroroot-ai/gibson/commit/7789d009a779077ef4f89a4b87a31dd9963f17a4))


### Bug Fixes

* **authz:** write direct_read tuple in TestModel_CatalogGating instead of can_read ([#411](https://github.com/zeroroot-ai/gibson/issues/411)) ([9667f22](https://github.com/zeroroot-ai/gibson/commit/9667f22641fdd4f3d9e76e6e4b805fe9188a5587))
* **cueruntime:** surface missing 'mission' wrapper as inline diagnostic ([#429](https://github.com/zeroroot-ai/gibson/issues/429)) ([4fef711](https://github.com/zeroroot-ai/gibson/commit/4fef711af8c7736617b210caf68bd4b207d89ddc))
* **llm:** bypass langchaingo for Anthropic Complete to avoid deprecated temperature ([#418](https://github.com/zeroroot-ai/gibson/issues/418)) ([a4bbb67](https://github.com/zeroroot-ai/gibson/commit/a4bbb67c228ad946150e9aeaf1ac41e654fcface))
* **missiondraft:** rename Redis field yaml → cue_source ([#428](https://github.com/zeroroot-ai/gibson/issues/428)) ([092655c](https://github.com/zeroroot-ai/gibson/commit/092655c08662099b786c6d82dc482994f258f405))
* **providerconfig:** migrate postgres store from dropped provider_configs to tenant_secrets ([#401](https://github.com/zeroroot-ai/gibson/issues/401)) ([18b80e3](https://github.com/zeroroot-ai/gibson/commit/18b80e37d2b04656d23a3050121df80ebe12ca74))
* **state:** align TestConsumerGroupMission pending assertions with NoAck behaviour ([#415](https://github.com/zeroroot-ai/gibson/issues/415)) ([b1a4ee9](https://github.com/zeroroot-ai/gibson/commit/b1a4ee900f3a9636b0af4760416a33b63ac15d3a)), closes [#413](https://github.com/zeroroot-ai/gibson/issues/413)
* **state:** prevent TestStreamRead goroutine hang under setec_integration ([#412](https://github.com/zeroroot-ai/gibson/issues/412)) ([5357052](https://github.com/zeroroot-ai/gibson/commit/53570524f3af47b3c5a5adf2b7d0b03e120e5286))
* **state:** replace log.Fatal with graceful skip in Example functions ([#417](https://github.com/zeroroot-ai/gibson/issues/417)) ([035ec1a](https://github.com/zeroroot-ai/gibson/commit/035ec1a976030ec6235f4424db5009116293c2e2)), closes [#414](https://github.com/zeroroot-ai/gibson/issues/414)
* **tests:** align vector/prompt/graphrag tests with current code contracts ([#389](https://github.com/zeroroot-ai/gibson/issues/389)) ([54948c0](https://github.com/zeroroot-ai/gibson/commit/54948c0b3401d9798a97cfe0db71d7d6d1e35d6e))


### Miscellaneous Chores

* remove DaemonOperatorService handlers for superseded RPCs ([#409](https://github.com/zeroroot-ai/gibson/issues/409)) ([5234197](https://github.com/zeroroot-ai/gibson/commit/52341978b26a472e4863effc21880a408a4ecf8a))

## [0.118.0](https://github.com/zeroroot-ai/gibson/compare/v0.117.0...v0.118.0) (2026-05-24)


### Features

* **daemon:** implement TenantAdminService.ListMembers ([#367](https://github.com/zeroroot-ai/gibson/issues/367)) ([bc65753](https://github.com/zeroroot-ai/gibson/commit/bc65753436c79e20ab89bbee80f1591f400677ee))


### Bug Fixes

* **authz:** add tenant#writer relation to FGA model (ADR-0037) ([#361](https://github.com/zeroroot-ai/gibson/issues/361)) ([58b0d7e](https://github.com/zeroroot-ai/gibson/commit/58b0d7e4326503de31e39132e50cca4294637350))
* **ci:** add paths-ignore for doc-only PRs to daemon build ([#365](https://github.com/zeroroot-ai/gibson/issues/365)) ([2aa9cbb](https://github.com/zeroroot-ai/gibson/commit/2aa9cbbb96abf1bd59b956bab20aa2596a1c5941)), closes [#362](https://github.com/zeroroot-ai/gibson/issues/362)
* **ci:** add Redis service container to test job (fixes [#368](https://github.com/zeroroot-ai/gibson/issues/368)) ([#371](https://github.com/zeroroot-ai/gibson/issues/371)) ([41c6887](https://github.com/zeroroot-ai/gibson/commit/41c688775f72348a91ae06cc942eaa3f3aa54be3))
* **ci:** add Redis service container to test job in build.yaml ([#377](https://github.com/zeroroot-ai/gibson/issues/377)) ([c265447](https://github.com/zeroroot-ai/gibson/commit/c2654470a429c041cfd721c532bde2d0d90dc082))
* **ci:** migrate build.yaml to reusable-image-build for :main tag ([#357](https://github.com/zeroroot-ai/gibson/issues/357)) ([6952dc9](https://github.com/zeroroot-ai/gibson/commit/6952dc96607e3eca657192396fde86d44c634bdc))
* **ci:** pass explicit GITHUB_TOKEN to release-please-action@v5 ([#360](https://github.com/zeroroot-ai/gibson/issues/360)) ([cf08526](https://github.com/zeroroot-ai/gibson/commit/cf0852691bb1445198ba110dce5be84fcc9516ab)), closes [#288](https://github.com/zeroroot-ai/gibson/issues/288)
* **ci:** publish-authz-registry silently skipped since v0.108.0 ([#356](https://github.com/zeroroot-ai/gibson/issues/356)) ([ca167eb](https://github.com/zeroroot-ai/gibson/commit/ca167eb52f0ccec3225ef859d9d3eb98e514ae71))
* **ci:** use security-extended queries for CodeQL ([#366](https://github.com/zeroroot-ai/gibson/issues/366)) ([68a95db](https://github.com/zeroroot-ai/gibson/commit/68a95dbdc004795848ec01a476c9fd639495f4b3)), closes [#363](https://github.com/zeroroot-ai/gibson/issues/363)
* **ci:** wire deploy repo auth in signup-smoke checkout step ([#355](https://github.com/zeroroot-ai/gibson/issues/355)) ([be40953](https://github.com/zeroroot-ai/gibson/commit/be4095312950fd993ec6808aea2d836a32566725)), closes [#341](https://github.com/zeroroot-ai/gibson/issues/341)
* **daemon:** register ModelAccessService on gRPC server ([#364](https://github.com/zeroroot-ai/gibson/issues/364)) ([a7ea0b7](https://github.com/zeroroot-ai/gibson/commit/a7ea0b7adc9b228661b743f4a5aee60ef59569be)), closes [#358](https://github.com/zeroroot-ai/gibson/issues/358)
* **queue:** remove raw go-redis import from internal/queue via redisBackend interface ([#354](https://github.com/zeroroot-ai/gibson/issues/354)) ([98018bb](https://github.com/zeroroot-ai/gibson/commit/98018bb42c4e630235f8f53b51c8deb1eff945ee))
* **tests:** repair stale AST allowlist line numbers in nil-guard + time.Now walkers ([#351](https://github.com/zeroroot-ai/gibson/issues/351)) ([b389211](https://github.com/zeroroot-ai/gibson/commit/b389211b6cb97c6c0a6a4e60c4d91e9bc59dd306))
* **vector:** translate VECTOR_NOT_FOUND to (nil, nil) in tenantScopedStore.Get ([#378](https://github.com/zeroroot-ai/gibson/issues/378)) ([339d570](https://github.com/zeroroot-ai/gibson/commit/339d5708810b459989ce9f5c1260eb6f61e7d702))

## [0.117.0](https://github.com/zeroroot-ai/gibson/compare/v0.116.0...v0.117.0) (2026-05-24)


### Features

* **daemon:** register TenantService + DaemonOperatorService; unregister admin services ([#350](https://github.com/zeroroot-ai/gibson/issues/350)) ([4ff5153](https://github.com/zeroroot-ai/gibson/commit/4ff5153bfa6a31473e7b0abaae8cf5a09fa97d5e)), closes [#342](https://github.com/zeroroot-ai/gibson/issues/342)


### Bug Fixes

* scope SPIFFE bypass to per-peer method allowlist; remove debug interceptor ([#344](https://github.com/zeroroot-ai/gibson/issues/344)) ([85f7abf](https://github.com/zeroroot-ai/gibson/commit/85f7abf6f9cb203d9aca33ecf7ad37f81c5a3868)), closes [#245](https://github.com/zeroroot-ai/gibson/issues/245) [#343](https://github.com/zeroroot-ai/gibson/issues/343)

## [0.116.0](https://github.com/zeroroot-ai/gibson/compare/v0.115.0...v0.116.0) (2026-05-24)


### Features

* **audit:** fire-and-forget Redis XADD + delete bespoke retry loop ([#320](https://github.com/zeroroot-ai/gibson/issues/320)) ([#335](https://github.com/zeroroot-ai/gibson/issues/335)) ([3f5cb82](https://github.com/zeroroot-ai/gibson/commit/3f5cb82a90dea86abbd7ac3ceb512e1cf91b0b0f))
* **graphrag:** gobreaker circuit breaker + graphHealthy runtime update ([#318](https://github.com/zeroroot-ai/gibson/issues/318)) ([#332](https://github.com/zeroroot-ai/gibson/issues/332)) ([2b3333d](https://github.com/zeroroot-ai/gibson/commit/2b3333dba8f83c64026aca466e56b06ca5eb98b9))
* **internal/queue:** move queue package from sdk to gibson internal ([#334](https://github.com/zeroroot-ai/gibson/issues/334)) ([f058d1c](https://github.com/zeroroot-ai/gibson/commit/f058d1cf1c1d57a53119aa81f5ca4d1fe07ea3c8))
* **llm:** HTTPTimeout in ProviderConfig + circuitLLMProvider wrapper ([#319](https://github.com/zeroroot-ai/gibson/issues/319)) ([#333](https://github.com/zeroroot-ai/gibson/issues/333)) ([4c6165b](https://github.com/zeroroot-ai/gibson/commit/4c6165bcd11eee3f2587ccfa279d4e4282dbefbc))
* **secrets:** gobreakerExecutor replaces ServiceCircuitBreaker + wire JWTCache into broker_init ([#321](https://github.com/zeroroot-ai/gibson/issues/321)) ([#336](https://github.com/zeroroot-ai/gibson/issues/336)) ([7a375c8](https://github.com/zeroroot-ai/gibson/commit/7a375c880ca0a99c33863ef73e415a0d6ef54c30))
* **vectordb:** implement Redis VSS adapter, delete Qdrant stub, wire into pool ([#330](https://github.com/zeroroot-ai/gibson/issues/330)) ([6c89a7f](https://github.com/zeroroot-ai/gibson/commit/6c89a7f6b4ad7db495ecbff79a21cfc67cde4e1d)), closes [#325](https://github.com/zeroroot-ai/gibson/issues/325)

## [0.115.0](https://github.com/zeroroot-ai/gibson/compare/v0.114.0...v0.115.0) (2026-05-24)


### Features

* **dataplane:** slim VectorCredentials to index_name only ([#327](https://github.com/zeroroot-ai/gibson/issues/327)) ([ba48eed](https://github.com/zeroroot-ai/gibson/commit/ba48eed1eb5fa54c50ffb701f7dd13b5e3131e13))
* **jwtsource:** JWTCache with background refresh and last-known-good ([#322](https://github.com/zeroroot-ai/gibson/issues/322)) ([f27ba8a](https://github.com/zeroroot-ai/gibson/commit/f27ba8addfe86c64180d2d28d99d4838fa405463)), closes [#317](https://github.com/zeroroot-ai/gibson/issues/317)


### Bug Fixes

* **memory:** drop qdrant from LongTermMemoryConfig valid backend enum ([#326](https://github.com/zeroroot-ai/gibson/issues/326)) ([5fcaf35](https://github.com/zeroroot-ai/gibson/commit/5fcaf357b613b607bc1967aae972972c183ded20))

## [0.114.0](https://github.com/zeroroot-ai/gibson/compare/v0.113.1...v0.114.0) (2026-05-24)


### Features

* **ci:** provider catalogue update workflow with per-provider API key gating ([#302](https://github.com/zeroroot-ai/gibson/issues/302)) ([37d1a31](https://github.com/zeroroot-ai/gibson/commit/37d1a31b580aeb9063dff6bb3f3694436b2b5f4a))
* **mission/cueruntime:** add cuelang.org/go dep and cueruntime package ([#304](https://github.com/zeroroot-ai/gibson/issues/304)) ([864e3f8](https://github.com/zeroroot-ai/gibson/commit/864e3f81a051217f9036f1f0bfddd8b4330d6eed))
* **mission:** wire cueruntime to editor RPCs; cue_source path; delete GetMissionSourceYAML ([#306](https://github.com/zeroroot-ai/gibson/issues/306)) ([9cb91c4](https://github.com/zeroroot-ai/gibson/commit/9cb91c4fdfbf5888335592f7a9abd72f9a6dbeef))
* **providers:** Bedrock IRSA toggle — daemon ([#297](https://github.com/zeroroot-ai/gibson/issues/297)) ([504a930](https://github.com/zeroroot-ai/gibson/commit/504a930e2efc88e99ee3232b50717a566ece9f42)), closes [#294](https://github.com/zeroroot-ai/gibson/issues/294)
* **providers:** catalogue hot-reload via ConfigMap mount ([#303](https://github.com/zeroroot-ai/gibson/issues/303)) ([091e689](https://github.com/zeroroot-ai/gibson/commit/091e6896abd62d55dc13a8333988eb94946589d9))
* **providers:** provider-catalogue.yaml initial population + daemon loading ([#300](https://github.com/zeroroot-ai/gibson/issues/300)) ([72f3f1b](https://github.com/zeroroot-ai/gibson/commit/72f3f1bc9049b5237b8ab1434f3b73cf692f83df)), closes [#293](https://github.com/zeroroot-ai/gibson/issues/293)


### Bug Fixes

* **authz:** add gibson.owner permission closure parity with gibson.admin ([#290](https://github.com/zeroroot-ai/gibson/issues/290)) ([0e5cf82](https://github.com/zeroroot-ai/gibson/commit/0e5cf82c0cf769c5a8a77bf631bd66cfaf09bce3))
* **authz:** make mission belongs_to tuple write required + self-heal missing tuples ([#312](https://github.com/zeroroot-ai/gibson/issues/312)) ([7f581b1](https://github.com/zeroroot-ai/gibson/commit/7f581b1f59e605d634350ddde7191ec1eebf9b4e)), closes [#310](https://github.com/zeroroot-ai/gibson/issues/310)
* **ci:** add actions:read to image-build job permissions ([#314](https://github.com/zeroroot-ai/gibson/issues/314)) ([49cf807](https://github.com/zeroroot-ai/gibson/commit/49cf807da04806a7e4168ccae2cc77b03e4bb625))
* **daemon:** fail fast when platform-postgres init fails ([#307](https://github.com/zeroroot-ai/gibson/issues/307)) ([c0f3e51](https://github.com/zeroroot-ai/gibson/commit/c0f3e514a05810f90818151be470b2b0c31a6d12)), closes [#246](https://github.com/zeroroot-ai/gibson/issues/246)
* **datapool:** propagate Redis password through per-tenant client pool ([#291](https://github.com/zeroroot-ai/gibson/issues/291)) ([9a7a666](https://github.com/zeroroot-ai/gibson/commit/9a7a6661f3c49ee11bf2761e27785cc103521eb9))
* **deps:** bump golang.org/x/net v0.53.0 → v0.55.0 (GO-2026-5026) ([#283](https://github.com/zeroroot-ai/gibson/issues/283)) ([50ee96a](https://github.com/zeroroot-ai/gibson/commit/50ee96a08614b649f90733d24aff297322ad1091))
* **deps:** bump platform-clients v0.6.0 → v0.7.0 ([#286](https://github.com/zeroroot-ai/gibson/issues/286)) ([cd6d5fa](https://github.com/zeroroot-ai/gibson/commit/cd6d5fa061630f61047ee33f76c2b727671a3f97))
* **gibsoncheck:** honor gibsoncheck:allow tenant-from-request directive + annotate 6 admin RPCs ([#277](https://github.com/zeroroot-ai/gibson/issues/277)) ([2b30f2f](https://github.com/zeroroot-ai/gibson/commit/2b30f2fa4450232347fd5f879c322fb5997edcd5))
* **observability:** remove pcotel.Init gRPC leak causing frame-too-large errors ([#313](https://github.com/zeroroot-ai/gibson/issues/313)) ([5b68c02](https://github.com/zeroroot-ai/gibson/commit/5b68c02490242789679b92037987d0b37d5ca807)), closes [#311](https://github.com/zeroroot-ai/gibson/issues/311)
* **secrets:** wire vault TokenRefresher into VaultFactory — eliminates stale-token circuit open ([#305](https://github.com/zeroroot-ai/gibson/issues/305)) ([b29f35c](https://github.com/zeroroot-ai/gibson/commit/b29f35c34e09f5559ffa326ffb3dae707fa15b55))
* **tests:** resolve pre-existing failures in harness, observability, orchestrator ([#308](https://github.com/zeroroot-ai/gibson/issues/308)) ([61e93e6](https://github.com/zeroroot-ai/gibson/commit/61e93e6b97a78553a2d773c9dcb01649e1484e3a))

## [0.113.1](https://github.com/zeroroot-ai/gibson/compare/v0.113.0...v0.113.1) (2026-05-21)


### Bug Fixes

* **ci:** restore build-and-push green — root-cause 20+ test classes ([#266](https://github.com/zeroroot-ai/gibson/issues/266)) ([da2f601](https://github.com/zeroroot-ai/gibson/commit/da2f601f8bafefc07dd6d156da064d6d2be4fdad))
* **ci:** second-pass test fixes following post-merge CI validation ([519dc58](https://github.com/zeroroot-ai/gibson/commit/519dc587fa89ff99530a9e0e50bb17b59d266d18))
* **saga:** remove already-completed short-circuit; idempotent steps re-run when artifact missing ([#270](https://github.com/zeroroot-ai/gibson/issues/270)) ([68e7f1f](https://github.com/zeroroot-ai/gibson/commit/68e7f1fa71b1007d3dd896682246fe4f968c9cd2))

## [0.113.0](https://github.com/zeroroot-ai/gibson/compare/v0.112.0...v0.113.0) (2026-05-21)


### Features

* **psaga:** add Runner.ContinueOnBlocked for teardown step-isolation ([#255](https://github.com/zeroroot-ai/gibson/issues/255)) ([a8c18da](https://github.com/zeroroot-ai/gibson/commit/a8c18da253c853760f82eaa4f90961c6308b9897))


### Bug Fixes

* **daemon:** broker_init VaultFactory uses blob-hash cache key shared with refresh closure ([#263](https://github.com/zeroroot-ai/gibson/issues/263)) ([7341b6f](https://github.com/zeroroot-ai/gibson/commit/7341b6f9b496354e382c4acccbddf6d5e3c45b53))

## [0.112.0](https://github.com/zeroroot-ai/gibson/compare/v0.111.0...v0.112.0) (2026-05-21)


### ⚠ BREAKING CHANGES

* **sandbox:** relocate spot-eviction handler to node-local sidecar binary ([#247](https://github.com/zeroroot-ai/gibson/issues/247))

### Features

* add signup-smoke CI workflow for daemon PR validation ([#256](https://github.com/zeroroot-ai/gibson/issues/256)) ([64a7e3a](https://github.com/zeroroot-ai/gibson/commit/64a7e3acf47bc19d550b3ce3c00d3216ebb0056e))
* **docker:** bundle sandbox-eviction-handler into the gibson image ([#250](https://github.com/zeroroot-ai/gibson/issues/250)) ([ff6c874](https://github.com/zeroroot-ai/gibson/commit/ff6c874f56e9a3d8a236535839f4936df8d157eb))
* **sandbox:** relocate spot-eviction handler to node-local sidecar binary ([#247](https://github.com/zeroroot-ai/gibson/issues/247)) ([478b377](https://github.com/zeroroot-ai/gibson/commit/478b3774064867c28cadd2ad02ebc4a673b254fd))


### Bug Fixes

* **build:** inject git sha and build time via ldflags ([#253](https://github.com/zeroroot-ai/gibson/issues/253)) ([0b2c636](https://github.com/zeroroot-ai/gibson/commit/0b2c6368b3ddcad8b146e26abeb34003636c4a3b))
* **observability:** strip URL scheme before passing endpoint to pcotel.Init ([#254](https://github.com/zeroroot-ai/gibson/issues/254)) ([f11e59c](https://github.com/zeroroot-ai/gibson/commit/f11e59c4c533f8b1a7621cfab0feae966e5a841c))

## [0.111.0](https://github.com/zeroroot-ai/gibson/compare/v0.110.0...v0.111.0) (2026-05-21)


### Features

* migrate budget service handler to platform-sdk import ([#243](https://github.com/zeroroot-ai/gibson/issues/243)) ([b28fd39](https://github.com/zeroroot-ai/gibson/commit/b28fd39767a3c1a909713e7b9780b82991dac288))

## [0.110.0](https://github.com/zeroroot-ai/gibson/compare/v0.109.0...v0.110.0) (2026-05-21)


### Features

* migrate daemon secrets imports from sdk to platform-clients ([#240](https://github.com/zeroroot-ai/gibson/issues/240)) ([3ca57d4](https://github.com/zeroroot-ai/gibson/commit/3ca57d4f5a25e1f020ba39f3ac35065bdbc1f99b))

## [0.109.0](https://github.com/zeroroot-ai/gibson/compare/v0.108.0...v0.109.0) (2026-05-20)


### Features

* migrate admin imports to platform-sdk; register daemonadminservice ([#235](https://github.com/zeroroot-ai/gibson/issues/235)) ([fa1c311](https://github.com/zeroroot-ai/gibson/commit/fa1c311499a23667bfb39654ac4de4b8c04040dc))

## [0.108.0](https://github.com/zeroroot-ai/gibson/compare/v0.107.0...v0.108.0) (2026-05-20)


### Features

* add idempotency_key dedup store with redis backend and server interceptor ([#231](https://github.com/zeroroot-ai/gibson/issues/231)) ([529677e](https://github.com/zeroroot-ai/gibson/commit/529677ecc48cc70550186758f39fea12a056b383))
* consume platform.v1 and tenant.v1 protos from platform-sdk ([#233](https://github.com/zeroroot-ai/gibson/issues/233)) ([683186b](https://github.com/zeroroot-ai/gibson/commit/683186bda2403903d322521c7929d94705caf167))

## [0.107.0](https://github.com/zeroroot-ai/gibson/compare/v0.106.0...v0.107.0) (2026-05-20)


### ⚠ BREAKING CHANGES

* **crypto:** file-mount KeyProvider; delete K8s key/crypto providers (ADR-0023, gibson#212/S10) ([#224](https://github.com/zeroroot-ai/gibson/issues/224))
* **authz:** FGA config resolver env-only (ADR-0023, gibson#205) ([#222](https://github.com/zeroroot-ai/gibson/issues/222))
* **daemon:** reserved-names provider via file-mount (ADR-0023, gibson#204) ([#221](https://github.com/zeroroot-ai/gibson/issues/221))
* **daemon:** delete network_policy_check; audit moves to tenant-operator (ADR-0023, gibson#209) ([#220](https://github.com/zeroroot-ai/gibson/issues/220))
* **daemon:** relocate internal/tenants → internal/datapool/admin; delete startup_migration_check (ADR-0023, gibson#210 + gibson#208 daemon half) ([#219](https://github.com/zeroroot-ai/gibson/issues/219))
* **datapool:** provisioning checker uses DataPlaneProbe (ADR-0023, gibson#206) ([#216](https://github.com/zeroroot-ai/gibson/issues/216))

### Features

* **authz:** FGA config resolver env-only (ADR-0023, gibson[#205](https://github.com/zeroroot-ai/gibson/issues/205)) ([#222](https://github.com/zeroroot-ai/gibson/issues/222)) ([33f2940](https://github.com/zeroroot-ai/gibson/commit/33f29407c662cb7192eb4df4de1441f065cb8be6))
* **crypto:** file-mount KeyProvider; delete K8s key/crypto providers (ADR-0023, gibson[#212](https://github.com/zeroroot-ai/gibson/issues/212)/S10) ([#224](https://github.com/zeroroot-ai/gibson/issues/224)) ([71c5be3](https://github.com/zeroroot-ai/gibson/commit/71c5be3f87944b70a94407d3866e22c9772e257e))
* **daemon:** delete network_policy_check; audit moves to tenant-operator (ADR-0023, gibson[#209](https://github.com/zeroroot-ai/gibson/issues/209)) ([#220](https://github.com/zeroroot-ai/gibson/issues/220)) ([ee89d9d](https://github.com/zeroroot-ai/gibson/commit/ee89d9d15bafc89d69ff497b66edf32b855845eb))
* **daemon:** relocate internal/tenants → internal/datapool/admin; delete startup_migration_check (ADR-0023, gibson[#210](https://github.com/zeroroot-ai/gibson/issues/210) + gibson[#208](https://github.com/zeroroot-ai/gibson/issues/208) daemon half) ([#219](https://github.com/zeroroot-ai/gibson/issues/219)) ([9e990fd](https://github.com/zeroroot-ai/gibson/commit/9e990fd5d6f9c07e9ede3c22e8f57d67807a3e03))
* **daemon:** reserved-names provider via file-mount (ADR-0023, gibson[#204](https://github.com/zeroroot-ai/gibson/issues/204)) ([#221](https://github.com/zeroroot-ai/gibson/issues/221)) ([273c6d0](https://github.com/zeroroot-ai/gibson/commit/273c6d004489c921291793481a4c0c1d7ec973f2))
* **datapool:** provisioning checker uses DataPlaneProbe (ADR-0023, gibson[#206](https://github.com/zeroroot-ai/gibson/issues/206)) ([#216](https://github.com/zeroroot-ai/gibson/issues/216)) ([b25aee1](https://github.com/zeroroot-ai/gibson/commit/b25aee1914532f4aeee41264db7aa4204e2a339d))
* **gibsoncheck:** nok8sapiindaemon — ban K8s API client construction from daemon source (ADR-0023, gibson[#214](https://github.com/zeroroot-ai/gibson/issues/214)) ([#223](https://github.com/zeroroot-ai/gibson/issues/223)) ([7f3a0f5](https://github.com/zeroroot-ai/gibson/commit/7f3a0f5de22850918a0051cf5838c42c5dbf2795))
* **walker:** authz_annotation_completeness — check registry entries for missing fields (slice 3.7) ([#196](https://github.com/zeroroot-ai/gibson/issues/196)) ([c74a918](https://github.com/zeroroot-ai/gibson/commit/c74a9187476ecaf3029e715c59968dcc7437f3e3))
* **walker:** narrow to receiver-field shape + widen scope to all 49 internal/* (slice 3.2) ([#190](https://github.com/zeroroot-ai/gibson/issues/190)) ([bf5e993](https://github.com/zeroroot-ai/gibson/commit/bf5e9937d33a40efc79977175d0dc13e8ef47be5))
* **walker:** no_context_background + no_time_now walkers on RPC handlers (slice 3.6 partial) ([#193](https://github.com/zeroroot-ai/gibson/issues/193)) ([999dc32](https://github.com/zeroroot-ai/gibson/commit/999dc32a68a1d2e8f41ee18b0a4e18ff0c7be48e))
* **walker:** tenant_id_source + tenant_client_only walkers (slice 3.5) ([#198](https://github.com/zeroroot-ai/gibson/issues/198)) ([e9e5606](https://github.com/zeroroot-ai/gibson/commit/e9e5606c6d97a3789674dc67f01b83ff8e5ce6f9))

## [0.106.0](https://github.com/zeroroot-ai/gibson/compare/v0.105.0...v0.106.0) (2026-05-19)


### Features

* add GetMissionDefinition RPC; return full structured proto (M5, gibson[#134](https://github.com/zeroroot-ai/gibson/issues/134)) ([#138](https://github.com/zeroroot-ai/gibson/issues/138)) ([b489a70](https://github.com/zeroroot-ai/gibson/commit/b489a7063f6f2e7bd2ffd4f61e9042fe58be78fe))
* **secrets:** spire jwt-svid source via workload api ([#169](https://github.com/zeroroot-ai/gibson/issues/169)) ([#185](https://github.com/zeroroot-ai/gibson/issues/185)) ([311de0e](https://github.com/zeroroot-ai/gibson/commit/311de0e47e3ac2b52202bf8cc402d418674a188e))
* **secrets:** spire jwt-svid source via workload api ([#169](https://github.com/zeroroot-ai/gibson/issues/169)) ([#187](https://github.com/zeroroot-ai/gibson/issues/187)) ([f0290cb](https://github.com/zeroroot-ai/gibson/commit/f0290cba5e10ea2d9115c065b67ecfcfcb0764f7))
* **secrets:** vault auth/jwt/login flow with pluggable JWTSource ([#168](https://github.com/zeroroot-ai/gibson/issues/168)) ([#184](https://github.com/zeroroot-ai/gibson/issues/184)) ([2cb4485](https://github.com/zeroroot-ai/gibson/commit/2cb44858bc1022d3d090204296b688d1a24be665))
* wire EffectivePerCallCap into LLM dispatch + document token-budget precedence (M4) ([#148](https://github.com/zeroroot-ai/gibson/issues/148)) ([da83427](https://github.com/zeroroot-ai/gibson/commit/da834275145c9e5bd1ace69e8d030cab9d00df6e)), closes [#133](https://github.com/zeroroot-ai/gibson/issues/133)


### Bug Fixes

* **authz:** FGA smoke — idempotent Write + sha256 store names ([#114](https://github.com/zeroroot-ai/gibson/issues/114)) ([#146](https://github.com/zeroroot-ai/gibson/issues/146)) ([d4a6671](https://github.com/zeroroot-ai/gibson/commit/d4a6671dcf964a6f15f0eb945f04d1b7d2dd498e))
* **checkpoint:** add thread and checkpoint reverse indexes to fix GetThread ([#155](https://github.com/zeroroot-ai/gibson/issues/155)) ([eeab862](https://github.com/zeroroot-ai/gibson/commit/eeab8620ab240f712d449c3cf2f571ea82bfffbb)), closes [#137](https://github.com/zeroroot-ai/gibson/issues/137)
* **daemon:** broker auth cache must not MustNewTenantID(cacheKey) ([#166](https://github.com/zeroroot-ai/gibson/issues/166)) ([0e59e55](https://github.com/zeroroot-ai/gibson/commit/0e59e55598ec2e4a0bad408b24a828fea884c892))
* **daemon:** prefer file-mount over env for impersonation signing keys ([#162](https://github.com/zeroroot-ai/gibson/issues/162)) ([ab23d5a](https://github.com/zeroroot-ai/gibson/commit/ab23d5a21be96d160358c27381bdfbe449c87e4a))
* **datapool:** inject PostgresDSNResolver — drop broker-shaped dependency ([#106](https://github.com/zeroroot-ai/gibson/issues/106)) ([#152](https://github.com/zeroroot-ai/gibson/issues/152)) ([f6f5700](https://github.com/zeroroot-ai/gibson/commit/f6f57004491c4e429b7005be640d4a11f4d67ede))
* **harness:** update stale Traverse test to match implemented behaviour ([#154](https://github.com/zeroroot-ai/gibson/issues/154)) ([a0b1967](https://github.com/zeroroot-ai/gibson/commit/a0b1967601aa64a56ede681987deb2c362499030)), closes [#147](https://github.com/zeroroot-ai/gibson/issues/147)
* **impersonation:** require persistent signing key + add rotation support ([#159](https://github.com/zeroroot-ai/gibson/issues/159)) ([b231ec6](https://github.com/zeroroot-ai/gibson/commit/b231ec642c3ac8b79d9a27b17b0a8fb732d30aac))
* **lint:** repair check-no-gibson-io allowlist and update eviction comment ([#156](https://github.com/zeroroot-ai/gibson/issues/156)) ([c7df684](https://github.com/zeroroot-ai/gibson/commit/c7df6842be87c81e1110feee9ebd74beec73b421)), closes [#142](https://github.com/zeroroot-ai/gibson/issues/142)
* **mission:** probe RedisJSON before running checkpoint store tests ([#157](https://github.com/zeroroot-ai/gibson/issues/157)) ([e1c2a5d](https://github.com/zeroroot-ai/gibson/commit/e1c2a5d1431a0ea086316019afa908f453f52904)), closes [#141](https://github.com/zeroroot-ai/gibson/issues/141)
* **secrets:** rip vault kubernetes-auth case from daemon (ADR-0009) ([#177](https://github.com/zeroroot-ai/gibson/issues/177)) ([50c245b](https://github.com/zeroroot-ai/gibson/commit/50c245b7406d6ba873b62f52aa73da283b07c33e))
* **tenant/names:** Namespace() returns tenant-&lt;slug&gt;, matching cluster reality ([#160](https://github.com/zeroroot-ai/gibson/issues/160)) ([67b5340](https://github.com/zeroroot-ai/gibson/commit/67b53403a7f3b85dcf9998b19f11b3abca8b183e))

## [0.105.0](https://github.com/zeroroot-ai/gibson/compare/v0.104.0...v0.105.0) (2026-05-17)


### ⚠ BREAKING CHANGES

* bump sdk to v0.105.1 + delete daemon-local MissionConstraints (M2-gibson) ([#140](https://github.com/zeroroot-ai/gibson/issues/140))

### Bug Fixes

* **ci:** disable anchore/sbom-action release-asset upload ([#130](https://github.com/zeroroot-ai/gibson/issues/130)) ([e96d128](https://github.com/zeroroot-ai/gibson/commit/e96d128072f4da313a3ef21cdd5472bd4f250f90))
* **llm:** enforce budget check and record usage in StreamLLM ([#136](https://github.com/zeroroot-ai/gibson/issues/136)) ([05536cf](https://github.com/zeroroot-ai/gibson/commit/05536cfd4051d7dac9e927a2e23f84ad23a0adc2)), closes [#135](https://github.com/zeroroot-ai/gibson/issues/135)


### Code Refactoring

* bump sdk to v0.105.1 + delete daemon-local MissionConstraints (M2-gibson) ([#140](https://github.com/zeroroot-ai/gibson/issues/140)) ([e4bbc4d](https://github.com/zeroroot-ai/gibson/commit/e4bbc4ddb1666cd07d15ea6a11c916b650a3211b))

## [0.43.0](https://github.com/zeroroot-ai/gibson/compare/v0.42.0...v0.43.0) (2026-05-17)


### Features

* **one-code-path/195:** FGA must be reachable — delete noopAuthorizer + require_ready=false + every s.authz==nil branch ([#111](https://github.com/zeroroot-ai/gibson/issues/111)) ([28a38d9](https://github.com/zeroroot-ai/gibson/commit/28a38d912dbdb64a5773f5f512fd9049482857a8))
* **one-code-path/205:** delete GIBSON_MODE — one binary every environment ([#112](https://github.com/zeroroot-ai/gibson/issues/112)) ([20b2f31](https://github.com/zeroroot-ai/gibson/commit/20b2f3168dc343b92ce32aca83b358c0ca0c8171))
* **one-code-path/207:** add per-RPC correlation ID interceptor ([#113](https://github.com/zeroroot-ai/gibson/issues/113)) ([7313736](https://github.com/zeroroot-ai/gibson/commit/731373657f04c2fab204b8aebbb9610da458aaad))


### Bug Fixes

* **ci:** chain authz-registry publish off release-please instead of tag trigger ([#97](https://github.com/zeroroot-ai/gibson/issues/97)) ([75dd1e6](https://github.com/zeroroot-ai/gibson/commit/75dd1e676bb167a9fe3730c3dcd396a3fdd3cfb4))
* **daemon:** allow multiple inbound peer SVIDs on gRPC mTLS listener ([#107](https://github.com/zeroroot-ai/gibson/issues/107)) ([77820d0](https://github.com/zeroroot-ai/gibson/commit/77820d02fb026740fecb9409d5e5c356d02feaa2))
* **daemon:** spiffe-bypass at gRPC auth interceptor for platform peers ([#108](https://github.com/zeroroot-ai/gibson/issues/108)) ([b950e28](https://github.com/zeroroot-ai/gibson/commit/b950e2897e8b36d845a49ed079f3caa29e1d9b28))
* remove infinite-recursion postgresProvider fallback in secrets registry ([#105](https://github.com/zeroroot-ai/gibson/issues/105)) ([9c90d7e](https://github.com/zeroroot-ai/gibson/commit/9c90d7eca68c5a088f4487a876c6c69084f6bbce)), closes [#101](https://github.com/zeroroot-ai/gibson/issues/101)
* tenant_id columns must be TEXT, not UUID (configstore + plugin_install) ([#100](https://github.com/zeroroot-ai/gibson/issues/100)) ([bbb6c23](https://github.com/zeroroot-ai/gibson/commit/bbb6c2329aaaa4e090cc7482f23b61cc4ee26c69))

## [0.42.0](https://github.com/zeroroot-ai/gibson/compare/v0.41.0...v0.42.0) (2026-05-13)


### Features

* **daemon:** activate ontology-extension registration in RegisterComponent ([#82](https://github.com/zeroroot-ai/gibson/issues/82)) ([6dd36ae](https://github.com/zeroroot-ai/gibson/commit/6dd36aeffe2420d3686367151ad428b1583d2b5e))

## [0.41.0](https://github.com/zeroroot-ai/gibson/compare/v0.40.0...v0.41.0) (2026-05-13)


### Features

* **daemon:** wire ontology reasoner into daemon + component service ([#79](https://github.com/zeroroot-ai/gibson/issues/79)) ([5eb766a](https://github.com/zeroroot-ai/gibson/commit/5eb766af3281346221edaf6c75cd1cb739ca9180))

## [0.40.0](https://github.com/zeroroot-ai/gibson/compare/v0.39.0...v0.40.0) (2026-05-13)


### Features

* add in-process ontology reasoner and semantic query methods ([#76](https://github.com/zeroroot-ai/gibson/issues/76)) ([f511471](https://github.com/zeroroot-ai/gibson/commit/f5114713a8aeffee418ae7d1d9b510c439a94a6a))
* **bootstrap:** add zitadel-ensure-project subcommand ([#49](https://github.com/zeroroot-ai/gibson/issues/49)) ([36a83c4](https://github.com/zeroroot-ai/gibson/commit/36a83c4988734ed690a397801b1bcae3aa774424))
* **bootstrap:** publish gibson-bootstrap-runner image ([#51](https://github.com/zeroroot-ai/gibson/issues/51)) ([e03a7eb](https://github.com/zeroroot-ai/gibson/commit/e03a7eb5b7e50102d4700e83f79f419d2386a060))
* **daemon:** own postgres migrations on startup ([#54](https://github.com/zeroroot-ai/gibson/issues/54)) ([c32e658](https://github.com/zeroroot-ai/gibson/commit/c32e6580e523ef1fbd6554178b14314f046c548c))


### Bug Fixes

* **agent:** update three stale test fixtures to match current behavior ([#66](https://github.com/zeroroot-ai/gibson/issues/66)) ([5ec29d8](https://github.com/zeroroot-ai/gibson/commit/5ec29d822fe69462ed74fe698a21074271d4ae94))
* **authz:** GetTenantQuotaUsage references nonexistent tenant.viewer relation ([#64](https://github.com/zeroroot-ai/gibson/issues/64)) ([43bf6eb](https://github.com/zeroroot-ai/gibson/commit/43bf6eb745bfa468818ed63d867109edd0b19635))
* **bootstrap:** trim whitespace from ZITADEL_ADMIN_PAT to drop trailing newline ([#52](https://github.com/zeroroot-ai/gibson/issues/52)) ([21426de](https://github.com/zeroroot-ai/gibson/commit/21426dec2445f96d59c1d8ffa75db2185c3a0b18))
* **ci:** replace ripgrep with grep in migration guards so they actually run on CI ([#68](https://github.com/zeroroot-ai/gibson/issues/68)) ([b025813](https://github.com/zeroroot-ai/gibson/commit/b025813139ec705c5a80952c88e0b1c78060a26b))
* **ci:** tag latest on workflow_dispatch from main, not only push ([#53](https://github.com/zeroroot-ai/gibson/issues/53)) ([1167c5b](https://github.com/zeroroot-ai/gibson/commit/1167c5b847dea086945082a0c3efeade94ef9694))
* **daemon/api:** seed mission-level authz tuples missing from two test fixtures ([#69](https://github.com/zeroroot-ai/gibson/issues/69)) ([881f1cf](https://github.com/zeroroot-ai/gibson/commit/881f1cf2ce9348b7fb61cd65fe04e77ca7eda7a6))
* **daemon:** unwedge five red tests in internal/daemon ([#71](https://github.com/zeroroot-ai/gibson/issues/71)) ([978daa8](https://github.com/zeroroot-ai/gibson/commit/978daa8f70f44f7a327eb77eadc9c8f82221daaf))
* **deps:** gate postgres_tls helper behind integration build tag so govulncheck stops flagging docker ([#72](https://github.com/zeroroot-ai/gibson/issues/72)) ([60eb57b](https://github.com/zeroroot-ai/gibson/commit/60eb57b69f562b81be1bcaf509f85cd16cccfe63))
* **gibsoncheck:** allowlist cmd/mission-storage-migrate and internal/secrets in forbidrawstoreimports ([#73](https://github.com/zeroroot-ai/gibson/issues/73)) ([ed60eea](https://github.com/zeroroot-ai/gibson/commit/ed60eeadb9f9fe1671875c48927c9680af0cecea))

## [0.39.0](https://github.com/zeroroot-ai/gibson/compare/v0.38.0...v0.39.0) (2026-05-11)


### Features

* **bootstrap:** zitadel-mint-user-pat subcommand (W4) ([#48](https://github.com/zeroroot-ai/gibson/issues/48)) ([4e3a303](https://github.com/zeroroot-ai/gibson/commit/4e3a30351672afd4fa5233829a2c61249a02bcd8))


### Bug Fixes

* **release:** collapse `-v` double-v in gibson-bootstrap tag + add workflow_dispatch ([#46](https://github.com/zeroroot-ai/gibson/issues/46)) ([465c991](https://github.com/zeroroot-ai/gibson/commit/465c99119e8d0d4eb7e6106b56514ffae42bd4d0))

## [0.38.0](https://github.com/zeroroot-ai/gibson/compare/v0.37.1...v0.38.0) (2026-05-11)


### Features

* **bootstrap:** add gibson-bootstrap binary for chart bootstrap-secrets Job ([#45](https://github.com/zeroroot-ai/gibson/issues/45)) ([4d2c286](https://github.com/zeroroot-ai/gibson/commit/4d2c286a977609bb98e1e09c92d6f0d6e8c408e1))
* **build:** point Dockerfile FROM at ghcr.io mirror ([#44](https://github.com/zeroroot-ai/gibson/issues/44)) ([9f9e8ec](https://github.com/zeroroot-ai/gibson/commit/9f9e8ec4a565869f45f5f891e1d7931cd7c51d82))


### Bug Fixes

* **build:** set GOTOOLCHAIN=auto so Docker builds tolerate base-image lag ([#40](https://github.com/zeroroot-ai/gibson/issues/40)) ([8bac2d9](https://github.com/zeroroot-ai/gibson/commit/8bac2d9e162736d6d9c729ab66d34b1eff7fe7a9))

## [0.37.1](https://github.com/zeroroot-ai/gibson/compare/v0.37.0...v0.37.1) (2026-05-11)


### Bug Fixes

* clear three gibson CI gates (Go 1.25.10, migrations selftest, authz-registry SDK lookup) ([#32](https://github.com/zeroroot-ai/gibson/issues/32)) ([3247868](https://github.com/zeroroot-ai/gibson/commit/324786862e363ec17b4c98811772f0e02eba11b7))

## [0.37.0](https://github.com/zeroroot-ai/gibson/compare/v0.36.0...v0.37.0) (2026-05-10)


### Features

* **mission:** delete mirror struct + ship offline storage migrator ([#35](https://github.com/zeroroot-ai/gibson/issues/35)) ([44d9ea3](https://github.com/zeroroot-ai/gibson/commit/44d9ea344af6e3f016b2d5575b6d05677e02361f))

## [0.36.0](https://github.com/zeroroot-ai/gibson/compare/v0.35.1...v0.36.0) (2026-05-10)


### Features

* **daemon:** collapse TenantQuota to two enforced fields + Postgres reader ([01a90b6](https://github.com/zeroroot-ai/gibson/commit/01a90b64904f0d5c61a2c27f780d24800c89dba2))
* install release-please and pr-title-lint ([#24](https://github.com/zeroroot-ai/gibson/issues/24)) ([54e1375](https://github.com/zeroroot-ai/gibson/commit/54e137584dac076976699d9a9d59e72ad4d95bc1))
* **mission:** add protojson MarshalDefinitionJSON / UnmarshalDefinitionJSON ([#28](https://github.com/zeroroot-ai/gibson/issues/28)) ([8d05586](https://github.com/zeroroot-ai/gibson/commit/8d05586ee7aa6ae1da520af26656e4ecda3c6113))
* **mission:** flip writer to protojson + dual-shape readers ([#30](https://github.com/zeroroot-ai/gibson/issues/30)) ([e91ede9](https://github.com/zeroroot-ai/gibson/commit/e91ede98207f3983927f2084fc193427fa71f9cc))
* **mission:** MissionStore interface speaks proto MissionDefinition ([#33](https://github.com/zeroroot-ai/gibson/issues/33)) ([6a5400c](https://github.com/zeroroot-ai/gibson/commit/6a5400c4fa3c500ff52cb4bbc31446504dbdff8f))
* **mission:** retype daemon helpers to proto MissionDefinition ([#34](https://github.com/zeroroot-ai/gibson/issues/34)) ([a9f136a](https://github.com/zeroroot-ai/gibson/commit/a9f136a720627aedf2d0b3d02d5d3cbfab71e890))
* **mission:** swap orchestrator pkg to proto MissionDefinition ([#31](https://github.com/zeroroot-ai/gibson/issues/31)) ([5e5731c](https://github.com/zeroroot-ai/gibson/commit/5e5731c04369c05c03b3c898fb77835659b2f530))


### Bug Fixes

* **authz:** remove misleading user-typed wildcard tuple comment ([3ddd29b](https://github.com/zeroroot-ai/gibson/commit/3ddd29bde209e7e16f5adadad49ae91c0ff92798))

## v0.32.0 — 2026-05-04 — daemon reads per-tenant credentials from Vault (tenant-provisioning-unification-phase2 Phase 6)

The daemon's per-tenant Postgres + Neo4j credential resolution now
prefers typed Vault payloads over local KEK derivation and Postgres
registry-table lookups. Operator-side counterpart (Phase 3 + Phase
6.3 typed Neo4j writer) writes credentials to Vault during
provisioning so the daemon never needs to hold MasterKEK or
cross-reference a registry for the bolt URI.

Spec: `tenant-provisioning-unification-phase2`.

### Changed

- **`internal/datapool/pgxpool_per_tenant.go`** — new `resolveDSN`
  method routes between Vault-sourced (production) and KEK-derived
  (parent-spec fallback) paths. When `Config.PostgresSecretsReader`
  is wired, the daemon reads `pdataplane.PostgresCredentials` JSON
  from Vault `infra/postgres` via `broker.Resolve(ctx, name)` and
  uses `creds.DSN` unchanged (with `pool_max_conns` appended). When
  the reader is nil, falls back to the legacy KEK-based derivation.

- **`internal/datapool/neo4j_endpoint_resolver_instance.go`** — new
  `tryVaultPayload` helper reads the typed
  `pdataplane.Neo4jCredentials` JSON from a single Vault path
  `infra/neo4j` (BoltURI + Username + Password). Eliminates the
  cross-reference to the `tenant_neo4j_endpoints` Postgres registry
  table for clusters where the operator has shipped Phase 6.3.
  Legacy split-key reader (`infra/neo4j/username` +
  `infra/neo4j/password`) + registry-table fallback retained for
  clusters mid-cutover.

- **`internal/daemon/daemon.go`** — wires `PostgresSecretsReader` via
  `FuncSecretsReader` closure that defers to `d.secretsService`
  resolve at RPC time (same pattern as the Neo4j resolver — captured
  lazily because `secretsService` is initialized after `NewPool`).

### Migration safety

Both refactors preserve the parent-spec code paths as fallbacks. A
cluster running this daemon with an older operator (no Vault writes)
continues to work via the legacy paths. The fallbacks are removable
once the chart's pre-upgrade backfill Job (Phase 8) has populated
Vault for every existing tenant — that is a future release.

---

## v0.31.0 — 2026-05-04 — platform package extensions (tenant-provisioning-unification-phase2 Phase 1)

Adds the platform-package primitives the tenant-operator + daemon need
for the Vault-as-credential-store cutover (Phase 2-8 of
tenant-provisioning-unification-phase2). Non-functional for the daemon
itself; consumed by the operator and daemon refactors in subsequent
releases.

Spec: `tenant-provisioning-unification-phase2`.

### Added

- **`pkg/platform/dataplane/payloads.go`** — typed Vault credential
  payload structs: `PostgresCredentials`, `Neo4jCredentials`,
  `RedisCredentials`, `VectorCredentials`, `LangfuseCredentials`. The
  operator marshals one of these to the canonical per-tenant Vault path
  (`infra/postgres`, `infra/neo4j`, etc.); the daemon unmarshals the
  same struct. Single source of truth for the JSON shape — no drift
  between operator writer and daemon reader.

- **`pkg/platform/saga/adapt.go`** — `FromStepFn` adapter wraps a
  function-form step into the new `Step` interface, with `AdaptOption`
  pattern (`WithRequires`, `WithRequiredClients`, `WithSkipFn`,
  `WithDeprovisionFn`). Eases incremental migration of the operator's
  flow files: a closure can be wrapped today and converted to a struct
  implementation later without changing runner-side construction.

- **`pkg/platform/saga.ValidateAtStartupVerbose`** — returns a one-line
  success summary suitable for the operator's startup log:
  `"saga: validated N step(s), all M capabilit(ies) satisfied
  (production mode | dev mode (capability checks bypassed))"`. Existing
  `ValidateAtStartup` signature unchanged for parent-spec callers;
  verbose form delegates to it.

### Tests

12 new unit tests covering JSON round-trip for every payload struct,
field-name regression guard, FromStepFn defaults + all options
together + nil-fn panic, and ValidateAtStartupVerbose
production/dev/failure paths.

### Module discipline

`go list -deps github.com/zeroroot-ai/gibson/pkg/platform/...` still
resolves only to stdlib + `github.com/zeroroot-ai/sdk/auth` + the
controller-runtime/k8s.io types from the parent spec. No new
transitive deps.

---

## v0.30.0 — 2026-05-04 — platform package foundation (tenant-provisioning-unification Phase 1)

Adds `core/gibson/pkg/platform/` — a leaf package that holds the
canonical naming, KEK derivation, saga step abstraction, and
shared-store constants that both the gibson daemon and the
tenant-operator must agree on byte-for-byte.

This release is non-functional for the daemon itself (no internal/
package consumes the new pkg/platform/ types yet — that wiring lands in
later phases). It exists so the tenant-operator can pin against
`gibson@v0.30.0` and start importing from `gibson/pkg/platform/...`
without us having to maintain duplicate copies of the naming logic in
two repos.

Spec: `tenant-provisioning-unification`.

### Added

- **`pkg/platform/tenant.Names`** value type. Sealed wrapper around
  `auth.TenantID` exposing typed methods for every per-tenant resource
  name: `PostgresDB()`, `PostgresAppRole()`, `Neo4jStatefulSet()`,
  `Neo4jBoltURI(operatorNs)`, `RedisIndexField()`, `QdrantCollection()`,
  `VaultPathPrefix()`, `VaultPolicyName()`, `VaultJWTRoleName()`,
  `FGAObject()`, `ZitadelOrgSlug()`, `LangfuseProject()`, `Namespace()`.
  Replaces the duplicated sanitizer code that lived in both the operator
  and the daemon. The Postgres role suffix is canonical `_app` (the
  legacy `_role` is retired by spec Requirement 1.3).

- **`pkg/platform/tenant.DeriveTenantKEK`** + `PostgresPasswordFromKEK`
  + `Zeroize`. HKDF-SHA256 derivation with KEKInfo
  `gibson/v1/tenant-kek` — byte-for-byte identical to the legacy
  `internal/datapool/kek.go` and `tenant-operator/internal/dataplane/kek.go`
  (verified by KAT vectors in tests). Used in dev mode; production paths
  call Vault transit derive instead.

- **`pkg/platform/saga.Step`** unified interface (`Name`, `Condition`,
  `Requires`, `RequiredClients`, `Provision`, `Deprovision`, `Skip`),
  plus `ConditionedObject` carrier interface. Replaces both the old
  `tenant-operator/internal/saga.Step` struct and the parallel
  `dataplane.Step` struct with a single abstraction.

- **`pkg/platform/saga.ClientCapability`** enum (12 values: postgres-admin,
  vault-admin, vault-transit, kubernetes, zitadel-admin, fga,
  redis-admin, qdrant-admin, stripe, langfuse, daemon-grpc, smtp).
  Each `Step` declares its required capabilities; the runner's
  `ValidateAtStartup` check fails the operator pod startup in
  production mode if any required capability isn't satisfied — killing
  the silent-no-op bug class.

- **`pkg/platform/saga.Runner`** with topological-order execution
  (`TopoSort`), aggregated startup-gate validation, exponential
  retry/backoff capped at MaxBackoff, condition writes via shared
  `SetCondition`/`FindCondition`/`IsConditionTrue` helpers, and
  pluggable `AuditHook` + `MetricsHook` so operator-specific Loki/
  Prometheus integration plugs in cleanly without polluting the
  platform package.

- **`pkg/platform/dataplane`** constants: `RedisIndexHashKey =
  "gibson:tenant:index"` (replacing the historical operator/daemon
  mismatch), `PlatformDB = "gibson_platform"` (renamed from
  `gibson_dashboard`; one-time chart Job handles the rename),
  `LegacyPlatformDB`, `VaultMasterKEKKey`, plus the per-tenant Vault
  path constants `VaultPathInfra{Postgres,Neo4j,Redis,Vector,Langfuse,KEK}`.

### Tests

22 new unit tests across `pkg/platform/{tenant,saga}/`. Including KAT
vectors for KEK derivation, regression guards against the recurring
`_role` vs `_app` and `tenant:index` vs `tenant_db_index` mistakes,
topo-sort cycle/unknown-ref/duplicate-name detection, and
ValidateAtStartup aggregation in both production and dev modes.

### Module discipline

`go list -deps github.com/zeroroot-ai/gibson/pkg/platform/...` resolves
only to stdlib + `github.com/zeroroot-ai/sdk/auth` + the standard
controller-runtime/k8s.io types needed for `metav1.Condition` and
`record.EventRecorder`. No daemon-internal driver pulls — keeping the
operator's go.sum footprint small when it adds the gibson dep in
Phase 2.

---

## v0.29.0 — 2026-05-04 — tenant secrets broker completion

Wires the per-tenant secrets-broker switch end-to-end. The dashboard's
`/settings/secrets-backend` page now actually changes which broker serves a
tenant's secrets — before this change, calls landed as `Unimplemented`
because the SDK admin v1 service was never registered, and even if a
config row had been written, the in-memory broker cache wouldn't have
invalidated until the daemon restarted.

Spec: `tenant-secrets-broker-completion`.

### Added

- **`gibson.admin.v1.TenantAdminService` is now registered in production.**
  `internal/daemon/grpc.go` constructs `internal/admin.NewTenantAdminServer`
  using the broker-stack outputs (`d.configStore`, `d.brokerAuditWriter`,
  `d.brokerFactories`, `d.secretsRegistry`, `d.secretsService`) stored on
  `daemonImpl` by `initBrokerStack`. Coexists alongside the daemon-local
  `gibson.tenant.v1.TenantAdminService` (different proto package). When
  the broker stack failed to initialize (no system KEK or dashboard
  Postgres), the new `internal/admin.NewUnavailableTenantAdminServer()`
  stub is registered instead, returning `codes.Unavailable` on each
  broker-config RPC so dashboards see an actionable error rather than the
  misleading `Unimplemented`.
- **`SetBrokerConfig` now invalidates the per-tenant broker cache.** The
  handler calls `Registry.Reload(ctx, tenant)` immediately after a
  successful persist. Without this, a tenant who switched providers kept
  hitting the previously-cached broker until the next pod restart.
- **`CountSecrets` admin RPC handler.** Delegates to
  `secrets.Service.List(ctx, sdksecrets.Filter{})` and returns
  `int64(len(names))`. No names, values, or per-row metadata leak through
  the response. Dashboard uses this to gate the migration-warning UX
  before a provider switch.
- **`MapProbeFactory`** in `internal/admin/probe_factory.go` adapts
  `map[string]secrets.ProviderFactory` to the `ProviderProbeFactory`
  interface for `TenantAdminConfig`.
- **`TenantAdminConfig.Reloader` and `TenantAdminConfig.SecretsService`**
  narrow interfaces (`Reload(ctx, tenant)` and `List(ctx, Filter)
  ([]string, error)`) — `*secrets.Registry` and `*secrets.Service`
  satisfy them implicitly, tests substitute fakes.

### Changed

- **SDK pin bumped to `v0.99.0`** (adds the `CountSecrets` RPC).
- **Authz registry regenerated** — one new entry in each of
  `registry.go`, `registry.yaml`, `permissions.ts`, `audit.csv` for
  `/gibson.admin.v1.TenantAdminService/CountSecrets` (`relation: "admin"`,
  `allowed_identities: USER`, same envelope as the rest of the
  broker-config trio).

### Tests

- New `internal/admin/tenant_admin_integration_test.go` drives the full
  handler → real `secrets.Registry` round-trip in-memory and asserts that
  post-`Set`, `Registry.For` returns the just-configured provider — the
  central regression-guard for this spec. Verified to fail red if the
  `Reload` call is removed.
- New unit tests cover `Reload`-on-success / no-`Reload`-on-probe-failure
  / no-`Reload`-on-persist-failure, plus `CountSecrets` happy path /
  empty / no-tenant-context / `List`-error-propagates, plus extended
  constructor validation for the two new required deps.

---

## v0.28.0 — 2026-05-02 — drop fga_model.fga coverage stub

Bumps SDK to v0.98.1 (drops the generator's FGA coverage stub) and removes
the now-unused `internal/authz/registry/fga_model.fga`. The OpenFGA model
remains hand-maintained at `internal/authz/model.fga` (the only source the
`gibson-fga-init` Job has ever consumed, via `files/fga-model.json`).

### Changes

- **`internal/authz/registry/fga_model.fga` deleted** — the generator no
  longer emits it; the file existed only as a derived snapshot of the
  proto-annotated relations and was never read at runtime.
- **`internal/authz/model.fga` banner** simplified — the "DO NOT confuse
  with the registry stub" warning is gone with the stub itself.
- **`scripts/check-fga-model-headers.sh`** trimmed to only assert the
  `AUTHORITATIVE-FGA-MODEL` marker on `model.fga`.
- **`.github/workflows/publish-private-authz-registry.yml`** stops pushing
  the `fga_model.fga` layer to `ghcr.io/zeroroot-ai/internal-authz-registry`;
  three layers ship now (`registry.yaml`, `permissions.ts`, `registry.go`).
- **`go.mod`** bumped to `github.com/zeroroot-ai/sdk v0.98.1`.

Spec: ad-hoc cleanup informed by the cross-repo-cohesion-fixes audit.

---

## v0.27.0 — 2026-05-02 — tenant-role-taxonomy

Introduces the three-tier tenant role hierarchy (`owner > admin > member`)
at the FGA level and surfaces the highest role through the daemon's
`ListMyMemberships` RPC. Adds a one-shot backfill binary to seed owner
tuples for existing tenants.

Spec: `tenant-role-taxonomy`.

### Changes

- **FGA model:** `internal/authz/model.fga` — `type tenant` gains
  `define owner: [user]` as the first relation. `define admin: [user]`
  is rewritten to `define admin: [user] or owner` (computed union). The
  existing `define member: [user] or admin` is unchanged. This means:
  - Check(`owner`, `admin`) → true (downward propagation)
  - Check(`owner`, `member`) → true (downward propagation)
  - Check(`admin`, `owner`) → false (no upward propagation)
  - Header documentation and `RELATION SEMANTICS` block updated with
    worked tuple examples for each role.

- **Daemon `ListMyMemberships`** — builds a `2*N`-item `BatchCheck`
  (one owner check + one admin check per tenant) in a single FGA call.
  New private helper `pickHighestRole(isOwner, isAdmin bool) string`
  returns the highest role. Per-tenant audit log line names the resolved
  role. Fail-closed-to-member degrade path on BatchCheck error preserved.

- **`cmd/tenant-owner-backfill`** — new binary that:
  - Lists all `Tenant` CRs (cluster-scoped).
  - For each tenant: finds the founding `TenantMember` (earliest
    `creationTimestamp` with non-empty `status.userId`).
  - Calls FGA Check for the `owner` relation; writes the tuple if missing.
  - Logs structured per-tenant outcome:
    `outcome=backfilled|already_owner|no_founder_found`.
  - Exits zero unconditionally (per-tenant skips do not fail the Job).
  - Built into the gibson container image at
    `/usr/local/bin/tenant-owner-backfill`.

- **`fga-smoke-test` CI workflow** — new
  `.github/workflows/fga-smoke-test.yml` runs `TestModel_TenantRoleHierarchy`
  (three hierarchy assertions against an ephemeral OpenFGA container via
  testcontainers) on every PR touching `internal/authz/model.fga`.

### No OCI registry / proto changes

The authz registry artifacts (`internal/authz/registry/`) are unchanged —
no proto annotations were modified. The OCI artifact at
`ghcr.io/zeroroot-ai/internal-authz-registry:v0.27.0` is published by CI
on tag push but its content is identical to v0.26.0.

### Validation

- `go build ./...` and `go test ./internal/authz/... ./internal/daemon/api/...` clean.
- `TestPickHighestRole` table test: 4 input combinations, all pass.
- `TestListMyMemberships_RoleDerivation_*`: 4 new cases, all pass.
- `go build ./cmd/tenant-owner-backfill/...` succeeds.

---

## v0.26.0 — 2026-05-01 — discovery-bitfield-coherence

Corrects the `allowed_identities` bitmask on the eleven
`DiscoveryService` RPCs from `8` (PLATFORM_OPERATOR-only) to `7`
(USER | SERVICE | COMPONENT). These RPCs carry `relation: "member"` —
any tenant member should be able to call them — but the incoherent
bitfield was silently blocking every USER caller after
`zero-trust-hardening` Req 2 enabled per-RPC identity-class
enforcement at ext-authz.

Spec: `discovery-bitfield-coherence`.

### Changes

- **SDK bump:** `github.com/zeroroot-ai/sdk` v0.95.0 → v0.96.0.
- **Registry regen:** all five registry artifacts regenerated via
  `make authz-registry`. The eleven affected RPCs (`WhoAmI`,
  `ListPlugins`, `DescribePlugin`, `ListTools`, `DescribeTool`,
  `ListAgents`, `DescribeAgent`, `ListLLMSlots`, `ListReportSurfaces`,
  `ValidateComponent`, `SuggestMissingCapability`) now show
  `allowed_identities: [USER, SERVICE, COMPONENT]` in `registry.yaml`
  and `USER|SERVICE|COMPONENT` in `audit.csv`. The `fga_model.fga` is
  unchanged — the FGA relations and object types are unaffected.
- **OCI artifact:** `ghcr.io/zeroroot-ai/internal-authz-registry:v0.26.0`
  published by the `publish-private-authz-registry` CI workflow on tag
  push.

### No handler changes

The daemon's `listCatalog` already unions the caller's tenant catalogue
with the `_system` shared catalogue; no code change was required.
Tenant-scoping is preserved at the FGA layer via
`object_deriver: "tenant_from_identity"` — a USER cannot probe another
tenant's catalogue.

### Validation

- `go build ./...` and `go test ./internal/authz/registry/...` clean.
- Registry drift gate: `make authz-registry && git diff --exit-code
  internal/authz/registry/` exits 0.

---

## v0.25.1 — 2026-05-01 — daemon loose-mode bypass for self-mode RPCs

Bugfix on top of v0.25.0. The daemon's `registryAwareUnary` /
`registryAwareStream` interceptors only bypassed strict tenant
validation for `entry.Unauthenticated` (Connect, Ping). Self-mode RPCs
(`ListMyMemberships`, `GetMyPermissions`) by design have no tenant
context — sign-in calls them BEFORE the active-tenant cookie is set —
but they fell through to the SDK's strict 5-header interceptor and
denied with `auth: identity headers absent: missing
[x-gibson-identity-tenant]`.

### Fix

Extended the bypass condition to `entry.Unauthenticated || entry.Self`.
The handler still receives a `caller.Subject` extracted from
ext-authz's verified identity header; tenant is left zero (handler
self-scopes). The four-layer defense from zero-trust-hardening is
unchanged: Envoy `jwt_authn` + ext-authz subject minting + daemon
SPIFFE-mTLS-pinned listener + ext-authz `AllowedIdentities` bitfield.

### Validation

- `go build ./...` and `go vet ./...` clean.
- Live verification on kind-gibson: sign-in flow's
  `ListMyMemberships` now returns 200 OK; ext-authz logs show
  `entry_mode=self result=allow`; daemon logs show no further
  `identity-check denied` warnings on these RPCs.

Closes self-mode-authz Req 4.6.

---

## v0.25.0 — 2026-05-01

### Security — self-mode-authz spec

- **SDK bump to v0.95.0; authz registry regenerated.**
  `GetMyPermissions` and `ListMyMemberships` now carry `self: true +
  allowed_identities: [USER]` in the generated registry, replacing the
  hotfix `unauthenticated: true` annotations. The `self` mode preserves
  JWT authentication via Envoy `jwt_authn` and applies the identity-class
  bitfield check (USER only) at ext-authz, while skipping the FGA tuple
  lookup that was impossible for pre-tenant-context self-bootstrap calls.
  Layer 4 of defense-in-depth (per-RPC identity-class enforcement) is
  restored on these two RPCs. Spec: self-mode-authz Req 4.1–4.3.

- **OCI registry artifact `ghcr.io/zeroroot-ai/internal-authz-registry:v0.25.0`
  is the first artifact containing `self: true` entries.**
  Requires ext-authz v0.2.0+ to parse; see Req 6.1 for release order
  requirements.

### Audit trail

- **`audit.csv` gains a `mode` column at the END of each row** (positional
  compatibility per design.md decision). Values: `rule | self |
  unauthenticated`. Self-mode rows populate `identities` while
  `relation`/`object_type`/`deriver` remain empty strings. Spec:
  self-mode-authz Req 5.1, 5.2, 5.3.

### Tests

- `TestGetMyPermissionsAndListMyMembershipsAreAuthenticated` — reworked to
  assert the new self-mode shape: `Self==true`, `AllowedIdentities.Has(USER)`,
  `Unauthenticated==false`, `Relation==""`. Failure message references spec
  `self-mode-authz`.
- `TestSelfModeEntriesAreUserOnly` — new test walking `registry.Registry`;
  asserts every `Self==true` entry has the USER bit in `AllowedIdentities`.
- `TestOnlyConnectAndPingAreUnauthenticated` — unchanged; the
  `unauthenticated: true` set does not grow (Req 4.5).

---

## v0.24.0 — 2026-05-01

### Fix — zero-trust-hardening follow-up

- **Authz registry: revert `tenant_admin`/`tenant_member` relations back to
  `admin`/`member`** on all `TenantAdminService` and `AdminService` RPCs.
  The v0.23.0 registry regen introduced the wrong relation names from a
  stale SDK proto snapshot; this fixes the drift.

---

## v0.23.0 — 2026-05-01

### Security — zero-trust-hardening spec

- **SDK bump to v0.92.0; authz registry regenerated.**
  `GetMyPermissions` and `ListMyMemberships` no longer carry `unauthenticated: true` in the
  generated registry — they now require an authenticated USER token through Envoy.
  Only `Connect` and `Ping` remain unauthenticated (pre-auth liveness checks).
  Closes the confused-deputy permission-enumeration oracle (Req 5.1, 5.2).

- **SPIFFE init is now fail-closed (Req 1.1).**
  Previously, if `workloadapi.NewX509Source` failed the daemon logged a warning
  and fell back to a plaintext gRPC listener, exposing the identity-header trust path
  to any in-cluster attacker that could reach the pod IP during a SPIRE outage.
  The daemon now returns a fatal error and refuses to start.

- **Non-loopback bind rejected without SPIFFE (Req 1.2).**
  Added `rejectNonLoopbackWithoutSPIFFE()` validator called at `buildGRPCServer` startup.
  Addresses `0.0.0.0`, `[::]`, `:port`, routable IPs, and non-loopback hostnames.
  Loopback-only builds (`127.0.0.1`, `localhost`, `[::1]`) continue to work with a
  startup warning.

- **Dead HMAC code removed (Req 8.1).**
  `loadHMACSecret()` in `internal/daemon/grpc.go` was a vestige of a removed identity-header
  HMAC verification layer. The function and its associated env var
  (`GIBSON_IDENTITY_HMAC_SECRET_PATH`) are deleted. The trust model is
  SPIFFE X.509 mTLS between Envoy and the daemon; no shared secret is involved.
  Stale `HMAC-verified` doc comments updated in `authconfig.go` and test files (Req 8.3).

### Tests

- `TestRejectNonLoopbackWithoutSPIFFE` — table-driven, 9 address cases (loopback/non-loopback).
- `TestSPIFFEInitFailClosed` — source-text value-lock asserting the old warn-and-fallback
  pattern is gone.
- `TestBuildGRPCServer_NonLoopbackWithoutSPIFFE` / `TestBuildGRPCServer_LoopbackWithoutSPIFFE`.
- `TestIdentityResolverHasNoAuthCallers` — AST walk via `golang.org/x/tools/go/packages`
  asserting zero non-test imports of `identityresolver` outside the package (Req 3.4).
- `TestOnlyConnectAndPingAreUnauthenticated` — registry regression guard (Req 5.3).
- `TestGetMyPermissionsAndListMyMembershipsAreAuthenticated` — explicit assertion on the
  two previously-misconfigured RPCs.

---
