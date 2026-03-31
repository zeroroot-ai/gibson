# Requirements: LLM Dashboard Integration (Remove Duplicative BYOK)

## Overview

This spec removes the duplicative BYOK (Bring Your Own Key) LLM provider configuration system in `internal/config/llm_*.go` and `internal/daemon/api/llm_provider*.go`, and instead wires the existing Gibson infrastructure to the dashboard.

**Problem**: The BYOK implementation duplicates functionality that already exists in Gibson:
- `internal/database/credential_dao_redis.go` - Encrypted credential storage with Redis/RediSearch
- `internal/llm/config.go` - LLM provider configuration (`ProviderConfig`, `LLMConfig`)
- `internal/llm/providers/factory.go` - Provider factory pattern
- `internal/crypto/keyprovider.go` - Master key provider interface
- `internal/daemon/credential_store.go` - Credential store with AES-256-GCM encryption

**Solution**: Remove the duplicate code and create dashboard API routes that leverage the existing infrastructure.

## User Stories

### US-1: Remove Duplicative BYOK Code
**As a** developer maintaining Gibson
**I want** the duplicative BYOK code removed
**So that** there is a single source of truth for LLM provider and credential management

**Acceptance Criteria:**
- [ ] `internal/config/llm_encryption.go` is deleted
- [ ] `internal/config/llm_encryption_test.go` is deleted
- [ ] `internal/config/llm_manager.go` is deleted
- [ ] `internal/config/llm_manager_test.go` is deleted
- [ ] `internal/config/llm_health_monitor.go` is deleted
- [ ] `internal/config/llm_reload.go` is deleted
- [ ] `internal/daemon/api/llm_provider.go` is deleted
- [ ] `internal/daemon/api/llm_provider_test.go` is deleted
- [ ] Any references to these files in other code are removed/updated

### US-2: Dashboard API for LLM Credentials
**As a** dashboard user
**I want** to manage LLM provider API keys through the dashboard
**So that** I can configure my LLM providers without editing config files

**Acceptance Criteria:**
- [ ] POST `/api/credentials` - Create an LLM credential (API key) with encrypted storage
- [ ] GET `/api/credentials` - List credentials (metadata only, no decrypted values)
- [ ] GET `/api/credentials/:id` - Get a single credential's metadata
- [ ] PUT `/api/credentials/:id` - Update a credential
- [ ] DELETE `/api/credentials/:id` - Delete a credential
- [ ] All credentials are stored using existing `RedisCredentialDAO`
- [ ] All encryption uses existing `crypto.AESGCMEncryptor` and `KeyProvider`
- [ ] Credentials have type `CredentialTypeLLMAPIKey` with provider field set

### US-3: Dashboard API for LLM Provider Configuration
**As a** dashboard user
**I want** to configure LLM providers and their models through the dashboard
**So that** I can manage which providers and models are available to agents

**Acceptance Criteria:**
- [ ] GET `/api/llm/providers` - List configured LLM providers
- [ ] GET `/api/llm/providers/:name` - Get a single provider's configuration
- [ ] PUT `/api/llm/providers/:name` - Update provider configuration
- [ ] POST `/api/llm/providers/:name/test` - Test connection to a provider
- [ ] Provider configs use existing `llm.ProviderConfig` struct
- [ ] Provider configs are stored in Redis (reuse pattern from existing config)
- [ ] API keys reference credentials by name (not stored inline)

### US-4: Health Monitoring
**As a** system administrator
**I want** health status for LLM providers visible in the dashboard
**So that** I can monitor provider availability

**Acceptance Criteria:**
- [ ] GET `/api/llm/providers/:name/health` - Get provider health status
- [ ] Health check uses existing `types.HealthStatus` structure
- [ ] Health is determined by attempting a lightweight API call to the provider
- [ ] Response includes last check time, status, and any error messages

### US-5: Credential Rotation Support
**As a** security-conscious administrator
**I want** to be notified when credentials need rotation
**So that** I can maintain good security hygiene

**Acceptance Criteria:**
- [ ] API returns `needs_rotation` flag based on credential age (90 days)
- [ ] Uses existing `types.CredentialRotation` structure
- [ ] Dashboard can trigger key rotation via PUT endpoint

## Non-Functional Requirements

### NFR-1: No Breaking Changes to Core LLM Subsystem
- The core `internal/llm/` package remains unchanged
- Existing agent harness LLM access continues to work
- Only dashboard API layer is added

### NFR-2: Backward Compatibility with Config Files
- Existing `gibson.yaml` LLM configuration continues to work
- Dashboard-configured providers are additive or can override file-based config
- Clear precedence: Dashboard configs > File configs > Environment variables

### NFR-3: Security
- API keys are never returned in API responses (only masked versions)
- All encryption uses existing 256-bit AES-GCM with scrypt key derivation
- Master key retrieval uses existing `crypto.KeyProvider` interface

### NFR-4: Testing
- Unit tests for all new API handlers
- Integration tests using existing testcontainers patterns
- 90% code coverage requirement

## Files to Delete (Duplicative Code)

| File | Reason |
|------|--------|
| `internal/config/llm_encryption.go` | Duplicates `internal/crypto/` |
| `internal/config/llm_encryption_test.go` | Tests for duplicate code |
| `internal/config/llm_manager.go` | Duplicates `internal/database/credential_dao_redis.go` + `internal/llm/config.go` |
| `internal/config/llm_manager_test.go` | Tests for duplicate code |
| `internal/config/llm_health_monitor.go` | Can use existing health infrastructure |
| `internal/config/llm_reload.go` | Hot reload can be implemented differently |
| `internal/daemon/api/llm_provider.go` | API handlers using duplicate code |
| `internal/daemon/api/llm_provider_test.go` | Tests for duplicate API handlers |

## Existing Infrastructure to Leverage

| Component | Location | Purpose |
|-----------|----------|---------|
| `RedisCredentialDAO` | `internal/database/credential_dao_redis.go` | Encrypted credential CRUD with RediSearch |
| `CredentialDAO` interface | `internal/database/credential_dao.go` | Abstraction for credential storage |
| `types.Credential` | `internal/types/credential.go` | Credential entity with encryption fields |
| `ProviderConfig` | `internal/llm/config.go` | LLM provider configuration structure |
| `LLMConfig` | `internal/llm/config.go` | Root LLM configuration with provider map |
| `providers.NewProvider` | `internal/llm/providers/factory.go` | Factory to create LLM providers |
| `crypto.KeyProvider` | `internal/crypto/keyprovider.go` | Master encryption key retrieval |
| `crypto.AESGCMEncryptor` | `internal/crypto/aes_gcm.go` | AES-256-GCM encryption/decryption |
| `DaemonCredentialStore` | `internal/daemon/credential_store.go` | Daemon's credential store implementation |

## Out of Scope

- Changes to the core LLM subsystem (`internal/llm/`)
- Changes to agent harness LLM access
- UI/frontend dashboard components (backend API only)
- Migration tooling for existing BYOK configs (none exist in production)
