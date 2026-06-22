-- Gibson Framework Database Schema
-- SQLite3 database with encryption support for credentials

-- Credentials table with encrypted storage
-- Stores API keys, tokens, and secrets with AES-256-GCM encryption
CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL,                    -- 'api_key', 'bearer_token', 'oauth', etc.
    provider TEXT,                         -- 'openai', 'anthropic', 'azure', etc.
    status TEXT DEFAULT 'active',          -- 'active', 'inactive', 'expired', 'revoked'
    description TEXT,

    -- Encryption fields (AES-256-GCM)
    encrypted_value BLOB NOT NULL,         -- Encrypted credential value
    encryption_iv BLOB NOT NULL,           -- Initialization vector (12 bytes for GCM)
    key_derivation_salt BLOB NOT NULL,     -- Salt for PBKDF2 key derivation

    -- Metadata (stored as JSON)
    tags TEXT,                             -- JSON array: ["production", "dev"]
    rotation_info TEXT,                    -- JSON: rotation policy and history
    usage TEXT,                            -- JSON: usage statistics and limits

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP
);

-- Indexes for credentials
CREATE INDEX IF NOT EXISTS idx_credentials_provider ON credentials(provider);
CREATE INDEX IF NOT EXISTS idx_credentials_status ON credentials(status);
CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(type);

-- Targets table
-- Represents LLM endpoints to test
CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL,                    -- 'llm', 'chat', 'completion', 'embedding'
    provider TEXT,                         -- 'openai', 'anthropic', 'local', etc.
    url TEXT NOT NULL,                     -- API endpoint URL
    model TEXT,                            -- Model identifier (e.g., 'gpt-4', 'claude-3')

    -- Configuration (stored as JSON)
    headers TEXT,                          -- JSON: custom HTTP headers
    config TEXT,                           -- JSON: provider-specific config
    capabilities TEXT,                     -- JSON: supported features

    -- Authentication
    auth_type TEXT,                        -- 'bearer', 'api_key', 'oauth', 'none'
    credential_id TEXT REFERENCES credentials(id) ON DELETE SET NULL,

    -- Metadata
    status TEXT DEFAULT 'active',          -- 'active', 'inactive', 'unreachable'
    description TEXT,
    tags TEXT,                             -- JSON array
    timeout INTEGER DEFAULT 30,            -- Request timeout in seconds

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for targets
CREATE INDEX IF NOT EXISTS idx_targets_provider ON targets(provider);
CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status);
CREATE INDEX IF NOT EXISTS idx_targets_type ON targets(type);
CREATE INDEX IF NOT EXISTS idx_targets_credential ON targets(credential_id);

-- Findings table
-- Stores security findings from red-team tests
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    remediation TEXT,
    severity TEXT,                         -- 'critical', 'high', 'medium', 'low', 'info'
    status TEXT DEFAULT 'open',            -- 'open', 'confirmed', 'false_positive', 'resolved'

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for findings
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

-- Trigger to update updated_at timestamp on credentials
CREATE TRIGGER IF NOT EXISTS update_credentials_timestamp
    AFTER UPDATE ON credentials
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE credentials SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Trigger to update updated_at timestamp on targets
CREATE TRIGGER IF NOT EXISTS update_targets_timestamp
    AFTER UPDATE ON targets
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE targets SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Trigger to update updated_at timestamp on findings
CREATE TRIGGER IF NOT EXISTS update_findings_timestamp
    AFTER UPDATE ON findings
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE findings SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
