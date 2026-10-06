-- Restores the three columns of migration 002 (sdk#129).
ALTER TABLE component_install
    ADD COLUMN IF NOT EXISTS manifest_hash  TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS runtime_mode   TEXT    NOT NULL DEFAULT 'process',
    ADD COLUMN IF NOT EXISTS setec_required BOOLEAN NOT NULL DEFAULT FALSE;
