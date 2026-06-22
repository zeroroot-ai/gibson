package mission

// getMissionOrchestratorSchema returns the schema for mission orchestrator enhancements
// This extends the existing missions table from migration 4 with additional fields
func getMissionOrchestratorSchema() string {
	return `
-- Migration 6: Mission Orchestrator Schema Enhancements
-- Extends the existing missions table with orchestration-specific fields

-- Add new columns to existing missions table for mission orchestration
ALTER TABLE missions ADD COLUMN target_id TEXT;
ALTER TABLE missions ADD COLUMN constraints TEXT;
ALTER TABLE missions ADD COLUMN metrics TEXT;
ALTER TABLE missions ADD COLUMN checkpoint TEXT;
ALTER TABLE missions ADD COLUMN error TEXT;

-- Create index for target_id lookups
CREATE INDEX IF NOT EXISTS idx_missions_target_id ON missions(target_id);

-- Create FTS5 virtual table for full-text search on missions
CREATE VIRTUAL TABLE IF NOT EXISTS missions_fts USING fts5(
    name,
    description,
    content=missions,
    content_rowid=rowid
);

-- Trigger to sync FTS on INSERT
CREATE TRIGGER IF NOT EXISTS missions_ai AFTER INSERT ON missions BEGIN
    INSERT INTO missions_fts(rowid, name, description)
    VALUES (new.rowid, new.name, new.description);
END;

-- Trigger to sync FTS on DELETE
CREATE TRIGGER IF NOT EXISTS missions_ad AFTER DELETE ON missions BEGIN
    INSERT INTO missions_fts(missions_fts, rowid, name, description)
    VALUES('delete', old.rowid, old.name, old.description);
END;

-- Trigger to sync FTS on UPDATE
CREATE TRIGGER IF NOT EXISTS missions_au AFTER UPDATE ON missions BEGIN
    INSERT INTO missions_fts(missions_fts, rowid, name, description)
    VALUES('delete', old.rowid, old.name, old.description);
    INSERT INTO missions_fts(rowid, name, description)
    VALUES (new.rowid, new.name, new.description);
END;
`
}
