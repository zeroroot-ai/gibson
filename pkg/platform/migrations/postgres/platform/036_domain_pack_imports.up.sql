-- domain_pack_imports: the Domain Packs that the platform owner imported
-- into this install (ADR-0133, gibson#712). A pack is data only. The daemon
-- adds each row to its catalog at start, next to the embedded pack files.
-- One row for each pack name. A higher version replaces the stored one.

CREATE TABLE IF NOT EXISTS domain_pack_imports (
    name        TEXT        PRIMARY KEY,
    version     INTEGER     NOT NULL CHECK (version >= 1),
    pack_json   BYTEA       NOT NULL,
    imported_by TEXT        NOT NULL,
    imported_at TIMESTAMPTZ NOT NULL
);
