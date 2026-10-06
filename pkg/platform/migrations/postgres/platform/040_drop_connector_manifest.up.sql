-- gibson#663: the connector_manifest table has no reader. The catalog that
-- the daemon embeds is the one source of each connector manifest (ADR-0136),
-- and the connector operator writes the credential Secret. Nothing launches a
-- connector from a stored manifest.
DROP TABLE IF EXISTS connector_manifest;
