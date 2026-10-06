-- sdk#129: the plugin manifest is gone (ADR-0097). A plugin reports no
-- manifest hash, runtime mode or setec flag at check-in, so these three
-- columns have no producer and no reader.
ALTER TABLE component_install
    DROP COLUMN IF EXISTS manifest_hash,
    DROP COLUMN IF EXISTS runtime_mode,
    DROP COLUMN IF EXISTS setec_required;
