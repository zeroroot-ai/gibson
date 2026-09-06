-- Revert gibson#997: drop the content_trust column.
ALTER TABLE component_install DROP COLUMN IF EXISTS content_trust;
