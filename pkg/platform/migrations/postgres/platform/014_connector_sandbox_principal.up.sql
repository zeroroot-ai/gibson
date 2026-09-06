-- gibson#723 (PRD gibson#721): record the (tenant, connector) capability-grant
-- principal alongside the sandbox so on-disable teardown can revoke it (a
-- torn-down connector must not be able to re-enroll). Existing rows predate
-- principal tracking and get '' — they cannot be revoked, only terminated;
-- new launches always carry it.
ALTER TABLE connector_sandbox ADD COLUMN principal_id TEXT NOT NULL DEFAULT '';
COMMENT ON COLUMN connector_sandbox.principal_id IS
    'Zitadel principal id minted for this launch; revoked on teardown (gibson#723).';
