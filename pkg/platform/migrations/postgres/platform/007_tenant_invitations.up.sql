-- 007_tenant_invitations.up.sql
--
-- gibson#626 / gibson#631: the daemon owns the member-invitation lifecycle.
-- A pending invitation is a row here; MembershipService.InviteMember writes it,
-- ListMembers surfaces it as a "invited" member, AcceptInvitation redeems it,
-- and Resend/Cancel/expiry mutate its status. The raw token is NEVER stored —
-- only its sha256 hash (the raw token rides the emailed accept link).
--
-- tenant_id is TEXT (slug), consistent with tenant_quotas (003) /
-- tenant_zitadel_orgs (006) and the TEXT-not-UUID precedent (004).

CREATE TABLE IF NOT EXISTS tenant_invitations (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    email         TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'member',
    token_hash    TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',  -- pending | accepted | cancelled | expired
    invited_by    TEXT NOT NULL DEFAULT '',
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One live invitation per (tenant, email): re-inviting refreshes the same row.
CREATE UNIQUE INDEX IF NOT EXISTS tenant_invitations_tenant_email_idx
    ON tenant_invitations (tenant_id, email);

-- AcceptInvitation looks up by token hash.
CREATE INDEX IF NOT EXISTS tenant_invitations_token_hash_idx
    ON tenant_invitations (token_hash);
