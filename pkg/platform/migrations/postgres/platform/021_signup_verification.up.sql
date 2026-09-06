-- 021_signup_verification.up.sql
--
-- signup_verification holds proof-of-mailbox-control for a self-serve signup
-- attempt. It is the only artefact a signup may create BEFORE the person has
-- demonstrated they control the address they typed.
--
-- Ordering rule this table exists to enforce: nothing persistent, billable or
-- tenant-visible is created until the emailed token is redeemed. The Zitadel
-- human user, the pending_tenant_provisioning row (migration 016), the Tenant
-- CR and everything downstream of it now happen strictly after redemption. A
-- request for an address the requester does not control therefore leaves
-- behind exactly one self-expiring row and one email — no identity, no tenant,
-- no billing object.
--
-- Like pending_tenant_provisioning, this lives in the PLATFORM (control-plane)
-- Postgres rather than a per-tenant database: at request time the tenant does
-- not exist, so there is no per-tenant database to write to.
--
-- The raw token is never stored. Only its sha256 hash is (internal/platform/token),
-- so a read of this table cannot be replayed into an account. Same for the
-- post-redemption session token.
CREATE TABLE IF NOT EXISTS signup_verification (
    -- id is the row identity. Opaque; never exposed to the browser.
    id                          UUID PRIMARY KEY,

    -- attempt_id correlates the row with the dashboard's signup-progress
    -- stream (UserService.SetSignupProgress). Not a capability on its own.
    attempt_id                  UUID NOT NULL,

    -- email is the normalized (lowercased, trimmed) address the verification
    -- link was sent to. It is the ONLY source of the owner email at completion
    -- time — the completion RPC does not accept an email from the client, so a
    -- redeemed session cannot be redirected at a different address.
    email                       TEXT NOT NULL,

    -- workspace_name / tier / owner names are the non-secret form fields,
    -- parked here across the verification round-trip so completion does not
    -- have to trust the browser for them either.
    workspace_name              TEXT NOT NULL,
    tier                        TEXT NOT NULL,
    owner_first_name            TEXT NOT NULL DEFAULT '',
    owner_last_name             TEXT NOT NULL DEFAULT '',

    -- token_hash is sha256(raw emailed token). UNIQUE so redemption is an
    -- indexed single-row compare-and-set. The raw token exists only in the
    -- recipient's mailbox.
    token_hash                  TEXT NOT NULL UNIQUE,

    -- status is the lifecycle:
    --   pending      — link sent, not yet clicked
    --   verified     — link redeemed, a completion session is live
    --   consumed     — the session was spent (tenant provisioned), or the row
    --                  was retired without ever being usable (the
    --                  account-exists notice path, which sends no token)
    --   expired      — the janitor aged out an unredeemed row
    --   send_failed  — the transport refused; the caller was told so
    status                      TEXT NOT NULL DEFAULT 'pending'
        CONSTRAINT signup_verification_status_check
        CHECK (status IN ('pending', 'verified', 'consumed', 'expired', 'send_failed')),

    -- expires_at bounds the emailed link (24h).
    expires_at                  TIMESTAMPTZ NOT NULL,

    -- verified_session_hash is sha256(session token) minted at redemption and
    -- handed to the browser as an httpOnly cookie. UNIQUE. NULL until redeemed.
    -- This is what authorizes completion; it is short-lived by design.
    verified_session_hash       TEXT UNIQUE,
    verified_session_expires_at TIMESTAMPTZ,

    -- stripe_customer_id is attached AFTER verification, when the card step
    -- runs. It is empty for the whole pre-verification window, which is the
    -- point: no billing object exists for an unproven address.
    stripe_customer_id          TEXT NOT NULL DEFAULT '',

    -- completion_attempts caps how many times one verified session may be
    -- spent trying to provision, so a failing completion cannot be looped.
    completion_attempts         INT NOT NULL DEFAULT 0,

    -- send_count / last_sent_at drive the resend cooldown.
    send_count                  INT NOT NULL DEFAULT 0,
    last_sent_at                TIMESTAMPTZ,

    -- client_ip_hash is sha256 of the requesting IP, for abuse forensics only.
    -- Hashed rather than stored raw: this row is created before any consent
    -- exists and may belong to someone who never asked for it.
    client_ip_hash              TEXT NOT NULL DEFAULT '',

    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at                 TIMESTAMPTZ
);

-- Resend cooldown lookup: the newest SENT row for an address, whatever its
-- status is now.
--
-- It must not be restricted to status='pending'. A collision row is retired the
-- moment the account-exists notice goes out, and a consumed row still counts
-- against the cooldown — otherwise redeeming a link would reset the sender's
-- own throttle. The sort key is last_sent_at for the same reason: created_at is
-- when the row appeared, not when a message left.
--
-- The predicate matters for cost, not just correctness. Anonymous callers grow
-- this table, so the cooldown lookup on the hot path must not degrade into a
-- scan of rows an attacker created.
CREATE INDEX IF NOT EXISTS signup_verification_last_sent_email_idx
    ON signup_verification (email, last_sent_at DESC)
    WHERE last_sent_at IS NOT NULL;

-- Janitor sweep: only rows that can still age out.
CREATE INDEX IF NOT EXISTS signup_verification_expiry_idx
    ON signup_verification (expires_at)
    WHERE status IN ('pending', 'verified');

-- Retention sweep: terminal rows are deleted after a week.
CREATE INDEX IF NOT EXISTS signup_verification_retention_idx
    ON signup_verification (updated_at)
    WHERE status IN ('consumed', 'expired', 'send_failed');
