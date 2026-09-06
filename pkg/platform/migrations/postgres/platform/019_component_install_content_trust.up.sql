-- gibson#997 / ADR-0010: record a component's content-trust classification on
-- its install so the daemon's dispatch policy can gate untrusted plugin
-- invocation (setec-or-deny under the hosted setec-only shape). Stored as the
-- canonical componentpb.ContentTrust enum name. Existing rows default to
-- CONTENT_TRUST_UNSPECIFIED, which the gate treats as trusted — so no behaviour
-- change for already-registered components.
ALTER TABLE component_install
    ADD COLUMN content_trust TEXT NOT NULL DEFAULT 'CONTENT_TRUST_UNSPECIFIED';
COMMENT ON COLUMN component_install.content_trust IS
    'Content-trust classification (componentpb.ContentTrust enum name): CONTENT_TRUST_TRUSTED | CONTENT_TRUST_UNTRUSTED | CONTENT_TRUST_UNSPECIFIED. Consumed by the dispatch-policy gate (ADR-0010 / gibson#997).';
