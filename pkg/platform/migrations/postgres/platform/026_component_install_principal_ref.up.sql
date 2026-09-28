-- gibson#154: record the principal a component registered as, on its install.
--
-- A plugin binds can_resolve on its declared secrets under the FGA user its
-- signed identity carries (bindDeclaredSecrets), and it streams
-- WatchComponentEvents under the same user. The admin RPCs that revoke or
-- rebind a secret (RevokePluginSecretBinding, EditPluginSecretBinding) derived
-- that user from the install id by a placeholder transform, so the tuple they
-- deleted and the channel they published to never matched the running plugin.
-- The install row now carries the real principal. Rows registered before this
-- migration hold '' and the admin RPCs refuse them until the plugin
-- re-registers, which every plugin does on restart.
ALTER TABLE component_install
    ADD COLUMN principal_ref TEXT NOT NULL DEFAULT '';
COMMENT ON COLUMN component_install.principal_ref IS
    'FGA user the component registered as (plugin_principal:<id> for a plugin). Empty for rows written before gibson#154; the plugin re-registers on restart.';
