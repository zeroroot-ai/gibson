// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package audit

// Actions of the records that the operator writes.
const (
	// ActionSagaStep is the record before a saga step changes state.
	ActionSagaStep = "operator.saga_step"
	// ActionLastBackup is the record before the last backup of a deleted
	// tenant is created (ADR-0075).
	ActionLastBackup = "operator.last_backup"
	// ActionIdentityProvision is the record before the operator creates or
	// corrects the Zitadel organization of a tenant.
	ActionIdentityProvision = "operator.identity_provision"
	// ActionIdentityDeprovision is the record before the operator deletes the
	// Zitadel organization of a tenant.
	ActionIdentityDeprovision = "operator.identity_deprovision"
	// ActionSecretsBackendProvision is the record before the operator creates
	// or corrects the OpenBao namespace of a tenant.
	ActionSecretsBackendProvision = "operator.secrets_backend_provision"
	// ActionSecretsBackendDeprovision is the record before the operator
	// deletes the OpenBao namespace of a tenant.
	ActionSecretsBackendDeprovision = "operator.secrets_backend_deprovision"
	// ActionDataPlaneProvision is the record before the operator creates or
	// corrects the Postgres, Redis and Neo4j stores of a tenant.
	ActionDataPlaneProvision = "operator.data_plane_provision"
	// ActionDataPlaneDeprovision is the record before the operator deletes
	// the data-plane stores of a tenant.
	ActionDataPlaneDeprovision = "operator.data_plane_deprovision"
	// ActionGrantsProvision is the record before the operator writes the FGA
	// grants of a tenant.
	ActionGrantsProvision = "operator.grants_provision"
	// ActionGrantsDeprovision is the record before the operator deletes the
	// FGA grants of a tenant.
	ActionGrantsDeprovision = "operator.grants_deprovision"

	// TenantMember (tenant-operator).

	// ActionMemberInvitationIssue is the record before the operator creates
	// the invitation token of a member.
	ActionMemberInvitationIssue = "operator.member_invitation_issue"
	// ActionMemberInvitationAccept is the record before the operator writes
	// the session tuples of a member and deletes the invitation token.
	ActionMemberInvitationAccept = "operator.member_invitation_accept"
	// ActionMemberInvitationExpire is the record before the operator deletes
	// the invitation token of an expired invitation.
	ActionMemberInvitationExpire = "operator.member_invitation_expire"
	// ActionMemberRoleAssign is the record before the operator creates the
	// Zitadel user of a member and assigns the tenant role.
	ActionMemberRoleAssign = "operator.member_role_assign"
	// ActionMemberRoleRevoke is the record before the operator revokes the
	// tenant role of a deleted member.
	ActionMemberRoleRevoke = "operator.member_role_revoke"

	// ConnectorInstance authz (tenant-operator).

	// ActionConnectorGrantsWrite is the record before the operator writes the
	// FGA grants of a connector.
	ActionConnectorGrantsWrite = "operator.connector_grants_write"
	// ActionConnectorGrantsDelete is the record before the operator deletes
	// the FGA grants of a connector.
	ActionConnectorGrantsDelete = "operator.connector_grants_delete"

	// ActionTenantRoleSync is the record before the operator repairs a drift
	// between the Zitadel and the FGA tenant roles.
	ActionTenantRoleSync = "operator.tenant_role_sync"
	// ActionOrphanFinalizerRemove is the record before the orphan reaper
	// removes the finalizer of an object whose Tenant is gone.
	ActionOrphanFinalizerRemove = "operator.orphan_finalizer_remove"
	// ActionFirstTenantEnqueue is the record before the operator queues the
	// first tenant of an install.
	ActionFirstTenantEnqueue = "operator.first_tenant_enqueue"
	// ActionBackfill is the record before one change of a startup backfill.
	ActionBackfill = "operator.backfill"

	// Connector operator.

	// ActionConnectorApply is the record before the connector operator
	// creates or changes the runtime of a connector.
	ActionConnectorApply = "operator.connector_apply"
	// ActionConnectorDelete is the record before the connector operator
	// revokes the grant of a connector and deletes its runtime.
	ActionConnectorDelete = "operator.connector_delete"
	// ActionConnectorAdopt is the record before the connector operator
	// adopts a connector into the daemon table.
	ActionConnectorAdopt = "operator.connector_adopt"
	// ActionConnectorCredentialWrite is the record before the connector
	// operator writes the connector-cred Secret of a connector.
	ActionConnectorCredentialWrite = "operator.connector_credential_write"
	// ActionConnectorCredentialWithdraw is the record before the connector
	// operator deletes the connector-cred Secret of a connector.
	ActionConnectorCredentialWithdraw = "operator.connector_credential_withdraw"

	// Platform operator.

	// ActionOIDCClientApply is the record of a change to a Zitadel OIDC
	// client, machine user, secret or membership.
	ActionOIDCClientApply = "operator.oidc_client_apply"
	// ActionOIDCClientDelete is the record of the delete of a Zitadel OIDC
	// client and its memberships.
	ActionOIDCClientDelete = "operator.oidc_client_delete"
	// ActionPlatformBootstrap is the record of a change to the platform
	// Zitadel project, roles and policies, the OpenBao transit key or the FGA
	// store and model.
	ActionPlatformBootstrap = "operator.platform_bootstrap"
)
