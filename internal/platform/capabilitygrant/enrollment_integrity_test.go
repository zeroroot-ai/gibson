// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package capabilitygrant — enrollment_integrity_test.go
//
// The invariants enrollment rests on, at the statement level:
//
//   - an enrollment credential buys exactly one identity, and buys it in the
//     same transaction that records it as spent;
//   - a host belongs to the tenant that first registered it, and a revoked host
//     stays revoked;
//   - every tenant-facing statement names the tenant, so an id from another
//     tenant reads and writes nothing;
//   - an executing component is authorized as ITSELF.
//
// These run against a *sql.DB backed by sqlmock rather than a fake store,
// because the invariants ARE the SQL: the tenant predicate, the ON CONFLICT
// guard and the rows-affected check are what a store-shaped fake would quietly
// paper over. The behaviour of those statements inside a real Postgres is
// covered by enrollment_integrity_integration_test.go.
package capabilitygrant

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
)

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// hostJWK is a well-formed Ed25519 JWK; jwkThumbprint accepts nothing else.
const hostJWK = `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
const agentJWK = `{"kty":"OKP","crv":"Ed25519","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"}`

// recordedQueries collects every statement sent to the mock so a test can
// assert on what was NOT in it — sqlmock's regexp matcher can only express what
// a statement must contain.
type recordedQueries struct {
	mu sync.Mutex
	q  []string
}

func (r *recordedQueries) all() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.q, "\n---\n")
}

// substringMatcher matches on a normalised substring (sqlmock's default is a
// regexp, which is unreadable for multi-line DDL) and records every statement.
func substringMatcher(rec *recordedQueries) sqlmock.QueryMatcher {
	return sqlmock.QueryMatcherFunc(func(expectedSQL, actualSQL string) error {
		rec.mu.Lock()
		rec.q = append(rec.q, actualSQL)
		rec.mu.Unlock()
		if !strings.Contains(normaliseSQL(actualSQL), normaliseSQL(expectedSQL)) {
			return errors.New("statement does not contain expected fragment:\nwant fragment: " +
				expectedSQL + "\ngot statement: " + actualSQL)
		}
		return nil
	})
}

// normaliseSQL collapses whitespace so a fragment can be written readably.
func normaliseSQL(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

type mockedService struct {
	svc  *CapabilityGrantService
	mock sqlmock.Sqlmock
	rec  *recordedQueries
	fga  *mockAuthorizer
}

func newMockedService(t *testing.T) *mockedService {
	t.Helper()
	rec := &recordedQueries{}
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(substringMatcher(rec)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	fga := &mockAuthorizer{}
	// The audit Writer is deliberately NOT started: Log() buffers without
	// touching the database, so audit writes cannot interleave with the
	// statements under assertion.
	svc := NewCapabilityGrantService(CapabilityGrantServiceConfig{
		Store:       NewCapabilityGrantStore(db),
		FGABridge:   NewFGABridge(fga, &mockRegistry{}, noopLogger()),
		Authorizer:  fga,
		AuditWriter: audit.NewWriter(db, noopLogger()),
		AuditQuery:  audit.NewQuery(db),
		Logger:      slog.New(slog.DiscardHandler),
	})
	return &mockedService{svc: svc, mock: mock, rec: rec, fga: fga}
}

// register drives a first registration with the given credential.
func (m *mockedService) register(ctx context.Context, tenant, credential string) (*RegisterCapabilityGrantResult, error) {
	return m.svc.RegisterCapabilityGrant(ctx,
		tenant, "owner-1", "hello-agent", "autonomous", "agent_principal:acct-1",
		json.RawMessage(hostJWK), json.RawMessage(agentJWK),
		"bootstrap", credential, nil,
	)
}

// expectEnrollmentWrites queues the host, agent and grant-clearing statements
// that follow a successful credential consumption.
func (m *mockedService) expectEnrollmentWrites() {
	m.mock.ExpectExec("INSERT INTO capability_grant_hosts").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectExec("INSERT INTO capability_grant_agents").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectExec("DELETE FROM capability_grant_grants").
		WillReturnResult(sqlmock.NewResult(0, 0))
}

func credentialHash(credential string) string {
	sum := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// The enrollment credential is one-time
// ---------------------------------------------------------------------------

// The credential is spent in the SAME transaction that creates the identity, so
// there is no window in which one exists without the other.
func TestRegisterCapabilityGrant_SpendsTheCredentialWithTheIdentity(t *testing.T) {
	m := newMockedService(t)

	m.mock.ExpectBegin()
	m.mock.ExpectExec("INSERT INTO capability_grant_bootstrap_consumptions").
		WithArgs(credentialHash("cred-abc"), "acme", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectExec("DELETE FROM capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 0))
	m.expectEnrollmentWrites()
	m.mock.ExpectCommit()

	res, err := m.register(context.Background(), "acme", "cred-abc")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NoError(t, m.mock.ExpectationsWereMet())

	assert.Contains(t, m.rec.all(), "ON CONFLICT (token_hash) DO NOTHING",
		"the conflict is what makes a second presentation fail")
	assert.NotContains(t, m.rec.all(), "cred-abc",
		"the credential itself must never reach the database")
}

// A credential already exchanged for an identity buys nothing the second time,
// and nothing is written on the way to finding that out.
func TestRegisterCapabilityGrant_RefusesAReplayedCredential(t *testing.T) {
	m := newMockedService(t)

	m.mock.ExpectBegin()
	// Zero rows affected is how Postgres reports the ON CONFLICT DO NOTHING.
	m.mock.ExpectExec("INSERT INTO capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 0))
	m.mock.ExpectRollback()

	_, err := m.register(context.Background(), "acme", "cred-abc")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrBootstrapCredentialConsumed)
	// Ordered expectations: reaching a host or agent INSERT would fail here.
	require.NoError(t, m.mock.ExpectationsWereMet())
	assert.NotContains(t, m.rec.all(), "INSERT INTO capability_grant_agents",
		"a replay must not mint a second identity")
}

// Fail closed: an enrollment with no credential to spend is refused rather than
// registered un-metered.
func TestRegisterCapabilityGrant_RefusesAnAbsentCredential(t *testing.T) {
	m := newMockedService(t)

	_, err := m.register(context.Background(), "acme", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "enrollment credential is required")
	assert.Empty(t, m.rec.all(), "nothing may be written without a credential")
}

// An unrecognised bootstrap_type is treated as a one-time credential, not
// waved through: only the host-key path is exempt.
func TestRegisterCapabilityGrant_UnknownBootstrapTypeIsStillConsumed(t *testing.T) {
	m := newMockedService(t)

	m.mock.ExpectBegin()
	m.mock.ExpectExec("INSERT INTO capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectExec("DELETE FROM capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 0))
	m.expectEnrollmentWrites()
	m.mock.ExpectCommit()

	_, err := m.svc.RegisterCapabilityGrant(context.Background(),
		"acme", "owner-1", "hello-agent", "autonomous", "agent_principal:acct-1",
		json.RawMessage(hostJWK), json.RawMessage(agentJWK),
		"something-else", "cred-abc", nil,
	)
	require.NoError(t, err)
	require.NoError(t, m.mock.ExpectationsWereMet())
}

// Re-registration proves possession of a persistent host key, which is not a
// one-time credential and is not consumed.
func TestRegisterCapabilityGrant_HostKeyReRegistrationSpendsNothing(t *testing.T) {
	m := newMockedService(t)

	m.mock.ExpectBegin()
	m.expectEnrollmentWrites()
	m.mock.ExpectCommit()

	_, err := m.svc.RegisterCapabilityGrant(context.Background(),
		"acme", "owner-1", "hello-agent", "autonomous", "agent_principal:acct-1",
		json.RawMessage(hostJWK), json.RawMessage(agentJWK),
		"host_jwt", "host-jwt-token", nil,
	)
	require.NoError(t, err)
	require.NoError(t, m.mock.ExpectationsWereMet())
	assert.NotContains(t, m.rec.all(), "capability_grant_bootstrap_consumptions")
}

// ---------------------------------------------------------------------------
// A host belongs to the tenant that registered it
// ---------------------------------------------------------------------------

// The upsert may only update a row of the SAME tenant that is not revoked, and
// never reassigns tenant_id.
func TestRegisterCapabilityGrant_HostUpsertGuardsTenantAndRevocation(t *testing.T) {
	m := newMockedService(t)

	m.mock.ExpectBegin()
	m.mock.ExpectExec("INSERT INTO capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectExec("DELETE FROM capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 0))
	m.expectEnrollmentWrites()
	m.mock.ExpectCommit()

	_, err := m.register(context.Background(), "acme", "cred-abc")
	require.NoError(t, err)

	sent := normaliseSQL(m.rec.all())
	assert.Contains(t, sent, "WHERE capability_grant_hosts.tenant_id = EXCLUDED.tenant_id",
		"an existing host may only be updated by its own tenant")
	assert.Contains(t, sent, "capability_grant_hosts.status <> 'revoked'",
		"a revoked host must not be returned to service by re-registering")
	assert.NotContains(t, sent, "tenant_id = EXCLUDED.tenant_id, user_id",
		"tenant_id must not appear in the UPDATE SET list")
}

// When the guard refuses the update — another tenant's host, or a revoked one —
// the registration fails and no agent is created under it.
func TestRegisterCapabilityGrant_RefusesAHostItMayNotClaim(t *testing.T) {
	m := newMockedService(t)

	m.mock.ExpectBegin()
	m.mock.ExpectExec("INSERT INTO capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectExec("DELETE FROM capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 0))
	m.mock.ExpectExec("INSERT INTO capability_grant_hosts").
		WillReturnResult(sqlmock.NewResult(0, 0)) // guard refused the update
	m.mock.ExpectRollback()

	_, err := m.register(context.Background(), "acme", "cred-abc")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrHostNotRegistrable)
	require.NoError(t, m.mock.ExpectationsWereMet())
}

// The agent insert is predicated on a live host of the same tenant.
func TestRegisterCapabilityGrant_AgentInsertRequiresALiveHostInTenant(t *testing.T) {
	m := newMockedService(t)

	m.mock.ExpectBegin()
	m.mock.ExpectExec("INSERT INTO capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectExec("DELETE FROM capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 0))
	m.mock.ExpectExec("INSERT INTO capability_grant_hosts").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectExec("WHERE EXISTS ( SELECT 1 FROM capability_grant_hosts h WHERE h.id = $2::text AND h.tenant_id = $3::text AND h.status <> 'revoked' )").
		WillReturnResult(sqlmock.NewResult(0, 0))
	m.mock.ExpectRollback()

	_, err := m.register(context.Background(), "acme", "cred-abc")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrHostNotRegistrable)
	require.NoError(t, m.mock.ExpectationsWereMet())
}

// ---------------------------------------------------------------------------
// Tenant-facing statements name the tenant
// ---------------------------------------------------------------------------

// Reading an agent's status carries the tenant into the WHERE clause, so an
// agent id belonging to somebody else reads as absent.
func TestGetCapabilityGrantStatus_ReadsOnlyWithinTheTenant(t *testing.T) {
	m := newMockedService(t)

	m.mock.ExpectQuery("FROM capability_grant_agents a WHERE a.id = $1 AND a.tenant_id = $2").
		WithArgs("agt_deadbeef", "acme").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	res, err := m.svc.GetCapabilityGrantStatus(context.Background(), "agt_deadbeef", "acme")
	require.NoError(t, err)
	assert.Nil(t, res, "another tenant's agent must read as absent")
	require.NoError(t, m.mock.ExpectationsWereMet())
}

func TestGetCapabilityGrantStatus_RequiresATenant(t *testing.T) {
	m := newMockedService(t)

	_, err := m.svc.GetCapabilityGrantStatus(context.Background(), "agt_deadbeef", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id is required")
	assert.Empty(t, m.rec.all())
}

// The grants read is predicated on the owning agent's tenant, because the
// grants table carries no tenant of its own.
func TestGetCapabilityGrantStatus_GrantsReadJoinsTheOwningAgentsTenant(t *testing.T) {
	m := newMockedService(t)

	m.mock.ExpectQuery("FROM capability_grant_agents a WHERE a.id = $1 AND a.tenant_id = $2").
		WithArgs("agt_deadbeef", "acme").
		WillReturnRows(agentRow("agt_deadbeef", "acme"))
	m.mock.ExpectQuery("JOIN capability_grant_agents a ON a.id = g.agent_id WHERE g.agent_id = $1 AND a.tenant_id = $2").
		WithArgs("agt_deadbeef", "acme").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "agent_id", "capability_name", "component_ref", "constraints", "status", "granted_at",
		}))

	res, err := m.svc.GetCapabilityGrantStatus(context.Background(), "agt_deadbeef", "acme")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NoError(t, m.mock.ExpectationsWereMet())
}

// Revoking somebody else's agent fails where the caller can see it, instead of
// reporting success while revoking a row it does not own.
func TestRevokeCapabilityGrant_RefusesAnotherTenantsAgent(t *testing.T) {
	m := newMockedService(t)

	m.mock.ExpectBegin()
	m.mock.ExpectExec("UPDATE capability_grant_agents SET status = 'revoked' WHERE id = $1 AND tenant_id = $2").
		WithArgs("agt_deadbeef", "acme").
		WillReturnResult(sqlmock.NewResult(0, 0))
	m.mock.ExpectRollback()

	err := m.svc.RevokeCapabilityGrant(context.Background(), "agt_deadbeef", "acme", "actor-1")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrAgentNotInTenant)
	require.NoError(t, m.mock.ExpectationsWereMet())
}

func TestRevokeCapabilityGrant_RequiresATenant(t *testing.T) {
	m := newMockedService(t)

	err := m.svc.RevokeCapabilityGrant(context.Background(), "agt_deadbeef", "", "actor-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id is required")
	assert.Empty(t, m.rec.all())
}

// ---------------------------------------------------------------------------
// An executing component is authorized as itself
// ---------------------------------------------------------------------------

// agentRow builds the row shape getAgent scans.
func agentRow(id, tenant string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "host_id", "tenant_id", "user_id", "name", "mode",
		"public_key_jwk", "status", "session_ttl_s", "max_lifetime_s",
		"last_active_at", "expires_at", "principal_ref", "created_at",
	}).AddRow(
		id, "host-1", tenant, "owner-1", "hello-agent", "autonomous",
		[]byte(agentJWK), "active", 3600, 86400,
		nil, nil, "agent_principal:acct-1", time.Now(),
	)
}

// The FGA check names the component principal and the component-scoped
// relation — not the fetched row's owner, whose own authority the component
// would otherwise borrow in full.
func TestExecuteAgentCapability_AuthorizesTheComponentPrincipal(t *testing.T) {
	m := newMockedService(t)

	var gotSubject, gotRelation string
	m.fga.checkFunc = func(user, relation, _ string) (bool, error) {
		gotSubject, gotRelation = user, relation
		return false, nil
	}
	m.mock.ExpectQuery("FROM capability_grant_agents a WHERE a.id = $1 AND a.tenant_id = $2").
		WithArgs("agt_deadbeef", "acme").
		WillReturnRows(agentRow("agt_deadbeef", "acme"))

	res, err := m.svc.ExecuteAgentCapability(
		context.Background(), "agt_deadbeef", "execute:tool:nmap", nil, "acme")
	require.NoError(t, err)
	assert.Equal(t, "error", res.Status)
	assert.Equal(t, "agent_principal:acct-1", gotSubject,
		"the executing component is the subject, not its enroller")
	assert.Equal(t, "can_execute_as_component", gotRelation)
	require.NoError(t, m.mock.ExpectationsWereMet())
}

// An agent id from another tenant does not resolve, so nothing is authorized
// and nothing is dispatched.
func TestExecuteAgentCapability_ReadsOnlyWithinTheTenant(t *testing.T) {
	m := newMockedService(t)

	m.fga.checkFunc = func(_, _, _ string) (bool, error) {
		t.Fatal("no FGA check may run for an agent outside the tenant")
		return true, nil
	}
	m.mock.ExpectQuery("FROM capability_grant_agents a WHERE a.id = $1 AND a.tenant_id = $2").
		WithArgs("agt_other", "acme").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	res, err := m.svc.ExecuteAgentCapability(
		context.Background(), "agt_other", "execute:tool:nmap", nil, "acme")
	require.NoError(t, err)
	assert.Equal(t, "agent not found", res.ErrorMessage)
	require.NoError(t, m.mock.ExpectationsWereMet())
}

func TestExecuteAgentCapability_RequiresATenant(t *testing.T) {
	m := newMockedService(t)

	_, err := m.svc.ExecuteAgentCapability(
		context.Background(), "agt_deadbeef", "execute:tool:nmap", nil, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant_id is required")
	assert.Empty(t, m.rec.all())
}

// An agent row with no component principal has no identity to authorize, so it
// is denied rather than falling back to a broader subject.
func TestExecuteAgentCapability_AgentWithoutAPrincipalIsDenied(t *testing.T) {
	m := newMockedService(t)

	m.fga.checkFunc = func(_, _, _ string) (bool, error) {
		t.Fatal("no FGA check may run for an agent with no principal")
		return true, nil
	}
	// Same row as agentRow, but with no principal_ref.
	rows := sqlmock.NewRows([]string{
		"id", "host_id", "tenant_id", "user_id", "name", "mode",
		"public_key_jwk", "status", "session_ttl_s", "max_lifetime_s",
		"last_active_at", "expires_at", "principal_ref", "created_at",
	}).AddRow("agt_deadbeef", "host-1", "acme", "owner-1", "hello-agent", "autonomous",
		[]byte(agentJWK), "active", 3600, 86400, nil, nil, "", time.Now())
	m.mock.ExpectQuery("FROM capability_grant_agents a WHERE a.id = $1 AND a.tenant_id = $2").
		WillReturnRows(rows)

	res, err := m.svc.ExecuteAgentCapability(
		context.Background(), "agt_deadbeef", "execute:tool:nmap", nil, "acme")
	require.NoError(t, err)
	assert.Equal(t, "permission denied: agent has no component principal", res.ErrorMessage)
}

// ---------------------------------------------------------------------------
// Store statements
// ---------------------------------------------------------------------------

func newMockedStore(t *testing.T) (*CapabilityGrantStore, sqlmock.Sqlmock, *recordedQueries) {
	t.Helper()
	rec := &recordedQueries{}
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(substringMatcher(rec)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return NewCapabilityGrantStore(db), mock, rec
}

func testEnrollment(tenant string, grants []Grant) Enrollment {
	return Enrollment{
		Host: Host{
			ID: "host-1", TenantID: tenant, UserID: "owner-1",
			PublicKeyJWK: json.RawMessage(hostJWK), Status: "active",
		},
		Agent: Agent{
			ID: "agt_1", HostID: "host-1", TenantID: tenant, UserID: "owner-1",
			Name: "a", Mode: "autonomous",
			PublicKeyJWK: json.RawMessage(agentJWK), Status: "active",
		},
		Grants:             grants,
		BootstrapTokenHash: "hash-1",
	}
}

// An enrollment whose host and agent disagree about the tenant is a caller bug
// and is refused before anything is written.
func TestEnroll_RefusesAMismatchedTenant(t *testing.T) {
	store, _, rec := newMockedStore(t)

	e := testEnrollment("acme", nil)
	e.Agent.TenantID = "evilcorp"
	err := store.Enroll(context.Background(), e)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match agent tenant")
	assert.Empty(t, rec.all())
}

func TestEnroll_RefusesAnAbsentTenant(t *testing.T) {
	store, _, rec := newMockedStore(t)

	e := testEnrollment("", nil)
	err := store.Enroll(context.Background(), e)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant are required")
	assert.Empty(t, rec.all())
}

// Grants are written under the same tenant predicate as everything else, so a
// grant cannot land on another tenant's agent.
func TestEnroll_WritesGrantsUnderTheTenantPredicate(t *testing.T) {
	store, mock, rec := newMockedStore(t)

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO capability_grant_hosts").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO capability_grant_agents").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM capability_grant_grants").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO capability_grant_grants").
		WithArgs("agt_1", "execute:tool:nmap", "component:tool/nmap", []byte("{}"), "active", "acme").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := store.Enroll(context.Background(), testEnrollment("acme", []Grant{{
		AgentID: "agt_1", CapabilityName: "execute:tool:nmap",
		ComponentRef: "component:tool/nmap", Status: "active",
	}}))
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
	assert.Contains(t, normaliseSQL(rec.all()),
		"WHERE EXISTS (SELECT 1 FROM capability_grant_agents a WHERE a.id = $1::text AND a.tenant_id = $6::text)")
}

// A grant insert that matches no agent in the tenant aborts the enrollment
// rather than silently writing nothing.
func TestEnroll_GrantForAnotherTenantsAgentAborts(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO capability_grant_hosts").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO capability_grant_agents").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM capability_grant_grants").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO capability_grant_grants").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err := store.Enroll(context.Background(), testEnrollment("acme", []Grant{{
		AgentID: "agt_1", CapabilityName: "execute:tool:nmap",
		ComponentRef: "component:tool/nmap", Status: "active",
	}}))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrAgentNotInTenant)
	require.NoError(t, mock.ExpectationsWereMet())
}

// A database failure while spending the credential aborts the enrollment, so a
// credential is never recorded as spent by a registration that did not happen.
func TestEnroll_CredentialWriteFailureAborts(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO capability_grant_bootstrap_consumptions").
		WillReturnError(errors.New("connection reset"))
	mock.ExpectRollback()

	err := store.Enroll(context.Background(), testEnrollment("acme", nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "consume credential")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestEnroll_SweepFailureAborts(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM capability_grant_bootstrap_consumptions").
		WillReturnError(errors.New("connection reset"))
	mock.ExpectRollback()

	err := store.Enroll(context.Background(), testEnrollment("acme", nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sweep consumed credentials")
}

func TestEnroll_BeginFailureIsReported(t *testing.T) {
	store, mock, _ := newMockedStore(t)
	mock.ExpectBegin().WillReturnError(errors.New("pool exhausted"))

	err := store.Enroll(context.Background(), testEnrollment("acme", nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "begin tx")
}

func TestEnroll_CommitFailureIsReported(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO capability_grant_hosts").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO capability_grant_agents").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM capability_grant_grants").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit().WillReturnError(errors.New("connection reset"))

	err := store.Enroll(context.Background(), testEnrollment("acme", nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "commit")
}

// The tenant-scoped agent read refuses to run without a tenant, so an empty
// tenant cannot degrade into an unscoped read.
func TestGetAgentInTenant_RequiresATenant(t *testing.T) {
	store, _, rec := newMockedStore(t)

	_, err := store.GetAgentInTenant(context.Background(), "", "agt_1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant is required")
	assert.Empty(t, rec.all())
}

func TestGetAgentInTenant_ReturnsTheAgent(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectQuery("FROM capability_grant_agents a WHERE a.id = $1 AND a.tenant_id = $2").
		WithArgs("agt_1", "acme").
		WillReturnRows(agentRow("agt_1", "acme"))

	ag, err := store.GetAgentInTenant(context.Background(), "acme", "agt_1")
	require.NoError(t, err)
	require.NotNil(t, ag)
	assert.Equal(t, "acme", ag.TenantID)
	assert.Equal(t, "agent_principal:acct-1", ag.PrincipalRef)
}

// The credential-verification read carries no tenant, by construction: the key
// id is the claimed identity and the tenant is what the caller is asking for.
func TestGetAgent_ResolvesIdentityWithoutATenant(t *testing.T) {
	store, mock, rec := newMockedStore(t)

	mock.ExpectQuery("FROM capability_grant_agents a WHERE a.id = $1").
		WithArgs("agt_1").
		WillReturnRows(agentRow("agt_1", "acme"))

	ag, err := store.GetAgent(context.Background(), "agt_1")
	require.NoError(t, err)
	require.NotNil(t, ag)
	assert.NotContains(t, normaliseSQL(rec.all()), "a.tenant_id = $2")
}

func TestGetAgent_UnknownAgentReadsAsAbsent(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectQuery("FROM capability_grant_agents").
		WillReturnRows(sqlmock.NewRows([]string{"id"}))

	ag, err := store.GetAgent(context.Background(), "agt_missing")
	require.NoError(t, err)
	assert.Nil(t, ag)
}

func TestGetAgent_QueryFailureIsReported(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectQuery("FROM capability_grant_agents").
		WillReturnError(errors.New("connection reset"))

	_, err := store.GetAgent(context.Background(), "agt_1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GetAgent")
}

// A status write aimed at another tenant's agent fails loudly.
func TestUpdateAgentStatus_RefusesAnotherTenantsAgent(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectExec("UPDATE capability_grant_agents SET status = $3 WHERE id = $1 AND tenant_id = $2").
		WithArgs("agt_1", "acme", "revoked").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := store.UpdateAgentStatus(context.Background(), "acme", "agt_1", "revoked")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrAgentNotInTenant)
}

func TestUpdateAgentStatus_UpdatesItsOwnTenantsAgent(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectExec("UPDATE capability_grant_agents SET status = $3 WHERE id = $1 AND tenant_id = $2").
		WillReturnResult(sqlmock.NewResult(0, 1))

	require.NoError(t, store.UpdateAgentStatus(context.Background(), "acme", "agt_1", "revoked"))
}

func TestUpdateAgentStatus_QueryFailureIsReported(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectExec("UPDATE capability_grant_agents").
		WillReturnError(errors.New("connection reset"))

	err := store.UpdateAgentStatus(context.Background(), "acme", "agt_1", "revoked")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "UpdateAgentStatus")
}

func TestGetGrants_RequiresATenant(t *testing.T) {
	store, _, rec := newMockedStore(t)

	_, err := store.GetGrants(context.Background(), "", "agt_1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant is required")
	assert.Empty(t, rec.all())
}

func TestGetGrants_ReturnsTheAgentsGrants(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectQuery("JOIN capability_grant_agents a ON a.id = g.agent_id").
		WithArgs("agt_1", "acme").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "agent_id", "capability_name", "component_ref", "constraints", "status", "granted_at",
		}).AddRow("g1", "agt_1", "execute:tool:nmap", "component:tool/nmap", []byte("{}"), "active", time.Now()))

	grants, err := store.GetGrants(context.Background(), "acme", "agt_1")
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Equal(t, "execute:tool:nmap", grants[0].CapabilityName)
}

func TestGetGrants_QueryFailureIsReported(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectQuery("FROM capability_grant_grants g").
		WillReturnError(errors.New("connection reset"))

	_, err := store.GetGrants(context.Background(), "acme", "agt_1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GetGrants")
}

// HasActiveGrant is the read side of gibson#1186 slice C's capability gate: it
// resolves by (tenant, principal_ref) — the CG-JWT's verified identity, which
// is what a request-time check actually has — rather than by the
// capability_grant_agents primary key GetGrants uses.
func TestHasActiveGrant_RequiresATenant(t *testing.T) {
	store, _, rec := newMockedStore(t)

	_, err := store.HasActiveGrant(context.Background(), "", "agent_principal:acct-1", "mission:delegate")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant is required")
	assert.Empty(t, rec.all())
}

func TestHasActiveGrant_RequiresAPrincipal(t *testing.T) {
	store, _, rec := newMockedStore(t)

	_, err := store.HasActiveGrant(context.Background(), "acme", "", "mission:delegate")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "principal_ref is required")
	assert.Empty(t, rec.all())
}

func TestHasActiveGrant_RequiresACapabilityName(t *testing.T) {
	store, _, rec := newMockedStore(t)

	_, err := store.HasActiveGrant(context.Background(), "acme", "agent_principal:acct-1", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "capability_name is required")
	assert.Empty(t, rec.all())
}

func TestHasActiveGrant_TrueWhenAnActiveGrantExists(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectQuery("JOIN capability_grant_agents a ON a.id = g.agent_id").
		WithArgs("acme", "agent_principal:acct-1", "mission:delegate").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	has, err := store.HasActiveGrant(context.Background(), "acme", "agent_principal:acct-1", "mission:delegate")
	require.NoError(t, err)
	assert.True(t, has)
}

func TestHasActiveGrant_FalseWhenNoneExists(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectQuery("JOIN capability_grant_agents a ON a.id = g.agent_id").
		WithArgs("acme", "agent_principal:acct-1", "mission:delegate").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	has, err := store.HasActiveGrant(context.Background(), "acme", "agent_principal:acct-1", "mission:delegate")
	require.NoError(t, err)
	assert.False(t, has)
}

func TestHasActiveGrant_QueryFailureIsReported(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectQuery("capability_grant_grants g").
		WillReturnError(errors.New("connection reset"))

	_, err := store.HasActiveGrant(context.Background(), "acme", "agent_principal:acct-1", "mission:delegate")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HasActiveGrant")
}

// CapabilityGrantService.HasCapability wraps the store call and fails closed on
// missing arguments without ever issuing a query.
func TestServiceHasCapability_MissingArgumentsDenyWithoutAQuery(t *testing.T) {
	m := newMockedService(t)

	cases := [][3]string{
		{"", "agent_principal:acct-1", "mission:delegate"},
		{"acme", "", "mission:delegate"},
		{"acme", "agent_principal:acct-1", ""},
	}
	for _, c := range cases {
		has, err := m.svc.HasCapability(context.Background(), c[0], c[1], c[2])
		require.NoError(t, err)
		assert.False(t, has)
	}
	assert.Empty(t, m.rec.all(), "a malformed check must never reach the database")
}

func TestServiceHasCapability_DelegatesToTheStore(t *testing.T) {
	m := newMockedService(t)

	m.mock.ExpectQuery("JOIN capability_grant_agents a ON a.id = g.agent_id").
		WithArgs("acme", "agent_principal:acct-1", "mission:delegate").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	has, err := m.svc.HasCapability(context.Background(), "acme", "agent_principal:acct-1", "mission:delegate")
	require.NoError(t, err)
	assert.True(t, has)
}

// Revoking an agent revokes its grants under the same tenant predicate.
func TestRevokeAgent_RevokesTheAgentAndItsGrants(t *testing.T) {
	store, mock, rec := newMockedStore(t)

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE capability_grant_agents SET status = 'revoked' WHERE id = $1 AND tenant_id = $2").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE capability_grant_grants SET status = 'revoked'").
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()

	require.NoError(t, store.RevokeAgent(context.Background(), "acme", "agt_1"))
	assert.Contains(t, normaliseSQL(rec.all()),
		"EXISTS (SELECT 1 FROM capability_grant_agents a WHERE a.id = $1 AND a.tenant_id = $2)")
}

func TestRevokeAgent_RequiresATenant(t *testing.T) {
	store, _, rec := newMockedStore(t)

	err := store.RevokeAgent(context.Background(), "", "agt_1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant is required")
	assert.Empty(t, rec.all())
}

func TestRevokeAgent_GrantUpdateFailureAborts(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE capability_grant_agents").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE capability_grant_grants").
		WillReturnError(errors.New("connection reset"))
	mock.ExpectRollback()

	err := store.RevokeAgent(context.Background(), "acme", "agt_1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update grants")
}

// Revoking a host cascades to its agents and their grants, all within the
// tenant.
func TestRevokeHost_CascadesWithinTheTenant(t *testing.T) {
	store, mock, rec := newMockedStore(t)

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE capability_grant_hosts SET status = 'revoked', updated_at = now() WHERE id = $1 AND tenant_id = $2").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE capability_grant_grants").
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec("UPDATE capability_grant_agents SET status = 'revoked' WHERE host_id = $1 AND tenant_id = $2").
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()

	require.NoError(t, store.RevokeHost(context.Background(), "acme", "host-1"))
	assert.Contains(t, normaliseSQL(rec.all()),
		"SELECT id FROM capability_grant_agents WHERE host_id = $1 AND tenant_id = $2")
}

func TestRevokeHost_RefusesAnotherTenantsHost(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE capability_grant_hosts").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err := store.RevokeHost(context.Background(), "acme", "host-1")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrHostNotInTenant)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRevokeHost_RequiresATenant(t *testing.T) {
	store, _, rec := newMockedStore(t)

	err := store.RevokeHost(context.Background(), "", "host-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant is required")
	assert.Empty(t, rec.all())
}

func TestRevokeHost_AgentUpdateFailureAborts(t *testing.T) {
	store, mock, _ := newMockedStore(t)

	mock.ExpectBegin()
	mock.ExpectExec("UPDATE capability_grant_hosts").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE capability_grant_grants").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE capability_grant_agents").
		WillReturnError(errors.New("connection reset"))
	mock.ExpectRollback()

	err := store.RevokeHost(context.Background(), "acme", "host-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update agents")
}

// ---------------------------------------------------------------------------
// Credential issuance
// ---------------------------------------------------------------------------

// A TTL beyond the maximum is an error. Quietly substituting a shorter one made
// the expiry the API reported to its caller wrong.
func TestMintBootstrapToken_RejectsATTLBeyondTheMaximum(t *testing.T) {
	m := newTestMinter(t)

	_, err := m.MintBootstrapToken(BootstrapClaims{
		TenantID: "acme", OwnerUserID: "u", PrincipalID: "agent_principal:1",
	}, maxBootstrapTTL+time.Minute)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds the 24h0m0s maximum")
}

// An unspecified TTL still takes the default, and the token really carries it.
func TestMintBootstrapToken_UnspecifiedTTLIsTheDefault(t *testing.T) {
	m := newTestMinter(t)

	tok, err := m.MintBootstrapToken(BootstrapClaims{
		TenantID: "acme", OwnerUserID: "u", PrincipalID: "agent_principal:1",
	}, 0)
	require.NoError(t, err)

	var claims jwt.MapClaims
	_, _, err = jwt.NewParser().ParseUnverified(tok, &claims)
	require.NoError(t, err)
	exp, err := claims.GetExpirationTime()
	require.NoError(t, err)
	assert.WithinDuration(t, exp.Time, time.Now().Add(defaultBootstrapTTL), time.Minute)
}

// A credential with no jti cannot be recorded as an individual credential in
// the audit trail, so it is refused.
func TestVerifyBootstrapToken_RejectsACredentialWithoutJTI(t *testing.T) {
	m := newTestMinter(t)

	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss":    "https://test.daemon",
		"aud":    bootstrapTokenAudience,
		"sub":    "agent_principal:1",
		"tenant": "acme",
		"owner":  "u",
		"exp":    time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = m.keyID()
	tok.Header["typ"] = bootstrapTokenType
	signed, err := tok.SignedString(m.keys.Current.priv)
	require.NoError(t, err)

	_, err = m.VerifyBootstrapToken(signed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing jti")
}

// ---------------------------------------------------------------------------
// The credential states what it may become (the `scope` claim)
// ---------------------------------------------------------------------------

// A credential that carries no scope at all is not a credential this daemon
// minted. Requiring the register scope means a bootstrap credential cannot be
// spent at any other surface that also trusts an EdDSA token signed by this key.
func TestVerifyBootstrapToken_RejectsACredentialWithoutTheRegisterScope(t *testing.T) {
	m := newTestMinter(t)

	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss":    "https://test.daemon",
		"aud":    bootstrapTokenAudience,
		"sub":    "agent_principal:1",
		"tenant": "acme",
		"owner":  "u",
		"jti":    "jti-1",
		"scope":  "capabilitygrant:something-else",
		"exp":    time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = m.keyID()
	tok.Header["typ"] = bootstrapTokenType
	signed, err := tok.SignedString(m.keys.Current.priv)
	require.NoError(t, err)

	_, err = m.VerifyBootstrapToken(signed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), bootstrapScopeRegister)
}

// The register scope is structural: it is what makes the credential spendable
// here, and it must not read back as a capability the registration may grant.
func TestMintBootstrapToken_RegisterScopeIsNotPartOfTheCeiling(t *testing.T) {
	m := newTestMinter(t)

	tok, err := m.MintBootstrapToken(BootstrapClaims{
		TenantID: "acme", OwnerUserID: "u", PrincipalID: "agent_principal:1",
	}, 0)
	require.NoError(t, err)

	claims, err := m.VerifyBootstrapToken(tok)
	require.NoError(t, err)
	assert.Empty(t, claims.CapabilityCeiling)
}

// A space-delimited scope cannot carry an entry containing whitespace, so the
// mint refuses it rather than emitting a ceiling that reads back as two
// different capabilities.
func TestMintBootstrapToken_RejectsAnUnrepresentableCeilingEntry(t *testing.T) {
	m := newTestMinter(t)

	for _, entry := range []string{"", "execute:tool:a b"} {
		_, err := m.MintBootstrapToken(BootstrapClaims{
			TenantID: "acme", OwnerUserID: "u", PrincipalID: "agent_principal:1",
			CapabilityCeiling: []string{entry},
		}, 0)
		require.Error(t, err, "ceiling entry %q must be refused", entry)
	}
}

// grantFGA wires the mock so both the enroller and the component principal hold
// can_execute on every component in names.
func (m *mockedService) grantFGA(names ...string) {
	objects := make([]string, 0, len(names))
	for _, n := range names {
		objects = append(objects, "component:tool/"+n)
	}
	m.fga.listObjectsFunc = func(_, relation, _ string) ([]string, error) {
		if relation == "can_execute" || relation == "component_execute_enabled" {
			return objects, nil
		}
		return nil, nil
	}
}

// The ceiling removes: a capability the credential does not name is not granted
// even though FGA resolved it for this principal. This is what stops a
// capability granted to the enroller AFTER the credential was minted from
// widening a registration already in flight.
func TestRegisterCapabilityGrant_CredentialCeilingNarrowsTheResolvedGrants(t *testing.T) {
	m := newMockedService(t)
	m.grantFGA("nmap", "zap")

	m.mock.ExpectBegin()
	m.mock.ExpectExec("INSERT INTO capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectExec("DELETE FROM capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 0))
	m.expectEnrollmentWrites()
	m.mock.ExpectExec("INSERT INTO capability_grant_grants").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectCommit()

	res, err := m.svc.RegisterCapabilityGrant(context.Background(),
		"acme", "owner-1", "hello-agent", "autonomous", "agent_principal:acct-1",
		json.RawMessage(hostJWK), json.RawMessage(agentJWK),
		"bootstrap", "cred-abc", []string{"execute:tool:nmap"},
	)
	require.NoError(t, err)
	require.NoError(t, m.mock.ExpectationsWereMet())

	require.Len(t, res.Capabilities, 1)
	assert.Equal(t, "execute:tool:nmap", res.Capabilities[0].Name)
	assert.NotContains(t, m.rec.all(), "zap")
}

// A ceiling can only remove. Naming a capability FGA did not resolve does not
// conjure it, so a forged or stale scope cannot widen a registration.
func TestRegisterCapabilityGrant_CredentialCeilingCannotWiden(t *testing.T) {
	m := newMockedService(t)
	m.grantFGA("nmap")

	m.mock.ExpectBegin()
	m.mock.ExpectExec("INSERT INTO capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectExec("DELETE FROM capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 0))
	m.expectEnrollmentWrites()
	m.mock.ExpectExec("INSERT INTO capability_grant_grants").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectCommit()

	res, err := m.svc.RegisterCapabilityGrant(context.Background(),
		"acme", "owner-1", "hello-agent", "autonomous", "agent_principal:acct-1",
		json.RawMessage(hostJWK), json.RawMessage(agentJWK),
		"bootstrap", "cred-abc",
		[]string{"execute:tool:nmap", "execute:tool:not-resolved"},
	)
	require.NoError(t, err)
	require.NoError(t, m.mock.ExpectationsWereMet())

	require.Len(t, res.Capabilities, 1)
	assert.Equal(t, "execute:tool:nmap", res.Capabilities[0].Name)
}

// mission:delegate is never an FGA relation (gibson#1186 slice C owner
// decision), so naming it in the ceiling is the ONLY way to obtain it — the
// opposite direction from every other ceiling entry, which can only narrow an
// FGA resolution that already produced it. This is appendSessionCapabilities,
// exercised through the full RegisterCapabilityGrant path rather than in
// isolation (see TestAppendSessionCapabilities in pure_helpers_test.go for the
// pure-function coverage).
func TestRegisterCapabilityGrant_CeilingGrantsMissionDelegate(t *testing.T) {
	m := newMockedService(t)
	// Deliberately NO m.grantFGA call: FGA resolves zero capabilities for this
	// principal, proving mission:delegate does not depend on any FGA grant.

	m.mock.ExpectBegin()
	m.mock.ExpectExec("INSERT INTO capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectExec("DELETE FROM capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 0))
	m.expectEnrollmentWrites()
	m.mock.ExpectExec("INSERT INTO capability_grant_grants").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectCommit()

	res, err := m.svc.RegisterCapabilityGrant(context.Background(),
		"acme", "owner-1", "hello-agent", "autonomous", "agent_principal:acct-1",
		json.RawMessage(hostJWK), json.RawMessage(agentJWK),
		"bootstrap", "cred-abc", []string{"mission:delegate"},
	)
	require.NoError(t, err)
	require.NoError(t, m.mock.ExpectationsWereMet())

	require.Len(t, res.Capabilities, 1)
	assert.Equal(t, "mission:delegate", res.Capabilities[0].Name)
	assert.Empty(t, res.Capabilities[0].ComponentRef, "a session capability is not scoped to any component")
}

// A ceiling entry that is neither an FGA-resolved capability nor one of the
// two reserved session names grants nothing — it is not silently treated as a
// session capability just because capsWithinCeiling had nothing to narrow.
func TestRegisterCapabilityGrant_UnreservedUnresolvedCeilingEntryGrantsNothing(t *testing.T) {
	m := newMockedService(t)

	m.mock.ExpectBegin()
	m.mock.ExpectExec("INSERT INTO capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectExec("DELETE FROM capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 0))
	m.expectEnrollmentWrites()
	m.mock.ExpectCommit()

	res, err := m.svc.RegisterCapabilityGrant(context.Background(),
		"acme", "owner-1", "hello-agent", "autonomous", "agent_principal:acct-1",
		json.RawMessage(hostJWK), json.RawMessage(agentJWK),
		"bootstrap", "cred-abc", []string{"execute:tool:never-granted"},
	)
	require.NoError(t, err)
	require.NoError(t, m.mock.ExpectationsWereMet())
	assert.Empty(t, res.Capabilities)
}

// An empty ceiling means the credential states none, so the FGA resolution
// stands. A credential that says nothing must not be read as granting nothing —
// that would break every credential minted without an explicit ceiling.
func TestRegisterCapabilityGrant_AnAbsentCeilingLeavesTheResolutionAlone(t *testing.T) {
	m := newMockedService(t)
	m.grantFGA("nmap", "zap")

	m.mock.ExpectBegin()
	m.mock.ExpectExec("INSERT INTO capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectExec("DELETE FROM capability_grant_bootstrap_consumptions").
		WillReturnResult(sqlmock.NewResult(0, 0))
	m.expectEnrollmentWrites()
	m.mock.ExpectExec("INSERT INTO capability_grant_grants").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectExec("INSERT INTO capability_grant_grants").
		WillReturnResult(sqlmock.NewResult(0, 1))
	m.mock.ExpectCommit()

	res, err := m.register(context.Background(), "acme", "cred-abc")
	require.NoError(t, err)
	require.NoError(t, m.mock.ExpectationsWereMet())
	assert.Len(t, res.Capabilities, 2)
}
