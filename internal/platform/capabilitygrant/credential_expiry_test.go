// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package capabilitygrant — credential_expiry_test.go
//
// An agent's registered lifetime has to actually end.
//
// expires_at is written at registration and was read by nothing: both
// credential paths tested only status == "active", so an agent past its expiry
// kept verifying its own tokens AND kept having its public key served to
// ext-authz. These tests pin the check in both places, and pin the two things
// it must NOT do: lapse an agent that set no expiry, and lapse one still inside
// its window.
package capabilitygrant

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// VerifyAgentJWT
// ---------------------------------------------------------------------------

// verifierWithAgent builds a verifier over a single agent whose expiry is
// expiresAt, plus a correctly-signed agent+jwt for it. The token itself is
// always well within its own exp — the only thing under test is the AGENT's
// lifetime, not the token's.
func verifierWithAgent(t *testing.T, expiresAt *time.Time) (*JWTVerifier, string, *fakeStore) {
	t.Helper()
	pub, priv := genKeyPair(t)
	store := newFakeStore()
	store.addAgent(&Agent{
		ID: "agent-001", HostID: "host-001", TenantID: "tenant-acme",
		UserID: "user-bob", Status: "active", PublicKeyJWK: pubKeyToJWK(pub),
		ExpiresAt: expiresAt,
	})
	now := time.Now()
	tp := buildAgentToken(priv, "agent-001", "host-001", "gibson-daemon", "jti-abc",
		now, now.Add(30*time.Second))
	return NewJWTVerifier(store), tp.token(), store
}

func timePtr(t time.Time) *time.Time { return &t }

func TestVerifyAgentJWT_RefusesALapsedAgent(t *testing.T) {
	v, token, store := verifierWithAgent(t, timePtr(time.Now().Add(-time.Hour)))

	_, err := v.VerifyAgentJWT(context.Background(), token, "gibson-daemon")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "lapsed")
	// A lapsed agent must not be stamped as active either — the refusal happens
	// before any side effect.
	assert.NotContains(t, store.lastActiveUpdated, "agent-001")
}

// The expiry check must not swallow agents that are still inside their window;
// a guard that refuses everything proves nothing.
func TestVerifyAgentJWT_AcceptsAnAgentInsideItsLifetime(t *testing.T) {
	v, token, _ := verifierWithAgent(t, timePtr(time.Now().Add(time.Hour)))

	claims, err := v.VerifyAgentJWT(context.Background(), token, "gibson-daemon")

	require.NoError(t, err)
	assert.Equal(t, "agent-001", claims.AgentID)
}

// No expiry recorded is not the same as an expiry that has passed.
func TestVerifyAgentJWT_AcceptsAnAgentWithNoRecordedExpiry(t *testing.T) {
	v, token, _ := verifierWithAgent(t, nil)

	claims, err := v.VerifyAgentJWT(context.Background(), token, "gibson-daemon")

	require.NoError(t, err)
	assert.Equal(t, "tenant-acme", claims.TenantID)
}

// ---------------------------------------------------------------------------
// AgentKeyDescriptor
// ---------------------------------------------------------------------------

// agentRowExpiring is agentRow with an expires_at, so the key-serving path can
// be driven at either side of the boundary.
func agentRowExpiring(id, tenant string, expiresAt any) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "host_id", "tenant_id", "user_id", "name", "mode",
		"public_key_jwk", "status", "session_ttl_s", "max_lifetime_s",
		"last_active_at", "expires_at", "principal_ref", "created_at",
	}).AddRow(
		id, "host-1", tenant, "owner-1", "hello-agent", "autonomous",
		[]byte(agentJWK), "active", 3600, 86400,
		nil, expiresAt, "agent_principal:acct-1", time.Now(),
	)
}

func TestAgentKeyDescriptor_WithholdsALapsedAgentsKey(t *testing.T) {
	m := newMockedService(t)
	m.mock.ExpectQuery("FROM capability_grant_agents a WHERE a.id = $1").
		WithArgs("agt_1").
		WillReturnRows(agentRowExpiring("agt_1", "acme", time.Now().Add(-time.Hour)))

	body, err := m.svc.AgentKeyDescriptor(context.Background(), "agt_1")

	require.Error(t, err)
	assert.Nil(t, body)
	assert.Contains(t, err.Error(), "lapsed")
}

func TestAgentKeyDescriptor_ServesAnAgentInsideItsLifetime(t *testing.T) {
	m := newMockedService(t)
	m.mock.ExpectQuery("FROM capability_grant_agents a WHERE a.id = $1").
		WithArgs("agt_1").
		WillReturnRows(agentRowExpiring("agt_1", "acme", time.Now().Add(time.Hour)))

	body, err := m.svc.AgentKeyDescriptor(context.Background(), "agt_1")

	require.NoError(t, err)
	assert.Contains(t, string(body), `"tenant":"acme"`)
}

func TestAgentKeyDescriptor_ServesAnAgentWithNoRecordedExpiry(t *testing.T) {
	m := newMockedService(t)
	m.mock.ExpectQuery("FROM capability_grant_agents a WHERE a.id = $1").
		WithArgs("agt_1").
		WillReturnRows(agentRowExpiring("agt_1", "acme", nil))

	body, err := m.svc.AgentKeyDescriptor(context.Background(), "agt_1")

	require.NoError(t, err)
	assert.Contains(t, string(body), `"principal":"agent_principal:acct-1"`)
}

// ---------------------------------------------------------------------------
// Tenant-predicate regression guard
// ---------------------------------------------------------------------------

// Every tenant-facing statement the store issues must name the tenant.
//
// This is a whole-surface guard rather than one assertion per method: the
// per-method tests pin the statement each method is EXPECTED to send, so a
// predicate dropped from a method nobody thought to re-check would still pass
// them. Driving every tenant-facing method and then asserting over the recorded
// SQL catches the one that was forgotten.
//
// The three credential-verification reads are deliberately absent from this
// list and carry no tenant by construction (see the store.go package comment):
// there the key id IS the claimed identity and the tenant is the answer, so a
// tenant argument would mean trusting a caller-asserted tenant during
// authentication.
func TestStore_EveryTenantFacingStatementNamesTheTenant(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		// fragment is the tenant predicate the statement must carry.
		fragment string
		drive    func(t *testing.T, s *CapabilityGrantStore, mock sqlmock.Sqlmock)
	}{
		{
			name:     "GetAgentInTenant",
			fragment: "a.tenant_id = $2",
			drive: func(t *testing.T, s *CapabilityGrantStore, mock sqlmock.Sqlmock) {
				mock.ExpectQuery("FROM capability_grant_agents").
					WillReturnRows(agentRow("agt_1", "acme"))
				_, err := s.GetAgentInTenant(ctx, "acme", "agt_1")
				require.NoError(t, err)
			},
		},
		{
			name:     "UpdateAgentStatus",
			fragment: "tenant_id = $2",
			drive: func(t *testing.T, s *CapabilityGrantStore, mock sqlmock.Sqlmock) {
				mock.ExpectExec("UPDATE capability_grant_agents").
					WillReturnResult(sqlmock.NewResult(0, 1))
				require.NoError(t, s.UpdateAgentStatus(ctx, "acme", "agt_1", "revoked"))
			},
		},
		{
			name:     "GetGrants",
			fragment: "a.tenant_id = $2",
			drive: func(t *testing.T, s *CapabilityGrantStore, mock sqlmock.Sqlmock) {
				mock.ExpectQuery("FROM capability_grant_grants").
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "agent_id", "capability_name", "component_ref",
						"constraints", "status", "granted_at",
					}))
				_, err := s.GetGrants(ctx, "acme", "agt_1")
				require.NoError(t, err)
			},
		},
		{
			name:     "ListAgentsByTenant",
			fragment: "tenant_id = $1",
			drive: func(t *testing.T, s *CapabilityGrantStore, mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT COUNT(*)").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
				mock.ExpectQuery("FROM capability_grant_agents").
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "host_id", "tenant_id", "user_id", "name", "mode",
						"public_key_jwk", "status", "session_ttl_s", "max_lifetime_s",
						"last_active_at", "expires_at", "created_at",
					}).AddRow(
						"agt_1", "host-1", "acme", "owner-1", "a", "autonomous",
						[]byte(agentJWK), "active", 3600, 86400, nil, nil, time.Now(),
					))
				_, _, err := s.ListAgentsByTenant(ctx, "acme", 10, 0)
				require.NoError(t, err)
			},
		},
		{
			name:     "RevokeAgent",
			fragment: "tenant_id = $2",
			drive: func(t *testing.T, s *CapabilityGrantStore, mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec("UPDATE capability_grant_agents").
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec("UPDATE capability_grant_grants").
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
				require.NoError(t, s.RevokeAgent(ctx, "acme", "agt_1"))
			},
		},
		{
			name:     "RevokeHost",
			fragment: "tenant_id = $2",
			drive: func(t *testing.T, s *CapabilityGrantStore, mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec("UPDATE capability_grant_hosts").
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec("UPDATE capability_grant_grants").
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec("UPDATE capability_grant_agents").
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
				require.NoError(t, s.RevokeHost(ctx, "acme", "host-1"))
			},
		},
		{
			name:     "Enroll",
			fragment: "tenant_id",
			drive: func(t *testing.T, s *CapabilityGrantStore, mock sqlmock.Sqlmock) {
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
				mock.ExpectCommit()
				require.NoError(t, s.Enroll(ctx, testEnrollment("acme", nil)))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, mock, rec := newMockedStore(t)
			tc.drive(t, store, mock)

			// Every statement that touched a capability_grant table must carry a
			// tenant predicate. The consumption sweep is exempt: it is keyed on
			// consumed_at alone and names no id, so it has nothing to scope.
			for _, stmt := range strings.Split(rec.all(), "\n---\n") {
				norm := normaliseSQL(stmt)
				if norm == "" || !strings.Contains(norm, "capability_grant") {
					continue
				}
				if strings.Contains(norm, "consumed_at <") {
					continue
				}
				assert.Contains(t, norm, "tenant_id",
					"%s issued a statement with no tenant predicate: %s", tc.name, norm)
			}
			assert.Contains(t, normaliseSQL(rec.all()), tc.fragment)
		})
	}
}
