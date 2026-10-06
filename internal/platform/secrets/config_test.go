// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// --- fakes ---

// fakeRowStore is an in-memory stand-in for TenantConfigStore.
type fakeRowStore struct {
	rows   map[string]fakeRowEntry
	setErr error
}

type fakeRowEntry struct {
	provider string
	blob     []byte
}

func newFakeRowStore() *fakeRowStore {
	return &fakeRowStore{rows: make(map[string]fakeRowEntry)}
}

func (f *fakeRowStore) GetRaw(_ context.Context, tenant auth.TenantID) (string, []byte, error) {
	row, ok := f.rows[tenant.String()]
	if !ok {
		return "", nil, ErrBrokerConfigNotFound
	}
	return row.provider, row.blob, nil
}

func (f *fakeRowStore) SetRaw(_ context.Context, tenant auth.TenantID, provider string, blob []byte, _ string) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.rows[tenant.String()] = fakeRowEntry{provider: provider, blob: blob}
	return nil
}

func (f *fakeRowStore) DeleteRaw(_ context.Context, tenant auth.TenantID) error {
	delete(f.rows, tenant.String())
	return nil
}

// fakeAuditCapture records emitted audit events. recorded marks each event
// that came through Record. recordErr makes Record fail.
type fakeAuditCapture struct {
	events    []AuditEvent
	recorded  []bool
	recordErr error
}

func (f *fakeAuditCapture) Audit(_ context.Context, event AuditEvent) {
	f.events = append(f.events, event)
	f.recorded = append(f.recorded, false)
}

func (f *fakeAuditCapture) Record(_ context.Context, event AuditEvent) error {
	if f.recordErr != nil {
		return f.recordErr
	}
	f.events = append(f.events, event)
	f.recorded = append(f.recorded, true)
	return nil
}

// newTestConfigStore builds the production ConfigStore over the fakes.
func newTestConfigStore(t *testing.T, rows configRows, factories map[string]ProviderFactory, aud ConfigStoreAuditWriter) *ConfigStore {
	t.Helper()
	cs, err := newConfigStore(rows, factories, aud)
	require.NoError(t, err)
	return cs
}

// fakeSecretsBroker is a minimal sdksecrets.Broker used for probe
// testing.
type fakeSecretsBroker struct {
	probeErr error
}

var _ sdksecrets.Broker = (*fakeSecretsBroker)(nil)

func (f *fakeSecretsBroker) Get(_ context.Context, _ auth.TenantID, _ string) ([]byte, error) {
	return nil, nil
}
func (f *fakeSecretsBroker) Put(_ context.Context, _ auth.TenantID, _ string, _ []byte) error {
	return nil
}
func (f *fakeSecretsBroker) Delete(_ context.Context, _ auth.TenantID, _ string) error { return nil }
func (f *fakeSecretsBroker) List(_ context.Context, _ auth.TenantID, _ sdksecrets.Filter) ([]string, error) {
	return nil, nil
}
func (f *fakeSecretsBroker) Health(_ context.Context) error { return nil }
func (f *fakeSecretsBroker) Probe(_ context.Context) error  { return f.probeErr }
func (f *fakeSecretsBroker) Capabilities() sdksecrets.Capabilities {
	return sdksecrets.Capabilities{CanPut: true, CanDelete: true, CanList: true}
}

// --- tests ---

var cfgTestTenant = auth.MustNewTenantID("acme-corp")

func TestConfigStore_GetNotFound(t *testing.T) {
	row := newFakeRowStore()
	aud := &fakeAuditCapture{}
	cs := newTestConfigStore(t, row, nil, aud)

	_, err := cs.Get(context.Background(), cfgTestTenant)
	require.ErrorIs(t, err, ErrBrokerConfigNotFound)
}

func TestConfigStore_SetProbeSuccess_PersistsRow(t *testing.T) {
	row := newFakeRowStore()
	aud := &fakeAuditCapture{}
	factories := map[string]ProviderFactory{
		"vault": func(_ []byte) (sdksecrets.Broker, error) {
			return &fakeSecretsBroker{}, nil
		},
	}
	cs := newTestConfigStore(t, row, factories, aud)

	cfg := BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{"address":"https://vault.example.com"}`)}
	require.NoError(t, cs.Set(context.Background(), cfgTestTenant, cfg, "operator-1"))

	got, err := cs.Get(context.Background(), cfgTestTenant)
	require.NoError(t, err)
	assert.Equal(t, "vault", got.Provider)
	assert.Equal(t, cfg.ConfigBlob, got.ConfigBlob)

	require.Len(t, aud.events, 1)
	assert.Equal(t, EffectAllow, aud.events[0].Effect)
	assert.Equal(t, ActionSecretConfigSet, aud.events[0].Action)
}

func TestConfigStore_SetProbeFailure_BlocksWrite(t *testing.T) {
	row := newFakeRowStore()
	aud := &fakeAuditCapture{}
	probeErr := errors.New("vault: connection refused")
	factories := map[string]ProviderFactory{
		"vault": func(_ []byte) (sdksecrets.Broker, error) {
			return &fakeSecretsBroker{probeErr: probeErr}, nil
		},
	}
	cs := newTestConfigStore(t, row, factories, aud)

	cfg := BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{"provider":"vault"}`)}
	err := cs.Set(context.Background(), cfgTestTenant, cfg, "operator-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "probe provider")

	// No row written.
	_, getErr := cs.Get(context.Background(), cfgTestTenant)
	require.ErrorIs(t, getErr, ErrBrokerConfigNotFound)

	require.Len(t, aud.events, 1)
	assert.Equal(t, EffectDeny, aud.events[0].Effect)
	assert.Equal(t, "probe_failed", aud.events[0].DecisionReason)
}

func TestConfigStore_SetUnknownProvider(t *testing.T) {
	row := newFakeRowStore()
	aud := &fakeAuditCapture{}
	cs := newTestConfigStore(t, row, map[string]ProviderFactory{}, aud)

	cfg := BrokerConfig{Provider: "unknown", ConfigBlob: []byte(`{}`)}
	err := cs.Set(context.Background(), cfgTestTenant, cfg, "op")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
	assert.Len(t, aud.events, 0)
}

func TestConfigStore_DeleteEmitsAllowAudit(t *testing.T) {
	row := newFakeRowStore()
	row.rows[cfgTestTenant.String()] = fakeRowEntry{provider: "vault", blob: []byte(`{}`)}
	aud := &fakeAuditCapture{}
	cs := newTestConfigStore(t, row, nil, aud)

	require.NoError(t, cs.Delete(context.Background(), cfgTestTenant, "operator-1"))

	_, getErr := cs.Get(context.Background(), cfgTestTenant)
	require.ErrorIs(t, getErr, ErrBrokerConfigNotFound)

	require.Len(t, aud.events, 1)
	assert.Equal(t, EffectAllow, aud.events[0].Effect)
}

func TestConfigStore_ConstructorFailBlocksWrite(t *testing.T) {
	row := newFakeRowStore()
	aud := &fakeAuditCapture{}
	constructErr := errors.New("bad config JSON")
	factories := map[string]ProviderFactory{
		"vault": func(_ []byte) (sdksecrets.Broker, error) {
			return nil, constructErr
		},
	}
	cs := newTestConfigStore(t, row, factories, aud)

	cfg := BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{"invalid":true}`)}
	err := cs.Set(context.Background(), cfgTestTenant, cfg, "op")
	require.Error(t, err)

	require.Len(t, aud.events, 1)
	assert.Equal(t, EffectDeny, aud.events[0].Effect)
	assert.Equal(t, "provider_construct_failed", aud.events[0].DecisionReason)
}

// TestConfigStore_SetRecordsBeforeTheWrite: the allow record comes through
// Record, before the row exists.
func TestConfigStore_SetRecordsBeforeTheWrite(t *testing.T) {
	row := newFakeRowStore()
	aud := &fakeAuditCapture{}
	factories := map[string]ProviderFactory{
		"vault": func(_ []byte) (sdksecrets.Broker, error) { return &fakeSecretsBroker{}, nil },
	}
	cs := newTestConfigStore(t, row, factories, aud)

	require.NoError(t, cs.Set(context.Background(), cfgTestTenant, BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{}`)}, "op"))
	require.Equal(t, []bool{true}, aud.recorded, "the allow record is durable")
}

// TestConfigStore_SetFailsWhenTheRecordFails: no row is written when the
// audit record cannot be written.
func TestConfigStore_SetFailsWhenTheRecordFails(t *testing.T) {
	row := newFakeRowStore()
	aud := &fakeAuditCapture{recordErr: errors.New("postgres down")}
	factories := map[string]ProviderFactory{
		"vault": func(_ []byte) (sdksecrets.Broker, error) { return &fakeSecretsBroker{}, nil },
	}
	cs := newTestConfigStore(t, row, factories, aud)

	err := cs.Set(context.Background(), cfgTestTenant, BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{}`)}, "op")
	require.ErrorContains(t, err, "audit record")
	_, getErr := cs.Get(context.Background(), cfgTestTenant)
	require.ErrorIs(t, getErr, ErrBrokerConfigNotFound, "no row without its audit record")
}

// TestConfigStore_SetWriteFailureAddsADenyRecord: the record of the attempt
// stays, and a second record states the failure.
func TestConfigStore_SetWriteFailureAddsADenyRecord(t *testing.T) {
	row := newFakeRowStore()
	row.setErr = errors.New("db down")
	aud := &fakeAuditCapture{}
	factories := map[string]ProviderFactory{
		"vault": func(_ []byte) (sdksecrets.Broker, error) { return &fakeSecretsBroker{}, nil },
	}
	cs := newTestConfigStore(t, row, factories, aud)

	err := cs.Set(context.Background(), cfgTestTenant, BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{}`)}, "op")
	require.ErrorContains(t, err, "persist")
	require.Len(t, aud.events, 2)
	assert.Equal(t, EffectAllow, aud.events[0].Effect)
	assert.Equal(t, "db_write_failed", aud.events[1].DecisionReason)
}

// TestConfigStore_DeleteFailsWhenTheRecordFails: the row stays when the
// audit record cannot be written.
func TestConfigStore_DeleteFailsWhenTheRecordFails(t *testing.T) {
	row := newFakeRowStore()
	row.rows[cfgTestTenant.String()] = fakeRowEntry{provider: "vault", blob: []byte(`{}`)}
	aud := &fakeAuditCapture{recordErr: errors.New("postgres down")}
	cs := newTestConfigStore(t, row, nil, aud)

	require.ErrorContains(t, cs.Delete(context.Background(), cfgTestTenant, "op"), "audit record")
	_, err := cs.Get(context.Background(), cfgTestTenant)
	require.NoError(t, err, "the row stays")
}

func TestNewConfigStore_RefusesNilInputs(t *testing.T) {
	_, err := NewConfigStore(nil, nil, &fakeAuditCapture{})
	require.Error(t, err)
	_, err = newConfigStore(newFakeRowStore(), nil, nil)
	require.Error(t, err)
}
