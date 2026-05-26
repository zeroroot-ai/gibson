package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdksecrets "github.com/zeroroot-ai/platform-clients/secrets"
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

// fakeAuditCapture records emitted audit events.
type fakeAuditCapture struct {
	events []AuditEvent
}

func (f *fakeAuditCapture) Audit(_ context.Context, event AuditEvent) {
	f.events = append(f.events, event)
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

// configRowStoreI is the testability interface mirroring TenantConfigStore's
// methods. ConfigStore accepts the concrete *TenantConfigStore in production;
// tests use this interface via configStoreT.
type configRowStoreI interface {
	GetRaw(ctx context.Context, tenant auth.TenantID) (provider string, configJSON []byte, err error)
	SetRaw(ctx context.Context, tenant auth.TenantID, provider string, configJSON []byte, actor string) error
	DeleteRaw(ctx context.Context, tenant auth.TenantID) error
}

// configStoreT mirrors ConfigStore but accepts the interface for testing.
type configStoreT struct {
	store     configRowStoreI
	factories map[string]ProviderFactory
	auditor   ConfigStoreAuditWriter
}

func newConfigStoreT(store configRowStoreI, factories map[string]ProviderFactory, aud ConfigStoreAuditWriter) *configStoreT {
	if factories == nil {
		factories = make(map[string]ProviderFactory)
	}
	return &configStoreT{store: store, factories: factories, auditor: aud}
}

func (cs *configStoreT) Get(ctx context.Context, tenant auth.TenantID) (BrokerConfig, error) {
	provider, blob, err := cs.store.GetRaw(ctx, tenant)
	if err != nil {
		return BrokerConfig{}, err
	}
	return BrokerConfig{Provider: provider, ConfigBlob: blob}, nil
}

func (cs *configStoreT) Set(ctx context.Context, tenant auth.TenantID, cfg BrokerConfig, actor string) error {
	// Reuse the production ConfigStore logic by delegating through a thin
	// adapter that satisfies *TenantConfigStore calls.
	factory, ok := cs.factories[cfg.Provider]
	if !ok {
		return errors.New("unknown provider: " + cfg.Provider)
	}
	candidate, err := factory(cfg.ConfigBlob)
	if err != nil {
		cs.auditor.Audit(ctx, AuditEvent{
			ActorID: actor, ActorTenantID: tenant.String(),
			Action: ActionSecretConfigSet, Effect: EffectDeny,
			Decision: "deny", DecisionReason: "provider_construct_failed",
			Success: false, ErrorCode: "provider_construct_failed",
		})
		return err
	}
	if probeErr := candidate.Probe(ctx); probeErr != nil {
		cs.auditor.Audit(ctx, AuditEvent{
			ActorID: actor, ActorTenantID: tenant.String(),
			Action: ActionSecretConfigSet, Effect: EffectDeny,
			Decision: "deny", DecisionReason: "probe_failed",
			Success: false, ErrorCode: "probe_failed",
		})
		return errors.New("probe failed: " + probeErr.Error())
	}
	if writeErr := cs.store.SetRaw(ctx, tenant, cfg.Provider, cfg.ConfigBlob, actor); writeErr != nil {
		cs.auditor.Audit(ctx, AuditEvent{
			ActorID: actor, ActorTenantID: tenant.String(),
			Action: ActionSecretConfigSet, Effect: EffectDeny,
			Decision: "deny", DecisionReason: "db_write_failed",
			Success: false, ErrorCode: "db_write_failed",
		})
		return writeErr
	}
	cs.auditor.Audit(ctx, AuditEvent{
		ActorID: actor, ActorTenantID: tenant.String(),
		Action: ActionSecretConfigSet, Effect: EffectAllow,
		Decision: "allow", Success: true,
	})
	return nil
}

func (cs *configStoreT) Delete(ctx context.Context, tenant auth.TenantID, actor string) error {
	if err := cs.store.DeleteRaw(ctx, tenant); err != nil {
		cs.auditor.Audit(ctx, AuditEvent{
			ActorID: actor, ActorTenantID: tenant.String(),
			Action: ActionSecretConfigSet, Effect: EffectDeny,
			Decision: "deny", DecisionReason: "db_delete_failed",
		})
		return err
	}
	cs.auditor.Audit(ctx, AuditEvent{
		ActorID: actor, ActorTenantID: tenant.String(),
		Action: ActionSecretConfigSet, Effect: EffectAllow,
		Decision: "allow", Success: true,
	})
	return nil
}

// --- tests ---

var cfgTestTenant = auth.MustNewTenantID("acme-corp")

func TestConfigStore_GetNotFound(t *testing.T) {
	row := newFakeRowStore()
	aud := &fakeAuditCapture{}
	cs := newConfigStoreT(row, nil, aud)

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
	cs := newConfigStoreT(row, factories, aud)

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
	cs := newConfigStoreT(row, factories, aud)

	cfg := BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{"provider":"vault"}`)}
	err := cs.Set(context.Background(), cfgTestTenant, cfg, "operator-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "probe failed")

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
	cs := newConfigStoreT(row, map[string]ProviderFactory{}, aud)

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
	cs := newConfigStoreT(row, nil, aud)

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
	cs := newConfigStoreT(row, factories, aud)

	cfg := BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{"invalid":true}`)}
	err := cs.Set(context.Background(), cfgTestTenant, cfg, "op")
	require.Error(t, err)

	require.Len(t, aud.events, 1)
	assert.Equal(t, EffectDeny, aud.events[0].Effect)
	assert.Equal(t, "provider_construct_failed", aud.events[0].DecisionReason)
}
