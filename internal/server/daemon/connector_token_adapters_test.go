// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// connector_token_adapters_test.go — the ConnectorAuthService wiring and the
// freshener adapter between the token reconciler and connectorauth.
package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	apiruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/infra/resilience"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/connectorauth"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// ---------------------------------------------------------------------------
// Fakes for a minimal secrets.Service
// ---------------------------------------------------------------------------

// memBroker is an in-memory sdksecrets.Broker; tenant-oblivious because these
// tests exercise one tenant at a time.
type memBroker struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemBroker() *memBroker { return &memBroker{data: map[string][]byte{}} }

func (b *memBroker) Get(_ context.Context, _ auth.TenantID, name string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.data[name]
	if !ok {
		return nil, sdksecrets.ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (b *memBroker) Put(_ context.Context, _ auth.TenantID, name string, value []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data[name] = append([]byte(nil), value...)
	return nil
}

func (b *memBroker) Delete(_ context.Context, _ auth.TenantID, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.data, name)
	return nil
}

func (b *memBroker) List(_ context.Context, _ auth.TenantID, _ sdksecrets.Filter) ([]string, error) {
	return nil, nil
}

func (b *memBroker) Health(context.Context) error { return nil }
func (b *memBroker) Probe(context.Context) error  { return nil }
func (b *memBroker) Capabilities() sdksecrets.Capabilities {
	return sdksecrets.Capabilities{CanPut: true, CanDelete: true, CanList: true}
}

type memRegistry struct{ broker *memBroker }

func (r memRegistry) For(context.Context, auth.TenantID) (sdksecrets.Broker, error) {
	return r.broker, nil
}

type nopAuditWriter struct{}

func (nopAuditWriter) Audit(context.Context, secrets.AuditEvent) {}

func newTestSecretsService(t *testing.T, broker *memBroker) *secrets.Service {
	t.Helper()
	svc, err := secrets.NewService(
		memRegistry{broker: broker},
		secrets.NewGobreakerExecutor(resilience.CircuitConfig{}),
		nopAuditWriter{},
	)
	if err != nil {
		t.Fatalf("secrets.NewService: %v", err)
	}
	return svc
}

// wiringAuthorizer is a non-nil authz.Authorizer; nothing in the wiring path
// calls it.
type wiringAuthorizer struct{ authz.Authorizer }

// ---------------------------------------------------------------------------
// registerConnectorAuth wiring
// ---------------------------------------------------------------------------

const connectorAuthServiceName = "gibson.tenant.v1.ConnectorAuthService"

func TestRegisterConnectorAuth_StubWithoutSecretsStack(t *testing.T) {
	d := &daemonImpl{logger: testObservabilityLogger()}
	srv := grpc.NewServer()

	d.registerConnectorAuth(context.Background(), srv)

	if _, ok := srv.GetServiceInfo()[connectorAuthServiceName]; !ok {
		t.Fatal("ConnectorAuthService must be registered (as the Unavailable stub) without a secrets stack")
	}
	if d.connectorTokenReconciler != nil {
		t.Error("no reconciler may be built without a secrets stack")
	}
}

func TestRegisterConnectorAuth_RegistersServiceWithoutAuthorizer(t *testing.T) {
	// The OAuth token reconciler no longer depends on the FGA authorizer or the
	// platform DB (ADR-0065): its connector set comes from ConnectorInstance
	// CRs. So the service and its status book come up regardless of the
	// authorizer. (Whether the reconciler itself is built depends on a kube
	// client, exercised deterministically in the fake-client test below; the
	// no-reconciler path is pinned by the without-secrets-stack test.)
	d := &daemonImpl{
		logger:         testObservabilityLogger(),
		secretsService: newTestSecretsService(t, newMemBroker()),
	}
	srv := grpc.NewServer()

	d.registerConnectorAuth(context.Background(), srv)

	if _, ok := srv.GetServiceInfo()[connectorAuthServiceName]; !ok {
		t.Fatal("ConnectorAuthService must be registered")
	}
	if d.connectorTokenStatus == nil {
		t.Error("the status book must be initialised alongside the service")
	}
}

func TestRegisterConnectorAuth_BuildsReconcilerWithKubeClient(t *testing.T) {
	// The OAuth token reconciler's connector set now comes from ConnectorInstance
	// CRs (ADR-0065), so it needs a kube lister — not the FGA authorizer or the
	// platform DB. Injecting a fake client is enough to build it.
	d := &daemonImpl{
		logger:         testObservabilityLogger(),
		secretsService: newTestSecretsService(t, newMemBroker()),
		connectorKube:  fakeConnectorKube(t),
	}
	srv := grpc.NewServer()

	d.registerConnectorAuth(context.Background(), srv)

	if _, ok := srv.GetServiceInfo()[connectorAuthServiceName]; !ok {
		t.Fatal("ConnectorAuthService must be registered")
	}
	if d.connectorTokenReconciler == nil {
		t.Fatal("the token reconciler must be built when a kube client is present")
	}
}

// fakeConnectorKube builds a controller-runtime fake client carrying the
// ConnectorInstance scheme, so the token reconciler can be wired without a live
// cluster.
func fakeConnectorKube(t *testing.T) client.Client {
	t.Helper()
	scheme := apiruntime.NewScheme()
	if err := connectorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("connector scheme: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).Build()
}

// ---------------------------------------------------------------------------
// connectorTokenFreshener
// ---------------------------------------------------------------------------

func testFreshener(t *testing.T, broker *memBroker, vendor *httptest.Server) (*connectorTokenFreshener, *connectorauth.StatusBook) {
	t.Helper()
	var client *http.Client
	if vendor != nil {
		client = vendor.Client()
	}
	refresher, err := connectorauth.NewRefresher(newTestSecretsService(t, broker), client, nil)
	if err != nil {
		t.Fatalf("NewRefresher: %v", err)
	}
	book := connectorauth.NewStatusBook()
	return &connectorTokenFreshener{
		refresher: refresher,
		book:      book,
		now:       func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}, book
}

func seedBrokerGrant(t *testing.T, broker *memBroker, connector, tokenEndpoint string) {
	t.Helper()
	blob, err := connectorauth.MarshalGrant(&connectorauth.Grant{
		RefreshToken:  "rt-1",
		TokenEndpoint: tokenEndpoint,
		ClientID:      "client-abc",
		AuthorizedBy:  "user:1",
		AuthorizedAt:  time.Unix(1_690_000_000, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = broker.Put(context.Background(), auth.MustNewTenantID("acme"), connectorauth.GrantSecretName(connector), blob)
}

// A connector nobody has authorized is a quiet no-op, not an error and not a
// status-book entry.
func TestConnectorTokenFreshener_NoGrantIsAQuietNoOp(t *testing.T) {
	f, book := testFreshener(t, newMemBroker(), nil)
	tenant := auth.MustNewTenantID("acme")

	refreshed, err := f.EnsureFresh(context.Background(), tenant, "connector-gitlab")
	if err != nil || refreshed {
		t.Fatalf("EnsureFresh = (%v, %v), want quiet no-op", refreshed, err)
	}
	if _, ok := book.Get("acme", "connector-gitlab"); ok {
		t.Error("no-grant must not be recorded as a refresh attempt")
	}
}

func TestConnectorTokenFreshener_RecordsASuccessfulRefresh(t *testing.T) {
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-1", "expires_in": 7200})
	}))
	defer vendor.Close()
	broker := newMemBroker()
	seedBrokerGrant(t, broker, "connector-gitlab", vendor.URL)
	f, book := testFreshener(t, broker, vendor)
	tenant := auth.MustNewTenantID("acme")

	refreshed, err := f.EnsureFresh(context.Background(), tenant, "connector-gitlab")
	if err != nil || !refreshed {
		t.Fatalf("EnsureFresh = (%v, %v), want a refresh", refreshed, err)
	}
	st, ok := book.Get("acme", "connector-gitlab")
	if !ok || st.LastError != "" {
		t.Fatalf("success must be recorded with no error; got %+v ok=%v", st, ok)
	}
}

func TestConnectorTokenFreshener_RecordsAFailedRefresh(t *testing.T) {
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer vendor.Close()
	broker := newMemBroker()
	seedBrokerGrant(t, broker, "connector-gitlab", vendor.URL)
	f, book := testFreshener(t, broker, vendor)
	tenant := auth.MustNewTenantID("acme")

	_, err := f.EnsureFresh(context.Background(), tenant, "connector-gitlab")
	if err == nil {
		t.Fatal("a vendor refusal must surface")
	}
	st, ok := book.Get("acme", "connector-gitlab")
	if !ok || st.LastError == "" {
		t.Fatalf("the failure must be recorded; got %+v ok=%v", st, ok)
	}
}

// The secrets service returns gRPC NotFound for an absent name; the adapter
// depends on that mapping to classify "no grant". This pins it end to end
// through a real secrets.Service.
func TestConnectorTokenFreshener_NotFoundMappingHolds(t *testing.T) {
	svc := newTestSecretsService(t, newMemBroker())
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	_, err := svc.Resolve(ctx, connectorauth.GrantSecretName("connector-gitlab"))
	if status.Code(err) != codes.NotFound {
		t.Fatalf("secrets.Service must map an absent secret to NotFound, got %v", err)
	}
}
