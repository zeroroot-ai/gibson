// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// connector_token_materializer_test.go — the daemon adapter that publishes a
// connector's fresh access token into the <connector>-connector-cred Secret
// (ADR-0015).
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/infra/reconciler"
	"github.com/zeroroot-ai/gibson/internal/platform/connectorauth"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	"github.com/zeroroot-ai/sdk/auth"
)

// fakeAccessStore is a tenant-oblivious connectorSecretResolver: the
// materializer scopes the tenant into ctx, and these tests use one tenant.
type fakeAccessStore struct{ data map[string][]byte }

func (s fakeAccessStore) Resolve(_ context.Context, name string) ([]byte, error) {
	v, ok := s.data[name]
	if !ok {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	return append([]byte(nil), v...), nil
}

// materializerKube builds a fake controller-runtime client carrying both the
// core Kubernetes types (for the Secret) and the ConnectorInstance API — the
// same scheme the daemon's real connector client uses.
func materializerKube(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := apiruntime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("clientgo scheme: %v", err)
	}
	if err := connectorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("connector scheme: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

// materializerNow is the fixed clock every materializer test measures the
// published token's expiry against.
var materializerNow = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

// accessMeta renders the platform's access-token bookkeeping blob with an
// expiry offset from materializerNow. It is what proves a token may still be
// served (ADR-0015 decision 4).
func accessMeta(t *testing.T, offset time.Duration) []byte {
	t.Helper()
	b, err := json.Marshal(connectorauth.AccessToken{ExpiresAt: materializerNow.Add(offset)})
	if err != nil {
		t.Fatalf("marshal access metadata: %v", err)
	}
	return b
}

func gitlabSandbox() reconciler.ConnectorSandbox {
	return reconciler.ConnectorSandbox{
		Tenant:       auth.MustNewTenantID("tenant-acme"),
		Connector:    "connector-gitlab",
		Namespace:    "tenant-acme",
		InstanceName: "connector-gitlab",
		InstanceUID:  types.UID("uid-123"),
	}
}

// Given a stored access token, Materialize writes the connector-cred Secret with
// the full "Bearer <token>" header under "authorization" and an ownerReference
// to the ConnectorInstance CR.
func TestConnectorTokenMaterializer_WritesBearerSecretWithOwnerRef(t *testing.T) {
	kube := materializerKube(t)
	store := fakeAccessStore{data: map[string][]byte{
		connectorauth.AccessSecretName("connector-gitlab"):     []byte("tok-abc"),
		connectorauth.AccessMetaSecretName("connector-gitlab"): accessMeta(t, time.Hour),
	}}
	m := &connectorTokenMaterializer{kube: kube, secrets: store, now: func() time.Time { return materializerNow }}

	if err := m.Materialize(context.Background(), gitlabSandbox()); err != nil {
		t.Fatalf("Materialize: %v", err)
	}

	var sec corev1.Secret
	key := client.ObjectKey{Namespace: "tenant-acme", Name: "connector-gitlab-connector-cred"}
	if err := kube.Get(context.Background(), key, &sec); err != nil {
		t.Fatalf("get materialized Secret: %v", err)
	}

	if got := string(sec.Data["authorization"]); got != "Bearer tok-abc" {
		t.Fatalf("authorization = %q, want %q", got, "Bearer tok-abc")
	}
	if sec.Type != corev1.SecretTypeOpaque {
		t.Errorf("Secret type = %q, want Opaque", sec.Type)
	}

	if len(sec.OwnerReferences) != 1 {
		t.Fatalf("owner references = %d, want 1", len(sec.OwnerReferences))
	}
	owner := sec.OwnerReferences[0]
	if owner.Kind != "ConnectorInstance" {
		t.Errorf("owner kind = %q, want ConnectorInstance", owner.Kind)
	}
	if owner.APIVersion != "gibson.zeroroot.ai/v1alpha1" {
		t.Errorf("owner apiVersion = %q, want gibson.zeroroot.ai/v1alpha1", owner.APIVersion)
	}
	if owner.Name != "connector-gitlab" {
		t.Errorf("owner name = %q, want connector-gitlab", owner.Name)
	}
	if owner.UID != types.UID("uid-123") {
		t.Errorf("owner uid = %q, want uid-123", owner.UID)
	}
}

// A connector with no published access token is a quiet no-op: no Secret is
// written and no error is returned (authorized-but-not-yet-minted).
func TestConnectorTokenMaterializer_NoTokenIsQuietNoOp(t *testing.T) {
	kube := materializerKube(t)
	m := &connectorTokenMaterializer{kube: kube, secrets: fakeAccessStore{data: map[string][]byte{}}}

	if err := m.Materialize(context.Background(), gitlabSandbox()); err != nil {
		t.Fatalf("Materialize with no token must be a no-op, got: %v", err)
	}

	var sec corev1.Secret
	key := client.ObjectKey{Namespace: "tenant-acme", Name: "connector-gitlab-connector-cred"}
	if err := kube.Get(context.Background(), key, &sec); !apierrors.IsNotFound(err) {
		t.Fatalf("no Secret may be written when there is no token; get err = %v", err)
	}
}

// Materialize is idempotent: a second pass updates the same Secret in place
// (self-heal) rather than failing or duplicating it.
func TestConnectorTokenMaterializer_UpdatesInPlace(t *testing.T) {
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "connector-gitlab-connector-cred", Namespace: "tenant-acme"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"authorization": []byte("Bearer stale")},
	}
	kube := materializerKube(t, existing)
	store := fakeAccessStore{data: map[string][]byte{
		connectorauth.AccessSecretName("connector-gitlab"):     []byte("tok-new"),
		connectorauth.AccessMetaSecretName("connector-gitlab"): accessMeta(t, time.Hour),
	}}
	m := &connectorTokenMaterializer{kube: kube, secrets: store, now: func() time.Time { return materializerNow }}

	if err := m.Materialize(context.Background(), gitlabSandbox()); err != nil {
		t.Fatalf("Materialize: %v", err)
	}

	var list corev1.SecretList
	if err := kube.List(context.Background(), &list, client.InNamespace("tenant-acme")); err != nil {
		t.Fatalf("list secrets: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("secret count = %d, want 1 (updated in place)", len(list.Items))
	}
	if got := string(list.Items[0].Data["authorization"]); got != "Bearer tok-new" {
		t.Fatalf("authorization = %q, want the refreshed %q", got, "Bearer tok-new")
	}
}

// --- ADR-0015 decision 4: no fallback cache

// TestConnectorTokenMaterializer_WithdrawsAnExpiredToken is the no-fallback-cache
// regression. The grant is revoked, the refresh fails, and the published access
// token passes its expiry. The credential Secret must go, because the ToolHive
// proxy presents whatever it mounts and would otherwise keep offering a dead
// token to the vendor for as long as the pod lives. Recovery is
// re-authorization, never a cached credential.
func TestConnectorTokenMaterializer_WithdrawsAnExpiredToken(t *testing.T) {
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "connector-gitlab-connector-cred", Namespace: "tenant-acme"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"authorization": []byte("Bearer tok-dead")},
	}
	kube := materializerKube(t, existing)
	store := fakeAccessStore{data: map[string][]byte{
		connectorauth.AccessSecretName("connector-gitlab"):     []byte("tok-dead"),
		connectorauth.AccessMetaSecretName("connector-gitlab"): accessMeta(t, -time.Second),
	}}
	m := &connectorTokenMaterializer{kube: kube, secrets: store, now: func() time.Time { return materializerNow }}

	if err := m.Materialize(context.Background(), gitlabSandbox()); err != nil {
		t.Fatalf("Materialize: %v", err)
	}

	var sec corev1.Secret
	key := client.ObjectKey{Namespace: "tenant-acme", Name: "connector-gitlab-connector-cred"}
	if err := kube.Get(context.Background(), key, &sec); !apierrors.IsNotFound(err) {
		t.Fatalf("an expired token must be withdrawn; get err = %v, secret = %v", err, sec.Data)
	}
}

// The withdrawal is idempotent: the next pass finds no Secret and succeeds, so
// a dead connector does not fill the log with the same failure every five
// minutes.
func TestConnectorTokenMaterializer_WithdrawIsIdempotent(t *testing.T) {
	kube := materializerKube(t)
	store := fakeAccessStore{data: map[string][]byte{
		connectorauth.AccessSecretName("connector-gitlab"):     []byte("tok-dead"),
		connectorauth.AccessMetaSecretName("connector-gitlab"): accessMeta(t, -time.Hour),
	}}
	m := &connectorTokenMaterializer{kube: kube, secrets: store, now: func() time.Time { return materializerNow }}

	for pass := 1; pass <= 2; pass++ {
		if err := m.Materialize(context.Background(), gitlabSandbox()); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
	}
}

// A token with no expiry bookkeeping is neither published nor withdrawn: the
// platform cannot prove it is live, and destroying a credential on a missing
// record would break a healthy connector. The refresher rewrites both secrets
// on its next pass, because it reads absent metadata as "needs refresh".
func TestConnectorTokenMaterializer_NoMetadataPublishesNothing(t *testing.T) {
	kube := materializerKube(t)
	store := fakeAccessStore{data: map[string][]byte{
		connectorauth.AccessSecretName("connector-gitlab"): []byte("tok-abc"),
	}}
	m := &connectorTokenMaterializer{kube: kube, secrets: store, now: func() time.Time { return materializerNow }}

	if err := m.Materialize(context.Background(), gitlabSandbox()); err != nil {
		t.Fatalf("Materialize: %v", err)
	}

	var sec corev1.Secret
	key := client.ObjectKey{Namespace: "tenant-acme", Name: "connector-gitlab-connector-cred"}
	if err := kube.Get(context.Background(), key, &sec); !apierrors.IsNotFound(err) {
		t.Fatalf("an unproven token must not be published; get err = %v", err)
	}
}

// Unreadable bookkeeping is loud, not silent: it proves neither freshness nor
// death, so the adapter publishes nothing and names the connector. The error
// never carries the broker bytes.
func TestConnectorTokenMaterializer_CorruptMetadataIsAnError(t *testing.T) {
	kube := materializerKube(t)
	store := fakeAccessStore{data: map[string][]byte{
		connectorauth.AccessSecretName("connector-gitlab"):     []byte("tok-abc"),
		connectorauth.AccessMetaSecretName("connector-gitlab"): []byte("{not json"),
	}}
	m := &connectorTokenMaterializer{kube: kube, secrets: store, now: func() time.Time { return materializerNow }}

	err := m.Materialize(context.Background(), gitlabSandbox())
	if err == nil {
		t.Fatal("corrupt access metadata must fail loud")
	}
	if got := err.Error(); !strings.Contains(got, "connector-gitlab") || strings.Contains(got, "tok-abc") {
		t.Errorf("error = %q, want the connector named and no token bytes", got)
	}
}

// A tenant store that fails for any reason other than "not found" is loud: a
// BYO Vault outage must not read as "nothing minted yet".
func TestConnectorTokenMaterializer_StoreFailureIsNotAMissingToken(t *testing.T) {
	kube := materializerKube(t)
	store := errorAccessStore{err: status.Error(codes.Unavailable, "byo vault unreachable")}
	m := &connectorTokenMaterializer{kube: kube, secrets: store, now: func() time.Time { return materializerNow }}

	err := m.Materialize(context.Background(), gitlabSandbox())
	if err == nil {
		t.Fatal("an unreachable tenant store must fail loud")
	}
	if !strings.Contains(err.Error(), "connector-gitlab") {
		t.Errorf("error = %q, want the connector named", err.Error())
	}
}

// errorAccessStore fails every Resolve, standing in for a tenant secret store
// the daemon cannot reach.
type errorAccessStore struct{ err error }

func (s errorAccessStore) Resolve(context.Context, string) ([]byte, error) { return nil, s.err }

// A withdrawal the API server refuses is reported, so a credential that could
// not be taken out of service is visible instead of silently assumed gone.
func TestConnectorTokenMaterializer_WithdrawFailureIsReported(t *testing.T) {
	kube := &deleteFailingClient{Client: materializerKube(t), err: errors.New("secret delete denied")}
	store := fakeAccessStore{data: map[string][]byte{
		connectorauth.AccessSecretName("connector-gitlab"):     []byte("tok-dead"),
		connectorauth.AccessMetaSecretName("connector-gitlab"): accessMeta(t, -time.Minute),
	}}
	m := &connectorTokenMaterializer{kube: kube, secrets: store, now: func() time.Time { return materializerNow }}

	err := m.Materialize(context.Background(), gitlabSandbox())
	if err == nil {
		t.Fatal("a refused withdrawal must be reported")
	}
	if !strings.Contains(err.Error(), "connector-gitlab-connector-cred") {
		t.Errorf("error = %q, want the Secret named", err.Error())
	}
}

// deleteFailingClient fails every Delete and passes everything else through.
type deleteFailingClient struct {
	client.Client
	err error
}

func (c *deleteFailingClient) Delete(context.Context, client.Object, ...client.DeleteOption) error {
	return c.err
}

// The default clock is time.Now: a materializer built without one still
// enforces expiry rather than treating every token as live.
func TestConnectorTokenMaterializer_DefaultClockIsNow(t *testing.T) {
	m := &connectorTokenMaterializer{}
	if got := m.clock(); got.IsZero() {
		t.Fatal("the default clock must return a real time")
	}
}
