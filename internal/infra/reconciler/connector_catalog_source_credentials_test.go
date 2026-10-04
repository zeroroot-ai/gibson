package reconciler

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// TestConnectorInstanceCatalogSource_CarriesDeclaredCredentials proves the
// desired set carries each declared credential ref with its derived env
// name, and that a connector with auth none but declared credentials is in
// the set (gibson#597). Without this the materializer never saw the refs.
func TestConnectorInstanceCatalogSource_CarriesDeclaredCredentials(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := connectorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ci := &connectorv1alpha1.ConnectorInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "connector-public", Namespace: "tenant-acme", UID: "uid-1"},
		Spec: connectorv1alpha1.ConnectorInstanceSpec{
			Connector: "connector-public",
			Auth:      connectorv1alpha1.ConnectorAuthNone,
			Credentials: []connectorv1alpha1.CredentialRef{
				{Key: "api-key"},
				{Key: "vendor-creds", Property: "token", TargetEnv: "VENDOR_TOKEN"},
			},
		},
	}
	plain := &connectorv1alpha1.ConnectorInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "connector-plain", Namespace: "tenant-acme", UID: "uid-2"},
		Spec:       connectorv1alpha1.ConnectorInstanceSpec{Connector: "connector-plain", Auth: connectorv1alpha1.ConnectorAuthNone},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ci, plain).Build()
	src := &ConnectorInstanceCatalogSource{Lister: c}

	desired, err := src.DesiredConnectors(context.Background())
	if err != nil {
		t.Fatalf("DesiredConnectors: %v", err)
	}
	if len(desired) != 1 || desired[0].Connector != "connector-public" {
		t.Fatalf("desired = %+v, want only the connector with declared credentials", desired)
	}
	got := desired[0].Credentials
	want := []ConnectorCredentialRef{
		{Key: "api-key", TargetEnv: "API_KEY"},
		{Key: "vendor-creds", Property: "token", TargetEnv: "VENDOR_TOKEN"},
	}
	if len(got) != len(want) {
		t.Fatalf("credentials = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("credentials[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}
