// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// fakeDesiredDaemon is the daemon of a test. adopt adds the pair to the
// desired set, as the daemon table does.
type fakeDesiredDaemon struct {
	desired  []*daemonoperatorv1.DesiredConnector
	listErr  error
	reports  []*daemonoperatorv1.ReportConnectorStatusRequest
	adopted  []string
	adoptErr error

	// cred is the answer of ConnectorCredential, credErr makes it fail, and
	// credReqs records each request.
	cred     *daemonoperatorv1.GetConnectorCredentialResponse
	credErr  error
	credReqs []*daemonoperatorv1.GetConnectorCredentialRequest
}

func (f *fakeDesiredDaemon) ConnectorCredential(
	_ context.Context, req *daemonoperatorv1.GetConnectorCredentialRequest,
) (*daemonoperatorv1.GetConnectorCredentialResponse, error) {
	f.credReqs = append(f.credReqs, req)
	if f.credErr != nil {
		return nil, f.credErr
	}
	if f.cred == nil {
		return &daemonoperatorv1.GetConnectorCredentialResponse{}, nil
	}
	return f.cred, nil
}

func (f *fakeDesiredDaemon) ListDesiredConnectors(context.Context) ([]*daemonoperatorv1.DesiredConnector, error) {
	return f.desired, f.listErr
}

func (f *fakeDesiredDaemon) ReportConnectorStatus(_ context.Context, req *daemonoperatorv1.ReportConnectorStatusRequest) error {
	f.reports = append(f.reports, req)
	return nil
}

func (f *fakeDesiredDaemon) AdoptConnector(_ context.Context, tenant, connector string) error {
	if f.adoptErr != nil {
		return f.adoptErr
	}
	f.adopted = append(f.adopted, pairKey(tenant, connector))
	f.desired = append(f.desired, gitlabWish(tenant))
	return nil
}

func (f *fakeDesiredDaemon) lastReport(t *testing.T) *daemonoperatorv1.ReportConnectorStatusRequest {
	t.Helper()
	if len(f.reports) == 0 {
		t.Fatal("the loop sent no report")
	}
	return f.reports[len(f.reports)-1]
}

func gitlabWish(tenant string) *daemonoperatorv1.DesiredConnector {
	return &daemonoperatorv1.DesiredConnector{
		TenantId: tenant, ConnectorId: "gitlab", Shape: "Remote",
		Endpoint: "https://gitlab.com/api/v4/mcp", Transport: "streamable-http", Auth: "oauth",
		EgressAllow: []string{"gitlab.com:443"},
	}
}

func desiredLoop(t *testing.T, d *fakeDesiredDaemon, objs ...client.Object) (*DesiredConnectorsRunnable, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := connectorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&connectorv1alpha1.ConnectorInstance{}).Build()
	return &DesiredConnectorsRunnable{Audit: (&audittest.Sink{}).Emitter(t), Client: c, Daemon: d}, c
}

func getCI(t *testing.T, c client.Client, ns, name string) (*connectorv1alpha1.ConnectorInstance, bool) {
	t.Helper()
	ci := &connectorv1alpha1.ConnectorInstance{}
	err := c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, ci)
	if apierrors.IsNotFound(err) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("get %s/%s: %v", ns, name, err)
	}
	return ci, true
}

func managedCI(ns, name, managedBy string) *connectorv1alpha1.ConnectorInstance {
	return &connectorv1alpha1.ConnectorInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{labelManagedBy: managedBy}},
		Spec:       connectorv1alpha1.ConnectorInstanceSpec{Connector: name},
	}
}

// One pass makes the ConnectorInstance of a wish, with the spec of the catalog
// entry and the label of the loop, and reports its phase.
func TestDesiredConnectors_MakesTheInstance(t *testing.T) {
	d := &fakeDesiredDaemon{desired: []*daemonoperatorv1.DesiredConnector{gitlabWish("acme")}}
	r, c := desiredLoop(t, d)
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	ci, ok := getCI(t, c, "tenant-acme", "gitlab")
	if !ok {
		t.Fatal("the ConnectorInstance was not made")
	}
	if ci.Labels[labelManagedBy] != connectorOperatorManagedBy || ci.Labels[labelConnectorID] != "gitlab" {
		t.Errorf("labels = %v", ci.Labels)
	}
	if ci.Spec.Shape != connectorv1alpha1.ConnectorShapeRemote || ci.Spec.Endpoint == "" ||
		ci.Spec.Runtime != connectorv1alpha1.ConnectorRuntimePod || ci.Spec.Auth != connectorv1alpha1.ConnectorAuthOAuth {
		t.Errorf("spec = %+v", ci.Spec)
	}
	if got := d.lastReport(t); got.GetPhase() != "Pending" || got.GetTenantId() != "acme" {
		t.Errorf("report = %v, want Pending for acme", got)
	}

	// The phase that the ConnectorInstance controller sets reaches the daemon.
	ci.Status.Phase = connectorv1alpha1.ConnectorInstancePhaseReady
	if err := c.Status().Update(context.Background(), ci); err != nil {
		t.Fatal(err)
	}
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if got := d.lastReport(t); got.GetPhase() != "Ready" {
		t.Errorf("report = %v, want Ready", got)
	}
}

// A ConnectorInstance of the loop that no tenant wants is deleted. A
// ConnectorInstance without the label of the loop is never touched.
func TestDesiredConnectors_PrunesOnlyItsOwn(t *testing.T) {
	d := &fakeDesiredDaemon{}
	r, c := desiredLoop(t, d,
		managedCI("tenant-acme", "gitlab", connectorOperatorManagedBy),
		managedCI("tenant-acme", "slack", "someone-else"),
	)
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if _, ok := getCI(t, c, "tenant-acme", "gitlab"); ok {
		t.Error("a ConnectorInstance that no tenant wants still exists")
	}
	if _, ok := getCI(t, c, "tenant-acme", "slack"); !ok {
		t.Error("the prune deleted a ConnectorInstance that the loop does not own")
	}
}

// A ConnectorInstance that the daemon wrote before the table is adopted and
// kept, in the same pass.
func TestDesiredConnectors_AdoptsAndKeepsLegacyInstances(t *testing.T) {
	d := &fakeDesiredDaemon{}
	r, c := desiredLoop(t, d, managedCI("tenant-acme", "gitlab", legacyConnectorServiceManagedBy))
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if len(d.adopted) != 1 || d.adopted[0] != "acme/gitlab" {
		t.Fatalf("adopted = %v, want acme/gitlab", d.adopted)
	}
	ci, ok := getCI(t, c, "tenant-acme", "gitlab")
	if !ok {
		t.Fatal("an adopted ConnectorInstance was deleted")
	}
	if ci.Labels[labelManagedBy] != connectorOperatorManagedBy {
		t.Errorf("label = %q, want the label of the loop", ci.Labels[labelManagedBy])
	}

	// A second pass adopts nothing again.
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if len(d.adopted) != 1 {
		t.Errorf("adopted = %v, want one adoption only", d.adopted)
	}
}

// A legacy ConnectorInstance of a connector that left the catalog is not
// adopted, and the same pass deletes it.
func TestDesiredConnectors_LegacyInstanceOutsideTheCatalogIsDeleted(t *testing.T) {
	d := &fakeDesiredDaemon{adoptErr: status.Error(codes.NotFound, "no entry")}
	r, c := desiredLoop(t, d, managedCI("tenant-acme", "osv", legacyConnectorServiceManagedBy))
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if _, ok := getCI(t, c, "tenant-acme", "osv"); ok {
		t.Error("a ConnectorInstance outside the catalog still exists")
	}
}

// A failed pull removes nothing, and a failed adoption stops the pass before
// any delete.
func TestDesiredConnectors_ErrorsRemoveNothing(t *testing.T) {
	d := &fakeDesiredDaemon{listErr: errors.New("daemon down")}
	r, c := desiredLoop(t, d, managedCI("tenant-acme", "gitlab", connectorOperatorManagedBy))
	if err := r.converge(context.Background()); err == nil {
		t.Fatal("converge returned no error although the pull failed")
	}
	if _, ok := getCI(t, c, "tenant-acme", "gitlab"); !ok {
		t.Error("a failed pull deleted a ConnectorInstance")
	}

	d2 := &fakeDesiredDaemon{adoptErr: errors.New("daemon down")}
	r2, c2 := desiredLoop(t, d2,
		managedCI("tenant-acme", "gitlab", legacyConnectorServiceManagedBy),
		managedCI("tenant-acme", "slack", connectorOperatorManagedBy),
	)
	if err := r2.converge(context.Background()); err == nil {
		t.Fatal("converge returned no error although the adoption failed")
	}
	if _, ok := getCI(t, c2, "tenant-acme", "slack"); !ok {
		t.Error("a failed adoption let the prune run")
	}
}

// A ConnectorInstance with the name of a wish and a different owner is not
// taken over, and the loop reports Failed.
func TestDesiredConnectors_RefusesAForeignInstance(t *testing.T) {
	d := &fakeDesiredDaemon{desired: []*daemonoperatorv1.DesiredConnector{gitlabWish("acme")}}
	r, c := desiredLoop(t, d, managedCI("tenant-acme", "gitlab", "someone-else"))
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if got := d.lastReport(t); got.GetPhase() != "Failed" {
		t.Errorf("report = %v, want Failed", got)
	}
	ci, _ := getCI(t, c, "tenant-acme", "gitlab")
	if ci.Spec.Shape != "" {
		t.Error("the loop changed a ConnectorInstance that it does not own")
	}
}

// A change of the catalog entry reaches the ConnectorInstance, and the
// credential refs stay.
func TestDesiredConnectors_UpdatesTheSpecAndKeepsCredentials(t *testing.T) {
	existing := managedCI("tenant-acme", "gitlab", connectorOperatorManagedBy)
	existing.Spec.Credentials = []connectorv1alpha1.CredentialRef{{Key: "gitlab-token"}}
	d := &fakeDesiredDaemon{desired: []*daemonoperatorv1.DesiredConnector{gitlabWish("acme")}}
	r, c := desiredLoop(t, d, existing)
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	ci, _ := getCI(t, c, "tenant-acme", "gitlab")
	if ci.Spec.Endpoint != "https://gitlab.com/api/v4/mcp" {
		t.Errorf("endpoint = %q, want the catalog value", ci.Spec.Endpoint)
	}
	if len(ci.Spec.Credentials) != 1 {
		t.Errorf("credentials = %v, want them kept", ci.Spec.Credentials)
	}
}

func credSecret(t *testing.T, c client.Client, ns, name string) (*corev1.Secret, bool) {
	t.Helper()
	sec := &corev1.Secret{}
	err := c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name + "-connector-cred"}, sec)
	if apierrors.IsNotFound(err) {
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return sec, true
}

// The loop writes the connector-cred Secret from the daemon answer, with an
// ownerReference to the ConnectorInstance, and replaces its whole content.
func TestDesiredConnectors_WritesTheCredentialSecret(t *testing.T) {
	d := &fakeDesiredDaemon{
		desired: []*daemonoperatorv1.DesiredConnector{gitlabWish("acme")},
		cred: &daemonoperatorv1.GetConnectorCredentialResponse{Data: map[string][]byte{
			"authorization": []byte("Bearer t1"), "OLD": []byte("x"),
		}},
	}
	r, c := desiredLoop(t, d)
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	sec, ok := credSecret(t, c, "tenant-acme", "gitlab")
	if !ok {
		t.Fatal("the Secret was not written")
	}
	if string(sec.Data["authorization"]) != "Bearer t1" {
		t.Errorf("authorization = %q", sec.Data["authorization"])
	}
	ci, _ := getCI(t, c, "tenant-acme", "gitlab")
	if len(sec.OwnerReferences) != 1 || sec.OwnerReferences[0].Name != "gitlab" ||
		sec.OwnerReferences[0].UID != ci.UID || sec.OwnerReferences[0].Kind != "ConnectorInstance" {
		t.Errorf("ownerReferences = %+v", sec.OwnerReferences)
	}
	if req := d.credReqs[len(d.credReqs)-1]; req.GetTenantId() != "acme" || req.GetConnectorId() != "gitlab" {
		t.Errorf("credential request = %v", req)
	}

	// A rotated token replaces the content, and a key that left is gone.
	d.cred = &daemonoperatorv1.GetConnectorCredentialResponse{Data: map[string][]byte{"authorization": []byte("Bearer t2")}}
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	sec, _ = credSecret(t, c, "tenant-acme", "gitlab")
	if string(sec.Data["authorization"]) != "Bearer t2" || len(sec.Data) != 1 {
		t.Errorf("data after the rotation = %v", sec.Data)
	}

	// A token past its expiry is withdrawn.
	d.cred = &daemonoperatorv1.GetConnectorCredentialResponse{Withdraw: true}
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if _, ok := credSecret(t, c, "tenant-acme", "gitlab"); ok {
		t.Error("the Secret of an expired token still exists")
	}
}

// The declared credential refs go to the daemon with their env names, and a
// connector with no auth and no ref asks for nothing.
func TestDesiredConnectors_CredentialRequestAndNoAuth(t *testing.T) {
	existing := managedCI("tenant-acme", "gitlab", connectorOperatorManagedBy)
	existing.Spec.Credentials = []connectorv1alpha1.CredentialRef{{Key: "gitlab-pat", Property: "token", TargetEnv: "GITLAB_PAT"}}
	d := &fakeDesiredDaemon{desired: []*daemonoperatorv1.DesiredConnector{gitlabWish("acme")}}
	r, _ := desiredLoop(t, d, existing)
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	refs := d.credReqs[0].GetCredentials()
	if len(refs) != 1 || refs[0].GetKey() != "gitlab-pat" || refs[0].GetTargetEnv() != "GITLAB_PAT" {
		t.Fatalf("refs = %v", refs)
	}

	none := gitlabWish("acme")
	none.ConnectorId, none.Auth = "osv", "none"
	d2 := &fakeDesiredDaemon{desired: []*daemonoperatorv1.DesiredConnector{none}}
	r2, _ := desiredLoop(t, d2)
	if err := r2.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if len(d2.credReqs) != 0 {
		t.Errorf("a connector with no auth asked for a credential: %v", d2.credReqs)
	}
}

// A failed credential read leaves the Secret as it is and the pass goes on.
func TestDesiredConnectors_CredentialErrorKeepsTheSecret(t *testing.T) {
	d := &fakeDesiredDaemon{
		desired: []*daemonoperatorv1.DesiredConnector{gitlabWish("acme")},
		cred:    &daemonoperatorv1.GetConnectorCredentialResponse{Data: map[string][]byte{"authorization": []byte("Bearer t1")}},
	}
	r, c := desiredLoop(t, d)
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	d.credErr = errors.New("daemon down")
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("a credential error failed the pass: %v", err)
	}
	if sec, ok := credSecret(t, c, "tenant-acme", "gitlab"); !ok || string(sec.Data["authorization"]) != "Bearer t1" {
		t.Error("a failed read changed the Secret")
	}
}
