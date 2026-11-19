// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/outsideagent"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

func syncTestManager(t *testing.T) manager.Manager {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := gibsonv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	mgr, err := manager.New(&rest.Config{Host: "localhost:1"}, manager.Options{
		Scheme:     scheme,
		Metrics:    metricsserver.Options{BindAddress: "0"},
		Controller: config.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	return mgr
}

func syncScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := gibsonv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

// stoppingRecords reads no records. It cancels the context on its second call,
// so a loop that runs on a short interval stops after two passes.
type stoppingRecords struct {
	calls  int
	cancel context.CancelFunc
}

func (s *stoppingRecords) TenantModelProviders(
	_ context.Context, _ string,
) ([]provision.DesiredModelProvider, []string, error) {
	s.calls++
	if s.calls >= 2 {
		s.cancel()
	}
	return nil, nil, errors.New("the daemon is down")
}

type stoppingOutsideRecords struct {
	calls  int
	cancel context.CancelFunc
}

func (s *stoppingOutsideRecords) TenantOutsideAgents(
	_ context.Context, _ string,
) ([]provision.DesiredOutsideAgent, error) {
	s.calls++
	if s.calls >= 2 {
		s.cancel()
	}
	return nil, errors.New("the daemon is down")
}

func TestModelProviderSync_LeaderElectionSetupAndLoop(t *testing.T) {
	r := &ModelProviderSyncRunnable{}
	if !r.NeedLeaderElection() {
		t.Error("the loop must run on the leader only")
	}
	mgr := syncTestManager(t)
	if err := r.SetupWithManager(mgr); err == nil || !strings.Contains(err.Error(), "daemon client is nil") {
		t.Errorf("no daemon error = %v", err)
	}
	r.Daemon = &fakeRecords{}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatalf("SetupWithManager: %v", err)
	}
	if r.Client == nil {
		t.Error("the client was not taken from the manager")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := &stoppingRecords{cancel: cancel}
	scheme := syncScheme(t)
	ready := tenantObject("acme", gibsonv1alpha1.TenantPhaseReady)
	loop := &ModelProviderSyncRunnable{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(ready).Build(),
		Daemon: stop, Interval: time.Millisecond,
	}
	if err := loop.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if stop.calls < 2 {
		t.Errorf("the loop made %d passes, want at least 2 (a failed pass must not stop it)", stop.calls)
	}
}

func TestModelProviderSync_ClientFailuresAreReported(t *testing.T) {
	existing := func(name, url string) *gibsonv1alpha1.ModelProvider {
		return &gibsonv1alpha1.ModelProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: "tenant-acme", Labels: map[string]string{LabelModelProviderFromRecord: "true"},
			},
			Spec: gibsonv1alpha1.ModelProviderSpec{
				TenantID: "acme", Type: gibsonv1alpha1.ModelProviderOpenAICompatible, BaseURL: url,
				CredentialSecret: "provider_cred:" + name,
			},
		}
	}
	record := provision.DesiredModelProvider{
		Name: "local", Type: "openai-compatible", BaseURL: "https://new.example", CredentialSecret: "provider_cred:local",
	}
	tests := []struct {
		name    string
		objs    []client.Object
		records []provision.DesiredModelProvider
		funcs   interceptor.Funcs
		wantErr string
	}{
		{
			name: "the tenants cannot be listed",
			funcs: interceptor.Funcs{List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList,
				_ ...client.ListOption,
			) error {
				return errInjected
			}},
			wantErr: "list tenants",
		},
		{
			name: "the model providers cannot be listed",
			funcs: interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList,
				opts ...client.ListOption,
			) error {
				if _, ok := list.(*gibsonv1alpha1.ModelProviderList); ok {
					return errInjected
				}
				return c.List(ctx, list, opts...)
			}},
			wantErr: "list the model providers",
		},
		{
			name: "a model provider without a record cannot be deleted",
			objs: []client.Object{existing("gone", "https://x")},
			funcs: interceptor.Funcs{Delete: func(_ context.Context, _ client.WithWatch, _ client.Object,
				_ ...client.DeleteOption,
			) error {
				return errInjected
			}},
			wantErr: "delete the model provider gone",
		},
		{
			name:    "a model provider cannot be created",
			records: []provision.DesiredModelProvider{record},
			funcs: interceptor.Funcs{Create: func(_ context.Context, _ client.WithWatch, _ client.Object,
				_ ...client.CreateOption,
			) error {
				return errInjected
			}},
			wantErr: "create the model provider local",
		},
		{
			name:    "a model provider cannot be updated",
			objs:    []client.Object{existing("local", "https://old.example")},
			records: []provision.DesiredModelProvider{record},
			funcs: interceptor.Funcs{Update: func(_ context.Context, _ client.WithWatch, _ client.Object,
				_ ...client.UpdateOption,
			) error {
				return errInjected
			}},
			wantErr: "update the model provider local",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := append([]client.Object{tenantObject("acme", gibsonv1alpha1.TenantPhaseReady)}, tt.objs...)
			c := fake.NewClientBuilder().WithScheme(syncScheme(t)).WithObjects(objs...).
				WithInterceptorFuncs(tt.funcs).Build()
			r := &ModelProviderSyncRunnable{
				Client: c, Daemon: &fakeRecords{byTenant: map[string][]provision.DesiredModelProvider{"acme": tt.records}},
			}
			err := r.Sync(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want one that holds %q", err, tt.wantErr)
			}
		})
	}
}

func TestModelProviderSync_ARecordThatAlreadyExistsIsNotAnError(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(syncScheme(t)).
		WithObjects(tenantObject("acme", gibsonv1alpha1.TenantPhaseReady)).
		WithInterceptorFuncs(interceptor.Funcs{Create: func(_ context.Context, _ client.WithWatch, obj client.Object,
			_ ...client.CreateOption,
		) error {
			return apierrors.NewAlreadyExists(schema.GroupResource{Resource: "modelproviders"}, obj.GetName())
		}}).Build()
	desired := provision.DesiredModelProvider{Name: "claude", Type: "anthropic"}
	desired.CredentialSecret = "provider_cred:claude"
	records := &fakeRecords{byTenant: map[string][]provision.DesiredModelProvider{"acme": {desired}}}
	r := &ModelProviderSyncRunnable{Client: c, Daemon: records}
	if err := r.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
}

func TestOutsideAgentSync_LeaderElectionSetupAndLoop(t *testing.T) {
	valid := outsideagent.Config{Namespace: testGatewayNS, GatewayName: "agent-gateway"}
	r := &OutsideAgentSyncRunnable{}
	if !r.NeedLeaderElection() {
		t.Error("the loop must run on the leader only")
	}
	mgr := syncTestManager(t)
	if err := r.SetupWithManager(mgr); err == nil || !strings.Contains(err.Error(), "daemon client is nil") {
		t.Errorf("no clients error = %v", err)
	}
	r = &OutsideAgentSyncRunnable{Daemon: &fakeOutsideRecords{}, Credentials: &fakeOutsideCredentials{}}
	if err := r.SetupWithManager(mgr); err == nil || !strings.Contains(err.Error(), "namespace is required") {
		t.Errorf("invalid render error = %v", err)
	}
	r.Render = valid
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatalf("SetupWithManager: %v", err)
	}
	if r.Client == nil {
		t.Error("the client was not taken from the manager")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := &stoppingOutsideRecords{cancel: cancel}
	loop := &OutsideAgentSyncRunnable{
		Client: fake.NewClientBuilder().WithScheme(syncScheme(t)).
			WithObjects(tenantObject("acme", gibsonv1alpha1.TenantPhaseReady)).Build(),
		Daemon: stop, Credentials: &fakeOutsideCredentials{}, Render: valid, Interval: time.Millisecond,
	}
	if err := loop.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if stop.calls < 2 {
		t.Errorf("the loop made %d passes, want at least 2", stop.calls)
	}
}

func ownedGatewayObject(kind, apiVersion, tenant, agent string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion(apiVersion)
	u.SetKind(kind)
	u.SetNamespace(testGatewayNS)
	u.SetName(outsideagent.ObjectName(tenant, agent))
	u.SetLabels(map[string]string{
		outsideagent.LabelManagedBy: "gibson-tenant-operator", outsideagent.LabelTenant: tenant,
		outsideagent.LabelOutsideAgent: agent,
	})
	return u
}

func TestOutsideAgentSync_ClientFailuresAreReported(t *testing.T) {
	withKey := map[string][]provision.DesiredOutsideAgent{
		"acme": {{Name: "scout", A2AURL: "https://scout.example/a2a", CredentialSecret: "scout-key"}},
	}
	noKey := map[string][]provision.DesiredOutsideAgent{
		"acme": {{Name: "scout", A2AURL: "https://scout.example/a2a"}},
	}
	goodCreds := &fakeOutsideCredentials{data: map[string]map[string][]byte{
		"acme/scout": {"Authorization": []byte("k")},
	}}
	tests := []struct {
		name    string
		records map[string][]provision.DesiredOutsideAgent
		creds   OutsideAgentCredentialSource
		objs    []client.Object
		funcs   interceptor.Funcs
		wantErr string
	}{
		{
			name: "the tenants cannot be listed",
			funcs: interceptor.Funcs{List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList,
				_ ...client.ListOption,
			) error {
				return errInjected
			}},
			wantErr: "list tenants",
		},
		{
			name:    "the unused credential Secret cannot be deleted",
			records: noKey,
			creds:   goodCreds,
			funcs: interceptor.Funcs{Delete: func(_ context.Context, _ client.WithWatch, _ client.Object,
				_ ...client.DeleteOption,
			) error {
				return errInjected
			}},
			wantErr: "delete the credential Secret",
		},
		{
			name:    "the daemon fails to give the credential",
			records: withKey,
			creds:   failingOutsideCredentials{},
			wantErr: "read the credential from the daemon",
		},
		{
			name:    "the daemon gives an empty credential",
			records: withKey,
			creds: &fakeOutsideCredentials{data: map[string]map[string][]byte{
				"acme/scout": {},
			}},
			wantErr: "empty credential",
		},
		{
			name:    "the credential Secret cannot be written",
			records: withKey,
			creds:   goodCreds,
			funcs: interceptor.Funcs{Create: func(_ context.Context, _ client.WithWatch, _ client.Object,
				_ ...client.CreateOption,
			) error {
				return errInjected
			}},
			wantErr: "create the credential Secret",
		},
		{
			name:    "a gateway object cannot be written",
			records: noKey,
			creds:   goodCreds,
			funcs: interceptor.Funcs{Create: func(_ context.Context, _ client.WithWatch, _ client.Object,
				_ ...client.CreateOption,
			) error {
				return errInjected
			}},
			wantErr: "create AgentgatewayBackend",
		},
		{
			name:    "the owned objects cannot be listed",
			records: noKey,
			creds:   goodCreds,
			funcs: interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList,
				opts ...client.ListOption,
			) error {
				if _, ok := list.(*unstructured.UnstructuredList); ok {
					return errInjected
				}
				return c.List(ctx, list, opts...)
			}},
			wantErr: "list AgentgatewayBackend",
		},
		{
			name:    "an object of a gone agent cannot be deleted",
			records: map[string][]provision.DesiredOutsideAgent{},
			creds:   goodCreds,
			objs:    []client.Object{ownedGatewayObject("HTTPRoute", "gateway.networking.k8s.io/v1", "acme", "old")},
			funcs: interceptor.Funcs{Delete: func(_ context.Context, _ client.WithWatch, _ client.Object,
				_ ...client.DeleteOption,
			) error {
				return errInjected
			}},
			wantErr: "delete HTTPRoute",
		},
		{
			name:    "the Secret of a gone agent cannot be deleted",
			records: map[string][]provision.DesiredOutsideAgent{},
			creds:   goodCreds,
			objs:    []client.Object{ownedGatewayObject("HTTPRoute", "gateway.networking.k8s.io/v1", "acme", "old")},
			funcs: interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch, obj client.Object,
				opts ...client.DeleteOption,
			) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return errInjected
				}
				return c.Delete(ctx, obj, opts...)
			}},
			wantErr: "delete the credential Secret",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := append([]client.Object{tenantObject("acme", gibsonv1alpha1.TenantPhaseReady)}, tt.objs...)
			c := fake.NewClientBuilder().WithScheme(syncScheme(t)).WithObjects(objs...).
				WithInterceptorFuncs(tt.funcs).Build()
			r := &OutsideAgentSyncRunnable{
				Client: c, Daemon: &fakeOutsideRecords{byTenant: tt.records}, Credentials: tt.creds,
				Render: outsideagent.Config{Namespace: testGatewayNS, GatewayName: "agent-gateway"},
			}
			err := r.Sync(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want one that holds %q", err, tt.wantErr)
			}
		})
	}
}

// failingOutsideCredentials fails each read with an error that is not "not found".
type failingOutsideCredentials struct{}

func (failingOutsideCredentials) OutsideAgentCredential(context.Context, string, string) (map[string][]byte, error) {
	return nil, errors.New("the daemon is down")
}

// A loop that has no interval uses its default, and it stops at once when the
// context has ended.
func TestSyncLoops_ADefaultIntervalStopsWithTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mp := &ModelProviderSyncRunnable{}
	if err := mp.Start(ctx); err != nil {
		t.Errorf("model provider loop: %v", err)
	}
	oa := &OutsideAgentSyncRunnable{}
	if err := oa.Start(ctx); err != nil {
		t.Errorf("outside agent loop: %v", err)
	}
}

func TestOutsideAgentSync_ARecordThatCannotBeRenderedIsReported(t *testing.T) {
	rec := &fakeOutsideRecords{byTenant: map[string][]provision.DesiredOutsideAgent{
		"acme": {{Name: "scout", A2AURL: "not a url"}},
	}}
	r, _ := outsideSyncRig(t, rec, &fakeOutsideCredentials{})
	err := r.Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "outside agent scout: render") {
		t.Fatalf("error = %v", err)
	}
}

func TestOutsideAgentSync_ATenantThatIsBeingDeletedLosesItsObjects(t *testing.T) {
	tenant := tenantObject("acme", gibsonv1alpha1.TenantPhaseReady)
	tenant.Finalizers = []string{"test/hold"}
	owned := ownedGatewayObject("HTTPRoute", "gateway.networking.k8s.io/v1", "acme", "scout")
	rec := &fakeOutsideRecords{byTenant: map[string][]provision.DesiredOutsideAgent{
		"acme": {{Name: "scout", A2AURL: "https://scout.example/a2a"}},
	}}
	r, c := outsideSyncRig(t, rec, &fakeOutsideCredentials{}, owned)
	if err := c.Delete(context.Background(), tenantObject("acme", "")); err != nil {
		t.Fatal(err)
	}
	// The fake client removes a tenant with no finalizer at once. Put it back
	// with a finalizer, then mark it for deletion.
	if err := c.Create(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(rec.asked) != 0 && rec.asked[0] == "acme" {
		t.Errorf("the records of a deleted tenant were read: %v", rec.asked)
	}
	route := schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRoute"}
	if _, ok := getGateway(t, c, route, outsideagent.ObjectName("acme", "scout")); ok {
		t.Error("the route of a deleted tenant stayed")
	}
}
