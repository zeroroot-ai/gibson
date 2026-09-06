// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

// connectorinstance_authz_controller_test.go — seed / converge / removal
// coverage for the connector FGA authz controller (ADR-0067, gibson#1548).

import (
	"context"
	"errors"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

// authzStubFGA records writes/deletes and can simulate the already-exists
// idempotent path or a hard failure. Independent from the saga recordingFGA
// to avoid cross-package coupling.
type authzStubFGA struct {
	written  []fga.Tuple
	deleted  []fga.Tuple
	writeErr error
}

func (s *authzStubFGA) Write(_ context.Context, tuples []fga.Tuple) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	s.written = append(s.written, tuples...)
	return nil
}
func (s *authzStubFGA) WriteConditional(_ context.Context, _ fga.ConditionalTuple) error { return nil }
func (s *authzStubFGA) Delete(_ context.Context, tuples []fga.Tuple) error {
	s.deleted = append(s.deleted, tuples...)
	return nil
}
func (s *authzStubFGA) Read(_ context.Context, _ fga.Tuple) ([]fga.Tuple, error) { return nil, nil }
func (s *authzStubFGA) Check(_ context.Context, _, _, _ string) (bool, error)    { return false, nil }
func (s *authzStubFGA) Ping(_ context.Context) error                             { return nil }

var _ fga.Client = (*authzStubFGA)(nil)

func authzTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(connectorv1alpha1.AddToScheme(s))
	return s
}

func newAuthzReconciler(t *testing.T, fgaClient fga.Client, seed ...client.Object) *ConnectorInstanceAuthzReconciler {
	t.Helper()
	s := authzTestScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(seed...).
		Build()
	return &ConnectorInstanceAuthzReconciler{Client: cl, Scheme: s, FGA: fgaClient}
}

func connectorCR(name, namespace string, finalizers ...string) *connectorv1alpha1.ConnectorInstance {
	return &connectorv1alpha1.ConnectorInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Finalizers: finalizers,
		},
		Spec: connectorv1alpha1.ConnectorInstanceSpec{
			Connector: name,
			Shape:     connectorv1alpha1.ConnectorShapeHosted,
			Image:     "ghcr.io/example/mcp:latest",
			Runtime:   connectorv1alpha1.ConnectorRuntimePod,
			Auth:      connectorv1alpha1.ConnectorAuthNone,
		},
	}
}

func reconcileOnce(t *testing.T, r *ConnectorInstanceAuthzReconciler, name, namespace string) {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: name, Namespace: namespace},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

func TestConnectorAuthz_SeedsTuplesAndFinalizer(t *testing.T) {
	stub := &authzStubFGA{}
	r := newAuthzReconciler(t, stub, connectorCR("gitlab", "tenant-acme"))

	reconcileOnce(t, r, "gitlab", "tenant-acme")

	want := fga.ConnectorComponentTuples("gitlab", "acme")
	if len(stub.written) != len(want) {
		t.Fatalf("wrote %d tuples, want %d: %+v", len(stub.written), len(want), stub.written)
	}
	for i, tuple := range want {
		if stub.written[i] != tuple {
			t.Errorf("tuple[%d] = %+v, want %+v", i, stub.written[i], tuple)
		}
	}

	// The converge also reseeds away the retired plugin-object borrow.
	legacy := fga.LegacyConnectorInvokeTuple("gitlab", "acme")
	if len(stub.deleted) != 1 || stub.deleted[0] != legacy {
		t.Fatalf("legacy invoke tuple not reseeded away: deleted = %+v", stub.deleted)
	}

	var ci connectorv1alpha1.ConnectorInstance
	if err := r.Get(context.Background(), types.NamespacedName{Name: "gitlab", Namespace: "tenant-acme"}, &ci); err != nil {
		t.Fatalf("get: %v", err)
	}
	found := false
	for _, f := range ci.Finalizers {
		if f == connectorAuthzFinalizer {
			found = true
		}
	}
	if !found {
		t.Fatalf("finalizer %q missing: %v", connectorAuthzFinalizer, ci.Finalizers)
	}
}

func TestConnectorAuthz_ConvergeIsIdempotent(t *testing.T) {
	stub := &authzStubFGA{}
	r := newAuthzReconciler(t, stub, connectorCR("gitlab", "tenant-acme"))

	reconcileOnce(t, r, "gitlab", "tenant-acme")
	// Second pass: the real backend answers already-exists; that must be
	// swallowed as idempotent success.
	stub.writeErr = fmt.Errorf("fga 400: %w", clients.ErrAlreadyExists)
	reconcileOnce(t, r, "gitlab", "tenant-acme")
}

func TestConnectorAuthz_DeleteRemovesTuplesThenFinalizer(t *testing.T) {
	stub := &authzStubFGA{}
	r := newAuthzReconciler(t, stub,
		connectorCR("gitlab", "tenant-acme", connectorAuthzFinalizer))

	// Delete with the finalizer present sets deletionTimestamp.
	var ci connectorv1alpha1.ConnectorInstance
	if err := r.Get(context.Background(), types.NamespacedName{Name: "gitlab", Namespace: "tenant-acme"}, &ci); err != nil {
		t.Fatalf("get: %v", err)
	}
	if err := r.Delete(context.Background(), &ci); err != nil {
		t.Fatalf("delete: %v", err)
	}

	reconcileOnce(t, r, "gitlab", "tenant-acme")

	want := fga.ConnectorComponentTuples("gitlab", "acme")
	if len(stub.deleted) != len(want) {
		t.Fatalf("deleted %d tuples, want %d: %+v", len(stub.deleted), len(want), stub.deleted)
	}
	// Finalizer removal lets the fake client finish the delete.
	err := r.Get(context.Background(), types.NamespacedName{Name: "gitlab", Namespace: "tenant-acme"}, &ci)
	if err == nil {
		t.Fatal("CR still present after finalizer removal")
	}
}

func TestConnectorAuthz_FGAFailureBlocksDeletion(t *testing.T) {
	stub := &authzStubFGA{}
	r := newAuthzReconciler(t, stub,
		connectorCR("gitlab", "tenant-acme", connectorAuthzFinalizer))

	var ci connectorv1alpha1.ConnectorInstance
	if err := r.Get(context.Background(), types.NamespacedName{Name: "gitlab", Namespace: "tenant-acme"}, &ci); err != nil {
		t.Fatalf("get: %v", err)
	}
	if err := r.Delete(context.Background(), &ci); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Force the tuple removal to fail: deletion must NOT complete.
	failing := &authzStubFGADeleteFail{}
	r.FGA = failing
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "gitlab", Namespace: "tenant-acme"},
	}); err == nil {
		t.Fatal("want error when tuple removal fails")
	}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "gitlab", Namespace: "tenant-acme"}, &ci); err != nil {
		t.Fatalf("CR must survive while tuples remain: %v", err)
	}
}

func TestConnectorAuthz_NonTenantNamespaceIsIgnored(t *testing.T) {
	stub := &authzStubFGA{}
	r := newAuthzReconciler(t, stub, connectorCR("gitlab", "gibson-system"))

	reconcileOnce(t, r, "gitlab", "gibson-system")

	if len(stub.written) != 0 {
		t.Fatalf("wrote tuples for a non-tenant namespace: %+v", stub.written)
	}
}

// authzStubFGADeleteFail fails every Delete.
type authzStubFGADeleteFail struct{ authzStubFGA }

func (s *authzStubFGADeleteFail) Delete(_ context.Context, _ []fga.Tuple) error {
	return errors.New("fga unreachable")
}

func TestConnectorAuthz_FGAWriteFailureReturnsError(t *testing.T) {
	stub := &authzStubFGA{writeErr: errors.New("fga unreachable")}
	r := newAuthzReconciler(t, stub, connectorCR("gitlab", "tenant-acme"))

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "gitlab", Namespace: "tenant-acme"},
	}); err == nil {
		t.Fatal("want error when the tuple seed fails")
	}
}

func TestConnectorAuthz_GetAndUpdateErrorsPropagate(t *testing.T) {
	boom := errors.New("apiserver down")
	s := authzTestScheme(t)

	t.Run("get", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(s).
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
					return boom
				},
			}).Build()
		r := &ConnectorInstanceAuthzReconciler{Client: cl, Scheme: s, FGA: &authzStubFGA{}}
		if _, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "gitlab", Namespace: "tenant-acme"},
		}); !errors.Is(err, boom) {
			t.Fatalf("get error not propagated: %v", err)
		}
	})

	t.Run("update on add-finalizer", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(s).
			WithObjects(connectorCR("gitlab", "tenant-acme")).
			WithInterceptorFuncs(interceptor.Funcs{
				Update: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.UpdateOption) error {
					return boom
				},
			}).Build()
		r := &ConnectorInstanceAuthzReconciler{Client: cl, Scheme: s, FGA: &authzStubFGA{}}
		if _, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "gitlab", Namespace: "tenant-acme"},
		}); !errors.Is(err, boom) {
			t.Fatalf("update error not propagated: %v", err)
		}
	})

	t.Run("update on remove-finalizer", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(s).
			WithObjects(connectorCR("gitlab", "tenant-acme", connectorAuthzFinalizer)).
			WithInterceptorFuncs(interceptor.Funcs{
				Update: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.UpdateOption) error {
					return boom
				},
			}).Build()
		r := &ConnectorInstanceAuthzReconciler{Client: cl, Scheme: s, FGA: &authzStubFGA{}}
		var ci connectorv1alpha1.ConnectorInstance
		if err := r.Get(context.Background(), types.NamespacedName{Name: "gitlab", Namespace: "tenant-acme"}, &ci); err != nil {
			t.Fatalf("get: %v", err)
		}
		if err := r.Delete(context.Background(), &ci); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if _, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "gitlab", Namespace: "tenant-acme"},
		}); !errors.Is(err, boom) {
			t.Fatalf("update error not propagated: %v", err)
		}
	})
}

func TestConnectorAuthz_SetupWithManager(t *testing.T) {
	s := authzTestScheme(t)
	mgr, err := manager.New(&rest.Config{Host: "localhost:1"}, manager.Options{
		Scheme:  s,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	r := &ConnectorInstanceAuthzReconciler{Client: mgr.GetClient(), Scheme: s, FGA: &authzStubFGA{}}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatalf("SetupWithManager: %v", err)
	}
}
