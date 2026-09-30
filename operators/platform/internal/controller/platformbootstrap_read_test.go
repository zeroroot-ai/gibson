// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
)

// countingReader records every Get so a test can prove which client served
// the PlatformBootstrap read.
type countingReader struct {
	client.Reader
	gets int
}

func (c *countingReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	c.gets++
	return c.Reader.Get(ctx, key, obj, opts...)
}

// countingClient is a full client that records every Get.
type countingClient struct {
	client.Client
	gets int
}

func (c *countingClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	c.gets++
	return c.Client.Get(ctx, key, obj, opts...)
}

// The reconciler reads the PlatformBootstrap through the uncached API reader
// when it has one. The manager's cached client lags the reconciler's own
// status write by up to a second, and a pass that reads stale status repeats
// a side effect it already recorded: identity run 36680224658 mailed the
// Platform owner's setup link twice, one second apart, that way.
func TestReconcile_ReadsThePlatformBootstrapUncached(t *testing.T) {
	s := mustScheme(t)
	pb := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{Name: "platform"}}
	cached := fake.NewClientBuilder().WithScheme(s).WithObjects(pb).WithStatusSubresource(pb).Build()
	uncached := &countingReader{Reader: fake.NewClientBuilder().WithScheme(s).WithObjects(pb).Build()}
	cachedReads := &countingClient{Client: cached}
	r := &PlatformBootstrapReconciler{Client: cachedReads, APIReader: uncached, Scheme: s}

	// A PlatformBootstrap with no finalizer yet: Reconcile reads it, adds the
	// finalizer and returns. That is enough to see which reader served it.
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pb)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if uncached.gets != 1 {
		t.Fatalf("the uncached reader served %d reads, want 1", uncached.gets)
	}
	if cachedReads.gets != 0 {
		t.Fatalf("the cached client served %d reads, want 0", cachedReads.gets)
	}

	// Without an API reader (tests, and any manager that gives none) the
	// client itself serves the read.
	r2 := &PlatformBootstrapReconciler{Client: cachedReads, Scheme: s}
	if got, ok := r2.reader().(*countingClient); !ok || got != cachedReads {
		t.Fatalf("reader() without APIReader = %T, want the Client", got)
	}
}

// A status write that fails is a reconcile error, never a silent loss: the
// next pass would read the old status and repeat the step.
func TestFinish_SurfacesAFailedStatusWrite(t *testing.T) {
	s := mustScheme(t)
	pb := &gibsonv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{Name: "platform"}}
	boom := errors.New("etcdserver: request timed out")
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(pb).WithStatusSubresource(pb).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
				return boom
			},
		}).Build()
	r := &PlatformBootstrapReconciler{Client: cli, Scheme: s}

	res, err := r.finish(context.Background(), pb, ctrl.Result{RequeueAfter: 30}, nil)
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("a failed status write must surface, got err=%v", err)
	}
	if res.RequeueAfter != 30 {
		t.Fatalf("the step's result must be kept, got %+v", res)
	}

	stepErr := errors.New("zitadel: dial tcp: connection refused")
	_, err = r.finish(context.Background(), pb, ctrl.Result{}, stepErr)
	if !errors.Is(err, stepErr) || !errors.Is(err, boom) || !strings.Contains(err.Error(), "status write failed") {
		t.Fatalf("both the step error and the status write error must be kept, got %v", err)
	}

	// A working write returns the step's result and error unchanged.
	ok := fake.NewClientBuilder().WithScheme(s).WithObjects(pb).WithStatusSubresource(pb).Build()
	r = &PlatformBootstrapReconciler{Client: ok, Scheme: s}
	if _, err := r.finish(context.Background(), pb, ctrl.Result{}, nil); err != nil {
		t.Fatalf("a working status write must not fail the pass: %v", err)
	}
}
