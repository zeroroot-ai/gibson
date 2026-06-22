/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package controller's test suite. Uses envtest to spin up a real
// kube-apiserver + etcd, registers the platform-operator CRDs, and
// exposes a controller-runtime Manager that individual reconciler
// tests can attach to.
//
// Tests are intentionally lightweight smoke checks — they prove the
// Reconcile wiring (CRD shape, finalizer, status conditions) without
// exercising the full Zitadel/Vault/FGA matrix. Phase 4.1 of the spec
// landed this skeleton; comprehensive matrix coverage is a follow-up.
package controller

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
)

var (
	cfg       *rest.Config
	k8sClient client.Client
	testEnv   *envtest.Environment
	ctx       context.Context
	cancel    context.CancelFunc
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gibsonv1alpha1.AddToScheme(scheme))

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	_ = ctrl.SetupSignalHandler()

	// Generous timeout for envtest — kube-apiserver cold-start under
	// CI can take 10+ seconds.
	SetDefaultEventuallyTimeout(30 * time.Second)
	SetDefaultEventuallyPollingInterval(100 * time.Millisecond)
})

var _ = AfterSuite(func() {
	cancel()
	By("tearing down the test environment")
	Expect(testEnv.Stop()).To(Succeed())
})
