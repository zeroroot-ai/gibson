// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

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
	"os"
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
	// envtest suites require the kubebuilder control-plane binaries
	// (etcd + kube-apiserver). The unit-test CI lane (build.yaml's flat
	// `go test ./...`) and bare local runs do not provide them, so the
	// suite must skip rather than hard-fail at BeforeSuite when the assets
	// are genuinely absent (gibson#920). CI's integration lane runs
	// `setup-envtest` first, which exports KUBEBUILDER_ASSETS, so the suite
	// still runs for real there — this skip never hides a regression in a
	// lane that has the binaries.
	if !envtestAssetsAvailable() {
		t.Skip("skipping envtest controller suite: kubebuilder assets absent " +
			"(set KUBEBUILDER_ASSETS or run `make test`, which invokes setup-envtest)")
	}

	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

// envtestAssetsAvailable reports whether the kubebuilder control-plane
// binaries can be located — either via KUBEBUILDER_ASSETS (set by
// setup-envtest) or the locally-downloaded `bin/k8s/<ver>` directory.
func envtestAssetsAvailable() bool {
	if os.Getenv("KUBEBUILDER_ASSETS") != "" {
		return true
	}
	return getFirstFoundEnvTestBinaryDir() != ""
}

// getFirstFoundEnvTestBinaryDir locates the first binary directory under
// the locally-downloaded `bin/k8s/` tree (populated by setup-envtest with
// `--bin-dir bin`). Returns "" when none exists.
func getFirstFoundEnvTestBinaryDir() string {
	basePath := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(basePath, entry.Name())
		}
	}
	return ""
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	// Allow running from IDEs / local `make test` where assets live under
	// bin/k8s/ rather than on KUBEBUILDER_ASSETS.
	if dir := getFirstFoundEnvTestBinaryDir(); dir != "" {
		testEnv.BinaryAssetsDirectory = dir
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
