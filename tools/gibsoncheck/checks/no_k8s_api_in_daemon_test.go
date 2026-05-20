package checks_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zero-day-ai/gibson/tools/gibsoncheck/checks"
)

// TestNoK8sAPIInDaemon_DaemonViolation verifies that a package under
// github.com/zero-day-ai/gibson/internal/daemon/ that imports any
// k8s.io/client-go subpackage is flagged.
func TestNoK8sAPIInDaemon_DaemonViolation(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.NoK8sAPIInDaemonAnalyzer,
		"github.com/zero-day-ai/gibson/internal/daemon/nok8sviolation")
}

// TestNoK8sAPIInDaemon_DaemonClean verifies that a daemon package with
// no K8s imports produces zero diagnostics.
func TestNoK8sAPIInDaemon_DaemonClean(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, checks.NoK8sAPIInDaemonAnalyzer,
		"github.com/zero-day-ai/gibson/internal/daemon/nok8sclean")
}

// TestNoK8sAPIInDaemon_AdminPoolExempt verifies that
// internal/datapool/admin/* is allowlisted — admin enumeration is
// legitimate behind the adminpoolacquire gate.
func TestNoK8sAPIInDaemon_AdminPoolExempt(t *testing.T) {
	testdata := analysistest.TestData()
	// No // want comments — exempt path produces zero diagnostics.
	analysistest.Run(t, testdata, checks.NoK8sAPIInDaemonAnalyzer,
		"github.com/zero-day-ai/gibson/internal/datapool/admin/k8sexempt")
}

// TestNoK8sAPIInDaemon_SagaExempt verifies that pkg/platform/saga/*
// is allowlisted — operator-shared library (S11 audit disposition).
func TestNoK8sAPIInDaemon_SagaExempt(t *testing.T) {
	testdata := analysistest.TestData()
	// No // want comments — exempt path produces zero diagnostics.
	analysistest.Run(t, testdata, checks.NoK8sAPIInDaemonAnalyzer,
		"github.com/zero-day-ai/gibson/pkg/platform/saga/k8sexempt")
}
