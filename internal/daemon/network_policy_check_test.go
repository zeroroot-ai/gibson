package daemon

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zero-day-ai/gibson/internal/observability"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func newTestLogger(buf *bytes.Buffer) *observability.Logger {
	return observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelDebug,
		Output:    buf,
	})
}

func TestValidateNetworkPolicies_NonSaaSMode(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	// When isSaaSMode is false, the function should return immediately
	// and not make any K8s API calls.
	validateNetworkPolicies(logger, "default", false)

	// Give a brief moment for any goroutine to start (it shouldn't)
	time.Sleep(100 * time.Millisecond)

	// No log output should be produced since we return before the goroutine
	assert.Empty(t, buf.String(), "expected no log output for non-SaaS mode")
}

func TestValidateNetworkPolicies_PoliciesExist(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	clientset := fake.NewSimpleClientset(&networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-tenant-isolation",
			Namespace: "gibson",
		},
	})

	doValidateNetworkPolicies(logger, "gibson", clientset)

	output := buf.String()
	assert.Contains(t, output, "network policy check passed")
	assert.Contains(t, output, "policy_count")
	// Should be INFO level
	assert.Contains(t, output, "INFO")
}

func TestValidateNetworkPolicies_NoPolicies(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	clientset := fake.NewSimpleClientset()

	doValidateNetworkPolicies(logger, "gibson", clientset)

	output := buf.String()
	assert.Contains(t, output, "SaaS mode enabled but no NetworkPolicy resources found")
	assert.Contains(t, output, "Tenant isolation may not be enforced")
	// Should be WARN level
	assert.Contains(t, output, "WARN")
}

func TestValidateNetworkPolicies_RBACDenied(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	clientset := fake.NewSimpleClientset()
	clientset.PrependReactor("list", "networkpolicies", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, fmt.Errorf("networkpolicies is forbidden: User cannot list resource \"networkpolicies\"")
	})

	doValidateNetworkPolicies(logger, "gibson", clientset)

	output := buf.String()
	assert.Contains(t, output, "unable to verify network policies")
	assert.Contains(t, output, "insufficient RBAC permissions")
	// Should be INFO level (not crash, not WARN)
	assert.Contains(t, output, "INFO")
	// Verify it does NOT contain WARN or ERROR
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		assert.NotContains(t, line, "WARN")
		assert.NotContains(t, line, "ERROR")
	}
}
