package authz

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInspectRpc_EmbeddedHealth confirms the unauthenticated health probe
// is surfaced correctly.
func TestInspectRpc_EmbeddedHealth(t *testing.T) {
	cmd := newInspectRpcCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"/gibson.daemon.v1.DaemonService/Ping"})

	require.NoError(t, cmd.Execute())

	out := buf.String()
	assert.Contains(t, out, "/gibson.daemon.v1.DaemonService/Ping")
	assert.Contains(t, out, "source:          embedded")
	assert.Contains(t, out, "unauthenticated: true")
}

// TestInspectRpc_AuthenticatedTenantScoped exercises the
// "no object/object_from → tenant fallback" display path.
func TestInspectRpc_AuthenticatedTenantScoped(t *testing.T) {
	cmd := newInspectRpcCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"/gibson.daemon.v1.DaemonService/RunMission"})

	require.NoError(t, cmd.Execute())

	out := buf.String()
	assert.Contains(t, out, "relation:        member")
	assert.Contains(t, out, "object:          (tenant from request context)")
	assert.Contains(t, out, "unauthenticated: false")
}

// TestInspectRpc_LiteralObject covers the literal-object branch (Shutdown
// uses object: system_tenant:_system).
func TestInspectRpc_LiteralObject(t *testing.T) {
	cmd := newInspectRpcCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"/gibson.daemon.admin.v1.DaemonAdminService/Shutdown"})

	require.NoError(t, cmd.Execute())

	out := buf.String()
	assert.Contains(t, out, "relation:        platform_operator")
	assert.Contains(t, out, "object:          system_tenant:_system")
}

// TestInspectRpc_NamedResolver covers the object_from branch (any
// ComponentService entry uses object_from: component_system).
func TestInspectRpc_NamedResolver(t *testing.T) {
	cmd := newInspectRpcCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"/gibson.component.v1.ComponentService/Heartbeat"})

	require.NoError(t, cmd.Execute())

	out := buf.String()
	assert.Contains(t, out, "object_from:     component_system")
}

// TestInspectRpc_NotFound confirms the default-deny diagnostic message.
func TestInspectRpc_NotFound(t *testing.T) {
	cmd := newInspectRpcCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"/no.Such/Method"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/no.Such/Method")
	assert.Contains(t, err.Error(), "default-deny applies")
}

// TestListRpcs_StableSortedOutput pins the high-level shape of `list-rpcs`
// output without coupling the test to every entry's text. The drift-gate
// test (registry_drift_test.go) is the source of truth for the entry set;
// this test confirms the CLI surfaces them in a sane shape.
func TestListRpcs_StableSortedOutput(t *testing.T) {
	cmd := newListRpcsCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{})

	require.NoError(t, cmd.Execute())
	out := buf.String()

	// Should contain a representative entry from each of the three
	// services covered by the registry.
	assert.Contains(t, out, "/gibson.daemon.v1.DaemonService/Ping")
	assert.Contains(t, out, "/gibson.daemon.admin.v1.DaemonAdminService/Shutdown")
	assert.Contains(t, out, "/gibson.component.v1.ComponentService/Heartbeat")

	// Stable sort: methods appear in alphabetical order.
	lines := strings.Split(out, "\n")
	var methods []string
	for _, line := range lines {
		// Method lines start with `/` and have no leading whitespace.
		if strings.HasPrefix(line, "/") {
			methods = append(methods, line)
		}
	}
	require.NotEmpty(t, methods, "must surface at least one method")
	for i := 1; i < len(methods); i++ {
		assert.LessOrEqual(t, methods[i-1], methods[i],
			"methods must be sorted at index %d", i)
	}
}
