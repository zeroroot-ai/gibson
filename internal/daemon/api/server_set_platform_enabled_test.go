package api

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/daemon/operator/v1"
)

// gibson#682 — SetPlatformEnabled publishes/unpublishes a component to the
// shared catalog by writing/deleting platform_enabled on system_tenant:_system.
func TestSetPlatformEnabled_Publish_WritesWhenAbsent(t *testing.T) {
	fga := newFakeAuthorizer() // Check returns false (absent) by default
	s := &DaemonServer{authorizer: fga}

	resp, err := s.SetPlatformEnabled(context.Background(), &daemonoperatorv1.SetPlatformEnabledRequest{
		ComponentRef: "connector-gitlab",
		Published:    true,
	})
	if err != nil {
		t.Fatalf("SetPlatformEnabled: %v", err)
	}
	if !resp.GetWritten() {
		t.Error("expected Written=true when absent")
	}
	if len(fga.writes) != 1 ||
		fga.writes[0].User != "system_tenant:_system" ||
		fga.writes[0].Relation != "platform_enabled" ||
		fga.writes[0].Object != "component:connector-gitlab" {
		t.Errorf("unexpected write tuples: %+v", fga.writes)
	}
}

func TestSetPlatformEnabled_Publish_IdempotentWhenPresent(t *testing.T) {
	fga := newFakeAuthorizer().allow("system_tenant:_system", "platform_enabled", "component:connector-gitlab")
	s := &DaemonServer{authorizer: fga}
	resp, err := s.SetPlatformEnabled(context.Background(), &daemonoperatorv1.SetPlatformEnabledRequest{
		ComponentRef: "connector-gitlab", Published: true,
	})
	if err != nil {
		t.Fatalf("SetPlatformEnabled: %v", err)
	}
	if resp.GetWritten() {
		t.Error("expected Written=false when already published")
	}
}

func TestSetPlatformEnabled_EmptyComponentRef(t *testing.T) {
	s := &DaemonServer{authorizer: newFakeAuthorizer()}
	_, err := s.SetPlatformEnabled(context.Background(), &daemonoperatorv1.SetPlatformEnabledRequest{Published: true})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty component_ref must be InvalidArgument, got %v", err)
	}
}

// gibson#733 / ADR-0049 — publishing a shared connector (an mcp-bridge plugin)
// may carry the component manifest so the on-enable reconciler can launch a
// per-tenant sandbox from it. The manifest is validated up front.

const sharedMCPBridgeManifest = `apiVersion: plugin.gibson.zeroroot.ai/v1
kind: Plugin
metadata:
  name: connector-gitlab
  version: 0.1.0
spec:
  workload_class: plugin
  runtime: mcp-bridge
  mcp_bridge:
    transport: stdio
    vendor:
      command: npx
      args: ["-y", "@modelcontextprotocol/server-gitlab"]
`

func TestSetPlatformEnabled_Publish_ValidManifest_NoDBSkipsPersist(t *testing.T) {
	fga := newFakeAuthorizer()
	s := &DaemonServer{authorizer: fga} // no platformDB → persist is skipped

	resp, err := s.SetPlatformEnabled(context.Background(), &daemonoperatorv1.SetPlatformEnabledRequest{
		ComponentRef: "connector-gitlab",
		Published:    true,
		ManifestYaml: []byte(sharedMCPBridgeManifest),
	})
	if err != nil {
		t.Fatalf("SetPlatformEnabled with a valid manifest must succeed: %v", err)
	}
	if !resp.GetWritten() {
		t.Error("expected Written=true")
	}
}

func TestSetPlatformEnabled_Publish_InvalidManifest_Rejected(t *testing.T) {
	s := &DaemonServer{authorizer: newFakeAuthorizer()}
	_, err := s.SetPlatformEnabled(context.Background(), &daemonoperatorv1.SetPlatformEnabledRequest{
		ComponentRef: "connector-gitlab",
		Published:    true,
		ManifestYaml: []byte("this is not yaml: ["),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid manifest_yaml must be InvalidArgument, got %v", err)
	}
}

func TestSetPlatformEnabled_Publish_NonMCPBridgeManifest_Rejected(t *testing.T) {
	s := &DaemonServer{authorizer: newFakeAuthorizer()}
	plain := `apiVersion: plugin.gibson.zeroroot.ai/v1
kind: Plugin
metadata: {name: plain, version: 1.0.0}
spec:
  workload_class: plugin
  runtime: process
  methods:
    - name: Echo
`
	_, err := s.SetPlatformEnabled(context.Background(), &daemonoperatorv1.SetPlatformEnabledRequest{
		ComponentRef: "plain",
		Published:    true,
		ManifestYaml: []byte(plain),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a non-mcp-bridge manifest must be InvalidArgument, got %v", err)
	}
}

func TestSetPlatformEnabled_Unpublish_NoManifestStillSucceeds(t *testing.T) {
	fga := newFakeAuthorizer().allow("system_tenant:_system", "platform_enabled", "component:connector-gitlab")
	s := &DaemonServer{authorizer: fga} // no platformDB → DeleteShared skipped
	resp, err := s.SetPlatformEnabled(context.Background(), &daemonoperatorv1.SetPlatformEnabledRequest{
		ComponentRef: "connector-gitlab", Published: false,
	})
	if err != nil {
		t.Fatalf("unpublish must succeed: %v", err)
	}
	if !resp.GetDeleted() {
		t.Error("expected Deleted=true")
	}
}
