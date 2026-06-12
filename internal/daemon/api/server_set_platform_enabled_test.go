package api

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/platform-sdk/gen/gibson/daemon/operator/v1"
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
