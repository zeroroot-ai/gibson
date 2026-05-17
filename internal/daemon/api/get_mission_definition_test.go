// Package api — get_mission_definition_test.go unit tests for DaemonService.GetMissionDefinition.
//
// Spec: mission-author-experience M5 (gibson#134).
package api

import (
	"context"
	"strings"
	"testing"

	daemonpb "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/v1"
)

// TestGetMissionDefinition_EmptyName verifies that an empty name returns
// codes.InvalidArgument.
func TestGetMissionDefinition_EmptyName(t *testing.T) {
	t.Parallel()
	srv := &DaemonServer{} // no pool
	_, err := srv.GetMissionDefinition(context.Background(), &daemonpb.GetMissionDefinitionRequest{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "name") {
		t.Errorf("expected 'name' in error message, got: %v", err)
	}
	assertGRPCStatusCode(t, err, "InvalidArgument")
}

// TestGetMissionDefinition_NilPool_Unavailable verifies that a nil poolGetter
// returns codes.Unavailable.
func TestGetMissionDefinition_NilPool_Unavailable(t *testing.T) {
	t.Parallel()
	srv := &DaemonServer{} // poolGetter = nil
	_, err := srv.GetMissionDefinition(context.Background(),
		&daemonpb.GetMissionDefinitionRequest{Name: "some-def"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	assertGRPCStatusCode(t, err, "Unavailable")
}
