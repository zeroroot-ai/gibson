package auth

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// TestLogAuditEvent_AuthzAllowRoutesToInfo verifies the new authz_allow
// event type lands on slog.Info, matching existing auth_success routing.
func TestLogAuditEvent_AuthzAllowRoutesToInfo(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	logAuditEvent(context.Background(), logger, &AuditEvent{
		EventType:          "authz_allow",
		Method:             "/gibson.test.v1.TestService/TestMethod",
		Subject:            "alice",
		TenantID:           "tenant-a",
		Roles:              []string{"admin"},
		PermissionRequired: "team:manage",
		PermissionsGranted: []string{"team:manage", "missions:read"},
		Success:            true,
	})

	out := buf.String()
	if !strings.Contains(out, "level=INFO") {
		t.Errorf("authz_allow should route to INFO, got: %s", out)
	}
	if !strings.Contains(out, "authz_allow") {
		t.Errorf("log should contain authz_allow event type, got: %s", out)
	}
	if !strings.Contains(out, "permission_required=team:manage") {
		t.Errorf("log should contain permission_required, got: %s", out)
	}
}

// TestLogAuditEvent_AuthzDenyRoutesToWarn verifies the new authz_deny
// event type lands on slog.Warn, matching existing auth_failure routing.
func TestLogAuditEvent_AuthzDenyRoutesToWarn(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	logAuditEvent(context.Background(), logger, &AuditEvent{
		EventType:          "authz_deny",
		Method:             "/gibson.test.v1.TestService/SecretMethod",
		Subject:            "bob",
		TenantID:           "tenant-b",
		Roles:              []string{"viewer"},
		PermissionRequired: "tenants:provision",
		Reason:             "missing_permission: tenants:provision",
		Success:            false,
	})

	out := buf.String()
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("authz_deny should route to WARN, got: %s", out)
	}
	if !strings.Contains(out, "authz_deny") {
		t.Errorf("log should contain authz_deny event type, got: %s", out)
	}
	if !strings.Contains(out, "reason=") {
		t.Errorf("log should contain reason, got: %s", out)
	}
	if !strings.Contains(out, "permission_required=tenants:provision") {
		t.Errorf("log should contain permission_required, got: %s", out)
	}
}

// TestLogAuditEvent_PermissionsGrantedEmittedWhenPopulated verifies the
// new PermissionsGranted field is emitted as a slog attr when non-empty.
func TestLogAuditEvent_PermissionsGrantedEmittedWhenPopulated(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	logAuditEvent(context.Background(), logger, &AuditEvent{
		EventType:          "authz_allow",
		Method:             "/gibson.test.v1.TestService/M",
		PermissionsGranted: []string{"a:b", "c:d"},
	})

	out := buf.String()
	if !strings.Contains(out, "permissions_granted") {
		t.Errorf("log should contain permissions_granted when non-empty, got: %s", out)
	}
}

// TestLogAuditEvent_PermissionsGrantedOmittedWhenEmpty verifies the new
// field is NOT emitted when empty (keeps log output lean for auth events
// that have no authz context).
func TestLogAuditEvent_PermissionsGrantedOmittedWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	logAuditEvent(context.Background(), logger, &AuditEvent{
		EventType: "auth_success",
		Subject:   "alice",
	})

	out := buf.String()
	if strings.Contains(out, "permissions_granted") {
		t.Errorf("permissions_granted should be omitted when empty, got: %s", out)
	}
	if strings.Contains(out, "permission_required") {
		t.Errorf("permission_required should be omitted when empty, got: %s", out)
	}
}
