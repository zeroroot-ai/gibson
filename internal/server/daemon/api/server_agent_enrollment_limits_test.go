package api

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

func TestSetAgentEnrollmentLimits_UpsertsTheCap(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := newPendingServer()
	srv.platformDB = db

	mock.ExpectExec("INSERT INTO agent_enrollment_limits").
		WithArgs("acme", "breach-checker", int64(900)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	_, err = srv.SetAgentEnrollmentLimits(context.Background(), &daemonoperatorv1.SetAgentEnrollmentLimitsRequest{
		TenantId: "acme", AgentName: "breach-checker", MaxRuntimeSeconds: 900,
	})
	if err != nil {
		t.Fatalf("SetAgentEnrollmentLimits: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestSetAgentEnrollmentLimits_RefusesBadInput(t *testing.T) {
	srv := newPendingServer()
	for name, req := range map[string]*daemonoperatorv1.SetAgentEnrollmentLimitsRequest{
		"no tenant": {AgentName: "a", MaxRuntimeSeconds: 1},
		"no agent":  {TenantId: "acme", MaxRuntimeSeconds: 1},
		"negative":  {TenantId: "acme", AgentName: "a", MaxRuntimeSeconds: -1},
	} {
		_, err := srv.SetAgentEnrollmentLimits(context.Background(), req)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: code = %v, want InvalidArgument", name, status.Code(err))
		}
	}
	srv.platformDB = nil
	_, err := srv.SetAgentEnrollmentLimits(context.Background(), &daemonoperatorv1.SetAgentEnrollmentLimitsRequest{TenantId: "acme", AgentName: "a", MaxRuntimeSeconds: 1})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("no db: code = %v, want Unavailable", status.Code(err))
	}
}

func TestAgentRunLimit_ReadsTheCapBack(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mock.ExpectQuery("SELECT max_runtime_seconds FROM agent_enrollment_limits").
		WithArgs("acme", "breach-checker").
		WillReturnRows(sqlmock.NewRows([]string{"max_runtime_seconds"}).AddRow(int64(900)))
	limit, ok, err := AgentRunLimit(context.Background(), db, "acme", "breach-checker")
	if err != nil || !ok || limit != 15*time.Minute {
		t.Fatalf("AgentRunLimit = (%v, %v, %v), want (15m, true, nil)", limit, ok, err)
	}

	mock.ExpectQuery("SELECT max_runtime_seconds FROM agent_enrollment_limits").
		WithArgs("acme", "unknown").
		WillReturnRows(sqlmock.NewRows([]string{"max_runtime_seconds"}))
	if _, ok, err := AgentRunLimit(context.Background(), db, "acme", "unknown"); err != nil || ok {
		t.Fatalf("no row: ok=%v err=%v, want false, nil", ok, err)
	}

	mock.ExpectQuery("SELECT max_runtime_seconds FROM agent_enrollment_limits").
		WithArgs("acme", "cleared").
		WillReturnRows(sqlmock.NewRows([]string{"max_runtime_seconds"}).AddRow(int64(0)))
	if _, ok, err := AgentRunLimit(context.Background(), db, "acme", "cleared"); err != nil || ok {
		t.Fatalf("zero cap: ok=%v err=%v, want false, nil", ok, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// TestAgentEnrollmentLimits_DatabaseFailuresAreNamed proves a failed write is
// an Internal status that names the table, and a failed read names the tenant
// and the agent. Neither is a silently uncapped run.
func TestAgentEnrollmentLimits_DatabaseFailuresAreNamed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := newPendingServer()
	srv.platformDB = db

	mock.ExpectExec("INSERT INTO agent_enrollment_limits").WillReturnError(errors.New("connection reset"))
	_, err = srv.SetAgentEnrollmentLimits(context.Background(), &daemonoperatorv1.SetAgentEnrollmentLimitsRequest{
		TenantId: "acme", AgentName: "breach-checker", MaxRuntimeSeconds: 900,
	})
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "agent_enrollment_limits") {
		t.Errorf("write failure = %v, want Internal naming the table", err)
	}

	mock.ExpectQuery("SELECT max_runtime_seconds FROM agent_enrollment_limits").WillReturnError(errors.New("connection reset"))
	_, ok, err := AgentRunLimit(context.Background(), db, "acme", "breach-checker")
	if err == nil || ok || !strings.Contains(err.Error(), "acme/breach-checker") {
		t.Errorf("read failure = (ok=%v, %v), want an error naming acme/breach-checker", ok, err)
	}
}
