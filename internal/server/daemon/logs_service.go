// Package daemon — logs_service.go
//
// logsServer implements gibson.daemon.logs.v1.LogsService: the daemon-mediated
// read path into tenant-scoped mission and daemon logs stored in Loki (E9,
// gibson#811). It resolves the caller's tenant from context and folds that
// tenant into the Loki query server-side — the dashboard never fetches Loki
// directly and never supplies a tenant scope (the tenant-isolation fix). It
// mirrors worldServer exactly: daemon-local, tenant-scoped observability over a
// backing store, read through Envoy + ext-authz.
package daemon

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/observability/lokilogs"
	logspb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/logs/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// resolveLogsQuerier builds the Loki log querier for LogsService from
// GIBSON_LOKI_URL (e.g. "http://gibson-loki:3100"). Loki is optional
// infrastructure: when the env var is unset (or the client cannot be built) the
// service is still registered, but every call returns codes.Unavailable via the
// fallback querier, so the dashboard degrades cleanly instead of the daemon
// failing to boot.
func resolveLogsQuerier(logger *slog.Logger) lokilogs.Querier {
	baseURL := os.Getenv("GIBSON_LOKI_URL")
	if baseURL == "" {
		logger.Info("GIBSON_LOKI_URL unset; LogsService will report logs backend unavailable")
		return unavailableLogsQuerier{}
	}
	client, err := lokilogs.NewClient(lokilogs.Config{BaseURL: baseURL}, logger)
	if err != nil {
		logger.Warn("failed to build Loki log client; LogsService will report unavailable", slog.String("error", err.Error()))
		return unavailableLogsQuerier{}
	}
	return client
}

// unavailableLogsQuerier is the fallback used when Loki is not configured. It
// satisfies lokilogs.Querier and always reports the backend unavailable, which
// the handler maps to codes.Unavailable.
type unavailableLogsQuerier struct{}

func (unavailableLogsQuerier) QueryMissionLogs(context.Context, lokilogs.MissionQuery) ([]lokilogs.Entry, error) {
	return nil, lokilogs.ErrLokiUnavailable
}

func (unavailableLogsQuerier) QueryDaemonLogs(context.Context, lokilogs.DaemonQuery) ([]lokilogs.Entry, error) {
	return nil, lokilogs.ErrLokiUnavailable
}

type logsServer struct {
	logspb.UnimplementedLogsServiceServer

	querier lokilogs.Querier
	logger  *slog.Logger
}

// NewLogsServer constructs the LogsService backed by a Loki log querier.
func NewLogsServer(querier lokilogs.Querier, logger *slog.Logger) *logsServer {
	if querier == nil {
		panic("logs server: querier cannot be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &logsServer{querier: querier, logger: logger}
}

// tenant resolves the caller's tenant from context. Cross-tenant access is
// structurally impossible — the returned tenant is the ONLY scope this request
// can ever read, and the client never supplies it.
func (s *logsServer) tenant(ctx context.Context) (string, error) {
	t, ok := auth.TenantFromContext(ctx)
	if !ok {
		return "", status.Error(codes.PermissionDenied, "no tenant in context")
	}
	return t.String(), nil
}

func (s *logsServer) QueryMissionLogs(ctx context.Context, req *logspb.QueryMissionLogsRequest) (*logspb.QueryMissionLogsResponse, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetMissionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "mission_id is required")
	}
	entries, err := s.querier.QueryMissionLogs(ctx, lokilogs.MissionQuery{
		TenantID:  tenant,
		MissionID: req.GetMissionId(),
		Start:     nanosToTime(req.GetStartUnixNanos()),
		End:       nanosToTime(req.GetEndUnixNanos()),
		Limit:     int(req.GetLimit()),
	})
	if err != nil {
		return nil, lokiErr(err)
	}
	return &logspb.QueryMissionLogsResponse{Entries: toProto(entries)}, nil
}

func (s *logsServer) QueryDaemonLogs(ctx context.Context, req *logspb.QueryDaemonLogsRequest) (*logspb.QueryDaemonLogsResponse, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return nil, err
	}
	entries, err := s.querier.QueryDaemonLogs(ctx, lokilogs.DaemonQuery{
		TenantID:  tenant,
		Level:     levelString(req.GetLevel()),
		MissionID: req.GetMissionId(),
		Start:     nanosToTime(req.GetStartUnixNanos()),
		End:       nanosToTime(req.GetEndUnixNanos()),
		Limit:     int(req.GetLimit()),
	})
	if err != nil {
		return nil, lokiErr(err)
	}
	return &logspb.QueryDaemonLogsResponse{Entries: toProto(entries)}, nil
}

// nanosToTime converts a Unix-nanos field to a time.Time; 0 -> zero value
// (the client meaning "use the server default").
func nanosToTime(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}

// levelString maps the proto LogLevel enum to the Loki level token, "" for
// LOG_LEVEL_UNSPECIFIED (no filter).
func levelString(l logspb.LogLevel) string {
	switch l {
	case logspb.LogLevel_LOG_LEVEL_DEBUG:
		return "DEBUG"
	case logspb.LogLevel_LOG_LEVEL_INFO:
		return "INFO"
	case logspb.LogLevel_LOG_LEVEL_WARN:
		return "WARN"
	case logspb.LogLevel_LOG_LEVEL_ERROR:
		return "ERROR"
	default:
		return ""
	}
}

func toProto(entries []lokilogs.Entry) []*logspb.LogEntry {
	out := make([]*logspb.LogEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, &logspb.LogEntry{
			UnixNanos: e.UnixNanos,
			Line:      e.Line,
			Labels:    e.Labels,
		})
	}
	return out
}

// lokiErr maps a Loki-unavailable error to codes.Unavailable so the dashboard
// can degrade gracefully; anything else stays Internal.
func lokiErr(err error) error {
	if errors.Is(err, lokilogs.ErrLokiUnavailable) {
		return status.Error(codes.Unavailable, "logs backend unavailable")
	}
	return status.Error(codes.Internal, err.Error())
}
