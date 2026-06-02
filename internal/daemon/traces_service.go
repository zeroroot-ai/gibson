// Package daemon — traces_service.go
//
// tracesServer implements tracespb.TracesServiceServer using the deferred
// credential-getter pattern established in graph_service.go. Each RPC:
//  1. Reads tenant from ctx (PermissionDenied if absent).
//  2. Resolves Langfuse credentials via credentialGetter() and the tenant ID.
//  3. Constructs a per-call langfuseClient from the decrypted credentials.
//  4. Executes the Langfuse REST call under a 10-second context timeout.
//  5. Marshals REST results to proto and returns.
//
// Tenant-scoping is enforced by the Langfuse project credentials themselves:
// each tenant is provisioned with a separate Langfuse project, and the
// credentials stored at infra/langfuse inside the tenant's Vault namespace
// scope all API calls to that project. Cross-tenant reads are structurally
// impossible — a caller in tenant A gets tenant A's credentials, which Langfuse
// rejects for tenant B's
// project.
//
// Spec: dashboard-no-backing-store-clients (Module 1 — TracesService).
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	daemonapi "github.com/zeroroot-ai/gibson/internal/daemon/api"
	tracespb "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/traces/v1"
	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
	"github.com/zeroroot-ai/sdk/auth"
)

const tracesQueryTimeout = 10 * time.Second

// tracesServer implements tracespb.TracesServiceServer.
// It uses the deferred-credential pattern: credentialGetter is called per-request
// so that the server can be registered before broker-stack initialization completes.
type tracesServer struct {
	tracespb.UnimplementedTracesServiceServer

	// credentialGetter returns the live CredentialHandler (may return nil before
	// the broker stack has been fully initialised). Nil return → Unavailable.
	credentialGetter func() *daemonapi.CredentialHandler
	logger           *slog.Logger
}

// NewTracesServer constructs a tracesServer.
// credentialGetter must not be nil. logger may be nil (defaults to slog.Default()).
func NewTracesServer(
	credentialGetter func() *daemonapi.CredentialHandler,
	logger *slog.Logger,
) *tracesServer {
	if credentialGetter == nil {
		panic("traces server: credentialGetter cannot be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &tracesServer{
		credentialGetter: credentialGetter,
		logger:           logger,
	}
}

// ---------------------------------------------------------------------------
// tracesLangfuseCredentialName mirrors langfuseCredentialName in the api
// package: the Langfuse project credentials live at pdataplane.VaultPathInfra-
// Langfuse ("infra/langfuse") — where the tenant-operator writes them and the
// per-tenant OpenBao policy grants read (secret/data/infra/*). The tenant is
// scoped by the per-tenant Vault namespace, so the name carries no tenant id.
// The legacy "langfuse_project:<id>" name resolved to a path the policy denied.
// ---------------------------------------------------------------------------

func tracesLangfuseCredentialName(_ string) string {
	return pdataplane.VaultPathInfraLangfuse
}

// resolveClient is the common preamble:
//  1. Read tenant from ctx → PermissionDenied if missing.
//  2. Get credential handler → Unavailable if nil.
//  3. Decrypt Langfuse credentials → NotFound if absent.
//  4. Construct langfuseClient.
func (s *tracesServer) resolveClient(ctx context.Context) (auth.TenantID, *langfuseClient, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok || tenant.IsZero() {
		return auth.TenantID{}, nil, status.Error(codes.PermissionDenied, "missing tenant in context")
	}

	credHandler := s.credentialGetter()
	if credHandler == nil {
		return auth.TenantID{}, nil, status.Error(codes.Unavailable, "credential handler not yet initialised")
	}

	name := tracesLangfuseCredentialName(tenant.String())
	_, decrypted, err := credHandler.GetDecrypted(ctx, name)
	if err != nil {
		s.logger.WarnContext(ctx, "TracesService: Langfuse credentials not found",
			slog.String("tenant", tenant.String()),
			slog.String("error", err.Error()),
		)
		return auth.TenantID{}, nil, status.Errorf(codes.NotFound, "Langfuse credentials not configured for this tenant")
	}

	var payload struct {
		PublicKey string `json:"public_key"`
		SecretKey string `json:"secret_key"`
		Host      string `json:"host"`
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal([]byte(decrypted), &payload); err != nil {
		s.logger.ErrorContext(ctx, "TracesService: failed to decode Langfuse credentials",
			slog.String("tenant", tenant.String()),
			slog.String("error", err.Error()),
		)
		return auth.TenantID{}, nil, status.Error(codes.Internal, "failed to decode Langfuse credentials")
	}

	client, err := newLangfuseClient(payload.Host, payload.PublicKey, payload.SecretKey)
	if err != nil {
		return auth.TenantID{}, nil, status.Errorf(codes.FailedPrecondition, "Langfuse credentials incomplete: %v", err)
	}

	return tenant, client, nil
}

// mapLangfuseError converts a typed langfuse error to the appropriate gRPC status.
func mapLangfuseError(err error) error {
	if err == nil {
		return nil
	}
	var authErr langfuseAuthError
	if errors.As(err, &authErr) {
		return status.Error(codes.PermissionDenied, "Langfuse credentials invalid")
	}
	var notFoundErr langfuseNotFoundError
	if errors.As(err, &notFoundErr) {
		return status.Errorf(codes.NotFound, "not found: %s", notFoundErr.resource)
	}
	var apiErr langfuseAPIError
	if errors.As(err, &apiErr) {
		return status.Errorf(codes.Internal, "Langfuse API error %d", apiErr.status)
	}
	return status.Errorf(codes.Internal, "Langfuse error: %v", err)
}

// parseTimestamp parses an ISO-8601 string into a *timestamppb.Timestamp.
// Returns nil on empty or unparseable input (never panics).
func parseTimestamp(s string) *timestamppb.Timestamp {
	if s == "" {
		return nil
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999Z",
		"2006-01-02T15:04:05Z",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return timestamppb.New(t)
		}
	}
	return nil
}

// traceToProto converts a langfuseTrace to a tracespb.TraceRecord.
func traceToProto(t *langfuseTrace) *tracespb.TraceRecord {
	if t == nil {
		return nil
	}
	return &tracespb.TraceRecord{
		Id:               t.ID,
		Name:             t.Name,
		Timestamp:        parseTimestamp(t.Timestamp),
		Tags:             t.Tags,
		UserId:           t.UserID,
		SessionId:        t.SessionID,
		TotalTokens:      t.TotalTokens,
		PromptTokens:     t.PromptTokens,
		CompletionTokens: t.CompletionTokens,
		LatencyMs:        t.Latency,
		ObservationIds:   t.Observations,
	}
}

// observationToProto converts a langfuseObservation to a tracespb.ObservationRecord.
func observationToProto(o *langfuseObservation) *tracespb.ObservationRecord {
	if o == nil {
		return nil
	}
	rec := &tracespb.ObservationRecord{
		Id:                  o.ID,
		TraceId:             o.TraceID,
		Type:                o.Type,
		Name:                o.Name,
		StartTime:           parseTimestamp(o.StartTime),
		EndTime:             parseTimestamp(o.EndTime),
		ParentObservationId: o.ParentObservationID,
		Model:               o.Model,
		PromptTokens:        o.PromptTokens,
		CompletionTokens:    o.CompletionTokens,
		TotalTokens:         o.TotalTokens,
		Level:               o.Level,
		StatusMessage:       o.StatusMessage,
	}
	if o.Input != nil {
		if b, err := json.Marshal(o.Input); err == nil {
			rec.InputJson = string(b)
		}
	}
	if o.Output != nil {
		if b, err := json.Marshal(o.Output); err == nil {
			rec.OutputJson = string(b)
		}
	}
	if o.Metadata != nil {
		if b, err := json.Marshal(o.Metadata); err == nil {
			rec.MetadataJson = string(b)
		}
	}
	return rec
}

// ---------------------------------------------------------------------------
// RPC implementations
// ---------------------------------------------------------------------------

// ListTraces implements TracesServiceServer.
//
// Pagination: AIP-158. page_token encodes the 1-based Langfuse page number as
// a decimal string (e.g. "2"). Omit for the first page. next_page_token is
// empty when all results have been returned.
func (s *tracesServer) ListTraces(
	ctx context.Context,
	req *tracespb.ListTracesRequest,
) (*tracespb.ListTracesResponse, error) {
	tenant, client, err := s.resolveClient(ctx)
	if err != nil {
		return nil, err
	}

	// Decode page_token → Langfuse 1-based page number.
	pageNum := int32(1)
	if tok := req.GetPageToken(); tok != "" {
		n, parseErr := strconv.ParseInt(tok, 10, 32)
		if parseErr != nil || n < 1 {
			return nil, status.Errorf(codes.InvalidArgument, "invalid page_token: %q", tok)
		}
		pageNum = int32(n)
	}

	pageSize := req.GetPageSize()
	if pageSize <= 0 {
		pageSize = 25
	}
	if pageSize > 100 {
		pageSize = 100
	}

	qctx, cancel := context.WithTimeout(ctx, tracesQueryTimeout)
	defer cancel()

	page, err := client.listTraces(qctx, langfuseListTracesOpts{
		Page:          pageNum,
		Limit:         pageSize,
		FromTimestamp: req.GetFromTimestamp(),
		ToTimestamp:   req.GetToTimestamp(),
		Name:          req.GetName(),
		UserID:        req.GetUserId(),
		Tags:          req.GetTags(),
	})
	if err != nil {
		s.logger.WarnContext(ctx, "TracesService.ListTraces: Langfuse call failed",
			slog.String("tenant", tenant.String()),
			slog.String("error", err.Error()),
		)
		return nil, mapLangfuseError(err)
	}

	pbTraces := make([]*tracespb.TraceRecord, 0, len(page.Data))
	for i := range page.Data {
		pbTraces = append(pbTraces, traceToProto(&page.Data[i]))
	}

	// Build next_page_token: non-empty only when there is a next page.
	nextToken := ""
	if page.Meta.Page < page.Meta.TotalPages {
		nextToken = strconv.FormatInt(int64(page.Meta.Page)+1, 10)
	}

	return &tracespb.ListTracesResponse{
		Traces:        pbTraces,
		NextPageToken: nextToken,
		TotalItems:    page.Meta.TotalItems,
	}, nil
}

// GetTrace implements TracesServiceServer.
func (s *tracesServer) GetTrace(
	ctx context.Context,
	req *tracespb.GetTraceRequest,
) (*tracespb.GetTraceResponse, error) {
	if req.GetTraceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "trace_id is required")
	}

	tenant, client, err := s.resolveClient(ctx)
	if err != nil {
		return nil, err
	}

	qctx, cancel := context.WithTimeout(ctx, tracesQueryTimeout)
	defer cancel()

	trace, err := client.getTrace(qctx, req.GetTraceId())
	if err != nil {
		s.logger.WarnContext(ctx, "TracesService.GetTrace: Langfuse call failed",
			slog.String("tenant", tenant.String()),
			slog.String("trace_id", req.GetTraceId()),
			slog.String("error", err.Error()),
		)
		return nil, mapLangfuseError(err)
	}

	return &tracespb.GetTraceResponse{Trace: traceToProto(trace)}, nil
}

// GetObservation implements TracesServiceServer.
func (s *tracesServer) GetObservation(
	ctx context.Context,
	req *tracespb.GetObservationRequest,
) (*tracespb.GetObservationResponse, error) {
	if req.GetObservationId() == "" {
		return nil, status.Error(codes.InvalidArgument, "observation_id is required")
	}

	tenant, client, err := s.resolveClient(ctx)
	if err != nil {
		return nil, err
	}

	qctx, cancel := context.WithTimeout(ctx, tracesQueryTimeout)
	defer cancel()

	obs, err := client.getObservation(qctx, req.GetObservationId())
	if err != nil {
		s.logger.WarnContext(ctx, "TracesService.GetObservation: Langfuse call failed",
			slog.String("tenant", tenant.String()),
			slog.String("observation_id", req.GetObservationId()),
			slog.String("error", err.Error()),
		)
		return nil, mapLangfuseError(err)
	}

	return &tracespb.GetObservationResponse{Observation: observationToProto(obs)}, nil
}

// AddTraceScore implements TracesServiceServer.
func (s *tracesServer) AddTraceScore(
	ctx context.Context,
	req *tracespb.AddTraceScoreRequest,
) (*tracespb.AddTraceScoreResponse, error) {
	if req.GetTraceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "trace_id is required")
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	tenant, client, err := s.resolveClient(ctx)
	if err != nil {
		return nil, err
	}

	qctx, cancel := context.WithTimeout(ctx, tracesQueryTimeout)
	defer cancel()

	if err := client.createScore(qctx, langfuseCreateScoreRequest{
		TraceID: req.GetTraceId(),
		Name:    req.GetName(),
		Value:   req.GetValue(),
		Comment: req.GetComment(),
	}); err != nil {
		s.logger.WarnContext(ctx, "TracesService.AddTraceScore: Langfuse call failed",
			slog.String("tenant", tenant.String()),
			slog.String("trace_id", req.GetTraceId()),
			slog.String("error", err.Error()),
		)
		return nil, mapLangfuseError(err)
	}

	return &tracespb.AddTraceScoreResponse{}, nil
}

// compile-time interface check.
var _ tracespb.TracesServiceServer = (*tracesServer)(nil)
