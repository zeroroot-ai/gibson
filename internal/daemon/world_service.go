// Package daemon — world_service.go
//
// worldServer implements gibson.world.v1.WorldService: the daemon-mediated read
// path into the ECS brain (epic ecs-brain, gibson#752). It resolves the caller's
// tenant from context and reads only that tenant's live brain World + Timeline
// via the per-tenant brain.Registry — the dashboard never touches the brain
// directly (it reads through here over Envoy + ext-authz, like TracesService).
//
// Note: until mission execution is wired to feed the brain (gated on the deferred
// worker contract, sdk#341), a tenant's World/Timeline is populated only by events
// submitted to its engine; the read API itself is complete and tenant-isolated.
package daemon

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/brain"
	worldpb "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

type worldServer struct {
	worldpb.UnimplementedWorldServiceServer

	registry *brain.Registry
	logger   *slog.Logger
}

// NewWorldServer constructs the WorldService backed by the per-tenant brain registry.
func NewWorldServer(registry *brain.Registry, logger *slog.Logger) *worldServer {
	if registry == nil {
		panic("world server: registry cannot be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &worldServer{registry: registry, logger: logger}
}

// engine resolves the caller's tenant from context and returns its brain engine
// (created on first use). Cross-tenant access is structurally impossible — a
// caller only ever reaches its own tenant's engine.
func (s *worldServer) engine(ctx context.Context) (*brain.Engine, error) {
	t, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	return s.registry.For(t.String()), nil
}

func (s *worldServer) ListMissions(ctx context.Context, _ *worldpb.ListMissionsRequest) (*worldpb.ListMissionsResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	resp := &worldpb.ListMissionsResponse{}
	for _, m := range e.Missions() {
		resp.Missions = append(resp.Missions, &worldpb.MissionView{
			Id: m.ID, Goal: m.Goal, Status: string(m.Status), Reason: m.Reason,
		})
	}
	return resp, nil
}

func (s *worldServer) ListHosts(ctx context.Context, _ *worldpb.ListHostsRequest) (*worldpb.ListHostsResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	resp := &worldpb.ListHostsResponse{}
	for _, h := range e.Hosts() {
		ports := make([]int32, len(h.OpenPorts))
		for i, p := range h.OpenPorts {
			ports[i] = int32(p)
		}
		resp.Hosts = append(resp.Hosts, &worldpb.HostView{
			ScopeId:   h.ScopeID,
			Address:   h.Address,
			OpenPorts: ports,
			Juicy:     h.Belief.Juicy,
			Attention: h.Attention,
			Surprise:  h.Surprise,
		})
	}
	return resp, nil
}

func (s *worldServer) ListFindings(ctx context.Context, _ *worldpb.ListFindingsRequest) (*worldpb.ListFindingsResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	resp := &worldpb.ListFindingsResponse{}
	for _, f := range e.Findings() {
		resp.Findings = append(resp.Findings, &worldpb.FindingView{
			Id: f.ID, Title: f.Title, ScopeId: f.ScopeID, Address: f.Address, Severity: f.Severity,
		})
	}
	return resp, nil
}

func (s *worldServer) ListLlmCalls(ctx context.Context, _ *worldpb.ListLlmCallsRequest) (*worldpb.ListLlmCallsResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	resp := &worldpb.ListLlmCallsResponse{}
	for _, c := range e.LlmCalls() {
		resp.LlmCalls = append(resp.LlmCalls, &worldpb.LlmCallView{
			CallId:           c.CallID,
			RunId:            c.RunID,
			Model:            c.Model,
			ScopeId:          c.ScopeID,
			PromptTokens:     int32(c.PromptTokens),
			CompletionTokens: int32(c.CompletionTokens),
		})
	}
	return resp, nil
}

func (s *worldServer) GetLlmCall(ctx context.Context, req *worldpb.GetLlmCallRequest) (*worldpb.GetLlmCallResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range e.LlmCalls() {
		if c.CallID != req.GetCallId() {
			continue
		}
		msgs := make([]*worldpb.LlmMessage, 0, len(c.Messages))
		for _, m := range c.Messages {
			msgs = append(msgs, &worldpb.LlmMessage{Role: m.Role, Content: m.Content})
		}
		return &worldpb.GetLlmCallResponse{Call: &worldpb.LlmCallDetail{
			CallId:           c.CallID,
			RunId:            c.RunID,
			Model:            c.Model,
			ScopeId:          c.ScopeID,
			PromptTokens:     int32(c.PromptTokens),
			CompletionTokens: int32(c.CompletionTokens),
			Messages:         msgs,
			Completion:       c.Completion,
		}}, nil
	}
	return nil, status.Errorf(codes.NotFound, "llm call %q not found", req.GetCallId())
}

func (s *worldServer) GetTimeline(ctx context.Context, _ *worldpb.GetTimelineRequest) (*worldpb.GetTimelineResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	resp := &worldpb.GetTimelineResponse{}
	for i, ev := range e.Events() {
		resp.Events = append(resp.Events, &worldpb.TimelineEvent{
			Seq:     uint64(i),
			Kind:    ev.Kind(),
			Summary: fmt.Sprintf("%+v", ev),
		})
	}
	return resp, nil
}

// GetFrameAt folds the tenant's Timeline to position seq and returns the World as
// of that frame (ADR-0001: World == fold(Timeline)). This is the Scroller's scrub
// primitive — a server-side fold, not a stored snapshot. seq is clamped to
// [0, total]; seq == total reproduces the live World.
func (s *worldServer) GetFrameAt(ctx context.Context, req *worldpb.GetFrameAtRequest) (*worldpb.GetFrameAtResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	total := len(e.Events())
	n := int(req.GetSeq())
	if n > total {
		n = total
	}

	w := e.FrameAt(n)

	resp := &worldpb.GetFrameAtResponse{Seq: uint64(n), Total: uint64(total)}
	for _, m := range w.MissionSnapshot() {
		resp.Missions = append(resp.Missions, &worldpb.MissionView{
			Id: m.ID, Goal: m.Goal, Status: string(m.Status), Reason: m.Reason,
		})
	}
	for _, h := range w.Snapshot() {
		ports := make([]int32, len(h.OpenPorts))
		for i, p := range h.OpenPorts {
			ports[i] = int32(p)
		}
		resp.Hosts = append(resp.Hosts, &worldpb.HostView{
			ScopeId:   h.ScopeID,
			Address:   h.Address,
			OpenPorts: ports,
			Juicy:     h.Belief.Juicy,
			Attention: h.Attention,
			Surprise:  h.Surprise,
		})
	}
	for _, f := range w.FindingSnapshot() {
		resp.Findings = append(resp.Findings, &worldpb.FindingView{
			Id: f.ID, Title: f.Title, ScopeId: f.ScopeID, Address: f.Address, Severity: f.Severity,
		})
	}
	return resp, nil
}

// ListReviewQueue returns the tenant's HITL review queue — surfaced surprises +
// Findings with any applied label (ADR-0006). Read-only projection; never gates
// a mission.
func (s *worldServer) ListReviewQueue(ctx context.Context, _ *worldpb.ListReviewQueueRequest) (*worldpb.ListReviewQueueResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	resp := &worldpb.ListReviewQueueResponse{}
	for _, it := range e.ReviewQueue() {
		item := &worldpb.ReviewItem{
			TargetId: it.TargetID,
			Kind:     it.Kind,
			Title:    it.Title,
			ScopeId:  it.ScopeID,
			Address:  it.Address,
			Severity: it.Severity,
			Labelled: it.Labelled,
		}
		if it.Labelled {
			item.Label = labelView(it.Label)
		}
		resp.Items = append(resp.Items, item)
	}
	return resp, nil
}

// SubmitLabel records a human review judgement as a tenant-scoped LabelApplied
// event (ADR-0006). It is async: the event is submitted to the tenant's engine
// and the call returns — the mission never waits on it (no runtime gate). The
// labelling user is taken from the caller's context server-side, so a caller can
// never attribute a label to another user; and because the event lands in the
// caller's tenant World only, labels pool tenant-wide and never cross tenants.
func (s *worldServer) SubmitLabel(ctx context.Context, req *worldpb.SubmitLabelRequest) (*worldpb.SubmitLabelResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetTargetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "target_id is required")
	}
	verdict := brain.LabelVerdict(req.GetVerdict())
	if !brain.ValidVerdict(verdict) {
		return nil, status.Errorf(codes.InvalidArgument, "unknown verdict %q (want true_positive|false_positive|dismiss)", req.GetVerdict())
	}
	userID, _ := auth.ActingUserFromContext(ctx) // provenance only; "" if absent
	e.Submit(brain.LabelApplied{
		TargetID: req.GetTargetId(),
		Verdict:  verdict,
		Severity: req.GetSeverity(),
		Category: req.GetCategory(),
		UserID:   userID,
	})
	return &worldpb.SubmitLabelResponse{}, nil
}

// ListLabels returns the tenant's pooled review labels (ADR-0006) — the HITL
// training signal the offline trainer consumes alongside auto-outcomes.
func (s *worldServer) ListLabels(ctx context.Context, _ *worldpb.ListLabelsRequest) (*worldpb.ListLabelsResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	resp := &worldpb.ListLabelsResponse{}
	for _, l := range e.Labels() {
		resp.Labels = append(resp.Labels, labelView(l))
	}
	return resp, nil
}

// labelView maps a brain label snapshot to its proto view.
func labelView(l brain.LabelSnapshot) *worldpb.LabelView {
	return &worldpb.LabelView{
		TargetId: l.TargetID,
		Verdict:  string(l.Verdict),
		Severity: l.Severity,
		Category: l.Category,
		UserId:   l.UserID,
	}
}
