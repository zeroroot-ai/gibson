// Package intelligence — gRPC adapter.
//
// GRPCServer wraps the existing in-process *Service so it satisfies
// intelligencepb.IntelligenceServiceServer. The adapter is a thin translation
// layer with no business logic — every handler decodes the proto request,
// calls the existing Service method, and encodes the SDK Go result back to
// proto. Translation tables mirror core/sdk/serve/platform_intelligence_proxy.go
// in reverse direction so request/response shapes match end-to-end.
//
// Per spec productionize-graph-intelligence Task 2, this fills the
// long-missing daemon-side endpoint that the SDK's platformIntelligenceProxy
// was designed to call (every prior call hit the Unimplemented-degradation
// fallback because no server was registered).
package intelligence

import (
	"context"
	"errors"
	"strings"

	intelligencepb "github.com/zero-day-ai/sdk/api/gen/intelligence/v1"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GRPCServer adapts the in-process intelligence.Service to the gRPC
// IntelligenceService interface. The wrapped *Service holds the Neo4j driver,
// per-query caching, circuit breaker, and OTel spans for the underlying
// queries; this adapter adds the gRPC-layer span and proto translation.
type GRPCServer struct {
	intelligencepb.UnimplementedIntelligenceServiceServer
	svc    *Service
	tracer trace.Tracer
}

// NewGRPCServer wraps an *intelligence.Service for gRPC exposure.
func NewGRPCServer(svc *Service) *GRPCServer {
	return &GRPCServer{
		svc:    svc,
		tracer: otel.Tracer("gibson.intelligence.grpc"),
	}
}

// errToStatus maps Service errors to gRPC status codes. Neo4j-unavailable
// (the existing circuit-breaker error from *Service) becomes Unavailable;
// everything else becomes Internal. Never panic.
func errToStatus(err error) error {
	if err == nil {
		return nil
	}
	// Best-effort detection of the circuit-breaker / connectivity error.
	// The *Service uses checkCircuit which returns a specific error;
	// fall back to substring sniffing to remain robust to message phrasing.
	msg := err.Error()
	switch {
	case errors.Is(err, ErrCircuitOpen):
		return status.Error(codes.Unavailable, msg)
	case strings.Contains(strings.ToLower(msg), "neo4j") && strings.Contains(strings.ToLower(msg), "unavailable"):
		return status.Error(codes.Unavailable, msg)
	default:
		return status.Error(codes.Internal, msg)
	}
}

// GetRecurringVulnerabilities serves the gRPC RPC by delegating to *Service.
func (s *GRPCServer) GetRecurringVulnerabilities(ctx context.Context, req *intelligencepb.GetRecurringVulnerabilitiesRequest) (*intelligencepb.GetRecurringVulnerabilitiesResponse, error) {
	ctx, span := s.tracer.Start(ctx, "gibson.intelligence.grpc.GetRecurringVulnerabilities")
	defer span.End()

	opts := sdkgraphrag.RecurringVulnOpts{
		Threshold:   int(req.GetThreshold()),
		TargetTypes: req.GetTargetTypes(),
		Limit:       int(req.GetLimit()),
		Offset:      int(req.GetOffset()),
	}
	if tr := req.GetTimeRange(); tr != nil {
		opts.TimeRange = &sdkgraphrag.TimeRange{Start: tr.GetStart().AsTime(), End: tr.GetEnd().AsTime()}
	}
	for _, sev := range req.GetSeverities() {
		opts.Severities = append(opts.Severities, protoSeverityToSDK(sev))
	}

	result, err := s.svc.GetRecurringVulnerabilities(ctx, opts)
	if err != nil {
		return nil, errToStatus(err)
	}

	resp := &intelligencepb.GetRecurringVulnerabilitiesResponse{
		TotalCount: int32(result.TotalCount),
	}
	if !result.TimeRange.Start.IsZero() || !result.TimeRange.End.IsZero() {
		resp.TimeRange = &intelligencepb.TimeRange{
			Start: timestamppb.New(result.TimeRange.Start),
			End:   timestamppb.New(result.TimeRange.End),
		}
	}
	for _, v := range result.Vulnerabilities {
		pv := &intelligencepb.RecurringVulnerability{
			VulnType:          v.VulnType,
			CveIds:            v.CVEIDs,
			CweIds:            v.CWEIDs,
			OccurrenceCount:   int32(v.OccurrenceCount),
			AffectedHostCount: int32(v.AffectedHostCount),
			SampleHosts:       v.SampleHosts,
		}
		if !v.FirstSeen.IsZero() {
			pv.FirstSeen = timestamppb.New(v.FirstSeen)
		}
		if !v.LastSeen.IsZero() {
			pv.LastSeen = timestamppb.New(v.LastSeen)
		}
		if len(v.SeverityDistribution) > 0 {
			pv.SeverityDistribution = make(map[string]int32, len(v.SeverityDistribution))
			for k, c := range v.SeverityDistribution {
				pv.SeverityDistribution[string(k)] = int32(c)
			}
		}
		resp.Vulnerabilities = append(resp.Vulnerabilities, pv)
	}
	return resp, nil
}

// GetRemediationMetrics serves the gRPC RPC by delegating to *Service.
func (s *GRPCServer) GetRemediationMetrics(ctx context.Context, req *intelligencepb.GetRemediationMetricsRequest) (*intelligencepb.GetRemediationMetricsResponse, error) {
	ctx, span := s.tracer.Start(ctx, "gibson.intelligence.grpc.GetRemediationMetrics")
	defer span.End()

	opts := sdkgraphrag.RemediationOpts{
		VulnType: req.GetVulnType(),
		GroupBy:  req.GetGroupBy(),
	}
	if tr := req.GetTimeRange(); tr != nil {
		opts.TimeRange = &sdkgraphrag.TimeRange{Start: tr.GetStart().AsTime(), End: tr.GetEnd().AsTime()}
	}

	result, err := s.svc.GetRemediationMetrics(ctx, opts)
	if err != nil {
		return nil, errToStatus(err)
	}

	resp := &intelligencepb.GetRemediationMetricsResponse{
		OverallRate:     result.OverallRate,
		OverallMttr:     result.OverallMTTR,
		DataLimitations: result.DataLimitations,
	}
	if !result.TimeRange.Start.IsZero() || !result.TimeRange.End.IsZero() {
		resp.TimeRange = &intelligencepb.TimeRange{
			Start: timestamppb.New(result.TimeRange.Start),
			End:   timestamppb.New(result.TimeRange.End),
		}
	}
	for _, m := range result.Metrics {
		resp.Metrics = append(resp.Metrics, &intelligencepb.RemediationMetric{
			GroupKey:           m.GroupKey,
			GroupValue:         m.GroupValue,
			RemediationRate:    m.RemediationRate,
			Mttr:               m.MTTR,
			RecurrenceRate:     m.RecurrenceRate,
			TotalFindings:      int32(m.TotalFindings),
			RemediatedFindings: int32(m.RemediatedFindings),
			TrendVsPrevious:    m.TrendVsPrevious,
		})
	}
	return resp, nil
}

// GetAssetRiskScore serves the gRPC RPC by delegating to *Service.
func (s *GRPCServer) GetAssetRiskScore(ctx context.Context, req *intelligencepb.GetAssetRiskScoreRequest) (*intelligencepb.GetAssetRiskScoreResponse, error) {
	ctx, span := s.tracer.Start(ctx, "gibson.intelligence.grpc.GetAssetRiskScore")
	defer span.End()

	opts := sdkgraphrag.RiskScoreOpts{
		AssetID:        req.GetAssetId(),
		Algorithm:      req.GetAlgorithm(),
		IncludeHistory: req.GetIncludeHistory(),
		Limit:          int(req.GetLimit()),
	}

	result, err := s.svc.GetAssetRiskScore(ctx, opts)
	if err != nil {
		return nil, errToStatus(err)
	}

	resp := &intelligencepb.GetAssetRiskScoreResponse{
		PortfolioRiskScore: result.PortfolioRiskScore,
		PortfolioRiskTier:  result.PortfolioRiskTier,
	}
	for _, a := range result.Assets {
		pa := &intelligencepb.AssetRiskScore{
			AssetId:         a.AssetID,
			AssetName:       a.AssetName,
			Score:           a.Score,
			Tier:            a.Tier,
			TrendVsPrevious: a.TrendVsPrevious,
			Recommendations: a.Recommendations,
		}
		for _, f := range a.Factors {
			pa.Factors = append(pa.Factors, &intelligencepb.RiskFactor{
				Name:        f.Name,
				Weight:      f.Weight,
				Value:       f.Value,
				Description: f.Description,
			})
		}
		for _, h := range a.HistoricalScores {
			ph := &intelligencepb.HistoricalRiskScore{Score: h.Score, Tier: h.Tier}
			if !h.Date.IsZero() {
				ph.Date = timestamppb.New(h.Date)
			}
			pa.HistoricalScores = append(pa.HistoricalScores, ph)
		}
		resp.Assets = append(resp.Assets, pa)
	}
	return resp, nil
}

// GetAttackPatterns serves the gRPC RPC by delegating to *Service.
func (s *GRPCServer) GetAttackPatterns(ctx context.Context, req *intelligencepb.GetAttackPatternsRequest) (*intelligencepb.GetAttackPatternsResponse, error) {
	ctx, span := s.tracer.Start(ctx, "gibson.intelligence.grpc.GetAttackPatterns")
	defer span.End()

	opts := sdkgraphrag.PatternOpts{
		Technique:      req.GetTechnique(),
		TargetType:     req.GetTargetType(),
		MinSuccessRate: req.GetMinSuccessRate(),
		Limit:          int(req.GetLimit()),
	}

	result, err := s.svc.GetAttackPatterns(ctx, opts)
	if err != nil {
		return nil, errToStatus(err)
	}

	resp := &intelligencepb.GetAttackPatternsResponse{
		TotalPatterns: int32(result.TotalPatterns),
	}
	for _, pat := range result.Patterns {
		pp := &intelligencepb.AttackPattern{
			PatternId:             pat.PatternID,
			SuccessRate:           pat.SuccessRate,
			OccurrenceCount:       int32(pat.OccurrenceCount),
			TargetCharacteristics: pat.TargetCharacteristics,
			SampleMissions:        pat.SampleMissions,
			Confidence:            pat.Confidence,
		}
		for _, tc := range pat.TechniqueChain {
			pp.TechniqueChain = append(pp.TechniqueChain, &intelligencepb.TechniqueInChain{
				Technique: tc.Technique,
				MitreId:   tc.MitreID,
				MitreName: tc.MitreName,
				Position:  int32(tc.Position),
			})
		}
		resp.Patterns = append(resp.Patterns, pp)
	}
	return resp, nil
}

// GetSimilarTargets serves the gRPC RPC by delegating to *Service.
func (s *GRPCServer) GetSimilarTargets(ctx context.Context, req *intelligencepb.GetSimilarTargetsRequest) (*intelligencepb.GetSimilarTargetsResponse, error) {
	ctx, span := s.tracer.Start(ctx, "gibson.intelligence.grpc.GetSimilarTargets")
	defer span.End()

	opts := sdkgraphrag.SimilarTargetsOpts{
		TargetID: req.GetTargetId(),
		K:        int(req.GetK()),
		Features: req.GetFeatures(),
	}

	result, err := s.svc.GetSimilarTargets(ctx, opts)
	if err != nil {
		return nil, errToStatus(err)
	}

	resp := &intelligencepb.GetSimilarTargetsResponse{
		ReferenceTargetId: result.ReferenceTargetID,
		FeaturesUsed:      result.FeaturesUsed,
	}
	for _, st := range result.SimilarTargets {
		pst := &intelligencepb.SimilarTarget{
			TargetId:              st.TargetID,
			TargetName:            st.TargetName,
			SimilarityScore:       st.SimilarityScore,
			SuccessfulFindings:    st.SuccessfulFindings,
			RecommendedTechniques: st.RecommendedTechniques,
		}
		if len(st.MatchingFeatures) > 0 {
			pst.MatchingFeatures = make(map[string]*intelligencepb.FeatureMatch, len(st.MatchingFeatures))
			for k, fm := range st.MatchingFeatures {
				pst.MatchingFeatures[k] = &intelligencepb.FeatureMatch{
					Feature:       fm.Feature,
					Overlap:       fm.Overlap,
					MatchedValues: fm.MatchedValues,
				}
			}
		}
		resp.SimilarTargets = append(resp.SimilarTargets, pst)
	}
	return resp, nil
}

// protoSeverityToSDK converts the proto Severity enum back to the SDK enum.
// Inverse of core/sdk/serve/platform_intelligence_proxy.go's sdkSeverityToProto.
func protoSeverityToSDK(s intelligencepb.Severity) sdkgraphrag.Severity {
	switch s {
	case intelligencepb.Severity_SEVERITY_CRITICAL:
		return sdkgraphrag.SeverityCritical
	case intelligencepb.Severity_SEVERITY_HIGH:
		return sdkgraphrag.SeverityHigh
	case intelligencepb.Severity_SEVERITY_MEDIUM:
		return sdkgraphrag.SeverityMedium
	case intelligencepb.Severity_SEVERITY_LOW:
		return sdkgraphrag.SeverityLow
	case intelligencepb.Severity_SEVERITY_INFO:
		return sdkgraphrag.SeverityInfo
	case intelligencepb.Severity_SEVERITY_INFORMATIONAL:
		return sdkgraphrag.SeverityInformational
	default:
		// SeverityUnspecified is not exported by the SDK; map to empty string
		// which the SDK treats as "no filter".
		return sdkgraphrag.Severity("")
	}
}
