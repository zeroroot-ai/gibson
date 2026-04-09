// Package intelligence provides cross-mission security analytics queries.
// It implements the IntelligenceQueries interface from the SDK, providing
// methods to analyze patterns, trends, and metrics across multiple missions.
package intelligence

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Service implements IntelligenceQueries with Neo4j backend.
// It provides caching, circuit breaker, and observability features.
type Service struct {
	driver neo4j.DriverWithContext
	logger *slog.Logger
	tracer trace.Tracer

	// Query implementations
	recurring   *RecurringVulnerabilityQuery
	remediation *RemediationMetricsQuery
	risk        *RiskScoreCalculator
	patterns    *AttackPatternAnalyzer
	similarity  *SimilarTargetFinder

	// Cache
	cache    *queryCache
	cacheTTL time.Duration
	cacheMu  sync.RWMutex

	// Circuit breaker
	failures       int
	lastFailure    time.Time
	circuitOpen    bool
	circuitTimeout time.Duration
}

// ServiceConfig configures the Intelligence Service.
type ServiceConfig struct {
	// Driver is the Neo4j driver (required)
	Driver neo4j.DriverWithContext

	// Logger for structured logging (optional, defaults to slog.Default())
	Logger *slog.Logger

	// CacheTTL is how long to cache results (optional, defaults to 5 minutes)
	CacheTTL time.Duration

	// CircuitTimeout is how long to wait before retrying after failures
	// (optional, defaults to 30 seconds)
	CircuitTimeout time.Duration
}

// NewService creates a new Intelligence Service.
func NewService(config ServiceConfig) *Service {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}
	if config.CircuitTimeout == 0 {
		config.CircuitTimeout = 30 * time.Second
	}

	return &Service{
		driver:         config.Driver,
		logger:         config.Logger,
		tracer:         otel.Tracer("gibson.intelligence"),
		recurring:      NewRecurringVulnerabilityQuery(config.Driver),
		remediation:    NewRemediationMetricsQuery(config.Driver),
		risk:           NewRiskScoreCalculator(config.Driver),
		patterns:       NewAttackPatternAnalyzer(config.Driver),
		similarity:     NewSimilarTargetFinder(config.Driver),
		cache:          newQueryCache(),
		cacheTTL:       config.CacheTTL,
		circuitTimeout: config.CircuitTimeout,
	}
}

// GetRecurringVulnerabilities finds vulnerabilities appearing across multiple targets.
func (s *Service) GetRecurringVulnerabilities(ctx context.Context, opts sdkgraphrag.RecurringVulnOpts) (*sdkgraphrag.RecurringVulnResult, error) {
	ctx, span := s.tracer.Start(ctx, "intelligence.get_recurring_vulnerabilities",
		trace.WithAttributes(
			attribute.Int("threshold", opts.Threshold),
			attribute.Int("limit", opts.Limit),
		))
	defer span.End()

	// Check circuit breaker
	if err := s.checkCircuit(); err != nil {
		return nil, err
	}

	// Check cache
	cacheKey := s.cache.key("recurring", opts)
	if cached := s.cache.get(cacheKey); cached != nil {
		s.logger.Debug("cache hit for recurring vulnerabilities")
		return cached.(*sdkgraphrag.RecurringVulnResult), nil
	}

	// Execute query
	result, err := s.recurring.Execute(ctx, opts)
	if err != nil {
		s.recordFailure()
		return nil, err
	}

	s.recordSuccess()

	// Cache result
	s.cache.set(cacheKey, result, s.cacheTTL)

	s.logger.Info("recurring vulnerabilities query completed",
		"count", len(result.Vulnerabilities),
		"total", result.TotalCount)

	return result, nil
}

// GetRemediationMetrics calculates remediation success rates and timing.
func (s *Service) GetRemediationMetrics(ctx context.Context, opts sdkgraphrag.RemediationOpts) (*sdkgraphrag.RemediationResult, error) {
	ctx, span := s.tracer.Start(ctx, "intelligence.get_remediation_metrics",
		trace.WithAttributes(
			attribute.String("vuln_type", opts.VulnType),
			attribute.String("group_by", opts.GroupBy),
		))
	defer span.End()

	if err := s.checkCircuit(); err != nil {
		return nil, err
	}

	cacheKey := s.cache.key("remediation", opts)
	if cached := s.cache.get(cacheKey); cached != nil {
		s.logger.Debug("cache hit for remediation metrics")
		return cached.(*sdkgraphrag.RemediationResult), nil
	}

	result, err := s.remediation.Execute(ctx, opts)
	if err != nil {
		s.recordFailure()
		return nil, err
	}

	s.recordSuccess()
	s.cache.set(cacheKey, result, s.cacheTTL)

	s.logger.Info("remediation metrics query completed",
		"overall_rate", result.OverallRate,
		"overall_mttr", result.OverallMTTR)

	return result, nil
}

// GetAssetRiskScore calculates risk scores for assets.
func (s *Service) GetAssetRiskScore(ctx context.Context, opts sdkgraphrag.RiskScoreOpts) (*sdkgraphrag.RiskScoreResult, error) {
	ctx, span := s.tracer.Start(ctx, "intelligence.get_asset_risk_score",
		trace.WithAttributes(
			attribute.String("asset_id", opts.AssetID),
			attribute.String("algorithm", opts.Algorithm),
		))
	defer span.End()

	if err := s.checkCircuit(); err != nil {
		return nil, err
	}

	cacheKey := s.cache.key("risk", opts)
	if cached := s.cache.get(cacheKey); cached != nil {
		s.logger.Debug("cache hit for asset risk score")
		return cached.(*sdkgraphrag.RiskScoreResult), nil
	}

	result, err := s.risk.Execute(ctx, opts)
	if err != nil {
		s.recordFailure()
		return nil, err
	}

	s.recordSuccess()
	s.cache.set(cacheKey, result, s.cacheTTL)

	s.logger.Info("risk score query completed",
		"assets", len(result.Assets),
		"portfolio_score", result.PortfolioRiskScore)

	return result, nil
}

// GetAttackPatterns identifies successful attack technique sequences.
func (s *Service) GetAttackPatterns(ctx context.Context, opts sdkgraphrag.PatternOpts) (*sdkgraphrag.PatternResult, error) {
	ctx, span := s.tracer.Start(ctx, "intelligence.get_attack_patterns",
		trace.WithAttributes(
			attribute.String("technique", opts.Technique),
			attribute.Float64("min_success_rate", opts.MinSuccessRate),
		))
	defer span.End()

	if err := s.checkCircuit(); err != nil {
		return nil, err
	}

	cacheKey := s.cache.key("patterns", opts)
	if cached := s.cache.get(cacheKey); cached != nil {
		s.logger.Debug("cache hit for attack patterns")
		return cached.(*sdkgraphrag.PatternResult), nil
	}

	result, err := s.patterns.Execute(ctx, opts)
	if err != nil {
		s.recordFailure()
		return nil, err
	}

	s.recordSuccess()
	s.cache.set(cacheKey, result, s.cacheTTL)

	s.logger.Info("attack patterns query completed",
		"patterns", len(result.Patterns),
		"total", result.TotalPatterns)

	return result, nil
}

// GetSimilarTargets finds targets similar to a reference target.
func (s *Service) GetSimilarTargets(ctx context.Context, opts sdkgraphrag.SimilarTargetsOpts) (*sdkgraphrag.SimilarTargetsResult, error) {
	ctx, span := s.tracer.Start(ctx, "intelligence.get_similar_targets",
		trace.WithAttributes(
			attribute.String("target_id", opts.TargetID),
			attribute.Int("k", opts.K),
		))
	defer span.End()

	if err := s.checkCircuit(); err != nil {
		return nil, err
	}

	cacheKey := s.cache.key("similarity", opts)
	if cached := s.cache.get(cacheKey); cached != nil {
		s.logger.Debug("cache hit for similar targets")
		return cached.(*sdkgraphrag.SimilarTargetsResult), nil
	}

	result, err := s.similarity.Execute(ctx, opts)
	if err != nil {
		s.recordFailure()
		return nil, err
	}

	s.recordSuccess()
	s.cache.set(cacheKey, result, s.cacheTTL)

	s.logger.Info("similar targets query completed",
		"reference", opts.TargetID,
		"matches", len(result.SimilarTargets))

	return result, nil
}

// checkCircuit checks if the circuit breaker is open.
func (s *Service) checkCircuit() error {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()

	if s.circuitOpen {
		if time.Since(s.lastFailure) > s.circuitTimeout {
			return nil // Allow retry
		}
		return ErrCircuitOpen
	}
	return nil
}

// recordFailure records a query failure.
func (s *Service) recordFailure() {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	s.failures++
	s.lastFailure = time.Now()

	// Open circuit after 5 consecutive failures
	if s.failures >= 5 {
		s.circuitOpen = true
		s.logger.Warn("intelligence service circuit breaker opened",
			"failures", s.failures)
	}
}

// recordSuccess resets failure count.
func (s *Service) recordSuccess() {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	s.failures = 0
	s.circuitOpen = false
}

// Compile-time interface check
var _ sdkgraphrag.IntelligenceQueries = (*Service)(nil)
