package orchestrator

import (
	"context"
	"log/slog"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// GraphQueries provides graph intelligence queries for enriching orchestrator decisions.
// This interface allows the orchestrator to query historical attack graph data to inform
// LLM decision-making with prior findings, successful patterns, known entities, and target history.
type GraphQueries interface {
	// GetTargetHistory retrieves historical scan information for a specific target.
	// This provides context about how many times we've scanned this target before,
	// when it was last scanned, and the severity distribution of previous findings.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - targetID: The unique identifier for the target (e.g., domain, IP address, host ID)
	//
	// Returns:
	//   - TargetHistory with scan statistics, or nil if target has no history
	//   - Error if query fails
	GetTargetHistory(ctx context.Context, targetID string) (*TargetHistory, error)

	// GetPriorFindings retrieves recent findings for a specific domain or target scope.
	// This allows the orchestrator to understand what vulnerabilities have been discovered
	// previously in similar contexts, informing technique selection and prioritization.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - domain: The domain or target scope to query (e.g., "example.com", "192.168.1.0/24")
	//   - limit: Maximum number of findings to return (ordered by severity, then recency)
	//
	// Returns:
	//   - Slice of HistoricalFinding ordered by severity (critical first) then discovery time
	//   - Error if query fails
	GetPriorFindings(ctx context.Context, domain string, limit int) ([]HistoricalFinding, error)

	// GetKnownEntities retrieves entities previously discovered for a target.
	// This provides awareness of known infrastructure, services, endpoints, and technologies
	// that have been identified in prior scans, helping avoid redundant discovery.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - targetID: The unique identifier for the target
	//
	// Returns:
	//   - Slice of EntitySummary representing known entities
	//   - Error if query fails
	GetKnownEntities(ctx context.Context, targetID string) ([]EntitySummary, error)

	// GetSuccessfulPatterns retrieves attack patterns that have historically been successful
	// for a specific target type. This informs technique selection by showing what has
	// worked before for similar targets.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - targetType: The type of target (e.g., "web_application", "api", "network")
	//
	// Returns:
	//   - Slice of AttackPattern ordered by success rate
	//   - Error if query fails
	GetSuccessfulPatterns(ctx context.Context, targetType string) ([]AttackPattern, error)
}

// TargetHistory contains historical scan statistics for a specific target.
// This provides the orchestrator with context about prior engagement with this target.
type TargetHistory struct {
	// TargetID is the unique identifier for this target
	TargetID string `json:"target_id"`

	// PreviousScanCount is the number of times this target has been scanned
	PreviousScanCount int `json:"previous_scan_count"`

	// LastScanDate is when this target was last scanned
	LastScanDate *time.Time `json:"last_scan_date,omitempty"`

	// TotalFindings is the total number of findings discovered across all scans
	TotalFindings int `json:"total_findings"`

	// Severity distribution of findings
	CriticalCount int `json:"critical_count"`
	HighCount     int `json:"high_count"`
	MediumCount   int `json:"medium_count"`
	LowCount      int `json:"low_count"`
}

// HistoricalFinding is a concise representation of a security finding from the graph.
// This provides the orchestrator with awareness of previously discovered vulnerabilities.
type HistoricalFinding struct {
	// ID is the unique identifier for this finding
	ID string `json:"id"`

	// Title is the finding title or summary
	Title string `json:"title"`

	// Severity indicates the severity level (critical, high, medium, low, info)
	Severity string `json:"severity"`

	// Category classifies the finding (e.g., "authentication", "injection", "misconfiguration")
	Category string `json:"category"`

	// DiscoveredAt is when this finding was first discovered
	DiscoveredAt time.Time `json:"discovered_at"`

	// TargetEntity describes what entity this finding relates to (e.g., "https://api.example.com/v1/users")
	TargetEntity string `json:"target_entity"`
}

// EntitySummary is a concise representation of a known entity from the graph.
// This provides the orchestrator with awareness of previously discovered infrastructure.
type EntitySummary struct {
	// ID is the unique identifier for this entity
	ID string `json:"id"`

	// Type indicates the entity type (e.g., "host", "port", "service", "endpoint", "domain")
	Type string `json:"type"`

	// Identifier is the human-readable identifier (e.g., "192.168.1.100:443", "api.example.com")
	Identifier string `json:"identifier"`

	// Properties contains key entity properties as a map
	// Examples: {"protocol": "https", "status_code": "200"} for endpoints
	//          {"state": "open", "service": "https"} for ports
	Properties map[string]any `json:"properties,omitempty"`

	// DiscoveredAt is when this entity was first discovered
	DiscoveredAt time.Time `json:"discovered_at"`
}

// AttackPattern represents a MITRE ATT&CK technique or custom attack pattern
// that has been historically successful for a specific target type.
type AttackPattern struct {
	// TechniqueID is the MITRE ATT&CK technique ID (e.g., "T1595.001") or custom pattern ID
	TechniqueID string `json:"technique_id"`

	// TechniqueName is the human-readable technique name
	TechniqueName string `json:"technique_name"`

	// Description provides context about what this technique does
	Description string `json:"description"`

	// SuccessRate is the percentage of times this technique resulted in findings (0.0 - 1.0)
	SuccessRate float64 `json:"success_rate"`

	// SampleCount is how many times this technique has been used (for confidence)
	SampleCount int `json:"sample_count"`

	// TargetTypes lists the target types this pattern has been successful against
	TargetTypes []string `json:"target_types"`
}

// GraphContext contains graph intelligence context for LLM decision-making.
// This struct is populated by querying the graph database and provides historical
// context to inform orchestrator decisions.
type GraphContext struct {
	// PriorFindings contains recent findings from this domain/scope
	PriorFindings []HistoricalFinding `json:"prior_findings,omitempty"`

	// KnownEntities contains previously discovered entities for this target
	KnownEntities []EntitySummary `json:"known_entities,omitempty"`

	// SuccessfulPatterns contains attack patterns that have worked for this target type
	SuccessfulPatterns []AttackPattern `json:"successful_patterns,omitempty"`

	// TargetHistory contains historical scan statistics for this target
	TargetHistory *TargetHistory `json:"target_history,omitempty"`

	// TargetRiskScore is a calculated risk score based on historical findings (0-100)
	// Higher scores indicate targets with more severe historical findings
	TargetRiskScore float64 `json:"target_risk_score,omitempty"`

	// QueryDuration tracks how long it took to gather this context
	QueryDuration time.Duration `json:"query_duration,omitempty"`

	// Truncated indicates if results were truncated due to limits
	Truncated bool `json:"truncated,omitempty"`
}

// Neo4jGraphQueries implements GraphQueries using Neo4j Cypher queries.
// It provides efficient graph queries with OpenTelemetry instrumentation and graceful degradation.
type Neo4jGraphQueries struct {
	driver  neo4j.DriverWithContext
	tracer  trace.Tracer
	logger  *slog.Logger
	metrics *graphQueryMetrics
}

// graphQueryMetrics provides Prometheus metrics for graph query operations.
type graphQueryMetrics struct {
	queryDuration  *prometheus.HistogramVec
	contextSize    *prometheus.GaugeVec
	queriesTotal   *prometheus.CounterVec
	queryErrors    *prometheus.CounterVec
	registerer     prometheus.Registerer
	registered     bool
}

// newGraphQueryMetrics creates and initializes graph query metrics.
// Metrics are registered with the provided registerer (use prometheus.DefaultRegisterer for default).
func newGraphQueryMetrics(registerer prometheus.Registerer) *graphQueryMetrics {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}

	m := &graphQueryMetrics{
		registerer: registerer,
		queryDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "gibson_orchestrator_graph_query_duration_seconds",
				Help: "Duration of graph intelligence queries in seconds",
				Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
			},
			[]string{"query_type"},
		),
		contextSize: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "gibson_orchestrator_graph_context_size",
				Help: "Size of graph context results (number of items returned)",
			},
			[]string{"context_type"},
		),
		queriesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_orchestrator_graph_queries_total",
				Help: "Total number of graph intelligence queries executed",
			},
			[]string{"query_type", "status"},
		),
		queryErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_orchestrator_graph_query_errors_total",
				Help: "Total number of graph query errors",
			},
			[]string{"query_type", "error_type"},
		),
	}

	return m
}

// register registers all metrics with the Prometheus registerer.
// Safe to call multiple times - only registers once.
func (m *graphQueryMetrics) register() error {
	if m.registered {
		return nil
	}

	collectors := []prometheus.Collector{
		m.queryDuration,
		m.contextSize,
		m.queriesTotal,
		m.queryErrors,
	}

	for _, collector := range collectors {
		if err := m.registerer.Register(collector); err != nil {
			// Check if already registered
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
				return err
			}
		}
	}

	m.registered = true
	return nil
}

// NewNeo4jGraphQueries creates a new Neo4jGraphQueries instance.
//
// Parameters:
//   - driver: Neo4j driver for executing queries
//   - logger: Structured logger for diagnostic output
//
// Returns:
//   - GraphQueries implementation ready to execute graph intelligence queries
func NewNeo4jGraphQueries(driver neo4j.DriverWithContext, logger *slog.Logger) GraphQueries {
	return NewNeo4jGraphQueriesWithMetrics(driver, logger, nil)
}

// NewNeo4jGraphQueriesWithMetrics creates a new Neo4jGraphQueries instance with custom metrics registerer.
//
// Parameters:
//   - driver: Neo4j driver for executing queries
//   - logger: Structured logger for diagnostic output
//   - registerer: Prometheus registerer for metrics (nil uses prometheus.DefaultRegisterer)
//
// Returns:
//   - GraphQueries implementation ready to execute graph intelligence queries with metrics
func NewNeo4jGraphQueriesWithMetrics(driver neo4j.DriverWithContext, logger *slog.Logger, registerer prometheus.Registerer) GraphQueries {
	if logger == nil {
		logger = slog.Default()
	}

	metrics := newGraphQueryMetrics(registerer)
	if err := metrics.register(); err != nil {
		logger.Warn("Failed to register graph query metrics", "error", err)
	}

	return &Neo4jGraphQueries{
		driver:  driver,
		tracer:  otel.Tracer("gibson.orchestrator.graph_queries"),
		logger:  logger,
		metrics: metrics,
	}
}

// GetTargetHistory retrieves historical scan information for a specific target.
func (q *Neo4jGraphQueries) GetTargetHistory(ctx context.Context, targetID string) (*TargetHistory, error) {
	const queryType = "get_target_history"
	startTime := time.Now()

	ctx, span := q.tracer.Start(ctx, "orchestrator.observe.graph_queries.get_target_history")
	defer span.End()

	span.SetAttributes(
		attribute.String("target_id", targetID),
		attribute.String("query_type", queryType),
	)

	// Create context with 500ms timeout
	queryCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	// Cypher query to get target history with severity distribution
	// We match on any entity (host, domain, endpoint, etc.) by id field
	cypher := `
		MATCH (target) WHERE target.id = $target_id
		OPTIONAL MATCH (finding:finding)-[:RELATES_TO]->(target)
		RETURN
			count(DISTINCT target) as scan_count,
			max(target.discovered_at) as last_scan,
			count(finding) as total_findings,
			sum(CASE WHEN finding.severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
			sum(CASE WHEN finding.severity = 'high' THEN 1 ELSE 0 END) as high_count,
			sum(CASE WHEN finding.severity = 'medium' THEN 1 ELSE 0 END) as medium_count,
			sum(CASE WHEN finding.severity = 'low' THEN 1 ELSE 0 END) as low_count
	`

	params := map[string]any{
		"target_id": targetID,
	}

	session := q.driver.NewSession(queryCtx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(queryCtx)

	result, err := session.Run(queryCtx, cypher, params)
	if err != nil {
		q.logger.WarnContext(ctx, "Failed to query target history",
			"error", err,
			"target_id", targetID,
		)
		span.RecordError(err)
		span.SetAttributes(attribute.String("error", err.Error()))

		// Record error metrics
		q.metrics.queriesTotal.WithLabelValues(queryType, "error").Inc()
		q.metrics.queryErrors.WithLabelValues(queryType, "query_execution").Inc()
		q.metrics.queryDuration.WithLabelValues(queryType).Observe(time.Since(startTime).Seconds())

		return nil, nil // Graceful degradation - return nil on error
	}

	if !result.Next(queryCtx) {
		// No history found - record as success with zero results
		duration := time.Since(startTime).Seconds()
		q.metrics.queriesTotal.WithLabelValues(queryType, "success").Inc()
		q.metrics.queryDuration.WithLabelValues(queryType).Observe(duration)
		q.metrics.contextSize.WithLabelValues("target_history").Set(0)
		return nil, nil
	}

	record := result.Record()

	// Extract scan count
	scanCount := int64(0)
	if val, ok := record.Get("scan_count"); ok {
		if count, ok := val.(int64); ok {
			scanCount = count
		}
	}

	// If no scans found, return nil
	if scanCount == 0 {
		return nil, nil
	}

	history := &TargetHistory{
		TargetID:          targetID,
		PreviousScanCount: int(scanCount),
	}

	// Extract last scan date
	if val, ok := record.Get("last_scan"); ok && val != nil {
		if dateStr, ok := val.(string); ok {
			if t, err := time.Parse(time.RFC3339, dateStr); err == nil {
				history.LastScanDate = &t
			}
		}
	}

	// Extract finding counts
	if val, ok := record.Get("total_findings"); ok {
		if count, ok := val.(int64); ok {
			history.TotalFindings = int(count)
		}
	}
	if val, ok := record.Get("critical_count"); ok {
		if count, ok := val.(int64); ok {
			history.CriticalCount = int(count)
		}
	}
	if val, ok := record.Get("high_count"); ok {
		if count, ok := val.(int64); ok {
			history.HighCount = int(count)
		}
	}
	if val, ok := record.Get("medium_count"); ok {
		if count, ok := val.(int64); ok {
			history.MediumCount = int(count)
		}
	}
	if val, ok := record.Get("low_count"); ok {
		if count, ok := val.(int64); ok {
			history.LowCount = int(count)
		}
	}

	// Record success metrics
	duration := time.Since(startTime).Seconds()
	resultCount := 1 // We return a single TargetHistory object

	span.SetAttributes(
		attribute.Int("scan_count", history.PreviousScanCount),
		attribute.Int("total_findings", history.TotalFindings),
		attribute.Int("result_count", resultCount),
	)

	q.metrics.queriesTotal.WithLabelValues(queryType, "success").Inc()
	q.metrics.queryDuration.WithLabelValues(queryType).Observe(duration)
	q.metrics.contextSize.WithLabelValues("target_history").Set(float64(resultCount))

	return history, nil
}

// GetPriorFindings retrieves recent findings for a specific domain or target scope.
func (q *Neo4jGraphQueries) GetPriorFindings(ctx context.Context, domain string, limit int) ([]HistoricalFinding, error) {
	const queryType = "get_prior_findings"
	startTime := time.Now()

	ctx, span := q.tracer.Start(ctx, "orchestrator.observe.graph_queries.get_prior_findings")
	defer span.End()

	span.SetAttributes(
		attribute.String("domain", domain),
		attribute.Int("limit", limit),
		attribute.String("query_type", queryType),
	)

	// Create context with 500ms timeout
	queryCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	// Cypher query to get prior findings related to domain entities
	// Ordered by severity weight (critical=4, high=3, medium=2, low=1), then by discovery time
	cypher := `
		MATCH (entity) WHERE entity.domain = $domain OR entity.id CONTAINS $domain
		MATCH (finding:finding)-[:RELATES_TO]->(entity)
		RETURN
			finding.id as id,
			finding.title as title,
			finding.severity as severity,
			finding.category as category,
			finding.discovered_at as discovered_at,
			entity.id as target_entity
		ORDER BY
			CASE finding.severity
				WHEN 'critical' THEN 4
				WHEN 'high' THEN 3
				WHEN 'medium' THEN 2
				WHEN 'low' THEN 1
				ELSE 0
			END DESC,
			finding.discovered_at DESC
		LIMIT $limit
	`

	params := map[string]any{
		"domain": domain,
		"limit":  int64(limit),
	}

	session := q.driver.NewSession(queryCtx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(queryCtx)

	result, err := session.Run(queryCtx, cypher, params)
	if err != nil {
		q.logger.WarnContext(ctx, "Failed to query prior findings",
			"error", err,
			"domain", domain,
		)
		span.RecordError(err)
		span.SetAttributes(attribute.String("error", err.Error()))

		// Record error metrics
		q.metrics.queriesTotal.WithLabelValues(queryType, "error").Inc()
		q.metrics.queryErrors.WithLabelValues(queryType, "query_execution").Inc()
		q.metrics.queryDuration.WithLabelValues(queryType).Observe(time.Since(startTime).Seconds())

		return []HistoricalFinding{}, nil // Graceful degradation - return empty slice
	}

	findings := []HistoricalFinding{}
	for result.Next(queryCtx) {
		record := result.Record()

		finding := HistoricalFinding{}

		// Extract fields with type assertions
		if val, ok := record.Get("id"); ok && val != nil {
			if str, ok := val.(string); ok {
				finding.ID = str
			}
		}
		if val, ok := record.Get("title"); ok && val != nil {
			if str, ok := val.(string); ok {
				finding.Title = str
			}
		}
		if val, ok := record.Get("severity"); ok && val != nil {
			if str, ok := val.(string); ok {
				finding.Severity = str
			}
		}
		if val, ok := record.Get("category"); ok && val != nil {
			if str, ok := val.(string); ok {
				finding.Category = str
			}
		}
		if val, ok := record.Get("target_entity"); ok && val != nil {
			if str, ok := val.(string); ok {
				finding.TargetEntity = str
			}
		}
		if val, ok := record.Get("discovered_at"); ok && val != nil {
			if dateStr, ok := val.(string); ok {
				if t, err := time.Parse(time.RFC3339, dateStr); err == nil {
					finding.DiscoveredAt = t
				}
			}
		}

		findings = append(findings, finding)
	}

	// Record success metrics
	duration := time.Since(startTime).Seconds()
	resultCount := len(findings)

	span.SetAttributes(
		attribute.Int("findings_count", resultCount),
		attribute.Int("result_count", resultCount),
	)

	q.metrics.queriesTotal.WithLabelValues(queryType, "success").Inc()
	q.metrics.queryDuration.WithLabelValues(queryType).Observe(duration)
	q.metrics.contextSize.WithLabelValues("prior_findings").Set(float64(resultCount))

	return findings, nil
}

// GetKnownEntities retrieves entities previously discovered for a target.
func (q *Neo4jGraphQueries) GetKnownEntities(ctx context.Context, targetID string) ([]EntitySummary, error) {
	const queryType = "get_known_entities"
	startTime := time.Now()

	ctx, span := q.tracer.Start(ctx, "orchestrator.observe.graph_queries.get_known_entities")
	defer span.End()

	span.SetAttributes(
		attribute.String("target_id", targetID),
		attribute.String("query_type", queryType),
	)

	// Create context with 500ms timeout
	queryCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	// Cypher query to get known entities related to a target
	// Match entities that are connected to the target via relationships
	cypher := `
		MATCH (target) WHERE target.id = $target_id
		OPTIONAL MATCH (target)-[*1..2]-(entity)
		WHERE entity.id IS NOT NULL
		WITH DISTINCT entity
		RETURN
			entity.id as id,
			labels(entity)[0] as type,
			entity.id as identifier,
			entity.discovered_at as discovered_at,
			properties(entity) as properties
		ORDER BY entity.discovered_at DESC
		LIMIT 100
	`

	params := map[string]any{
		"target_id": targetID,
	}

	session := q.driver.NewSession(queryCtx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(queryCtx)

	result, err := session.Run(queryCtx, cypher, params)
	if err != nil {
		q.logger.WarnContext(ctx, "Failed to query known entities",
			"error", err,
			"target_id", targetID,
		)
		span.RecordError(err)
		span.SetAttributes(attribute.String("error", err.Error()))

		// Record error metrics
		q.metrics.queriesTotal.WithLabelValues(queryType, "error").Inc()
		q.metrics.queryErrors.WithLabelValues(queryType, "query_execution").Inc()
		q.metrics.queryDuration.WithLabelValues(queryType).Observe(time.Since(startTime).Seconds())

		return []EntitySummary{}, nil // Graceful degradation - return empty slice
	}

	entities := []EntitySummary{}
	for result.Next(queryCtx) {
		record := result.Record()

		entity := EntitySummary{
			Properties: make(map[string]any),
		}

		// Extract fields
		if val, ok := record.Get("id"); ok && val != nil {
			if str, ok := val.(string); ok {
				entity.ID = str
			}
		}
		if val, ok := record.Get("type"); ok && val != nil {
			if str, ok := val.(string); ok {
				entity.Type = str
			}
		}
		if val, ok := record.Get("identifier"); ok && val != nil {
			if str, ok := val.(string); ok {
				entity.Identifier = str
			}
		}
		if val, ok := record.Get("discovered_at"); ok && val != nil {
			if dateStr, ok := val.(string); ok {
				if t, err := time.Parse(time.RFC3339, dateStr); err == nil {
					entity.DiscoveredAt = t
				}
			}
		}
		if val, ok := record.Get("properties"); ok && val != nil {
			if props, ok := val.(map[string]any); ok {
				// Filter out framework fields to keep only business properties
				for k, v := range props {
					if k != "id" && k != "discovered_at" && k != "discovered_by" &&
						k != "mission_id" && k != "mission_run_id" && k != "agent_run_id" {
						entity.Properties[k] = v
					}
				}
			}
		}

		entities = append(entities, entity)
	}

	// Record success metrics
	duration := time.Since(startTime).Seconds()
	resultCount := len(entities)

	span.SetAttributes(
		attribute.Int("entities_count", resultCount),
		attribute.Int("result_count", resultCount),
	)

	q.metrics.queriesTotal.WithLabelValues(queryType, "success").Inc()
	q.metrics.queryDuration.WithLabelValues(queryType).Observe(duration)
	q.metrics.contextSize.WithLabelValues("known_entities").Set(float64(resultCount))

	return entities, nil
}

// GetSuccessfulPatterns retrieves attack patterns that have historically been successful
// for a specific target type.
func (q *Neo4jGraphQueries) GetSuccessfulPatterns(ctx context.Context, targetType string) ([]AttackPattern, error) {
	const queryType = "get_successful_patterns"
	startTime := time.Now()

	ctx, span := q.tracer.Start(ctx, "orchestrator.observe.graph_queries.get_successful_patterns")
	defer span.End()

	span.SetAttributes(
		attribute.String("target_type", targetType),
		attribute.String("query_type", queryType),
	)

	// Create context with 500ms timeout
	queryCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	// Cypher query to get successful attack patterns
	// This assumes we track techniques used and findings discovered
	// Success rate = (findings discovered using technique) / (total uses of technique)
	cypher := `
		MATCH (entity) WHERE labels(entity)[0] = $target_type
		MATCH (finding:finding)-[:RELATES_TO]->(entity)
		WHERE finding.technique_id IS NOT NULL
		WITH finding.technique_id as technique_id,
		     finding.technique_name as technique_name,
		     finding.description as description,
		     count(DISTINCT finding) as finding_count,
		     collect(DISTINCT labels(entity)[0]) as target_types
		RETURN
			technique_id,
			technique_name,
			description,
			1.0 as success_rate,
			finding_count as sample_count,
			target_types
		ORDER BY finding_count DESC
		LIMIT 10
	`

	params := map[string]any{
		"target_type": targetType,
	}

	session := q.driver.NewSession(queryCtx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(queryCtx)

	result, err := session.Run(queryCtx, cypher, params)
	if err != nil {
		q.logger.WarnContext(ctx, "Failed to query successful patterns",
			"error", err,
			"target_type", targetType,
		)
		span.RecordError(err)
		span.SetAttributes(attribute.String("error", err.Error()))

		// Record error metrics
		q.metrics.queriesTotal.WithLabelValues(queryType, "error").Inc()
		q.metrics.queryErrors.WithLabelValues(queryType, "query_execution").Inc()
		q.metrics.queryDuration.WithLabelValues(queryType).Observe(time.Since(startTime).Seconds())

		return []AttackPattern{}, nil // Graceful degradation - return empty slice
	}

	patterns := []AttackPattern{}
	for result.Next(queryCtx) {
		record := result.Record()

		pattern := AttackPattern{
			TargetTypes: []string{},
		}

		// Extract fields
		if val, ok := record.Get("technique_id"); ok && val != nil {
			if str, ok := val.(string); ok {
				pattern.TechniqueID = str
			}
		}
		if val, ok := record.Get("technique_name"); ok && val != nil {
			if str, ok := val.(string); ok {
				pattern.TechniqueName = str
			}
		}
		if val, ok := record.Get("description"); ok && val != nil {
			if str, ok := val.(string); ok {
				pattern.Description = str
			}
		}
		if val, ok := record.Get("success_rate"); ok && val != nil {
			if rate, ok := val.(float64); ok {
				pattern.SuccessRate = rate
			}
		}
		if val, ok := record.Get("sample_count"); ok && val != nil {
			if count, ok := val.(int64); ok {
				pattern.SampleCount = int(count)
			}
		}
		if val, ok := record.Get("target_types"); ok && val != nil {
			if types, ok := val.([]any); ok {
				for _, t := range types {
					if typeStr, ok := t.(string); ok {
						pattern.TargetTypes = append(pattern.TargetTypes, typeStr)
					}
				}
			}
		}

		patterns = append(patterns, pattern)
	}

	// Record success metrics
	duration := time.Since(startTime).Seconds()
	resultCount := len(patterns)

	span.SetAttributes(
		attribute.Int("patterns_count", resultCount),
		attribute.Int("result_count", resultCount),
	)

	q.metrics.queriesTotal.WithLabelValues(queryType, "success").Inc()
	q.metrics.queryDuration.WithLabelValues(queryType).Observe(duration)
	q.metrics.contextSize.WithLabelValues("successful_patterns").Set(float64(resultCount))

	return patterns, nil
}
