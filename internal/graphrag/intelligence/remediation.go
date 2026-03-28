package intelligence

import (
	"context"
	"fmt"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
)

// RemediationMetricsQuery calculates remediation success rates and timing.
type RemediationMetricsQuery struct {
	driver neo4j.DriverWithContext
}

// NewRemediationMetricsQuery creates a new remediation metrics query handler.
func NewRemediationMetricsQuery(driver neo4j.DriverWithContext) *RemediationMetricsQuery {
	return &RemediationMetricsQuery{
		driver: driver,
	}
}

// Execute runs the remediation metrics query.
func (q *RemediationMetricsQuery) Execute(ctx context.Context, opts sdkgraphrag.RemediationOpts) (*sdkgraphrag.RemediationResult, error) {
	// Build Cypher query based on groupBy option
	query, params := q.buildQuery(opts)

	// Execute query
	session := q.driver.NewSession(ctx, neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeRead,
	})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		records, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, fmt.Errorf("failed to execute remediation metrics query: %w", err)
		}

		var metrics []sdkgraphrag.RemediationMetric
		for records.Next(ctx) {
			record := records.Record()
			metric := q.parseMetric(record, opts.GroupBy)
			metrics = append(metrics, metric)
		}

		if err := records.Err(); err != nil {
			return nil, fmt.Errorf("error iterating results: %w", err)
		}

		return metrics, nil
	})

	if err != nil {
		return nil, err
	}

	metrics := result.([]sdkgraphrag.RemediationMetric)

	// Calculate overall metrics
	overallRate, overallMTTR := q.calculateOverallMetrics(metrics)

	// Build time range
	timeRange := sdkgraphrag.TimeRange{}
	if opts.TimeRange != nil {
		timeRange = *opts.TimeRange
	} else {
		timeRange = sdkgraphrag.TimeRange{
			Start: time.Now().AddDate(0, -3, 0),
			End:   time.Now(),
		}
	}

	// Check for data limitations
	dataLimitations := ""
	if len(metrics) == 0 {
		dataLimitations = "no remediation data found for the specified parameters"
	}

	return &sdkgraphrag.RemediationResult{
		Metrics:         metrics,
		OverallRate:     overallRate,
		OverallMTTR:     overallMTTR,
		TimeRange:       timeRange,
		DataLimitations: dataLimitations,
	}, nil
}

// buildQuery constructs the Cypher query for remediation metrics.
func (q *RemediationMetricsQuery) buildQuery(opts sdkgraphrag.RemediationOpts) (string, map[string]any) {
	params := map[string]any{}

	// Build WHERE clauses
	whereParts := []string{}

	if opts.VulnType != "" && opts.VulnType != "all" {
		whereParts = append(whereParts, "f.vuln_type = $vuln_type")
		params["vuln_type"] = opts.VulnType
	}

	if opts.TimeRange != nil {
		whereParts = append(whereParts, "f.created_at >= $start_time AND f.created_at <= $end_time")
		params["start_time"] = opts.TimeRange.Start.Unix()
		params["end_time"] = opts.TimeRange.End.Unix()
	}

	whereClause := ""
	if len(whereParts) > 0 {
		whereClause = "WHERE " + joinStrings(whereParts, " AND ")
	}

	// Determine grouping field
	var groupByField string
	switch opts.GroupBy {
	case "severity":
		groupByField = "f.severity"
	case "target_type":
		groupByField = "h.target_type"
	default:
		groupByField = "f.vuln_type"
	}

	// Build query
	query := fmt.Sprintf(`
		MATCH (f:Finding)
		OPTIONAL MATCH (f)-[:AFFECTS]->(h:Host)
		%s
		WITH %s AS group_value,
			 count(*) AS total_findings,
			 sum(CASE WHEN f.status = 'remediated' THEN 1 ELSE 0 END) AS remediated_count,
			 sum(CASE WHEN f.status = 'recurred' THEN 1 ELSE 0 END) AS recurred_count,
			 collect(CASE WHEN f.remediated_at IS NOT NULL THEN f.remediated_at - f.created_at ELSE NULL END) AS remediation_times
		RETURN group_value,
			   total_findings,
			   remediated_count,
			   recurred_count,
			   remediation_times,
			   CASE WHEN total_findings > 0 THEN toFloat(remediated_count) / total_findings * 100 ELSE 0 END AS remediation_rate,
			   CASE WHEN total_findings > 0 THEN toFloat(recurred_count) / total_findings * 100 ELSE 0 END AS recurrence_rate
		ORDER BY total_findings DESC
	`, whereClause, groupByField)

	return query, params
}

// parseMetric converts a Neo4j record to a RemediationMetric.
func (q *RemediationMetricsQuery) parseMetric(record *neo4j.Record, groupBy string) sdkgraphrag.RemediationMetric {
	metric := sdkgraphrag.RemediationMetric{
		GroupKey: groupBy,
	}

	if groupBy == "" {
		metric.GroupKey = "vuln_type"
	}

	if val, ok := record.Get("group_value"); ok && val != nil {
		metric.GroupValue = val.(string)
	}

	if val, ok := record.Get("total_findings"); ok && val != nil {
		metric.TotalFindings = int(val.(int64))
	}

	if val, ok := record.Get("remediated_count"); ok && val != nil {
		metric.RemediatedFindings = int(val.(int64))
	}

	if val, ok := record.Get("remediation_rate"); ok && val != nil {
		metric.RemediationRate = val.(float64)
	}

	if val, ok := record.Get("recurrence_rate"); ok && val != nil {
		metric.RecurrenceRate = val.(float64)
	}

	// Calculate MTTR from remediation times
	if val, ok := record.Get("remediation_times"); ok && val != nil {
		times := val.([]any)
		var totalTime int64
		var count int
		for _, t := range times {
			if t != nil {
				totalTime += t.(int64)
				count++
			}
		}
		if count > 0 {
			// Convert seconds to days
			metric.MTTR = float64(totalTime) / float64(count) / 86400
		}
	}

	return metric
}

// calculateOverallMetrics calculates aggregate metrics across all groups.
func (q *RemediationMetricsQuery) calculateOverallMetrics(metrics []sdkgraphrag.RemediationMetric) (float64, float64) {
	if len(metrics) == 0 {
		return 0, 0
	}

	var totalFindings, totalRemediated int
	var totalMTTRWeight, totalMTTR float64

	for _, m := range metrics {
		totalFindings += m.TotalFindings
		totalRemediated += m.RemediatedFindings
		if m.MTTR > 0 {
			totalMTTRWeight += float64(m.RemediatedFindings)
			totalMTTR += m.MTTR * float64(m.RemediatedFindings)
		}
	}

	overallRate := 0.0
	if totalFindings > 0 {
		overallRate = float64(totalRemediated) / float64(totalFindings) * 100
	}

	overallMTTR := 0.0
	if totalMTTRWeight > 0 {
		overallMTTR = totalMTTR / totalMTTRWeight
	}

	return overallRate, overallMTTR
}

// joinStrings is a simple string joiner.
func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += sep + parts[i]
	}
	return result
}
