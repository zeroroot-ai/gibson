// Package intelligence provides cross-mission security analytics queries.
package intelligence

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// RecurringVulnerabilityQuery finds vulnerabilities that recur across multiple targets.
type RecurringVulnerabilityQuery struct {
	driver neo4j.DriverWithContext
}

// NewRecurringVulnerabilityQuery creates a new recurring vulnerability query handler.
func NewRecurringVulnerabilityQuery(driver neo4j.DriverWithContext) *RecurringVulnerabilityQuery {
	return &RecurringVulnerabilityQuery{
		driver: driver,
	}
}

// Execute runs the recurring vulnerability query.
func (q *RecurringVulnerabilityQuery) Execute(ctx context.Context, opts sdkgraphrag.RecurringVulnOpts) (*sdkgraphrag.RecurringVulnResult, error) {
	// Apply defaults
	if opts.Threshold <= 0 {
		opts.Threshold = 3
	}
	if opts.Limit <= 0 {
		opts.Limit = 100
	}

	// Build Cypher query
	query, params := q.buildQuery(opts)

	// Execute query
	session := q.driver.NewSession(ctx, neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeRead,
	})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		records, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, fmt.Errorf("failed to execute recurring vulnerability query: %w", err)
		}

		var vulnerabilities []sdkgraphrag.RecurringVulnerability
		for records.Next(ctx) {
			record := records.Record()
			vuln := q.parseVulnerability(record)
			vulnerabilities = append(vulnerabilities, vuln)
		}

		if err := records.Err(); err != nil {
			return nil, fmt.Errorf("error iterating results: %w", err)
		}

		return vulnerabilities, nil
	})

	if err != nil {
		return nil, err
	}

	vulnerabilities := result.([]sdkgraphrag.RecurringVulnerability)

	// Build time range from opts or actual data
	timeRange := sdkgraphrag.TimeRange{}
	if opts.TimeRange != nil {
		timeRange = *opts.TimeRange
	} else {
		timeRange = sdkgraphrag.TimeRange{
			Start: time.Now().AddDate(0, -3, 0), // Default 3 months
			End:   time.Now(),
		}
	}

	return &sdkgraphrag.RecurringVulnResult{
		Vulnerabilities: vulnerabilities,
		TotalCount:      len(vulnerabilities),
		TimeRange:       timeRange,
	}, nil
}

// buildQuery constructs the Cypher query for recurring vulnerabilities.
func (q *RecurringVulnerabilityQuery) buildQuery(opts sdkgraphrag.RecurringVulnOpts) (string, map[string]any) {
	params := map[string]any{
		"threshold": opts.Threshold,
		"limit":     opts.Limit,
		"offset":    opts.Offset,
	}

	var whereClauses []string

	// Time range filter
	if opts.TimeRange != nil {
		whereClauses = append(whereClauses, "f.created_at >= $start_time AND f.created_at <= $end_time")
		params["start_time"] = opts.TimeRange.Start.Unix()
		params["end_time"] = opts.TimeRange.End.Unix()
	}

	// Severity filter
	if len(opts.Severities) > 0 {
		severities := make([]string, len(opts.Severities))
		for i, sev := range opts.Severities {
			severities[i] = string(sev)
		}
		whereClauses = append(whereClauses, "f.severity IN $severities")
		params["severities"] = severities
	}

	// Target type filter
	if len(opts.TargetTypes) > 0 {
		whereClauses = append(whereClauses, "h.target_type IN $target_types")
		params["target_types"] = opts.TargetTypes
	}

	whereClause := ""
	if len(whereClauses) > 0 {
		whereClause = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	// Cypher query to find recurring vulnerabilities
	query := fmt.Sprintf(`
		MATCH (f:Finding)-[:AFFECTS]->(h:Host)
		%s
		WITH f.vuln_type AS vuln_type,
			 COALESCE(f.cve_ids, []) AS cve_ids,
			 COALESCE(f.cwe_ids, []) AS cwe_ids,
			 f.severity AS severity,
			 f.created_at AS created_at,
			 h.id AS host_id
		WITH vuln_type,
			 collect(DISTINCT cve_ids) AS all_cves,
			 collect(DISTINCT cwe_ids) AS all_cwes,
			 count(*) AS occurrence_count,
			 count(DISTINCT host_id) AS affected_host_count,
			 collect(severity) AS severities,
			 min(created_at) AS first_seen,
			 max(created_at) AS last_seen,
			 collect(DISTINCT host_id)[0..5] AS sample_hosts
		WHERE occurrence_count >= $threshold
		RETURN vuln_type,
			   all_cves,
			   all_cwes,
			   occurrence_count,
			   affected_host_count,
			   severities,
			   first_seen,
			   last_seen,
			   sample_hosts
		ORDER BY occurrence_count DESC
		SKIP $offset
		LIMIT $limit
	`, whereClause)

	return query, params
}

// parseVulnerability converts a Neo4j record to a RecurringVulnerability.
func (q *RecurringVulnerabilityQuery) parseVulnerability(record *neo4j.Record) sdkgraphrag.RecurringVulnerability {
	vuln := sdkgraphrag.RecurringVulnerability{
		SeverityDistribution: make(map[sdkgraphrag.Severity]int),
	}

	if val, ok := record.Get("vuln_type"); ok && val != nil {
		vuln.VulnType = val.(string)
	}

	if val, ok := record.Get("occurrence_count"); ok && val != nil {
		vuln.OccurrenceCount = int(val.(int64))
	}

	if val, ok := record.Get("affected_host_count"); ok && val != nil {
		vuln.AffectedHostCount = int(val.(int64))
	}

	if val, ok := record.Get("first_seen"); ok && val != nil {
		vuln.FirstSeen = time.Unix(val.(int64), 0)
	}

	if val, ok := record.Get("last_seen"); ok && val != nil {
		vuln.LastSeen = time.Unix(val.(int64), 0)
	}

	// Parse CVE IDs
	if val, ok := record.Get("all_cves"); ok && val != nil {
		for _, cves := range val.([]any) {
			if cveList, ok := cves.([]any); ok {
				for _, cve := range cveList {
					if cveStr, ok := cve.(string); ok {
						vuln.CVEIDs = append(vuln.CVEIDs, cveStr)
					}
				}
			}
		}
		// Deduplicate
		vuln.CVEIDs = dedupe(vuln.CVEIDs)
	}

	// Parse CWE IDs
	if val, ok := record.Get("all_cwes"); ok && val != nil {
		for _, cwes := range val.([]any) {
			if cweList, ok := cwes.([]any); ok {
				for _, cwe := range cweList {
					if cweStr, ok := cwe.(string); ok {
						vuln.CWEIDs = append(vuln.CWEIDs, cweStr)
					}
				}
			}
		}
		// Deduplicate
		vuln.CWEIDs = dedupe(vuln.CWEIDs)
	}

	// Parse severity distribution
	if val, ok := record.Get("severities"); ok && val != nil {
		for _, sev := range val.([]any) {
			if sevStr, ok := sev.(string); ok {
				severity := sdkgraphrag.Severity(sevStr)
				vuln.SeverityDistribution[severity]++
			}
		}
	}

	// Parse sample hosts
	if val, ok := record.Get("sample_hosts"); ok && val != nil {
		for _, host := range val.([]any) {
			if hostStr, ok := host.(string); ok {
				vuln.SampleHosts = append(vuln.SampleHosts, hostStr)
			}
		}
	}

	return vuln
}

// dedupe removes duplicate strings from a slice.
func dedupe(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
