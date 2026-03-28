package intelligence

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
)

// AttackPatternAnalyzer identifies successful attack technique sequences.
type AttackPatternAnalyzer struct {
	driver neo4j.DriverWithContext
}

// NewAttackPatternAnalyzer creates a new attack pattern analyzer.
func NewAttackPatternAnalyzer(driver neo4j.DriverWithContext) *AttackPatternAnalyzer {
	return &AttackPatternAnalyzer{
		driver: driver,
	}
}

// Execute runs the attack pattern analysis.
func (a *AttackPatternAnalyzer) Execute(ctx context.Context, opts sdkgraphrag.PatternOpts) (*sdkgraphrag.PatternResult, error) {
	// Apply defaults
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.MinSuccessRate <= 0 {
		opts.MinSuccessRate = 0.1 // Default 10% minimum success rate
	}

	// Execute query
	session := a.driver.NewSession(ctx, neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeRead,
	})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		query, params := a.buildQuery(opts)
		records, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, fmt.Errorf("failed to execute attack pattern query: %w", err)
		}

		var patterns []sdkgraphrag.IntelligenceAttackPattern
		for records.Next(ctx) {
			record := records.Record()
			pattern := a.parsePattern(record)
			if pattern.SuccessRate >= opts.MinSuccessRate {
				patterns = append(patterns, pattern)
			}
		}

		if err := records.Err(); err != nil {
			return nil, fmt.Errorf("error iterating results: %w", err)
		}

		return patterns, nil
	})

	if err != nil {
		return nil, err
	}

	patterns := result.([]sdkgraphrag.IntelligenceAttackPattern)

	return &sdkgraphrag.PatternResult{
		Patterns:      patterns,
		TotalPatterns: len(patterns),
	}, nil
}

// buildQuery constructs the Cypher query for attack patterns.
func (a *AttackPatternAnalyzer) buildQuery(opts sdkgraphrag.PatternOpts) (string, map[string]any) {
	params := map[string]any{
		"limit":            opts.Limit,
		"min_success_rate": opts.MinSuccessRate,
	}

	var whereClauses []string

	if opts.Technique != "" && opts.Technique != "all" {
		whereClauses = append(whereClauses, "(t.technique = $technique OR t.mitre_id = $technique)")
		params["technique"] = opts.Technique
	}

	if opts.TargetType != "" {
		whereClauses = append(whereClauses, "h.target_type = $target_type")
		params["target_type"] = opts.TargetType
	}

	whereClause := ""
	if len(whereClauses) > 0 {
		whereClause = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	// Query to find technique chains that led to findings
	// This analyzes the sequence of techniques used in successful attacks
	query := fmt.Sprintf(`
		// Find missions with findings (successful attacks)
		MATCH (m:Mission)-[:PRODUCED]->(f:Finding)

		// Find techniques used in those missions
		MATCH (m)-[:USED_TECHNIQUE]->(t:Technique)
		OPTIONAL MATCH (t)-[:PRECEDES]->(next:Technique)<-[:USED_TECHNIQUE]-(m)
		OPTIONAL MATCH (f)-[:AFFECTS]->(h:Host)
		%s

		// Group by technique sequences
		WITH t.technique AS technique,
			 t.mitre_id AS mitre_id,
			 t.mitre_name AS mitre_name,
			 collect(DISTINCT next.technique) AS next_techniques,
			 count(DISTINCT f) AS finding_count,
			 count(DISTINCT m) AS mission_count,
			 collect(DISTINCT h.target_type) AS target_types,
			 collect(DISTINCT m.id)[0..3] AS sample_missions

		// Calculate success rate (missions with findings / total missions)
		WITH technique, mitre_id, mitre_name, next_techniques,
			 finding_count, mission_count, target_types, sample_missions,
			 CASE WHEN mission_count > 0
				  THEN toFloat(finding_count) / mission_count
				  ELSE 0 END AS success_rate

		WHERE success_rate >= $min_success_rate

		RETURN technique,
			   mitre_id,
			   mitre_name,
			   next_techniques,
			   finding_count,
			   mission_count,
			   success_rate,
			   target_types,
			   sample_missions
		ORDER BY success_rate DESC, finding_count DESC
		LIMIT $limit
	`, whereClause)

	return query, params
}

// parsePattern converts a Neo4j record to an IntelligenceAttackPattern.
func (a *AttackPatternAnalyzer) parsePattern(record *neo4j.Record) sdkgraphrag.IntelligenceAttackPattern {
	pattern := sdkgraphrag.IntelligenceAttackPattern{
		PatternID:             uuid.New().String(),
		TargetCharacteristics: make(map[string]string),
	}

	// Parse main technique
	var mainTechnique sdkgraphrag.TechniqueInChain
	mainTechnique.Position = 0

	if val, ok := record.Get("technique"); ok && val != nil {
		mainTechnique.Technique = val.(string)
	}
	if val, ok := record.Get("mitre_id"); ok && val != nil {
		mainTechnique.MitreID = val.(string)
	}
	if val, ok := record.Get("mitre_name"); ok && val != nil {
		mainTechnique.MitreName = val.(string)
	}

	pattern.TechniqueChain = append(pattern.TechniqueChain, mainTechnique)

	// Parse chained techniques
	if val, ok := record.Get("next_techniques"); ok && val != nil {
		for i, next := range val.([]any) {
			if nextStr, ok := next.(string); ok && nextStr != "" {
				pattern.TechniqueChain = append(pattern.TechniqueChain, sdkgraphrag.TechniqueInChain{
					Technique: nextStr,
					Position:  i + 1,
				})
			}
		}
	}

	// Parse metrics
	if val, ok := record.Get("success_rate"); ok && val != nil {
		pattern.SuccessRate = val.(float64)
	}
	if val, ok := record.Get("finding_count"); ok && val != nil {
		pattern.OccurrenceCount = int(val.(int64))
	}

	// Parse target characteristics
	if val, ok := record.Get("target_types"); ok && val != nil {
		types := val.([]any)
		if len(types) > 0 {
			typeStrs := make([]string, 0, len(types))
			for _, t := range types {
				if tStr, ok := t.(string); ok {
					typeStrs = append(typeStrs, tStr)
				}
			}
			pattern.TargetCharacteristics["target_types"] = strings.Join(typeStrs, ", ")
		}
	}

	// Parse sample missions
	if val, ok := record.Get("sample_missions"); ok && val != nil {
		for _, m := range val.([]any) {
			if mStr, ok := m.(string); ok {
				pattern.SampleMissions = append(pattern.SampleMissions, mStr)
			}
		}
	}

	// Calculate confidence based on occurrence count
	pattern.Confidence = a.calculateConfidence(pattern.OccurrenceCount, pattern.SuccessRate)

	return pattern
}

// calculateConfidence determines confidence level based on data quality.
func (a *AttackPatternAnalyzer) calculateConfidence(occurrences int, successRate float64) float64 {
	// Base confidence from occurrence count
	baseConfidence := 0.0
	switch {
	case occurrences >= 100:
		baseConfidence = 0.95
	case occurrences >= 50:
		baseConfidence = 0.85
	case occurrences >= 20:
		baseConfidence = 0.75
	case occurrences >= 10:
		baseConfidence = 0.65
	case occurrences >= 5:
		baseConfidence = 0.55
	default:
		baseConfidence = 0.40
	}

	// Adjust for success rate (high success rates are more confident)
	if successRate > 0.8 {
		baseConfidence += 0.05
	} else if successRate < 0.2 {
		baseConfidence -= 0.10
	}

	// Clamp to valid range
	if baseConfidence > 1.0 {
		baseConfidence = 1.0
	}
	if baseConfidence < 0.1 {
		baseConfidence = 0.1
	}

	return baseConfidence
}
