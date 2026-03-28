package intelligence

import (
	"context"
	"fmt"
	"math"
	"sort"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
)

// SimilarTargetFinder finds targets similar to a reference target.
type SimilarTargetFinder struct {
	driver neo4j.DriverWithContext
}

// NewSimilarTargetFinder creates a new similar target finder.
func NewSimilarTargetFinder(driver neo4j.DriverWithContext) *SimilarTargetFinder {
	return &SimilarTargetFinder{
		driver: driver,
	}
}

// Execute runs the similar target discovery.
func (f *SimilarTargetFinder) Execute(ctx context.Context, opts sdkgraphrag.SimilarTargetsOpts) (*sdkgraphrag.SimilarTargetsResult, error) {
	// Apply defaults
	if opts.K <= 0 {
		opts.K = 10
	}
	if len(opts.Features) == 0 {
		opts.Features = []string{"technology_stack", "port_profile", "vuln_profile"}
	}

	// Fetch reference target data
	session := f.driver.NewSession(ctx, neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeRead,
	})
	defer session.Close(ctx)

	// First, get reference target data
	refData, err := f.getTargetData(ctx, session, opts.TargetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get reference target data: %w", err)
	}

	// Get all other targets for comparison
	candidates, err := f.getCandidateTargets(ctx, session, opts.TargetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get candidate targets: %w", err)
	}

	// Calculate similarity for each candidate
	similarTargets := make([]sdkgraphrag.SimilarTarget, 0, len(candidates))
	for _, candidate := range candidates {
		similarity := f.calculateSimilarity(refData, candidate, opts.Features)
		if similarity.SimilarityScore > 0 {
			similarTargets = append(similarTargets, similarity)
		}
	}

	// Sort by similarity score descending
	sort.Slice(similarTargets, func(i, j int) bool {
		return similarTargets[i].SimilarityScore > similarTargets[j].SimilarityScore
	})

	// Limit to K results
	if len(similarTargets) > opts.K {
		similarTargets = similarTargets[:opts.K]
	}

	return &sdkgraphrag.SimilarTargetsResult{
		ReferenceTargetID: opts.TargetID,
		SimilarTargets:    similarTargets,
		FeaturesUsed:      opts.Features,
	}, nil
}

// targetData holds computed features for a target.
type targetData struct {
	targetID       string
	targetName     string
	technologies   []string
	ports          []int
	services       []string
	vulnTypes      []string
	findings       []string
	techniques     []string
}

// getTargetData fetches feature data for a single target.
func (f *SimilarTargetFinder) getTargetData(ctx context.Context, session neo4j.SessionWithContext, targetID string) (*targetData, error) {
	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		query := `
			MATCH (h:Host {id: $target_id})
			OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
			OPTIONAL MATCH (p)-[:RUNS_SERVICE]->(s:Service)
			OPTIONAL MATCH (s)-[:USES_TECHNOLOGY]->(tech:Technology)
			OPTIONAL MATCH (h)<-[:AFFECTS]-(f:Finding)
			OPTIONAL MATCH (f)<-[:PRODUCED]-(m:Mission)-[:USED_TECHNIQUE]->(t:Technique)
			RETURN h.id AS target_id,
				   COALESCE(h.hostname, h.ip, h.id) AS target_name,
				   collect(DISTINCT tech.name) AS technologies,
				   collect(DISTINCT p.number) AS ports,
				   collect(DISTINCT s.name) AS services,
				   collect(DISTINCT f.vuln_type) AS vuln_types,
				   collect(DISTINCT f.id) AS finding_ids,
				   collect(DISTINCT t.technique) AS techniques
		`
		records, err := tx.Run(ctx, query, map[string]any{"target_id": targetID})
		if err != nil {
			return nil, err
		}

		if records.Next(ctx) {
			record := records.Record()
			return f.parseTargetData(record), nil
		}

		return nil, fmt.Errorf("target not found: %s", targetID)
	})

	if err != nil {
		return nil, err
	}

	return result.(*targetData), nil
}

// getCandidateTargets fetches data for all potential similar targets.
func (f *SimilarTargetFinder) getCandidateTargets(ctx context.Context, session neo4j.SessionWithContext, excludeID string) ([]*targetData, error) {
	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		query := `
			MATCH (h:Host)
			WHERE h.id <> $exclude_id
			OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
			OPTIONAL MATCH (p)-[:RUNS_SERVICE]->(s:Service)
			OPTIONAL MATCH (s)-[:USES_TECHNOLOGY]->(tech:Technology)
			OPTIONAL MATCH (h)<-[:AFFECTS]-(f:Finding)
			OPTIONAL MATCH (f)<-[:PRODUCED]-(m:Mission)-[:USED_TECHNIQUE]->(t:Technique)
			WITH h,
				 collect(DISTINCT tech.name) AS technologies,
				 collect(DISTINCT p.number) AS ports,
				 collect(DISTINCT s.name) AS services,
				 collect(DISTINCT f.vuln_type) AS vuln_types,
				 collect(DISTINCT f.id) AS finding_ids,
				 collect(DISTINCT t.technique) AS techniques
			RETURN h.id AS target_id,
				   COALESCE(h.hostname, h.ip, h.id) AS target_name,
				   technologies,
				   ports,
				   services,
				   vuln_types,
				   finding_ids,
				   techniques
			LIMIT 1000
		`
		records, err := tx.Run(ctx, query, map[string]any{"exclude_id": excludeID})
		if err != nil {
			return nil, err
		}

		var targets []*targetData
		for records.Next(ctx) {
			record := records.Record()
			targets = append(targets, f.parseTargetData(record))
		}

		return targets, records.Err()
	})

	if err != nil {
		return nil, err
	}

	return result.([]*targetData), nil
}

// parseTargetData converts a Neo4j record to targetData.
func (f *SimilarTargetFinder) parseTargetData(record *neo4j.Record) *targetData {
	data := &targetData{}

	if val, ok := record.Get("target_id"); ok && val != nil {
		data.targetID = val.(string)
	}
	if val, ok := record.Get("target_name"); ok && val != nil {
		data.targetName = val.(string)
	}
	if val, ok := record.Get("technologies"); ok && val != nil {
		for _, t := range val.([]any) {
			if s, ok := t.(string); ok && s != "" {
				data.technologies = append(data.technologies, s)
			}
		}
	}
	if val, ok := record.Get("ports"); ok && val != nil {
		for _, p := range val.([]any) {
			if n, ok := p.(int64); ok {
				data.ports = append(data.ports, int(n))
			}
		}
	}
	if val, ok := record.Get("services"); ok && val != nil {
		for _, s := range val.([]any) {
			if str, ok := s.(string); ok && str != "" {
				data.services = append(data.services, str)
			}
		}
	}
	if val, ok := record.Get("vuln_types"); ok && val != nil {
		for _, v := range val.([]any) {
			if s, ok := v.(string); ok && s != "" {
				data.vulnTypes = append(data.vulnTypes, s)
			}
		}
	}
	if val, ok := record.Get("finding_ids"); ok && val != nil {
		for _, f := range val.([]any) {
			if s, ok := f.(string); ok && s != "" {
				data.findings = append(data.findings, s)
			}
		}
	}
	if val, ok := record.Get("techniques"); ok && val != nil {
		for _, t := range val.([]any) {
			if s, ok := t.(string); ok && s != "" {
				data.techniques = append(data.techniques, s)
			}
		}
	}

	return data
}

// calculateSimilarity computes similarity between reference and candidate.
func (f *SimilarTargetFinder) calculateSimilarity(ref, candidate *targetData, features []string) sdkgraphrag.SimilarTarget {
	result := sdkgraphrag.SimilarTarget{
		TargetID:         candidate.targetID,
		TargetName:       candidate.targetName,
		MatchingFeatures: make(map[string]sdkgraphrag.FeatureMatch),
	}

	var totalScore float64
	var featureCount int

	for _, feature := range features {
		var match sdkgraphrag.FeatureMatch
		var score float64

		switch feature {
		case "technology_stack":
			score, match = f.jaccardSimilarity("technology_stack", ref.technologies, candidate.technologies)
		case "port_profile":
			score, match = f.portSimilarity(ref.ports, candidate.ports)
		case "vuln_profile":
			score, match = f.jaccardSimilarity("vuln_profile", ref.vulnTypes, candidate.vulnTypes)
		case "network_topology":
			// Use services as proxy for network topology
			score, match = f.jaccardSimilarity("network_topology", ref.services, candidate.services)
		}

		if match.Overlap > 0 {
			result.MatchingFeatures[feature] = match
		}
		totalScore += score
		featureCount++
	}

	if featureCount > 0 {
		result.SimilarityScore = totalScore / float64(featureCount)
	}

	// Add successful findings and techniques from candidate
	result.SuccessfulFindings = candidate.findings
	result.RecommendedTechniques = candidate.techniques

	return result
}

// jaccardSimilarity calculates Jaccard similarity between two string sets.
func (f *SimilarTargetFinder) jaccardSimilarity(feature string, set1, set2 []string) (float64, sdkgraphrag.FeatureMatch) {
	match := sdkgraphrag.FeatureMatch{
		Feature: feature,
	}

	if len(set1) == 0 && len(set2) == 0 {
		return 0, match
	}

	// Create sets
	s1 := make(map[string]bool)
	for _, v := range set1 {
		s1[v] = true
	}

	s2 := make(map[string]bool)
	for _, v := range set2 {
		s2[v] = true
	}

	// Calculate intersection
	var intersection []string
	for v := range s1 {
		if s2[v] {
			intersection = append(intersection, v)
		}
	}

	// Calculate union size
	union := make(map[string]bool)
	for v := range s1 {
		union[v] = true
	}
	for v := range s2 {
		union[v] = true
	}

	if len(union) == 0 {
		return 0, match
	}

	score := float64(len(intersection)) / float64(len(union))
	match.Overlap = score
	match.MatchedValues = intersection

	return score, match
}

// portSimilarity calculates similarity between port profiles.
func (f *SimilarTargetFinder) portSimilarity(ports1, ports2 []int) (float64, sdkgraphrag.FeatureMatch) {
	match := sdkgraphrag.FeatureMatch{
		Feature: "port_profile",
	}

	if len(ports1) == 0 && len(ports2) == 0 {
		return 0, match
	}

	// Create sets
	p1 := make(map[int]bool)
	for _, p := range ports1 {
		p1[p] = true
	}

	p2 := make(map[int]bool)
	for _, p := range ports2 {
		p2[p] = true
	}

	// Calculate intersection
	var intersection []string
	for p := range p1 {
		if p2[p] {
			intersection = append(intersection, fmt.Sprintf("%d", p))
		}
	}

	// Calculate union
	union := make(map[int]bool)
	for p := range p1 {
		union[p] = true
	}
	for p := range p2 {
		union[p] = true
	}

	if len(union) == 0 {
		return 0, match
	}

	// Use weighted similarity - common ports (80, 443, 22, etc.) are weighted less
	// because they appear on many targets
	commonPorts := map[int]float64{
		80: 0.5, 443: 0.5, 22: 0.6, 21: 0.7, 25: 0.7, 53: 0.6,
		3306: 0.8, 5432: 0.8, 27017: 0.8, 6379: 0.8, 8080: 0.6,
	}

	var weightedIntersection, weightedUnion float64
	for p := range union {
		weight := commonPorts[p]
		if weight == 0 {
			weight = 1.0 // Uncommon ports have full weight
		}
		weightedUnion += weight
		if p1[p] && p2[p] {
			weightedIntersection += weight
		}
	}

	score := 0.0
	if weightedUnion > 0 {
		score = weightedIntersection / weightedUnion
	}

	// Clamp and adjust
	score = math.Min(score, 1.0)

	match.Overlap = score
	match.MatchedValues = intersection

	return score, match
}
