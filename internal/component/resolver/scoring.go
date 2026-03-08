package resolver

import (
	"context"
	"math"

	"github.com/zero-day-ai/gibson/internal/component"
)

// ScoringCriteria defines weights for different factors in component scoring.
// Each weight is a value between 0.0 and 1.0. The sum of all weights should
// ideally be 1.0, but it will be normalized if not.
type ScoringCriteria struct {
	// CapabilityWeight determines importance of capability matching (default: 0.35)
	CapabilityWeight float64

	// VersionWeight determines importance of version preference (default: 0.25)
	// Newer versions score higher
	VersionWeight float64

	// HealthWeight determines importance of health status (default: 0.20)
	// Healthy components score higher
	HealthWeight float64

	// LoadWeight determines importance of current load (default: 0.15)
	// Less loaded components score higher
	LoadWeight float64

	// LocalityWeight determines importance of locality (default: 0.05)
	// Local components score higher than remote
	LocalityWeight float64
}

// DefaultScoringCriteria returns the default scoring weights.
func DefaultScoringCriteria() *ScoringCriteria {
	return &ScoringCriteria{
		CapabilityWeight: 0.35,
		VersionWeight:    0.25,
		HealthWeight:     0.20,
		LoadWeight:       0.15,
		LocalityWeight:   0.05,
	}
}

// Normalize ensures all weights sum to 1.0.
// This allows users to specify relative weights without calculating exact proportions.
func (s *ScoringCriteria) Normalize() *ScoringCriteria {
	total := s.CapabilityWeight + s.VersionWeight + s.HealthWeight + s.LoadWeight + s.LocalityWeight
	if total == 0 {
		// All weights are zero, return default
		return DefaultScoringCriteria()
	}

	if total == 1.0 {
		// Already normalized
		return s
	}

	// Normalize all weights
	return &ScoringCriteria{
		CapabilityWeight: s.CapabilityWeight / total,
		VersionWeight:    s.VersionWeight / total,
		HealthWeight:     s.HealthWeight / total,
		LoadWeight:       s.LoadWeight / total,
		LocalityWeight:   s.LocalityWeight / total,
	}
}

// ComponentScorer provides methods for scoring and ranking components.
type ComponentScorer interface {
	// Score calculates a total score for a component based on multiple criteria.
	// Returns a value between 0.0 (worst match) and 1.0 (perfect match).
	Score(ctx context.Context, comp *component.Component, requiredCapabilities []string, preferredVersion string) (float64, error)

	// ScoreMultiple scores multiple components and returns them sorted by score (highest first).
	ScoreMultiple(ctx context.Context, components []*component.Component, requiredCapabilities []string, preferredVersion string) ([]ScoredComponent, error)
}

// ScoredComponent represents a component with its calculated score.
type ScoredComponent struct {
	Component      *component.Component
	Score          float64
	CapabilityScore float64
	VersionScore    float64
	HealthScore     float64
	LoadScore       float64
	LocalityScore   float64
}

// DefaultComponentScorer implements ComponentScorer with configurable criteria.
type DefaultComponentScorer struct {
	criteria         *ScoringCriteria
	capabilityMatcher CapabilityMatcher
	lifecycleManager component.LifecycleManager
}

// NewComponentScorer creates a new component scorer with the given criteria and dependencies.
func NewComponentScorer(criteria *ScoringCriteria, lifecycle component.LifecycleManager) ComponentScorer {
	if criteria == nil {
		criteria = DefaultScoringCriteria()
	}
	criteria = criteria.Normalize()

	return &DefaultComponentScorer{
		criteria:         criteria,
		capabilityMatcher: NewCapabilityMatcher(),
		lifecycleManager: lifecycle,
	}
}

// Score calculates a total score for a component.
func (s *DefaultComponentScorer) Score(ctx context.Context, comp *component.Component, requiredCapabilities []string, preferredVersion string) (float64, error) {
	if comp == nil {
		return 0.0, nil
	}

	// Calculate individual scores
	capScore := s.scoreCapabilities(comp, requiredCapabilities)
	verScore := s.scoreVersion(comp, preferredVersion)
	healthScore := s.scoreHealth(ctx, comp)
	loadScore := s.scoreLoad(ctx, comp)
	localityScore := s.scoreLocality(comp)

	// Combine scores with weights
	totalScore := (capScore * s.criteria.CapabilityWeight) +
		(verScore * s.criteria.VersionWeight) +
		(healthScore * s.criteria.HealthWeight) +
		(loadScore * s.criteria.LoadWeight) +
		(localityScore * s.criteria.LocalityWeight)

	// Ensure score is in valid range [0, 1]
	if totalScore < 0 {
		totalScore = 0
	}
	if totalScore > 1 {
		totalScore = 1
	}

	return totalScore, nil
}

// ScoreMultiple scores multiple components and returns them sorted by score.
func (s *DefaultComponentScorer) ScoreMultiple(ctx context.Context, components []*component.Component, requiredCapabilities []string, preferredVersion string) ([]ScoredComponent, error) {
	results := make([]ScoredComponent, 0, len(components))

	for _, comp := range components {
		if comp == nil {
			continue
		}

		// Calculate individual scores for detailed breakdown
		capScore := s.scoreCapabilities(comp, requiredCapabilities)
		verScore := s.scoreVersion(comp, preferredVersion)
		healthScore := s.scoreHealth(ctx, comp)
		loadScore := s.scoreLoad(ctx, comp)
		localityScore := s.scoreLocality(comp)

		// Calculate total score
		totalScore := (capScore * s.criteria.CapabilityWeight) +
			(verScore * s.criteria.VersionWeight) +
			(healthScore * s.criteria.HealthWeight) +
			(loadScore * s.criteria.LoadWeight) +
			(localityScore * s.criteria.LocalityWeight)

		// Ensure score is in valid range
		if totalScore < 0 {
			totalScore = 0
		}
		if totalScore > 1 {
			totalScore = 1
		}

		results = append(results, ScoredComponent{
			Component:      comp,
			Score:          totalScore,
			CapabilityScore: capScore,
			VersionScore:    verScore,
			HealthScore:     healthScore,
			LoadScore:       loadScore,
			LocalityScore:   localityScore,
		})
	}

	// Sort by score descending (highest score first)
	sortScoredComponents(results)

	return results, nil
}

// scoreCapabilities calculates the capability match score.
func (s *DefaultComponentScorer) scoreCapabilities(comp *component.Component, required []string) float64 {
	if comp.Manifest == nil {
		// No manifest means no capability information
		if len(required) == 0 {
			return 1.0 // No requirements, so it's a match
		}
		return 0.0 // Has requirements but no capabilities
	}

	actual := comp.Manifest.Capabilities
	return s.capabilityMatcher.Score(required, actual)
}

// scoreVersion calculates the version preference score.
// Newer versions score higher. If a preferred version is specified,
// exact matches score highest, closer versions score higher.
func (s *DefaultComponentScorer) scoreVersion(comp *component.Component, preferred string) float64 {
	if comp.Version == "" {
		return 0.5 // Unknown version gets neutral score
	}

	// If no preferred version, just favor newer versions
	if preferred == "" {
		// Parse version and calculate score based on major.minor.patch
		// Higher versions get higher scores (up to a reasonable limit)
		parts := parseVersionParts(comp.Version)
		// Normalize to 0-1 range assuming versions won't exceed 100.100.100
		score := (float64(parts[0])/100.0 + float64(parts[1])/10000.0 + float64(parts[2])/1000000.0)
		if score > 1.0 {
			score = 1.0
		}
		return score
	}

	// If preferred version specified, score based on proximity
	if comp.Version == preferred {
		return 1.0 // Exact match
	}

	// Calculate version distance
	cmp := CompareVersions(comp.Version, preferred)
	if cmp == 0 {
		return 1.0 // Exact match
	}

	// Parse both versions to calculate distance
	actualParts := parseVersionParts(comp.Version)
	preferredParts := parseVersionParts(preferred)

	// Calculate Manhattan distance between versions
	distance := math.Abs(float64(actualParts[0]-preferredParts[0])) +
		math.Abs(float64(actualParts[1]-preferredParts[1]))/10.0 +
		math.Abs(float64(actualParts[2]-preferredParts[2]))/100.0

	// Convert distance to score (closer = higher score)
	// Use exponential decay for distance penalty
	score := math.Exp(-distance)
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	return score
}

// scoreHealth calculates the health status score.
func (s *DefaultComponentScorer) scoreHealth(ctx context.Context, comp *component.Component) float64 {
	if s.lifecycleManager == nil {
		// No lifecycle manager, use component status field
		switch comp.Status {
		case component.ComponentStatusRunning:
			return 1.0
		case component.ComponentStatusStopped:
			return 0.5
		case component.ComponentStatusError:
			return 0.0
		case component.ComponentStatusAvailable:
			return 0.7
		default:
			return 0.3
		}
	}

	// Query lifecycle manager for actual health status
	status, err := s.lifecycleManager.GetStatus(ctx, comp)
	if err != nil {
		// Error getting status, use component status as fallback
		return 0.3
	}

	switch status {
	case component.ComponentStatusRunning:
		return 1.0
	case component.ComponentStatusStopped:
		return 0.5
	case component.ComponentStatusError:
		return 0.0
	case component.ComponentStatusAvailable:
		return 0.7
	default:
		return 0.3
	}
}

// scoreLoad calculates the load score.
// This is a placeholder - in a real implementation, this would query metrics
// or the component's runtime to determine current load.
func (s *DefaultComponentScorer) scoreLoad(ctx context.Context, comp *component.Component) float64 {
	// TODO: Integrate with metrics system to get actual load
	// For now, running components get a neutral score, stopped ones get high score
	switch comp.Status {
	case component.ComponentStatusRunning:
		return 0.5 // Assume moderate load if running
	case component.ComponentStatusStopped, component.ComponentStatusAvailable:
		return 1.0 // Not running means no load
	default:
		return 0.5
	}
}

// scoreLocality calculates the locality score.
// Local components score higher than remote ones.
func (s *DefaultComponentScorer) scoreLocality(comp *component.Component) float64 {
	switch comp.Source {
	case component.ComponentSourceInternal:
		return 1.0 // Internal components are most local
	case component.ComponentSourceConfig:
		return 0.9 // Config-based components are local
	case component.ComponentSourceExternal:
		return 0.7 // External (cloned) components are local but less preferred
	case component.ComponentSourceRemote:
		return 0.5 // Remote components are least preferred
	default:
		return 0.5
	}
}

// sortScoredComponents sorts components by score in descending order (highest first).
func sortScoredComponents(components []ScoredComponent) {
	// Simple insertion sort - fine for typical component counts
	for i := 1; i < len(components); i++ {
		key := components[i]
		j := i - 1
		for j >= 0 && components[j].Score < key.Score {
			components[j+1] = components[j]
			j--
		}
		components[j+1] = key
	}
}
