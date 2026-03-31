// Package component provides health status helpers for component lifecycle management.
//
// This file contains shared helper functions used by the component registry and adapter
// to compute and report component health status.
package component

import (
	"strings"
	"time"
)

// Health status constants for ComponentInfo metadata.
const (
	// HealthStatusHealthy indicates the component is operational.
	HealthStatusHealthy = "healthy"

	// HealthStatusDegraded indicates the component is partially functional.
	HealthStatusDegraded = "degraded"

	// HealthStatusUnhealthy indicates the component is not functioning.
	HealthStatusUnhealthy = "unhealthy"

	// MetadataKeyHealth is the metadata key for health status.
	MetadataKeyHealth = "health_status"

	// MetadataKeyLastHealthCheck is the metadata key for last health check timestamp.
	MetadataKeyLastHealthCheck = "last_health_check"
)

// GetHealthStatus extracts health status from ComponentInfo metadata.
// Returns "healthy" if not set.
func GetHealthStatus(info ComponentInfo) string {
	if info.Metadata == nil {
		return HealthStatusHealthy
	}
	status, exists := info.Metadata[MetadataKeyHealth]
	if !exists {
		return HealthStatusHealthy
	}
	return status
}

// GetLastHealthCheck extracts last health check timestamp from ComponentInfo metadata.
// Returns zero time if not set or unparseable.
func GetLastHealthCheck(info ComponentInfo) time.Time {
	if info.Metadata == nil {
		return time.Time{}
	}
	timestampStr, exists := info.Metadata[MetadataKeyLastHealthCheck]
	if !exists {
		return time.Time{}
	}
	timestamp, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return time.Time{}
	}
	return timestamp
}

// aggregateHealth computes the overall health status from healthy/unhealthy counts.
//
// Returns:
//   - "healthy" if all instances are healthy (unhealthyCount == 0)
//   - "degraded" if some instances are unhealthy but not all
//   - "unhealthy" if all instances are unhealthy (healthyCount == 0)
func aggregateHealth(healthyCount, unhealthyCount int) string {
	if unhealthyCount == 0 {
		return HealthStatusHealthy
	}
	if healthyCount == 0 {
		return HealthStatusUnhealthy
	}
	return HealthStatusDegraded
}

// parseCommaSeparated parses a comma-separated string into a slice of trimmed strings.
//
// Empty strings and whitespace-only entries are filtered out.
// For example: "a, b, c" -> ["a", "b", "c"]
func parseCommaSeparated(value string) []string {
	if value == "" {
		return []string{}
	}

	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}
