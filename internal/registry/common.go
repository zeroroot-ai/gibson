// Package registry provides service discovery and registration infrastructure for Gibson.
//
// This file contains shared helper functions used by both EmbeddedRegistry and ExternalRegistry.
package registry

import (
	"path/filepath"
	"strings"
	"time"

	sdkregistry "github.com/zero-day-ai/sdk/registry"
)

// Health status constants for ServiceInfo metadata
const (
	// HealthStatusHealthy indicates the component is operational
	HealthStatusHealthy = "healthy"

	// HealthStatusDegraded indicates the component is partially functional
	HealthStatusDegraded = "degraded"

	// HealthStatusUnhealthy indicates the component is not functioning
	HealthStatusUnhealthy = "unhealthy"

	// MetadataKeyHealth is the metadata key for health status
	MetadataKeyHealth = "health_status"

	// MetadataKeyLastHealthCheck is the metadata key for last health check timestamp
	MetadataKeyLastHealthCheck = "last_health_check"
)

// buildKey constructs the etcd key for a service instance.
//
// Format: /{namespace}/{kind}/{name}/{instance-id}
// Example: /gibson/agent/k8skiller/550e8400-e29b-41d4-a716-446655440000
//
// This key structure enables efficient prefix-based queries:
//   - All services: /{namespace}/
//   - All agents: /{namespace}/agent/
//   - All k8skiller agents: /{namespace}/agent/k8skiller/
//   - Specific instance: /{namespace}/agent/k8skiller/{instance-id}
func buildKey(namespace, kind, name, instanceID string) string {
	return filepath.Join("/", namespace, kind, name, instanceID)
}

// buildPrefix constructs the etcd key prefix for discovering services.
//
// Format: /{namespace}/{kind}/{name}/
// Example: /gibson/agent/k8skiller/
//
// The trailing slash is important for prefix queries - it ensures we only
// match instances of this specific service, not other services whose names
// happen to start with the same string.
func buildPrefix(namespace, kind, name string) string {
	return filepath.Join("/", namespace, kind, name) + "/"
}

// ensureHealthMetadata ensures that ServiceInfo has health status metadata.
// If not present, it initializes with "healthy" status and current timestamp.
func ensureHealthMetadata(info *sdkregistry.ServiceInfo) {
	if info.Metadata == nil {
		info.Metadata = make(map[string]string)
	}

	// Set health status if not present
	if _, exists := info.Metadata[MetadataKeyHealth]; !exists {
		info.Metadata[MetadataKeyHealth] = HealthStatusHealthy
	}

	// Always update last health check timestamp
	info.Metadata[MetadataKeyLastHealthCheck] = time.Now().Format(time.RFC3339)
}

// GetHealthStatus extracts health status from ServiceInfo metadata.
// Returns "healthy" if not set.
func GetHealthStatus(info sdkregistry.ServiceInfo) string {
	if info.Metadata == nil {
		return HealthStatusHealthy
	}
	status, exists := info.Metadata[MetadataKeyHealth]
	if !exists {
		return HealthStatusHealthy
	}
	return status
}

// GetLastHealthCheck extracts last health check timestamp from ServiceInfo metadata.
// Returns zero time if not set or unparseable.
func GetLastHealthCheck(info sdkregistry.ServiceInfo) time.Time {
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
