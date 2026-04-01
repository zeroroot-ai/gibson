package extraction

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zero-day-ai/sdk/api/gen/toolspb"
	"google.golang.org/protobuf/proto"
)

// NmapExtractor extracts entities from nmap scan results.
// It converts NmapResponse proto messages into standardized DiscoveryResult containing:
//   - Host entities (IP, hostname, OS detection)
//   - Port entities (number, protocol, state)
//   - Service entities (name, version, product, banner)
//
// All entities are linked via parent references (port.host_id, service.port_id)
// and UUIDs are deterministically generated for idempotency.
type NmapExtractor struct{}

// NewNmapExtractor creates a new NmapExtractor instance.
func NewNmapExtractor() *NmapExtractor {
	return &NmapExtractor{}
}

// ToolName returns the identifier for the nmap tool.
func (e *NmapExtractor) ToolName() string {
	return "nmap"
}

// CanExtract validates that this extractor can process NmapResponse messages.
func (e *NmapExtractor) CanExtract(msg proto.Message) bool {
	_, ok := msg.(*toolspb.NmapResponse)
	return ok
}

// Extract converts an NmapResponse into a DiscoveryResult.
// It extracts:
//   - Hosts with IP, hostname, OS information
//   - Ports with number, protocol, state
//   - Services with name, version, product, banner
//
// Returns an error if the message type is invalid.
// Returns an empty result (not an error) if no hosts were found.
func (e *NmapExtractor) Extract(ctx context.Context, msg proto.Message) (*ExtractionResult, error) {
	// Type assertion (safe because CanExtract was called first)
	resp, ok := msg.(*toolspb.NmapResponse)
	if !ok {
		return nil, fmt.Errorf("expected *toolspb.NmapResponse, got %T", msg)
	}

	// Handle empty scan results gracefully
	if len(resp.Hosts) == 0 {
		return &ExtractionResult{
			Discovery: &graphragpb.DiscoveryResult{},
			Metadata: map[string]string{
				"status":       "no_hosts_found",
				"total_hosts":  fmt.Sprintf("%d", resp.TotalHosts),
				"hosts_up":     fmt.Sprintf("%d", resp.HostsUp),
				"hosts_down":   fmt.Sprintf("%d", resp.HostsDown),
				"nmap_version": resp.NmapVersion,
			},
		}, nil
	}

	// Create discovery result
	discovery := &graphragpb.DiscoveryResult{}
	var rootHostID string

	// Track statistics
	var totalPorts, totalServices int

	// Extract all hosts
	for _, nmapHost := range resp.Hosts {
		// Skip hosts that are not up (unless explicitly recorded)
		if nmapHost.State != "" && nmapHost.State != "up" {
			continue
		}

		// Generate deterministic UUID for host
		hostID := e.generateHostID(nmapHost.Ip)

		// Create host entity
		host := e.extractHost(nmapHost, hostID)
		discovery.Hosts = append(discovery.Hosts, host)

		// Track first host as root entity
		if rootHostID == "" {
			rootHostID = hostID
		}

		// Extract ports for this host
		for _, nmapPort := range nmapHost.Ports {
			portID := e.generatePortID(hostID, nmapPort.Number, nmapPort.Protocol)

			port := e.extractPort(nmapPort, portID, hostID)
			discovery.Ports = append(discovery.Ports, port)
			totalPorts++

			// Extract service if present
			if nmapPort.Service != nil && nmapPort.Service.Name != "" {
				serviceID := e.generateServiceID(portID)

				service := e.extractService(nmapPort.Service, serviceID, portID)
				discovery.Services = append(discovery.Services, service)
				totalServices++
			}
		}
	}

	// Build extraction result with metadata
	result := &ExtractionResult{
		Discovery:    discovery,
		RootEntityID: rootHostID,
		Metadata: map[string]string{
			"tool_name":     "nmap",
			"nmap_version":  resp.NmapVersion,
			"host_count":    fmt.Sprintf("%d", len(discovery.Hosts)),
			"port_count":    fmt.Sprintf("%d", totalPorts),
			"service_count": fmt.Sprintf("%d", totalServices),
			"total_hosts":   fmt.Sprintf("%d", resp.TotalHosts),
			"hosts_up":      fmt.Sprintf("%d", resp.HostsUp),
			"hosts_down":    fmt.Sprintf("%d", resp.HostsDown),
			"scan_duration": fmt.Sprintf("%.2f", resp.ScanDuration),
		},
	}

	return result, nil
}

// extractHost creates a Host entity from NmapHost data.
func (e *NmapExtractor) extractHost(nmapHost *toolspb.NmapHost, hostID string) *graphragpb.Host {
	host := &graphragpb.Host{
		Id:    &hostID,
		Ip:    nmapHost.Ip,
		State: stringPtr(nmapHost.State),
	}

	// Add hostname if available (prefer first hostname or the hostname field)
	if nmapHost.Hostname != "" {
		host.Hostname = stringPtr(nmapHost.Hostname)
	} else if len(nmapHost.Hostnames) > 0 {
		host.Hostname = stringPtr(nmapHost.Hostnames[0])
	}

	// Extract OS information from best match
	if len(nmapHost.OsMatches) > 0 {
		bestMatch := nmapHost.OsMatches[0]
		host.Os = stringPtr(bestMatch.Name)

		// Try to extract OS version from classes if available
		if len(bestMatch.Classes) > 0 {
			osClass := bestMatch.Classes[0]
			if osClass.OsGen != "" {
				host.OsVersion = stringPtr(osClass.OsGen)
			}
		}
	}

	return host
}

// extractPort creates a Port entity from NmapPort data.
func (e *NmapExtractor) extractPort(nmapPort *toolspb.NmapPort, portID, hostID string) *graphragpb.Port {
	port := &graphragpb.Port{
		Id:       &portID,
		HostId:   hostID,
		Number:   nmapPort.Number,
		Protocol: nmapPort.Protocol,
		State:    stringPtr(nmapPort.State),
	}

	// Add state reason if available
	if nmapPort.StateReason != "" {
		port.Reason = stringPtr(nmapPort.StateReason)
	}

	return port
}

// extractService creates a Service entity from NmapService data.
func (e *NmapExtractor) extractService(nmapService *toolspb.NmapService, serviceID, portID string) *graphragpb.Service {
	service := &graphragpb.Service{
		Id:     &serviceID,
		PortId: portID,
		Name:   nmapService.Name,
	}

	// Add product/software name if available
	if nmapService.Product != "" {
		service.Product = stringPtr(nmapService.Product)
	}

	// Add version if available
	if nmapService.Version != "" {
		service.Version = stringPtr(nmapService.Version)
	}

	// Add extra info (can serve as banner)
	if nmapService.ExtraInfo != "" {
		service.ExtraInfo = stringPtr(nmapService.ExtraInfo)
		// Use extra info as banner since nmap doesn't have separate banner field
		service.Banner = stringPtr(nmapService.ExtraInfo)
	}

	// Add CPE if available (use first one)
	if len(nmapService.Cpe) > 0 {
		service.Cpe = stringPtr(nmapService.Cpe[0])
	}

	return service
}

// UUID generation helpers - ensure deterministic IDs for idempotency

// generateHostID creates a deterministic UUID for a host based on its IP.
// This ensures re-scanning the same IP produces the same ID.
func (e *NmapExtractor) generateHostID(ip string) string {
	namespace := uuid.NameSpaceOID
	name := fmt.Sprintf("host:%s", ip)
	return uuid.NewSHA1(namespace, []byte(name)).String()
}

// generatePortID creates a deterministic UUID for a port.
// It's based on the parent host ID, port number, and protocol.
func (e *NmapExtractor) generatePortID(hostID string, portNum int32, protocol string) string {
	namespace := uuid.NameSpaceOID
	name := fmt.Sprintf("port:%s:%d:%s", hostID, portNum, protocol)
	return uuid.NewSHA1(namespace, []byte(name)).String()
}

// generateServiceID creates a deterministic UUID for a service.
// It's based on the parent port ID.
func (e *NmapExtractor) generateServiceID(portID string) string {
	namespace := uuid.NameSpaceOID
	name := fmt.Sprintf("service:%s", portID)
	return uuid.NewSHA1(namespace, []byte(name)).String()
}

// Helper to create string pointers for optional proto fields
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
