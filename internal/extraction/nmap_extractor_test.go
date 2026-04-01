package extraction

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/api/gen/toolspb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestNmapExtractor_ToolName(t *testing.T) {
	extractor := NewNmapExtractor()
	assert.Equal(t, "nmap", extractor.ToolName())
}

func TestNmapExtractor_CanExtract(t *testing.T) {
	extractor := NewNmapExtractor()

	tests := []struct {
		name     string
		msg      proto.Message
		expected bool
	}{
		{
			name:     "valid NmapResponse",
			msg:      &toolspb.NmapResponse{},
			expected: true,
		},
		{
			name:     "invalid empty proto",
			msg:      &emptypb.Empty{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractor.CanExtract(tt.msg)
			assert.Equal(t, tt.expected, result)
		})
	}

	// Test nil separately
	t.Run("nil message", func(t *testing.T) {
		result := extractor.CanExtract(nil)
		assert.False(t, result)
	})
}

func TestNmapExtractor_Extract_EmptyResponse(t *testing.T) {
	extractor := NewNmapExtractor()
	ctx := context.Background()

	resp := &toolspb.NmapResponse{
		TotalHosts:   5,
		HostsUp:      0,
		HostsDown:    5,
		NmapVersion:  "7.80",
		ScanDuration: 12.5,
		Hosts:        []*toolspb.NmapHost{},
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Discovery)

	// Should have empty discovery result
	assert.Empty(t, result.Discovery.Hosts)
	assert.Empty(t, result.Discovery.Ports)
	assert.Empty(t, result.Discovery.Services)

	// Should have metadata
	assert.Equal(t, "no_hosts_found", result.Metadata["status"])
	assert.Equal(t, "5", result.Metadata["total_hosts"])
	assert.Equal(t, "0", result.Metadata["hosts_up"])
	assert.Equal(t, "5", result.Metadata["hosts_down"])
	assert.Equal(t, "7.80", result.Metadata["nmap_version"])
}

func TestNmapExtractor_Extract_InvalidMessageType(t *testing.T) {
	extractor := NewNmapExtractor()
	ctx := context.Background()

	result, err := extractor.Extract(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "expected *toolspb.NmapResponse")
}

func TestNmapExtractor_Extract_SingleHost(t *testing.T) {
	extractor := NewNmapExtractor()
	ctx := context.Background()

	resp := &toolspb.NmapResponse{
		TotalHosts:   1,
		HostsUp:      1,
		HostsDown:    0,
		NmapVersion:  "7.80",
		ScanDuration: 5.2,
		Hosts: []*toolspb.NmapHost{
			{
				Ip:       "192.168.1.1",
				Hostname: "router.local",
				State:    "up",
				Ports:    []*toolspb.NmapPort{},
			},
		},
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Discovery)

	// Verify host extraction
	assert.Len(t, result.Discovery.Hosts, 1)
	host := result.Discovery.Hosts[0]
	assert.Equal(t, "192.168.1.1", host.Ip)
	assert.Equal(t, "router.local", *host.Hostname)
	assert.Equal(t, "up", *host.State)
	assert.NotNil(t, host.Id)
	assert.NotEmpty(t, *host.Id)

	// Verify root entity
	assert.Equal(t, *host.Id, result.RootEntityID)

	// Verify metadata
	assert.Equal(t, "1", result.Metadata["host_count"])
	assert.Equal(t, "0", result.Metadata["port_count"])
	assert.Equal(t, "0", result.Metadata["service_count"])
}

func TestNmapExtractor_Extract_HostWithPorts(t *testing.T) {
	extractor := NewNmapExtractor()
	ctx := context.Background()

	resp := &toolspb.NmapResponse{
		TotalHosts:   1,
		HostsUp:      1,
		HostsDown:    0,
		NmapVersion:  "7.80",
		ScanDuration: 8.3,
		Hosts: []*toolspb.NmapHost{
			{
				Ip:       "10.0.0.5",
				Hostname: "webserver",
				State:    "up",
				Ports: []*toolspb.NmapPort{
					{
						Number:      80,
						Protocol:    "tcp",
						State:       "open",
						StateReason: "syn-ack",
					},
					{
						Number:      443,
						Protocol:    "tcp",
						State:       "open",
						StateReason: "syn-ack",
					},
					{
						Number:      22,
						Protocol:    "tcp",
						State:       "closed",
						StateReason: "reset",
					},
				},
			},
		},
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify host
	assert.Len(t, result.Discovery.Hosts, 1)
	host := result.Discovery.Hosts[0]
	assert.Equal(t, "10.0.0.5", host.Ip)

	// Verify ports
	assert.Len(t, result.Discovery.Ports, 3)

	port80 := result.Discovery.Ports[0]
	assert.Equal(t, int32(80), port80.Number)
	assert.Equal(t, "tcp", port80.Protocol)
	assert.Equal(t, "open", *port80.State)
	assert.Equal(t, "syn-ack", *port80.Reason)
	assert.Equal(t, *host.Id, port80.HostId)
	assert.NotEmpty(t, *port80.Id)

	port443 := result.Discovery.Ports[1]
	assert.Equal(t, int32(443), port443.Number)
	assert.Equal(t, "tcp", port443.Protocol)
	assert.Equal(t, *host.Id, port443.HostId)

	port22 := result.Discovery.Ports[2]
	assert.Equal(t, int32(22), port22.Number)
	assert.Equal(t, "closed", *port22.State)

	// Verify metadata
	assert.Equal(t, "1", result.Metadata["host_count"])
	assert.Equal(t, "3", result.Metadata["port_count"])
	assert.Equal(t, "0", result.Metadata["service_count"])
}

func TestNmapExtractor_Extract_HostWithServices(t *testing.T) {
	extractor := NewNmapExtractor()
	ctx := context.Background()

	resp := &toolspb.NmapResponse{
		TotalHosts:   1,
		HostsUp:      1,
		HostsDown:    0,
		NmapVersion:  "7.80",
		ScanDuration: 15.7,
		Hosts: []*toolspb.NmapHost{
			{
				Ip:       "172.16.0.10",
				Hostname: "api.example.com",
				State:    "up",
				Ports: []*toolspb.NmapPort{
					{
						Number:      80,
						Protocol:    "tcp",
						State:       "open",
						StateReason: "syn-ack",
						Service: &toolspb.NmapService{
							Name:       "http",
							Product:    "nginx",
							Version:    "1.18.0",
							ExtraInfo:  "Ubuntu",
							Confidence: 10,
							Cpe:        []string{"cpe:/a:nginx:nginx:1.18.0"},
						},
					},
					{
						Number:      443,
						Protocol:    "tcp",
						State:       "open",
						StateReason: "syn-ack",
						Service: &toolspb.NmapService{
							Name:      "https",
							Product:   "nginx",
							Version:   "1.18.0",
							ExtraInfo: "Ubuntu",
							Cpe:       []string{"cpe:/a:nginx:nginx:1.18.0"},
						},
					},
					{
						Number:      3306,
						Protocol:    "tcp",
						State:       "open",
						StateReason: "syn-ack",
						Service: &toolspb.NmapService{
							Name:    "mysql",
							Product: "MySQL",
							Version: "8.0.27",
						},
					},
				},
			},
		},
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify host
	assert.Len(t, result.Discovery.Hosts, 1)

	// Verify ports
	assert.Len(t, result.Discovery.Ports, 3)

	// Verify services
	assert.Len(t, result.Discovery.Services, 3)

	// Check HTTP service
	httpService := result.Discovery.Services[0]
	assert.Equal(t, "http", httpService.Name)
	assert.Equal(t, "nginx", *httpService.Product)
	assert.Equal(t, "1.18.0", *httpService.Version)
	assert.Equal(t, "Ubuntu", *httpService.ExtraInfo)
	assert.Equal(t, "Ubuntu", *httpService.Banner) // ExtraInfo should be used as banner
	assert.Equal(t, "cpe:/a:nginx:nginx:1.18.0", *httpService.Cpe)
	assert.Equal(t, *result.Discovery.Ports[0].Id, httpService.PortId)

	// Check HTTPS service
	httpsService := result.Discovery.Services[1]
	assert.Equal(t, "https", httpsService.Name)
	assert.Equal(t, "nginx", *httpsService.Product)

	// Check MySQL service
	mysqlService := result.Discovery.Services[2]
	assert.Equal(t, "mysql", mysqlService.Name)
	assert.Equal(t, "MySQL", *mysqlService.Product)
	assert.Equal(t, "8.0.27", *mysqlService.Version)

	// Verify metadata
	assert.Equal(t, "1", result.Metadata["host_count"])
	assert.Equal(t, "3", result.Metadata["port_count"])
	assert.Equal(t, "3", result.Metadata["service_count"])
	assert.Equal(t, "7.80", result.Metadata["nmap_version"])
	assert.Equal(t, "15.70", result.Metadata["scan_duration"])
}

func TestNmapExtractor_Extract_HostWithOS(t *testing.T) {
	extractor := NewNmapExtractor()
	ctx := context.Background()

	resp := &toolspb.NmapResponse{
		TotalHosts:   1,
		HostsUp:      1,
		HostsDown:    0,
		NmapVersion:  "7.80",
		ScanDuration: 20.1,
		Hosts: []*toolspb.NmapHost{
			{
				Ip:       "192.168.1.100",
				Hostname: "linux-server",
				State:    "up",
				OsMatches: []*toolspb.OSMatch{
					{
						Name:     "Linux 5.4",
						Accuracy: 95,
						Classes: []*toolspb.OSClass{
							{
								Type:     "general purpose",
								Vendor:   "Linux",
								OsFamily: "Linux",
								OsGen:    "5.X",
								Accuracy: 95,
								Cpe:      []string{"cpe:/o:linux:linux_kernel:5"},
							},
						},
					},
					{
						Name:     "Linux 5.10",
						Accuracy: 90,
						Classes: []*toolspb.OSClass{
							{
								Type:     "general purpose",
								Vendor:   "Linux",
								OsFamily: "Linux",
								OsGen:    "5.X",
								Accuracy: 90,
							},
						},
					},
				},
				Ports: []*toolspb.NmapPort{},
			},
		},
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify OS detection
	assert.Len(t, result.Discovery.Hosts, 1)
	host := result.Discovery.Hosts[0]
	assert.Equal(t, "Linux 5.4", *host.Os)
	assert.Equal(t, "5.X", *host.OsVersion)
}

func TestNmapExtractor_Extract_MultipleHosts(t *testing.T) {
	extractor := NewNmapExtractor()
	ctx := context.Background()

	resp := &toolspb.NmapResponse{
		TotalHosts:   3,
		HostsUp:      3,
		HostsDown:    0,
		NmapVersion:  "7.80",
		ScanDuration: 25.6,
		Hosts: []*toolspb.NmapHost{
			{
				Ip:       "10.0.0.1",
				Hostname: "host1",
				State:    "up",
				Ports: []*toolspb.NmapPort{
					{Number: 22, Protocol: "tcp", State: "open"},
				},
			},
			{
				Ip:       "10.0.0.2",
				Hostname: "host2",
				State:    "up",
				Ports: []*toolspb.NmapPort{
					{Number: 80, Protocol: "tcp", State: "open"},
					{Number: 443, Protocol: "tcp", State: "open"},
				},
			},
			{
				Ip:       "10.0.0.3",
				Hostname: "host3",
				State:    "up",
				Ports:    []*toolspb.NmapPort{},
			},
		},
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify all hosts extracted
	assert.Len(t, result.Discovery.Hosts, 3)
	assert.Equal(t, "10.0.0.1", result.Discovery.Hosts[0].Ip)
	assert.Equal(t, "10.0.0.2", result.Discovery.Hosts[1].Ip)
	assert.Equal(t, "10.0.0.3", result.Discovery.Hosts[2].Ip)

	// Verify all ports extracted
	assert.Len(t, result.Discovery.Ports, 3)

	// Verify root entity is first host
	assert.Equal(t, *result.Discovery.Hosts[0].Id, result.RootEntityID)

	// Verify metadata
	assert.Equal(t, "3", result.Metadata["host_count"])
	assert.Equal(t, "3", result.Metadata["port_count"])
}

func TestNmapExtractor_Extract_HostWithMultipleHostnames(t *testing.T) {
	extractor := NewNmapExtractor()
	ctx := context.Background()

	resp := &toolspb.NmapResponse{
		TotalHosts:   1,
		HostsUp:      1,
		HostsDown:    0,
		NmapVersion:  "7.80",
		ScanDuration: 5.0,
		Hosts: []*toolspb.NmapHost{
			{
				Ip:        "192.168.1.1",
				Hostnames: []string{"gateway.local", "router.local", "admin.local"},
				State:     "up",
				Ports:     []*toolspb.NmapPort{},
			},
		},
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should use first hostname from the list
	assert.Len(t, result.Discovery.Hosts, 1)
	host := result.Discovery.Hosts[0]
	assert.Equal(t, "gateway.local", *host.Hostname)
}

func TestNmapExtractor_Extract_HostDownFiltered(t *testing.T) {
	extractor := NewNmapExtractor()
	ctx := context.Background()

	resp := &toolspb.NmapResponse{
		TotalHosts:   2,
		HostsUp:      1,
		HostsDown:    1,
		NmapVersion:  "7.80",
		ScanDuration: 10.0,
		Hosts: []*toolspb.NmapHost{
			{
				Ip:    "10.0.0.1",
				State: "up",
				Ports: []*toolspb.NmapPort{},
			},
			{
				Ip:    "10.0.0.2",
				State: "down",
				Ports: []*toolspb.NmapPort{},
			},
		},
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should only extract hosts that are up
	assert.Len(t, result.Discovery.Hosts, 1)
	assert.Equal(t, "10.0.0.1", result.Discovery.Hosts[0].Ip)
}

func TestNmapExtractor_Extract_DeterministicUUIDs(t *testing.T) {
	extractor := NewNmapExtractor()
	ctx := context.Background()

	resp := &toolspb.NmapResponse{
		TotalHosts:  1,
		HostsUp:     1,
		HostsDown:   0,
		NmapVersion: "7.80",
		Hosts: []*toolspb.NmapHost{
			{
				Ip:    "192.168.1.1",
				State: "up",
				Ports: []*toolspb.NmapPort{
					{Number: 80, Protocol: "tcp", State: "open"},
				},
			},
		},
	}

	// Extract twice
	result1, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)

	result2, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)

	// Host IDs should be identical
	assert.Equal(t, *result1.Discovery.Hosts[0].Id, *result2.Discovery.Hosts[0].Id)

	// Port IDs should be identical
	assert.Equal(t, *result1.Discovery.Ports[0].Id, *result2.Discovery.Ports[0].Id)
}

func TestNmapExtractor_Extract_PortProtocolInUUID(t *testing.T) {
	extractor := NewNmapExtractor()
	ctx := context.Background()

	resp := &toolspb.NmapResponse{
		TotalHosts:  1,
		HostsUp:     1,
		HostsDown:   0,
		NmapVersion: "7.80",
		Hosts: []*toolspb.NmapHost{
			{
				Ip:    "192.168.1.1",
				State: "up",
				Ports: []*toolspb.NmapPort{
					{Number: 53, Protocol: "tcp", State: "open"},
					{Number: 53, Protocol: "udp", State: "open"},
				},
			},
		},
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)

	// Port IDs should be different because protocols differ
	assert.Len(t, result.Discovery.Ports, 2)
	assert.NotEqual(t, *result.Discovery.Ports[0].Id, *result.Discovery.Ports[1].Id)
}

func TestNmapExtractor_Extract_ServiceWithoutOptionalFields(t *testing.T) {
	extractor := NewNmapExtractor()
	ctx := context.Background()

	resp := &toolspb.NmapResponse{
		TotalHosts:  1,
		HostsUp:     1,
		HostsDown:   0,
		NmapVersion: "7.80",
		Hosts: []*toolspb.NmapHost{
			{
				Ip:    "192.168.1.1",
				State: "up",
				Ports: []*toolspb.NmapPort{
					{
						Number:   80,
						Protocol: "tcp",
						State:    "open",
						Service: &toolspb.NmapService{
							Name: "http",
							// No product, version, extra_info, or cpe
						},
					},
				},
			},
		},
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)

	// Service should still be extracted with just name
	assert.Len(t, result.Discovery.Services, 1)
	service := result.Discovery.Services[0]
	assert.Equal(t, "http", service.Name)
	assert.Nil(t, service.Product)
	assert.Nil(t, service.Version)
	assert.Nil(t, service.ExtraInfo)
	assert.Nil(t, service.Banner)
	assert.Nil(t, service.Cpe)
}

func TestNmapExtractor_Integration_WithRegistry(t *testing.T) {
	// Create registry and register extractor
	registry := NewExtractorRegistry()
	extractor := NewNmapExtractor()

	err := registry.Register(extractor)
	require.NoError(t, err)

	// Verify registration
	assert.True(t, registry.Has("nmap"))

	// Create test response
	resp := &toolspb.NmapResponse{
		TotalHosts:  1,
		HostsUp:     1,
		HostsDown:   0,
		NmapVersion: "7.80",
		Hosts: []*toolspb.NmapHost{
			{
				Ip:    "10.0.0.1",
				State: "up",
				Ports: []*toolspb.NmapPort{
					{
						Number:   443,
						Protocol: "tcp",
						State:    "open",
						Service: &toolspb.NmapService{
							Name:    "https",
							Product: "nginx",
							Version: "1.20.0",
						},
					},
				},
			},
		},
	}

	// Extract via registry
	ctx := context.Background()
	result, err := registry.ExtractFromResponse(ctx, "nmap", resp)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify extraction worked
	assert.Len(t, result.Discovery.Hosts, 1)
	assert.Len(t, result.Discovery.Ports, 1)
	assert.Len(t, result.Discovery.Services, 1)
	assert.Equal(t, "10.0.0.1", result.Discovery.Hosts[0].Ip)
	assert.Equal(t, "https", result.Discovery.Services[0].Name)
}
