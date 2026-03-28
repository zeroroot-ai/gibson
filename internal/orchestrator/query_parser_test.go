package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQueryParser_Parse_IPAddresses(t *testing.T) {
	parser := NewQueryParser()

	tests := []struct {
		name     string
		query    string
		expected []string
	}{
		{
			name:     "single IPv4",
			query:    "show hosts for 192.168.1.1",
			expected: []string{"192.168.1.1"},
		},
		{
			name:     "multiple IPv4",
			query:    "services on 10.0.0.1 and 10.0.0.2",
			expected: []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name:     "no IP",
			query:    "show all hosts",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.Parse(tt.query)
			assert.Equal(t, tt.expected, result.IPAddresses)
		})
	}
}

func TestQueryParser_Parse_EntityTypes(t *testing.T) {
	parser := NewQueryParser()

	tests := []struct {
		name     string
		query    string
		expected []string
	}{
		{
			name:     "host",
			query:    "show all hosts",
			expected: []string{"host"},
		},
		{
			name:     "services",
			query:    "list services",
			expected: []string{"service"},
		},
		{
			name:     "findings",
			query:    "show vulnerabilities",
			expected: []string{"finding"},
		},
		{
			name:     "multiple types",
			query:    "hosts with services and ports",
			expected: []string{"host", "service", "port"},
		},
		{
			name:     "alias - server",
			query:    "list all servers",
			expected: []string{"host"},
		},
		{
			name:     "alias - vuln",
			query:    "show vulns",
			expected: []string{"finding"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.Parse(tt.query)
			assert.ElementsMatch(t, tt.expected, result.EntityTypes)
		})
	}
}

func TestQueryParser_Parse_Ports(t *testing.T) {
	parser := NewQueryParser()

	tests := []struct {
		name     string
		query    string
		expected []int
	}{
		{
			name:     "port with keyword",
			query:    "hosts with port 22",
			expected: []int{22},
		},
		{
			name:     "port with colon",
			query:    "connect to 192.168.1.1:443",
			expected: []int{443},
		},
		{
			name:     "port with protocol",
			query:    "scan 80/tcp",
			expected: []int{80},
		},
		{
			name:     "no port",
			query:    "show all hosts",
			expected: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.Parse(tt.query)
			assert.Equal(t, tt.expected, result.Ports)
		})
	}
}

func TestQueryParser_Parse_Severities(t *testing.T) {
	parser := NewQueryParser()

	tests := []struct {
		name     string
		query    string
		expected []string
	}{
		{
			name:     "critical",
			query:    "show critical findings",
			expected: []string{"critical"},
		},
		{
			name:     "high and medium",
			query:    "high or medium severity issues",
			expected: []string{"high", "medium"},
		},
		{
			name:     "no severity",
			query:    "show all findings",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.Parse(tt.query)
			assert.ElementsMatch(t, tt.expected, result.Severities)
		})
	}
}

func TestQueryParser_Parse_CVEIDs(t *testing.T) {
	parser := NewQueryParser()

	tests := []struct {
		name     string
		query    string
		expected []string
	}{
		{
			name:     "single CVE",
			query:    "find CVE-2021-44228",
			expected: []string{"CVE-2021-44228"},
		},
		{
			name:     "multiple CVEs",
			query:    "check for CVE-2021-44228 and CVE-2022-1234",
			expected: []string{"CVE-2021-44228", "CVE-2022-1234"},
		},
		{
			name:     "no CVE",
			query:    "show all findings",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.Parse(tt.query)
			assert.Equal(t, tt.expected, result.CVEIDs)
		})
	}
}

func TestQueryParser_Parse_RelationshipPatterns(t *testing.T) {
	parser := NewQueryParser()

	tests := []struct {
		name             string
		query            string
		expectedLen      int
		expectedContains []string
	}{
		{
			name:             "services on",
			query:            "services on 192.168.1.1",
			expectedLen:      1,
			expectedContains: []string{"services on"},
		},
		{
			name:             "ports on",
			query:            "open ports on host",
			expectedLen:      2, // matches both "open ports on" and "ports on"
			expectedContains: []string{"open ports on", "ports on"},
		},
		{
			name:             "findings for",
			query:            "findings for this host",
			expectedLen:      1,
			expectedContains: []string{"findings for"},
		},
		{
			name:        "no relationship pattern",
			query:       "show all hosts",
			expectedLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.Parse(tt.query)
			assert.Len(t, result.RelationshipPatterns, tt.expectedLen)
			for _, expected := range tt.expectedContains {
				found := false
				for _, rp := range result.RelationshipPatterns {
					if rp.Pattern == expected {
						found = true
						break
					}
				}
				assert.True(t, found, "expected pattern %q not found", expected)
			}
		})
	}
}

func TestQueryParser_Parse_Hostnames(t *testing.T) {
	parser := NewQueryParser()

	tests := []struct {
		name     string
		query    string
		expected []string
	}{
		{
			name:     "single hostname",
			query:    "scan api.example.com",
			expected: []string{"api.example.com"},
		},
		{
			name:     "multiple hostnames",
			query:    "check www.example.com and mail.example.org",
			expected: []string{"www.example.com", "mail.example.org"},
		},
		{
			name:     "no hostname",
			query:    "scan 192.168.1.1",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.Parse(tt.query)
			assert.ElementsMatch(t, tt.expected, result.Hostnames)
		})
	}
}

func TestQueryParser_HasEntityFilters(t *testing.T) {
	parser := NewQueryParser()

	tests := []struct {
		name     string
		query    string
		expected bool
	}{
		{
			name:     "with IP",
			query:    "services on 192.168.1.1",
			expected: true,
		},
		{
			name:     "with hostname",
			query:    "scan api.example.com",
			expected: true,
		},
		{
			name:     "with port",
			query:    "check port 22",
			expected: true,
		},
		{
			name:     "no filters",
			query:    "show all services",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.Parse(tt.query)
			assert.Equal(t, tt.expected, result.HasEntityFilters())
		})
	}
}

func TestQueryParser_HasRelationshipQuery(t *testing.T) {
	parser := NewQueryParser()

	tests := []struct {
		name     string
		query    string
		expected bool
	}{
		{
			name:     "services on",
			query:    "services on 192.168.1.1",
			expected: true,
		},
		{
			name:     "ports on",
			query:    "ports on this host",
			expected: true,
		},
		{
			name:     "no relationship",
			query:    "show host 192.168.1.1",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.Parse(tt.query)
			assert.Equal(t, tt.expected, result.HasRelationshipQuery())
		})
	}
}

func TestQueryParser_ToEntityQuery(t *testing.T) {
	parser := NewQueryParser()

	result := parser.Parse("hosts with 192.168.1.1")
	eq := result.ToEntityQuery("mission-123", 50)

	assert.Contains(t, eq.EntityTypes, "host")
	assert.Equal(t, "mission-123", eq.MissionRunID)
	assert.Equal(t, 50, eq.MaxResults)
	assert.Equal(t, "192.168.1.1", eq.Filters["ip"])
}

func TestQueryParser_Confidence(t *testing.T) {
	parser := NewQueryParser()

	// Structured query with IP should have higher confidence
	structured := parser.Parse("services on 192.168.1.1")
	assert.Greater(t, structured.Confidence, 0.25)

	// Unstructured query should have lower confidence
	unstructured := parser.Parse("tell me about the network")
	assert.Less(t, unstructured.Confidence, 0.5)
}

func TestQueryParser_ComplexQuery(t *testing.T) {
	parser := NewQueryParser()

	result := parser.Parse("show critical findings for 192.168.1.1 with CVE-2021-44228")

	assert.Contains(t, result.IPAddresses, "192.168.1.1")
	assert.Contains(t, result.EntityTypes, "finding")
	assert.Contains(t, result.Severities, "critical")
	assert.Contains(t, result.CVEIDs, "CVE-2021-44228")
	assert.True(t, result.HasEntityFilters())
	assert.True(t, result.HasRelationshipQuery())
}
