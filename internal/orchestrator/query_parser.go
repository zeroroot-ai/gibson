package orchestrator

import (
	"regexp"
	"strings"
)

// QueryParser extracts entity types, identifiers, and relationship patterns
// from natural language queries. It uses simple pattern matching rather than
// ML-based NLP to maintain deterministic behavior.
//
// Supported extractions:
//   - Entity types: host, port, service, endpoint, finding, domain, subdomain, technology
//   - IP addresses: IPv4 format (e.g., "192.168.1.1")
//   - Hostnames: FQDN format (e.g., "api.example.com")
//   - Port numbers: numeric (e.g., "port 22", "443")
//   - Severities: critical, high, medium, low, info
//   - Relationship patterns: "services on", "findings for", "ports on"
type QueryParser struct {
	// entityTypePatterns maps entity type aliases to canonical names
	entityTypePatterns map[string]string

	// relationshipPatterns maps query phrases to relationship types
	relationshipPatterns map[string]RelationshipPattern

	// compiled regex patterns
	ipv4Pattern     *regexp.Regexp
	hostnamePattern *regexp.Regexp
	portPattern     *regexp.Regexp
	severityPattern *regexp.Regexp
	cvePattern      *regexp.Regexp
}

// ParsedQuery contains the structured information extracted from a query.
type ParsedQuery struct {
	// OriginalQuery is the raw query text.
	OriginalQuery string

	// EntityTypes detected in the query.
	EntityTypes []string

	// IPAddresses detected in the query.
	IPAddresses []string

	// Hostnames detected in the query.
	Hostnames []string

	// Ports detected in the query.
	Ports []int

	// Severities detected in the query (for findings).
	Severities []string

	// CVEIDs detected in the query.
	CVEIDs []string

	// RelationshipPatterns detected in the query.
	RelationshipPatterns []RelationshipPattern

	// Confidence is the overall parse confidence (0.0-1.0).
	// Higher values indicate more structured, less ambiguous queries.
	Confidence float64

	// Keywords are the remaining unstructured keywords.
	Keywords []string
}

// RelationshipPattern represents a detected relationship query pattern.
type RelationshipPattern struct {
	// Pattern is the matched phrase (e.g., "services on").
	Pattern string

	// FromType is the source entity type.
	FromType string

	// ToType is the target entity type.
	ToType string

	// RelationshipType is the graph relationship (e.g., "RUNS_SERVICE").
	RelationshipType string
}

// NewQueryParser creates a new QueryParser with default patterns.
func NewQueryParser() *QueryParser {
	p := &QueryParser{
		entityTypePatterns: map[string]string{
			// Host variations
			"host":    "host",
			"hosts":   "host",
			"ip":      "host",
			"ips":     "host",
			"server":  "host",
			"servers": "host",
			"machine": "host",

			// Port variations
			"port":  "port",
			"ports": "port",

			// Service variations
			"service":  "service",
			"services": "service",
			"daemon":   "service",
			"daemons":  "service",

			// Endpoint variations
			"endpoint":  "endpoint",
			"endpoints": "endpoint",
			"url":       "endpoint",
			"urls":      "endpoint",
			"api":       "endpoint",
			"apis":      "endpoint",

			// Finding variations
			"finding":         "finding",
			"findings":        "finding",
			"vulnerability":   "finding",
			"vulnerabilities": "finding",
			"vuln":            "finding",
			"vulns":           "finding",
			"issue":           "finding",
			"issues":          "finding",

			// Domain variations
			"domain":  "domain",
			"domains": "domain",

			// Subdomain variations
			"subdomain":  "subdomain",
			"subdomains": "subdomain",

			// Technology variations
			"technology":   "technology",
			"technologies": "technology",
			"tech":         "technology",
			"framework":    "technology",
			"frameworks":   "technology",

			// Certificate variations
			"certificate":  "certificate",
			"certificates": "certificate",
			"cert":         "certificate",
			"certs":        "certificate",
			"ssl":          "certificate",
			"tls":          "certificate",
		},
		relationshipPatterns: map[string]RelationshipPattern{
			"services on": {
				Pattern:          "services on",
				FromType:         "host",
				ToType:           "service",
				RelationshipType: "HAS_PORT->RUNS_SERVICE",
			},
			"services running on": {
				Pattern:          "services running on",
				FromType:         "host",
				ToType:           "service",
				RelationshipType: "HAS_PORT->RUNS_SERVICE",
			},
			"ports on": {
				Pattern:          "ports on",
				FromType:         "host",
				ToType:           "port",
				RelationshipType: "HAS_PORT",
			},
			"open ports on": {
				Pattern:          "open ports on",
				FromType:         "host",
				ToType:           "port",
				RelationshipType: "HAS_PORT",
			},
			"findings for": {
				Pattern:          "findings for",
				FromType:         "*",
				ToType:           "finding",
				RelationshipType: "AFFECTS",
			},
			"vulnerabilities on": {
				Pattern:          "vulnerabilities on",
				FromType:         "*",
				ToType:           "finding",
				RelationshipType: "AFFECTS",
			},
			"endpoints on": {
				Pattern:          "endpoints on",
				FromType:         "service",
				ToType:           "endpoint",
				RelationshipType: "HAS_ENDPOINT",
			},
			"technologies used by": {
				Pattern:          "technologies used by",
				FromType:         "*",
				ToType:           "technology",
				RelationshipType: "USES_TECHNOLOGY",
			},
			"subdomains of": {
				Pattern:          "subdomains of",
				FromType:         "domain",
				ToType:           "subdomain",
				RelationshipType: "HAS_SUBDOMAIN",
			},
		},
	}

	// Compile regex patterns
	p.ipv4Pattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	p.hostnamePattern = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
	p.portPattern = regexp.MustCompile(`\bport\s+(\d{1,5})\b|\b:(\d{1,5})\b|\b(\d{1,5})(?:/tcp|/udp)\b`)
	p.severityPattern = regexp.MustCompile(`\b(critical|high|medium|low|info)\b`)
	p.cvePattern = regexp.MustCompile(`\bCVE-\d{4}-\d{4,}\b`)

	return p
}

// Parse extracts structured information from a natural language query.
func (p *QueryParser) Parse(query string) *ParsedQuery {
	result := &ParsedQuery{
		OriginalQuery:        query,
		EntityTypes:          []string{},
		IPAddresses:          []string{},
		Hostnames:            []string{},
		Ports:                []int{},
		Severities:           []string{},
		CVEIDs:               []string{},
		RelationshipPatterns: []RelationshipPattern{},
		Keywords:             []string{},
		Confidence:           0.0,
	}

	lowerQuery := strings.ToLower(query)

	// Extract IP addresses
	if matches := p.ipv4Pattern.FindAllString(query, -1); len(matches) > 0 {
		result.IPAddresses = matches
	}

	// Extract hostnames (excluding IPs)
	potentialHostnames := p.hostnamePattern.FindAllString(lowerQuery, -1)
	for _, hostname := range potentialHostnames {
		if !p.ipv4Pattern.MatchString(hostname) {
			result.Hostnames = append(result.Hostnames, hostname)
		}
	}

	// Extract port numbers
	portMatches := p.portPattern.FindAllStringSubmatch(lowerQuery, -1)
	for _, match := range portMatches {
		for i := 1; i < len(match); i++ {
			if match[i] != "" {
				port := 0
				// Simple atoi
				for _, c := range match[i] {
					if c >= '0' && c <= '9' {
						port = port*10 + int(c-'0')
					}
				}
				if port > 0 && port <= 65535 {
					result.Ports = append(result.Ports, port)
				}
			}
		}
	}

	// Extract severities
	severityMatches := p.severityPattern.FindAllString(lowerQuery, -1)
	seen := make(map[string]bool)
	for _, sev := range severityMatches {
		if !seen[sev] {
			result.Severities = append(result.Severities, sev)
			seen[sev] = true
		}
	}

	// Extract CVE IDs
	if matches := p.cvePattern.FindAllString(strings.ToUpper(query), -1); len(matches) > 0 {
		result.CVEIDs = matches
	}

	// Extract entity types
	entityTypeSeen := make(map[string]bool)
	words := strings.Fields(lowerQuery)
	for _, word := range words {
		// Clean punctuation
		word = strings.Trim(word, ".,;:!?()[]{}\"'")
		if entityType, ok := p.entityTypePatterns[word]; ok {
			if !entityTypeSeen[entityType] {
				result.EntityTypes = append(result.EntityTypes, entityType)
				entityTypeSeen[entityType] = true
			}
		}
	}

	// Extract relationship patterns
	for phrase, pattern := range p.relationshipPatterns {
		if strings.Contains(lowerQuery, phrase) {
			result.RelationshipPatterns = append(result.RelationshipPatterns, pattern)
		}
	}

	// Extract remaining keywords (filter out recognized patterns)
	result.Keywords = p.extractKeywords(query, result)

	// Calculate confidence
	result.Confidence = p.calculateConfidence(result)

	return result
}

// extractKeywords extracts remaining keywords that weren't recognized as patterns.
func (p *QueryParser) extractKeywords(query string, parsed *ParsedQuery) []string {
	// Remove recognized patterns from query
	remaining := strings.ToLower(query)

	// Remove IPs
	for _, ip := range parsed.IPAddresses {
		remaining = strings.ReplaceAll(remaining, ip, "")
	}

	// Remove hostnames
	for _, hostname := range parsed.Hostnames {
		remaining = strings.ReplaceAll(remaining, hostname, "")
	}

	// Remove relationship patterns
	for _, rp := range parsed.RelationshipPatterns {
		remaining = strings.ReplaceAll(remaining, rp.Pattern, "")
	}

	// Remove common stop words and entity type words
	stopWords := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true,
		"on": true, "in": true, "for": true, "with": true, "of": true,
		"to": true, "from": true, "by": true, "is": true, "are": true,
		"what": true, "which": true, "where": true, "who": true, "how": true,
		"all": true, "any": true, "show": true, "find": true, "get": true,
		"list": true, "me": true, "my": true, "port": true,
	}

	// Add entity type patterns as stop words
	for pattern := range p.entityTypePatterns {
		stopWords[pattern] = true
	}

	// Extract remaining words
	keywords := []string{}
	words := strings.Fields(remaining)
	for _, word := range words {
		word = strings.Trim(word, ".,;:!?()[]{}\"'")
		if word != "" && !stopWords[word] && len(word) > 1 {
			// Skip pure numbers (they're likely port numbers already extracted)
			isPureNumber := true
			for _, c := range word {
				if c < '0' || c > '9' {
					isPureNumber = false
					break
				}
			}
			if !isPureNumber {
				keywords = append(keywords, word)
			}
		}
	}

	return keywords
}

// calculateConfidence estimates how structured/unambiguous the query is.
func (p *QueryParser) calculateConfidence(parsed *ParsedQuery) float64 {
	confidence := 0.0
	factors := 0.0

	// More specific identifiers increase confidence
	if len(parsed.IPAddresses) > 0 {
		confidence += 0.3
		factors++
	}
	if len(parsed.Hostnames) > 0 {
		confidence += 0.3
		factors++
	}
	if len(parsed.Ports) > 0 {
		confidence += 0.2
		factors++
	}

	// Entity types increase confidence
	if len(parsed.EntityTypes) > 0 {
		confidence += 0.2
		factors++
	}

	// Relationship patterns increase confidence
	if len(parsed.RelationshipPatterns) > 0 {
		confidence += 0.3
		factors++
	}

	// CVE IDs are very specific
	if len(parsed.CVEIDs) > 0 {
		confidence += 0.4
		factors++
	}

	// Severities add some specificity
	if len(parsed.Severities) > 0 {
		confidence += 0.1
		factors++
	}

	// Remaining keywords reduce confidence (more ambiguity)
	if len(parsed.Keywords) > 3 {
		confidence -= 0.1
	}

	if factors == 0 {
		// Pure keyword query - low confidence
		return 0.2
	}

	// Normalize
	result := confidence / factors
	if result > 1.0 {
		result = 1.0
	}
	if result < 0.0 {
		result = 0.0
	}

	return result
}

// HasEntityFilters returns true if the parsed query has specific entity filters
// (IPs, hostnames, ports) that can be used for direct lookup.
func (pq *ParsedQuery) HasEntityFilters() bool {
	return len(pq.IPAddresses) > 0 || len(pq.Hostnames) > 0 || len(pq.Ports) > 0
}

// HasRelationshipQuery returns true if the parsed query implies relationship traversal.
func (pq *ParsedQuery) HasRelationshipQuery() bool {
	return len(pq.RelationshipPatterns) > 0
}

// ToEntityQuery converts the parsed query to an EntityQuery for graph lookup.
func (pq *ParsedQuery) ToEntityQuery(missionRunID string, maxResults int) EntityQuery {
	eq := EntityQuery{
		EntityTypes:  pq.EntityTypes,
		MissionRunID: missionRunID,
		MaxResults:   maxResults,
		Filters:      make(map[string]interface{}),
	}

	// Add IP filter if present
	if len(pq.IPAddresses) == 1 {
		eq.Filters["ip"] = pq.IPAddresses[0]
	}

	// Add hostname filter if present
	if len(pq.Hostnames) == 1 {
		eq.Filters["hostname"] = pq.Hostnames[0]
	}

	// Add severity filter if present
	if len(pq.Severities) == 1 {
		eq.Filters["severity"] = pq.Severities[0]
	}

	return eq
}
