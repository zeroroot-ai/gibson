package neo4j

import (
	"net/url"
	"strings"
	"testing"

	"github.com/zero-day-ai/gibson/internal/types"
)

func TestBrowserURL(t *testing.T) {
	tests := []struct {
		name        string
		baseURL     string
		missionID   types.ID
		queryType   QueryType
		wantErr     bool
		errContains string
		validate    func(t *testing.T, result string)
	}{
		{
			name:      "valid full query",
			baseURL:   "http://localhost:7474",
			missionID: types.NewID(),
			queryType: QueryTypeFull,
			wantErr:   false,
			validate: func(t *testing.T, result string) {
				if !strings.HasPrefix(result, "http://localhost:7474/browser/?cmd=edit&arg=") {
					t.Errorf("URL should start with base URL and browser path, got: %s", result)
				}
				// Verify URL is properly formed
				parsed, err := url.Parse(result)
				if err != nil {
					t.Errorf("Generated URL is not valid: %v", err)
				}
				// Verify query parameters
				if parsed.Query().Get("cmd") != "edit" {
					t.Errorf("Expected cmd=edit, got: %s", parsed.Query().Get("cmd"))
				}
				if parsed.Query().Get("arg") == "" {
					t.Error("Expected arg parameter with Cypher query")
				}
			},
		},
		{
			name:      "valid hosts query",
			baseURL:   "https://neo4j.example.com",
			missionID: types.NewID(),
			queryType: QueryTypeHosts,
			wantErr:   false,
			validate: func(t *testing.T, result string) {
				if !strings.HasPrefix(result, "https://neo4j.example.com/browser/") {
					t.Errorf("URL should start with HTTPS base URL, got: %s", result)
				}
				// Decode and verify query contains hosts-specific logic
				parsed, _ := url.Parse(result)
				query, _ := url.QueryUnescape(parsed.Query().Get("arg"))
				if !strings.Contains(query, "HAS_PORT") {
					t.Error("Hosts query should contain HAS_PORT relationship")
				}
			},
		},
		{
			name:      "valid vulnerabilities query",
			baseURL:   "http://localhost:7474",
			missionID: types.NewID(),
			queryType: QueryTypeVulnerabilities,
			wantErr:   false,
			validate: func(t *testing.T, result string) {
				parsed, _ := url.Parse(result)
				query, _ := url.QueryUnescape(parsed.Query().Get("arg"))
				if !strings.Contains(query, "Vulnerability") {
					t.Error("Vulnerabilities query should reference Vulnerability nodes")
				}
				if !strings.Contains(query, "AFFECTS") {
					t.Error("Vulnerabilities query should contain AFFECTS relationship")
				}
			},
		},
		{
			name:      "valid attack paths query",
			baseURL:   "http://localhost:7474",
			missionID: types.NewID(),
			queryType: QueryTypeAttackPaths,
			wantErr:   false,
			validate: func(t *testing.T, result string) {
				parsed, _ := url.Parse(result)
				query, _ := url.QueryUnescape(parsed.Query().Get("arg"))
				if !strings.Contains(query, "shortestPath") {
					t.Error("Attack paths query should use shortestPath function")
				}
			},
		},
		{
			name:      "base URL with trailing slash",
			baseURL:   "http://localhost:7474/",
			missionID: types.NewID(),
			queryType: QueryTypeFull,
			wantErr:   false,
			validate: func(t *testing.T, result string) {
				// Should handle trailing slash correctly (no double slash)
				if strings.Contains(result, "//browser/") {
					t.Error("URL should not contain double slash before /browser/")
				}
			},
		},
		{
			name:        "empty base URL",
			baseURL:     "",
			missionID:   types.NewID(),
			queryType:   QueryTypeFull,
			wantErr:     true,
			errContains: "baseURL cannot be empty",
		},
		{
			name:        "empty mission ID",
			baseURL:     "http://localhost:7474",
			missionID:   "",
			queryType:   QueryTypeFull,
			wantErr:     true,
			errContains: "missionID cannot be empty",
		},
		{
			name:        "invalid base URL",
			baseURL:     "://invalid",
			missionID:   types.NewID(),
			queryType:   QueryTypeFull,
			wantErr:     true,
			errContains: "invalid baseURL",
		},
		{
			name:        "base URL without scheme",
			baseURL:     "localhost:7474",
			missionID:   types.NewID(),
			queryType:   QueryTypeFull,
			wantErr:     true,
			errContains: "must include", // Can be "scheme" or "host" depending on parser
		},
		{
			name:      "special characters in mission ID",
			baseURL:   "http://localhost:7474",
			missionID: types.ID("mission-with-special-chars-123"),
			queryType: QueryTypeFull,
			wantErr:   false,
			validate: func(t *testing.T, result string) {
				parsed, _ := url.Parse(result)
				query, _ := url.QueryUnescape(parsed.Query().Get("arg"))
				if !strings.Contains(query, "mission-with-special-chars-123") {
					t.Error("Mission ID should be preserved in query")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := BrowserURL(tt.baseURL, tt.missionID, tt.queryType)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errContains)
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Expected error containing '%s', got: %s", tt.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
		})
	}
}

func TestQueryType_String(t *testing.T) {
	tests := []struct {
		queryType QueryType
		want      string
	}{
		{QueryTypeFull, "full"},
		{QueryTypeHosts, "hosts"},
		{QueryTypeVulnerabilities, "vulnerabilities"},
		{QueryTypeAttackPaths, "attack_paths"},
		{QueryType(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.queryType.String()
			if got != tt.want {
				t.Errorf("QueryType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQueryReference(t *testing.T) {
	missionID := types.NewID()

	tests := []struct {
		name      string
		queryType QueryType
		contains  []string
	}{
		{
			name:      "full query reference",
			queryType: QueryTypeFull,
			contains:  []string{"Mission", "OPTIONAL MATCH", "relationships"},
		},
		{
			name:      "hosts query reference",
			queryType: QueryTypeHosts,
			contains:  []string{"Host", "HAS_PORT", "Port"},
		},
		{
			name:      "vulnerabilities query reference",
			queryType: QueryTypeVulnerabilities,
			contains:  []string{"Vulnerability", "AFFECTS", "Service"},
		},
		{
			name:      "attack paths query reference",
			queryType: QueryTypeAttackPaths,
			contains:  []string{"shortestPath", "Host", "Vulnerability"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := QueryReference(missionID, tt.queryType)
			if result == "" {
				t.Error("Query reference should not be empty")
			}
			for _, substr := range tt.contains {
				if !strings.Contains(result, substr) {
					t.Errorf("Query should contain '%s', got: %s", substr, result)
				}
			}
			// Verify mission ID is in the query
			if !strings.Contains(result, missionID.String()) {
				t.Error("Query should contain mission ID")
			}
		})
	}
}

func TestMustBrowserURL(t *testing.T) {
	t.Run("valid input does not panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("MustBrowserURL panicked unexpectedly: %v", r)
			}
		}()
		result := MustBrowserURL("http://localhost:7474", types.NewID(), QueryTypeFull)
		if result == "" {
			t.Error("MustBrowserURL should return non-empty result")
		}
	})

	t.Run("invalid input panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("MustBrowserURL should panic on invalid input")
			}
		}()
		_ = MustBrowserURL("", types.NewID(), QueryTypeFull)
	})
}

func TestURLEncoding(t *testing.T) {
	// Test that special characters in queries are properly encoded
	missionID := types.ID("mission-123")
	baseURL := "http://localhost:7474"

	result, err := BrowserURL(baseURL, missionID, QueryTypeFull)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Parse the full URL
	parsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("Generated URL is not valid: %v", err)
	}

	// The query parameter is automatically decoded by parsed.Query().Get()
	// So we need to check the raw query string instead
	rawQuery := parsed.RawQuery
	if rawQuery == "" {
		t.Fatal("Raw query string is missing")
	}

	// Verify special characters are encoded in the raw query
	// Note: url.QueryEscape uses + for spaces and %XX for other characters
	if !strings.Contains(rawQuery, "+") && !strings.Contains(rawQuery, "%20") {
		t.Logf("Raw query: %s", rawQuery)
		t.Error("Encoded query should contain encoded spaces (+ or %20)")
	}
	if !strings.Contains(rawQuery, "%") {
		t.Logf("Raw query: %s", rawQuery)
		t.Error("Encoded query should contain percent-encoded characters")
	}

	// Now get the decoded value and verify content
	encodedQuery := parsed.Query().Get("arg")
	if encodedQuery == "" {
		t.Fatal("Query parameter 'arg' is missing")
	}

	// Verify decoded content is present
	if !strings.Contains(encodedQuery, "Mission") {
		t.Error("Decoded query should contain 'Mission'")
	}
	if !strings.Contains(encodedQuery, "{") {
		t.Error("Decoded query should contain curly braces for Cypher syntax")
	}
	if !strings.Contains(encodedQuery, "\"") {
		t.Error("Decoded query should contain quotes for string values")
	}
	if !strings.Contains(encodedQuery, " ") {
		t.Error("Decoded query should contain spaces")
	}
}

func BenchmarkBrowserURL(b *testing.B) {
	baseURL := "http://localhost:7474"
	missionID := types.NewID()

	b.Run("full_query", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = BrowserURL(baseURL, missionID, QueryTypeFull)
		}
	})

	b.Run("hosts_query", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = BrowserURL(baseURL, missionID, QueryTypeHosts)
		}
	})
}
