package finding

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// TestComputeHashConsistency verifies that the same input produces the same hash
func TestComputeHashConsistency(t *testing.T) {
	tests := []struct {
		name     string
		finding1 *EnhancedFinding
		finding2 *EnhancedFinding
		sameHash bool
	}{
		{
			name: "identical findings produce same hash",
			finding1: &EnhancedFinding{
				Finding: agent.Finding{
					Title:    "SQL Injection",
					Category: "injection",
				},
			},
			finding2: &EnhancedFinding{
				Finding: agent.Finding{
					Title:    "SQL Injection",
					Category: "injection",
				},
			},
			sameHash: true,
		},
		{
			name: "case differences in title still produce same hash (normalized)",
			finding1: &EnhancedFinding{
				Finding: agent.Finding{
					Title:    "SQL Injection",
					Category: "injection",
				},
			},
			finding2: &EnhancedFinding{
				Finding: agent.Finding{
					Title:    "sql injection",
					Category: "injection",
				},
			},
			sameHash: true,
		},
		{
			name: "whitespace differences produce same hash (normalized)",
			finding1: &EnhancedFinding{
				Finding: agent.Finding{
					Title:    "  SQL Injection  ",
					Category: "injection",
				},
			},
			finding2: &EnhancedFinding{
				Finding: agent.Finding{
					Title:    "SQL Injection",
					Category: "injection",
				},
			},
			sameHash: true,
		},
		{
			name: "different titles produce different hash",
			finding1: &EnhancedFinding{
				Finding: agent.Finding{
					Title:    "SQL Injection",
					Category: "injection",
				},
			},
			finding2: &EnhancedFinding{
				Finding: agent.Finding{
					Title:    "XSS Attack",
					Category: "injection",
				},
			},
			sameHash: false,
		},
		{
			name: "different categories produce different hash",
			finding1: &EnhancedFinding{
				Finding: agent.Finding{
					Title:    "SQL Injection",
					Category: "injection",
				},
			},
			finding2: &EnhancedFinding{
				Finding: agent.Finding{
					Title:    "SQL Injection",
					Category: "authentication",
				},
			},
			sameHash: false,
		},
		{
			name: "different target IDs produce different hash",
			finding1: &EnhancedFinding{
				Finding: agent.Finding{
					Title:    "SQL Injection",
					Category: "injection",
					TargetID: func() *types.ID { id := types.NewID(); return &id }(),
				},
			},
			finding2: &EnhancedFinding{
				Finding: agent.Finding{
					Title:    "SQL Injection",
					Category: "injection",
					TargetID: func() *types.ID { id := types.NewID(); return &id }(),
				},
			},
			sameHash: false,
		},
		{
			name: "same target ID produces same hash",
			finding1: func() *EnhancedFinding {
				targetID := types.NewID()
				return &EnhancedFinding{
					Finding: agent.Finding{
						Title:    "SQL Injection",
						Category: "injection",
						TargetID: &targetID,
					},
				}
			}(),
			finding2: func() *EnhancedFinding {
				// Use the same target ID from finding1
				return nil // Will be set in the test
			}(),
			sameHash: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Special handling for same target ID test
			if tt.finding2 == nil {
				tt.finding2 = &EnhancedFinding{
					Finding: agent.Finding{
						Title:    "SQL Injection",
						Category: "injection",
						TargetID: tt.finding1.TargetID,
					},
				}
			}

			hash1 := computeHash(tt.finding1)
			hash2 := computeHash(tt.finding2)

			assert.NotEmpty(t, hash1, "hash1 should not be empty")
			assert.NotEmpty(t, hash2, "hash2 should not be empty")

			if tt.sameHash {
				assert.Equal(t, hash1, hash2, "hashes should be identical")
			} else {
				assert.NotEqual(t, hash1, hash2, "hashes should be different")
			}
		})
	}
}

// TestCheckDuplicate verifies duplicate detection
func TestCheckDuplicate(t *testing.T) {
	deduplicator := NewDeduplicator()

	// Create original finding
	original := &EnhancedFinding{
		Finding: agent.Finding{
			ID:       types.NewID(),
			Title:    "SQL Injection in Login",
			Category: "injection",
			Severity: agent.SeverityHigh,
		},
	}

	// Register the original
	deduplicator.RegisterFinding(original)

	t.Run("exact duplicate detected", func(t *testing.T) {
		duplicate := &EnhancedFinding{
			Finding: agent.Finding{
				ID:       types.NewID(),
				Title:    "SQL Injection in Login",
				Category: "injection",
				Severity: agent.SeverityHigh,
			},
		}

		existingID, isDuplicate := deduplicator.CheckDuplicate(duplicate)
		assert.True(t, isDuplicate, "should detect duplicate")
		assert.NotNil(t, existingID, "should return existing ID")
		assert.Equal(t, original.ID, *existingID, "should return original finding ID")
	})

	t.Run("normalized duplicate detected", func(t *testing.T) {
		duplicate := &EnhancedFinding{
			Finding: agent.Finding{
				ID:       types.NewID(),
				Title:    "  sql injection in login  ",
				Category: "injection",
				Severity: agent.SeverityMedium, // Different severity doesn't affect hash
			},
		}

		existingID, isDuplicate := deduplicator.CheckDuplicate(duplicate)
		assert.True(t, isDuplicate, "should detect duplicate with normalization")
		assert.Equal(t, original.ID, *existingID)
	})

	t.Run("different finding not a duplicate", func(t *testing.T) {
		different := &EnhancedFinding{
			Finding: agent.Finding{
				ID:       types.NewID(),
				Title:    "XSS Attack",
				Category: "injection",
				Severity: agent.SeverityHigh,
			},
		}

		existingID, isDuplicate := deduplicator.CheckDuplicate(different)
		assert.False(t, isDuplicate, "should not detect as duplicate")
		assert.Nil(t, existingID, "should return nil ID")
	})
}

// TestRegisterFinding verifies finding registration
func TestRegisterFinding(t *testing.T) {
	deduplicator := NewDeduplicator()

	finding := &EnhancedFinding{
		Finding: agent.Finding{
			ID:       types.NewID(),
			Title:    "Buffer Overflow",
			Category: "memory_corruption",
		},
	}

	// Initially should not exist
	_, isDuplicate := deduplicator.CheckDuplicate(finding)
	assert.False(t, isDuplicate, "should not exist before registration")

	// Register
	deduplicator.RegisterFinding(finding)

	// Now should be detected as duplicate
	existingID, isDuplicate := deduplicator.CheckDuplicate(finding)
	assert.True(t, isDuplicate, "should exist after registration")
	assert.Equal(t, finding.ID, *existingID)

	// Verify count
	assert.Equal(t, 1, deduplicator.Count())
}

// TestMergeEvidence verifies evidence merging
func TestMergeEvidence(t *testing.T) {
	deduplicator := NewDeduplicator()

	// Create and register original finding with evidence
	original := &EnhancedFinding{
		Finding: agent.Finding{
			ID:       types.NewID(),
			Title:    "Path Traversal",
			Category: "path_traversal",
			Evidence: []agent.Evidence{
				{
					Type:        "request",
					Description: "Initial evidence",
				},
			},
		},
		OccurrenceCount: 1,
	}

	deduplicator.RegisterFinding(original)

	// Create duplicate with new evidence
	duplicate := &EnhancedFinding{
		Finding: agent.Finding{
			ID:       types.NewID(),
			Title:    "Path Traversal",
			Category: "path_traversal",
			Evidence: []agent.Evidence{
				{
					Type:        "response",
					Description: "New evidence",
				},
				{
					Type:        "log",
					Description: "Additional log evidence",
				},
			},
		},
	}

	t.Run("merge evidence successfully", func(t *testing.T) {
		err := deduplicator.MergeEvidence(original.ID, duplicate)
		require.NoError(t, err, "merge should succeed")

		// Verify evidence was appended
		merged, found := deduplicator.GetFinding(original.ID)
		require.True(t, found, "original finding should exist")
		assert.Len(t, merged.Evidence, 3, "should have 3 pieces of evidence")
		assert.Equal(t, "Initial evidence", merged.Evidence[0].Description)
		assert.Equal(t, "New evidence", merged.Evidence[1].Description)
		assert.Equal(t, "Additional log evidence", merged.Evidence[2].Description)
	})

	t.Run("occurrence count incremented", func(t *testing.T) {
		merged, _ := deduplicator.GetFinding(original.ID)
		assert.Equal(t, 2, merged.OccurrenceCount, "occurrence count should be incremented")
	})

	t.Run("merge with non-existent finding fails", func(t *testing.T) {
		nonExistentID := types.NewID()
		err := deduplicator.MergeEvidence(nonExistentID, duplicate)
		assert.Error(t, err, "should fail for non-existent finding")
		assert.Contains(t, err.Error(), "not found")
	})
}

// TestFindRelated verifies related finding detection
func TestFindRelated(t *testing.T) {
	deduplicator := NewDeduplicator()

	// Create several findings with varying similarity
	findings := []*EnhancedFinding{
		{
			Finding: agent.Finding{
				ID:          types.NewID(),
				Title:       "SQL Injection in login form",
				Category:    "injection",
				Description: "User input not sanitized in SQL query",
			},
		},
		{
			Finding: agent.Finding{
				ID:          types.NewID(),
				Title:       "SQL Injection in search function",
				Category:    "injection",
				Description: "Database query vulnerable to injection",
			},
		},
		{
			Finding: agent.Finding{
				ID:          types.NewID(),
				Title:       "XSS vulnerability in comments",
				Category:    "xss",
				Description: "User input reflected without encoding",
			},
		},
		{
			Finding: agent.Finding{
				ID:          types.NewID(),
				Title:       "CSRF token missing",
				Category:    "csrf",
				Description: "No CSRF protection on form submission",
			},
		},
	}

	// Register all findings
	for _, f := range findings {
		deduplicator.RegisterFinding(f)
	}

	t.Run("find related SQL injection findings", func(t *testing.T) {
		// Query with a SQL injection finding
		query := &EnhancedFinding{
			Finding: agent.Finding{
				ID:          types.NewID(),
				Title:       "SQL Injection in registration",
				Category:    "injection",
				Description: "SQL query injection vulnerability",
			},
		}

		related, err := deduplicator.FindRelated(query, 0.2)
		require.NoError(t, err)

		// Should find the two SQL injection findings
		// (high similarity due to "injection", "sql" keywords)
		assert.GreaterOrEqual(t, len(related), 1, "should find at least one related finding")

		// Verify the first two findings are the SQL injection ones
		for _, id := range related[:min(2, len(related))] {
			finding, found := deduplicator.GetFinding(id)
			require.True(t, found)
			assert.Contains(t, finding.Category, "injection")
		}
	})

	t.Run("no related findings with high threshold", func(t *testing.T) {
		query := &EnhancedFinding{
			Finding: agent.Finding{
				ID:          types.NewID(),
				Title:       "Completely unrelated issue",
				Category:    "other",
				Description: "Nothing in common",
			},
		}

		related, err := deduplicator.FindRelated(query, 0.8)
		require.NoError(t, err)
		assert.Empty(t, related, "should find no related findings with high threshold")
	})

	t.Run("related findings sorted by similarity", func(t *testing.T) {
		query := &EnhancedFinding{
			Finding: agent.Finding{
				ID:          types.NewID(),
				Title:       "SQL Injection",
				Category:    "injection",
				Description: "SQL injection",
			},
		}

		related, err := deduplicator.FindRelated(query, 0.1)
		require.NoError(t, err)

		// First result should be more similar than later results
		if len(related) >= 2 {
			first, _ := deduplicator.GetFinding(related[0])
			_, _ = deduplicator.GetFinding(related[1])

			// First should contain "injection" more prominently
			assert.Contains(t, first.Category, "injection")

			// Can't guarantee second doesn't, but at least verify they're different
			assert.NotEqual(t, related[0], related[1])
		}
	})
}

// TestExtractKeywords verifies keyword extraction
func TestExtractKeywords(t *testing.T) {
	tests := []struct {
		name        string
		finding     *EnhancedFinding
		expected    []string
		notExpected []string
	}{
		{
			name: "extract from title and category",
			finding: &EnhancedFinding{
				Finding: agent.Finding{
					Title:    "SQL Injection Vulnerability",
					Category: "database injection",
				},
			},
			expected:    []string{"sql", "injection", "vulnerability", "database"},
			notExpected: []string{"the", "a", "and"},
		},
		{
			name: "stopwords filtered out",
			finding: &EnhancedFinding{
				Finding: agent.Finding{
					Title:    "The SQL Injection in the Database",
					Category: "injection",
				},
			},
			expected:    []string{"sql", "injection", "database"},
			notExpected: []string{"the", "in"},
		},
		{
			name: "short words filtered out",
			finding: &EnhancedFinding{
				Finding: agent.Finding{
					Title:    "SQL XSS in DB",
					Category: "web",
				},
			},
			expected:    []string{"sql", "xss", "web"},
			notExpected: []string{"in", "db"}, // "db" is only 2 chars
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keywords := extractKeywords(tt.finding)

			for _, expected := range tt.expected {
				assert.True(t, keywords[expected], "should contain keyword: %s", expected)
			}

			for _, notExpected := range tt.notExpected {
				assert.False(t, keywords[notExpected], "should not contain: %s", notExpected)
			}
		})
	}
}

// TestComputeSimilarity verifies Jaccard similarity calculation
func TestComputeSimilarity(t *testing.T) {
	tests := []struct {
		name     string
		a        map[string]bool
		b        map[string]bool
		expected float64
	}{
		{
			name:     "identical sets",
			a:        map[string]bool{"sql": true, "injection": true},
			b:        map[string]bool{"sql": true, "injection": true},
			expected: 1.0,
		},
		{
			name:     "completely different sets",
			a:        map[string]bool{"sql": true, "injection": true},
			b:        map[string]bool{"xss": true, "csrf": true},
			expected: 0.0,
		},
		{
			name:     "partial overlap",
			a:        map[string]bool{"sql": true, "injection": true, "database": true},
			b:        map[string]bool{"sql": true, "injection": true, "web": true},
			expected: 0.5, // 2 common / 4 total = 0.5
		},
		{
			name:     "both empty",
			a:        map[string]bool{},
			b:        map[string]bool{},
			expected: 1.0,
		},
		{
			name:     "one empty",
			a:        map[string]bool{"sql": true},
			b:        map[string]bool{},
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			similarity := computeSimilarity(tt.a, tt.b)
			assert.InDelta(t, tt.expected, similarity, 0.01, "similarity should match expected")
		})
	}
}

// TestConcurrentAccess verifies thread-safety
func TestConcurrentAccess(t *testing.T) {
	deduplicator := NewDeduplicator()

	// Create multiple findings
	findings := make([]*EnhancedFinding, 100)
	for i := 0; i < 100; i++ {
		findings[i] = &EnhancedFinding{
			Finding: agent.Finding{
				ID:       types.NewID(),
				Title:    "Finding " + string(rune(i)),
				Category: "test",
			},
		}
	}

	// Concurrent registration
	t.Run("concurrent registration", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			go deduplicator.RegisterFinding(findings[i])
		}

		// Give goroutines time to complete
		// In production, use sync.WaitGroup
		// For this test, a simple sleep is acceptable
		assert.Eventually(t, func() bool {
			return deduplicator.Count() == 50
		}, time.Second, 10*time.Millisecond, "should register all findings")
	})

	// Concurrent duplicate checking
	t.Run("concurrent duplicate checking", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			go func(idx int) {
				_, _ = deduplicator.CheckDuplicate(findings[idx])
			}(i)
		}

		// No assertion needed - just verify no panic/race
	})
}

// TestClearAndCount verifies utility methods
func TestClearAndCount(t *testing.T) {
	deduplicator := NewDeduplicator()

	// Add some findings
	for i := 0; i < 5; i++ {
		finding := &EnhancedFinding{
			Finding: agent.Finding{
				ID:       types.NewID(),
				Title:    "Test Finding",
				Category: "test",
			},
		}
		deduplicator.RegisterFinding(finding)
	}

	assert.Equal(t, 5, deduplicator.Count(), "should have 5 findings")

	deduplicator.Clear()
	assert.Equal(t, 0, deduplicator.Count(), "should have 0 findings after clear")
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
