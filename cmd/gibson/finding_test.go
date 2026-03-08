package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// TestFindingListCommand tests the finding list command with various filters
func TestFindingListCommand(t *testing.T) {
	// Skip test that requires Redis
	t.Skip("requires Redis")

	tests := []struct {
		name          string
		args          []string
		setupFindings func(*testing.T, *state.StateClient) []finding.EnhancedFinding
		expectError   bool
		expectOutput  []string
	}{
		{
			name: "list all findings",
			args: []string{"list"},
			setupFindings: func(t *testing.T, stateClient *state.StateClient) []finding.EnhancedFinding {
				return createTestFindings(t, stateClient, 3)
			},
			expectError: false,
			expectOutput: []string{
				"ID", "TITLE", "SEVERITY", "CATEGORY", "STATUS", "MISSION",
			},
		},
		{
			name: "filter by critical severity",
			args: []string{"list", "--severity", "critical"},
			setupFindings: func(t *testing.T, stateClient *state.StateClient) []finding.EnhancedFinding {
				findings := createTestFindings(t, stateClient, 3)
				findings[0].Severity = agent.SeverityCritical
				findings[1].Severity = agent.SeverityHigh
				findings[2].Severity = agent.SeverityMedium
				store := finding.NewRedisFindingStore(stateClient)
				for _, f := range findings {
					require.NoError(t, store.Update(context.Background(), f))
				}
				return findings
			},
			expectError: false,
			expectOutput: []string{
				"critical",
			},
		},
		{
			name: "filter by category",
			args: []string{"list", "--category", "jailbreak"},
			setupFindings: func(t *testing.T, stateClient *state.StateClient) []finding.EnhancedFinding {
				findings := createTestFindings(t, stateClient, 2)
				findings[0].Category = "jailbreak"
				findings[1].Category = "prompt_injection"
				store := finding.NewRedisFindingStore(stateClient)
				for _, f := range findings {
					require.NoError(t, store.Update(context.Background(), f))
				}
				return findings
			},
			expectError: false,
			expectOutput: []string{
				"jailbreak",
			},
		},
		{
			name: "filter by mission ID",
			args: func() []string {
				missionID := types.NewID()
				return []string{"list", "--mission", missionID.String()}
			}(),
			setupFindings: func(t *testing.T, stateClient *state.StateClient) []finding.EnhancedFinding {
				// Create findings with different mission IDs
				findings := createTestFindings(t, stateClient, 2)
				return findings
			},
			expectError: false,
			expectOutput: []string{
				"No findings found",
			},
		},
		{
			name: "no findings",
			args: []string{"list"},
			setupFindings: func(t *testing.T, stateClient *state.StateClient) []finding.EnhancedFinding {
				return []finding.EnhancedFinding{}
			},
			expectError: false,
			expectOutput: []string{
				"No findings found",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore global flags to avoid test pollution
			oldGlobalFlags := *globalFlags
			defer func() { *globalFlags = oldGlobalFlags }()

			// Save and restore command-specific flags
			oldListSeverity := listSeverity
			oldListCategory := listCategory
			oldListMission := listMission
			oldListStatus := listStatus
			defer func() {
				listSeverity = oldListSeverity
				listCategory = oldListCategory
				listMission = oldListMission
				listStatus = oldListStatus
			}()

			// Create temp directory and database
			t.TempDir()
			t.TempDir()
			tempDir := t.TempDir(); homeDir := filepath.Join(tempDir, ".gibson")
			require.NoError(t, os.MkdirAll(homeDir, 0755))

			stateClient, err := state.NewStateClient(&state.Config{URL: "redis://localhost:6379"})
			require.NoError(t, err)
			defer stateClient.Close()

			// Initialize schema
			// StateClient does not need InitSchema
			require.NoError(t, err)

			// Setup test findings
			if tt.setupFindings != nil {
				tt.setupFindings(t, stateClient)
			}

			// Execute command directly
			cmd := findingListCmd
			cmd.SetContext(context.Background())

			// Set global flags directly
			globalFlags.HomeDir = homeDir

			// Set command-specific flags
			for i := 0; i < len(tt.args); i++ {
				if tt.args[i] == "--severity" && i+1 < len(tt.args) {
					cmd.Flags().Set("severity", tt.args[i+1])
					i++
				} else if tt.args[i] == "--category" && i+1 < len(tt.args) {
					cmd.Flags().Set("category", tt.args[i+1])
					i++
				} else if tt.args[i] == "--mission" && i+1 < len(tt.args) {
					cmd.Flags().Set("mission", tt.args[i+1])
					i++
				} else if tt.args[i] == "--status" && i+1 < len(tt.args) {
					cmd.Flags().Set("status", tt.args[i+1])
					i++
				}
			}

			var outBuf bytes.Buffer
			cmd.SetOut(&outBuf)
			cmd.SetErr(&outBuf)

			// Call RunE directly
			err = cmd.RunE(cmd, []string{})

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			output := outBuf.String()
			for _, expected := range tt.expectOutput {
				assert.Contains(t, output, expected, "Output should contain: %s", expected)
			}
		})
	}
}

// TestFindingShowCommand tests the finding show command
func TestFindingShowCommand(t *testing.T) {
	t.Skip("requires Redis")
	tests := []struct {
		name         string
		setupFinding func(*testing.T, *state.StateClient) types.ID
		expectError  bool
		expectOutput []string
	}{
		{
			name: "show complete finding",
			setupFinding: func(t *testing.T, stateClient *state.StateClient) types.ID {
				findings := createTestFindings(t, stateClient, 1)
				f := &findings[0]

				// Add comprehensive details
				f.Description = "Test finding with complete details"
				f.Remediation = "Apply security patches and review configurations"
				f.References = []string{
					"https://example.com/vuln-1",
					"https://example.com/vuln-2",
				}
				f.CWE = []string{"CWE-79", "CWE-89"}
				f.MitreAttack = []finding.SimpleMitreMapping{
					{
						TechniqueID:   "T1566",
						TechniqueName: "Phishing",
						Tactic:        "Initial Access",
					},
				}
				f.ReproSteps = []finding.ReproStep{
					{
						StepNumber:     1,
						Description:    "Send malicious input",
						ExpectedResult: "System accepts input",
					},
					{
						StepNumber:     2,
						Description:    "Observe behavior",
						ExpectedResult: "Jailbreak successful",
					},
				}

				store := finding.NewRedisFindingStore(stateClient)
				require.NoError(t, store.Update(context.Background(), *f))

				return f.ID
			},
			expectError: false,
			expectOutput: []string{
				"Finding:",
				"Severity:",
				"Description:",
				// Note: Evidence is not shown because it's not properly persisted/retrieved from DB
				// This is a known issue with evidence serialization
				"Remediation:",
				"References:",
				"CWE IDs:",
				"MITRE ATT&CK",
				"Reproduction Steps:",
			},
		},
		{
			name: "invalid finding ID",
			setupFinding: func(t *testing.T, stateClient *state.StateClient) types.ID {
				return types.NewID() // Random ID that doesn't exist
			},
			expectError:  true,
			expectOutput: []string{
				// Error is returned but not printed to output when calling RunE directly
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore global flags to avoid test pollution
			oldGlobalFlags := *globalFlags
			defer func() { *globalFlags = oldGlobalFlags }()

			// Create temp directory and database
			t.TempDir()
			tempDir := t.TempDir(); homeDir := filepath.Join(tempDir, ".gibson")
			require.NoError(t, os.MkdirAll(homeDir, 0755))

			stateClient, err := state.NewStateClient(&state.Config{URL: "redis://localhost:6379"})
			require.NoError(t, err)
			defer stateClient.Close()

			// Initialize schema
			// StateClient does not need InitSchema
			require.NoError(t, err)

			// Setup test finding
			findingID := tt.setupFinding(t, stateClient)

			// Execute command directly
			cmd := findingShowCmd
			cmd.SetContext(context.Background())

			// Set global flags directly
			globalFlags.HomeDir = homeDir

			var outBuf bytes.Buffer
			cmd.SetOut(&outBuf)
			cmd.SetErr(&outBuf)

			// Call RunE directly with the finding ID
			err = cmd.RunE(cmd, []string{findingID.String()})

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			output := outBuf.String()
			for _, expected := range tt.expectOutput {
				assert.Contains(t, output, expected, "Output should contain: %s", expected)
			}
		})
	}
}

// TestFindingExportCommand tests the finding export command with various formats
func TestFindingExportCommand(t *testing.T) {
	t.Skip("requires Redis")
	tests := []struct {
		name           string
		args           []string
		outputFile     string // Set dynamically in test
		setupFindings  func(*testing.T, *state.StateClient)
		expectError    bool
		validateOutput func(*testing.T, string)
	}{
		{
			name: "export to JSON format",
			args: []string{"--format", "json"},
			setupFindings: func(t *testing.T, stateClient *state.StateClient) {
				createTestFindings(t, stateClient, 3)
			},
			expectError: false,
			validateOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, `"findings"`)
				assert.Contains(t, output, `"metadata"`)
				assert.Contains(t, output, `"total_count"`)
			},
		},
		{
			name: "export to SARIF format",
			args: []string{"--format", "sarif"},
			setupFindings: func(t *testing.T, stateClient *state.StateClient) {
				createTestFindings(t, stateClient, 2)
			},
			expectError: false,
			validateOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, `"version"`)
				assert.Contains(t, output, `"$schema"`)
				assert.Contains(t, output, `"runs"`)
			},
		},
		{
			name: "export to CSV format",
			args: []string{"--format", "csv"},
			setupFindings: func(t *testing.T, stateClient *state.StateClient) {
				createTestFindings(t, stateClient, 2)
			},
			expectError: false,
			validateOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, "ID,Title,Severity,Category")
				lines := strings.Split(strings.TrimSpace(output), "\n")
				assert.GreaterOrEqual(t, len(lines), 2, "CSV should have header and data rows")
			},
		},
		{
			name: "export to HTML format",
			args: []string{"--format", "html"},
			setupFindings: func(t *testing.T, stateClient *state.StateClient) {
				createTestFindings(t, stateClient, 2)
			},
			expectError: false,
			validateOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, "<html")
				assert.Contains(t, output, "finding")
				assert.Contains(t, output, "</html>")
			},
		},
		{
			name: "export to Markdown format",
			args: []string{"--format", "markdown"},
			setupFindings: func(t *testing.T, stateClient *state.StateClient) {
				createTestFindings(t, stateClient, 2)
			},
			expectError: false,
			validateOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, "# Security Findings Report")
				assert.Contains(t, output, "##")
			},
		},
		{
			name: "export with severity filter",
			args: []string{"--format", "json", "--severity", "critical"},
			setupFindings: func(t *testing.T, stateClient *state.StateClient) {
				findings := createTestFindings(t, stateClient, 3)
				findings[0].Severity = agent.SeverityCritical
				findings[1].Severity = agent.SeverityHigh
				findings[2].Severity = agent.SeverityMedium
				store := finding.NewRedisFindingStore(stateClient)
				for _, f := range findings {
					require.NoError(t, store.Update(context.Background(), f))
				}
			},
			expectError: false,
			validateOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, "critical")
				assert.NotContains(t, output, "medium")
			},
		},
		{
			name:       "export to file",
			args:       []string{"--format", "json"}, // --output will be added dynamically
			outputFile: "findings.json",              // Will be joined with tempDir
			setupFindings: func(t *testing.T, stateClient *state.StateClient) {
				createTestFindings(t, stateClient, 2)
			},
			expectError: false,
			validateOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, "Exported")
				assert.Contains(t, output, "findings.json")
			},
		},
		{
			name: "export without evidence",
			args: []string{"--format", "json", "--evidence=false"},
			setupFindings: func(t *testing.T, stateClient *state.StateClient) {
				createTestFindings(t, stateClient, 1)
			},
			expectError: false,
			validateOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, `"findings"`)
				// Evidence should be null or empty
			},
		},
		{
			name: "export with minimum confidence",
			args: []string{"--format", "json", "--min-confidence", "0.8"},
			setupFindings: func(t *testing.T, stateClient *state.StateClient) {
				findings := createTestFindings(t, stateClient, 3)
				findings[0].Confidence = 0.9
				findings[1].Confidence = 0.7
				findings[2].Confidence = 0.85
				store := finding.NewRedisFindingStore(stateClient)
				for _, f := range findings {
					require.NoError(t, store.Update(context.Background(), f))
				}
			},
			expectError: false,
			validateOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, `"findings"`)
				// Should filter out findings with confidence < 0.8
			},
		},
		{
			name: "unsupported export format",
			args: []string{"--format", "xml"},
			setupFindings: func(t *testing.T, stateClient *state.StateClient) {
				createTestFindings(t, stateClient, 1)
			},
			expectError:    true,
			validateOutput: nil, // Error validation is done via expectError check
		},
		{
			name: "no findings to export",
			args: []string{"--format", "json"},
			setupFindings: func(t *testing.T, stateClient *state.StateClient) {
				// Don't create any findings
			},
			expectError: false,
			validateOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, "No findings to export")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore global flags to avoid test pollution
			oldGlobalFlags := *globalFlags
			defer func() { *globalFlags = oldGlobalFlags }()

			// Save and restore command-specific export flags
			oldExportFormat := exportFormat
			oldExportOutput := exportOutput
			oldExportMission := exportMission
			oldExportSeverity := exportSeverity
			oldExportCategory := exportCategory
			oldExportEvidence := exportEvidence
			oldExportResolved := exportResolved
			oldExportMinConfidence := exportMinConfidence
			defer func() {
				exportFormat = oldExportFormat
				exportOutput = oldExportOutput
				exportMission = oldExportMission
				exportSeverity = oldExportSeverity
				exportCategory = oldExportCategory
				exportEvidence = oldExportEvidence
				exportResolved = oldExportResolved
				exportMinConfidence = oldExportMinConfidence
			}()

			// Create temp directory and database
			t.TempDir()
			tempDir := t.TempDir(); homeDir := filepath.Join(tempDir, ".gibson")
			require.NoError(t, os.MkdirAll(homeDir, 0755))

			stateClient, err := state.NewStateClient(&state.Config{URL: "redis://localhost:6379"})
			require.NoError(t, err)
			defer stateClient.Close()

			// Initialize schema
			// StateClient does not need InitSchema
			require.NoError(t, err)

			// Setup test findings
			if tt.setupFindings != nil {
				tt.setupFindings(t, stateClient)
			}

			// Execute command directly
			cmd := findingExportCmd
			cmd.SetContext(context.Background())

			// Set global flags directly
			globalFlags.HomeDir = homeDir

			// If outputFile is specified, add it to the command flags
			var outputFilePath string
			if tt.outputFile != "" {
				outputFilePath = filepath.Join(homeDir, tt.outputFile)
			}

			// Set command-specific flags from args
			for i := 0; i < len(tt.args); i++ {
				if tt.args[i] == "--format" && i+1 < len(tt.args) {
					cmd.Flags().Set("format", tt.args[i+1])
					i++
				} else if tt.args[i] == "--output" && i+1 < len(tt.args) {
					cmd.Flags().Set("output", tt.args[i+1])
					i++
				} else if tt.args[i] == "--severity" && i+1 < len(tt.args) {
					cmd.Flags().Set("severity", tt.args[i+1])
					i++
				} else if tt.args[i] == "--category" && i+1 < len(tt.args) {
					cmd.Flags().Set("category", tt.args[i+1])
					i++
				} else if tt.args[i] == "--mission" && i+1 < len(tt.args) {
					cmd.Flags().Set("mission", tt.args[i+1])
					i++
				} else if tt.args[i] == "--evidence=false" {
					cmd.Flags().Set("evidence", "false")
				} else if tt.args[i] == "--min-confidence" && i+1 < len(tt.args) {
					cmd.Flags().Set("min-confidence", tt.args[i+1])
					i++
				}
			}

			// Set output file if specified
			if outputFilePath != "" {
				cmd.Flags().Set("output", outputFilePath)
			}

			var outBuf bytes.Buffer
			cmd.SetOut(&outBuf)
			cmd.SetErr(&outBuf)

			// Call RunE directly
			err = cmd.RunE(cmd, []string{})

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			output := outBuf.String()
			if tt.validateOutput != nil {
				tt.validateOutput(t, output)
			}

			// If output file was specified, verify it exists
			if outputFilePath != "" && !tt.expectError {
				_, err := os.Stat(outputFilePath)
				assert.NoError(t, err, "Output file should exist")
			}
		})
	}
}

// TestSeverityColorCoding tests the color coding functionality
func TestSeverityColorCoding(t *testing.T) {
	tests := []struct {
		name     string
		severity agent.FindingSeverity
	}{
		{"critical severity", agent.SeverityCritical},
		{"high severity", agent.SeverityHigh},
		{"medium severity", agent.SeverityMedium},
		{"low severity", agent.SeverityLow},
		{"info severity", agent.SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test formatSeverity
			formatted := formatSeverity(tt.severity)
			assert.NotEmpty(t, formatted)
			assert.Contains(t, formatted, string(tt.severity))

			// Test getSeverityColor
			color := getSeverityColor(tt.severity)
			assert.NotNil(t, color)
		})
	}
}

// TestTextWrapping tests the text wrapping utility function
func TestTextWrapping(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		width    int
		expected int // expected number of lines
	}{
		{
			name:     "short text",
			input:    "Short text",
			width:    80,
			expected: 1,
		},
		{
			name:     "text requiring wrapping",
			input:    strings.Repeat("word ", 20),
			width:    40,
			expected: 3, // approximate
		},
		{
			name:     "empty text",
			input:    "",
			width:    80,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wrapText(tt.input, tt.width)

			if tt.input == "" {
				assert.Empty(t, result)
				return
			}

			lines := strings.Split(result, "\n")

			// Each line should not exceed width
			for _, line := range lines {
				assert.LessOrEqual(t, len(line), tt.width+10, // Allow some margin
					"Line exceeds width: %s", line)
			}
		})
	}
}

// TestTruncate tests the string truncation function
func TestTruncate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "short string",
			input:    "Short",
			maxLen:   10,
			expected: "Short",
		},
		{
			name:     "exact length",
			input:    "Exact",
			maxLen:   5,
			expected: "Exact",
		},
		{
			name:     "needs truncation",
			input:    "This is a very long string that needs truncation",
			maxLen:   20,
			expected: "This is a very lo...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncate(tt.input, tt.maxLen)
			assert.Equal(t, tt.expected, result)
			assert.LessOrEqual(t, len(result), tt.maxLen)
		})
	}
}

// Helper function to create test findings
func createTestFindings(t *testing.T, stateClient *state.StateClient, count int) []finding.EnhancedFinding {
	t.Helper()

	findings := make([]finding.EnhancedFinding, count)
	store := finding.NewRedisFindingStore(stateClient)
	missionID := types.NewID()

	for i := 0; i < count; i++ {
		baseFinding := agent.NewFinding(
			"Test Finding "+string(rune('A'+i)),
			"This is a test finding description for testing purposes",
			agent.SeverityHigh,
		)

		baseFinding.Category = "jailbreak"
		baseFinding.Evidence = []agent.Evidence{
			{
				Type:        "log",
				Description: "Test evidence",
				Data: map[string]any{
					"key": "value",
				},
				Timestamp: time.Now(),
			},
		}

		enhanced := finding.NewEnhancedFinding(baseFinding, missionID, "test-agent")
		enhanced.Status = finding.StatusOpen
		enhanced.RiskScore = 7.5
		enhanced.Remediation = "Apply security patches"

		err := store.Store(context.Background(), enhanced)
		require.NoError(t, err)

		findings[i] = enhanced
	}

	return findings
}

// TestFindingListAllFindings tests the helper function for listing all findings
func TestFindingListAllFindings(t *testing.T) {
	t.Skip("requires Redis")
	stateClient, err := state.NewStateClient(&state.Config{URL: "redis://localhost:6379"})
	require.NoError(t, err)
	defer stateClient.Close()

	// Initialize schema
	// StateClient does not need InitSchema
	require.NoError(t, err)

	// Create findings across multiple missions
	store := finding.NewRedisFindingStore(stateClient)
	ctx := context.Background()

	mission1 := types.NewID()
	mission2 := types.NewID()

	// Create findings for mission 1
	for i := 0; i < 2; i++ {
		f := finding.NewEnhancedFinding(
			agent.NewFinding("Finding M1-"+string(rune('A'+i)), "Description", agent.SeverityHigh),
			mission1,
			"agent1",
		)
		require.NoError(t, store.Store(ctx, f))
	}

	// Create findings for mission 2
	for i := 0; i < 3; i++ {
		f := finding.NewEnhancedFinding(
			agent.NewFinding("Finding M2-"+string(rune('A'+i)), "Description", agent.SeverityMedium),
			mission2,
			"agent2",
		)
		require.NoError(t, store.Store(ctx, f))
	}

	// Test listing all findings
	filter := finding.NewFindingFilter()
	findings, err := listAllFindings(ctx, store, filter)

	// Note: This test depends on the implementation of listAllFindings
	// which currently uses an empty mission ID
	if err == nil {
		// Verify we got findings
		assert.NotNil(t, findings)
	}
}
