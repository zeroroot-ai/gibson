package attack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/types"
)

func TestNewOutputHandler(t *testing.T) {
	tests := []struct {
		name         string
		format       string
		expectedType string
	}{
		{
			name:         "text format",
			format:       OutputFormatText,
			expectedType: "*attack.TextOutputHandler",
		},
		{
			name:         "json format",
			format:       OutputFormatJSON,
			expectedType: "*attack.JSONOutputHandler",
		},
		{
			name:         "sarif format",
			format:       OutputFormatSARIF,
			expectedType: "*attack.SARIFOutputHandler",
		},
		{
			name:         "invalid format defaults to text",
			format:       "invalid",
			expectedType: "*attack.TextOutputHandler",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			handler := NewOutputHandler(tt.format, buf, false, false)
			assert.NotNil(t, handler)
			assert.Contains(t, typeOf(handler), tt.expectedType)
		})
	}
}

func TestTextOutputHandler_OnStart(t *testing.T) {
	tests := []struct {
		name             string
		opts             *AttackOptions
		verbose          bool
		quiet            bool
		expectedContains []string
		notExpected      []string
	}{
		{
			name: "normal mode with URL",
			opts: &AttackOptions{
				TargetURL:      "https://api.example.com",
				TargetType:     "llm_api",
				TargetProvider: "openai",
				AgentName:      "prompt-injection",
			},
			verbose: false,
			quiet:   false,
			expectedContains: []string{
				"Gibson Attack",
				"https://api.example.com",
				"llm_api",
				"openai",
				"prompt-injection",
			},
			notExpected: []string{"Configuration:"},
		},
		{
			name: "verbose mode shows configuration",
			opts: &AttackOptions{
				TargetURL:         "https://api.example.com",
				AgentName:         "test-agent",
				MaxTurns:          10,
				Timeout:           5 * time.Minute,
				MaxFindings:       5,
				SeverityThreshold: "high",
				RateLimit:         10,
				PayloadIDs:        []string{"p1", "p2"},
				PayloadCategory:   "injection",
				Techniques:        []string{"T1059"},
			},
			verbose: true,
			quiet:   false,
			expectedContains: []string{
				"Configuration:",
				"Max Turns:",
				"10",
				"Timeout:",
				"5m",
				"Max Findings:",
				"5",
				"Min Severity:",
				"high",
				"Rate Limit:",
				"10 req/s",
				"Payload IDs:",
				"p1, p2",
				"Category:",
				"injection",
				"Techniques:",
				"T1059",
			},
		},
		{
			name: "quiet mode shows nothing",
			opts: &AttackOptions{
				TargetURL: "https://api.example.com",
				AgentName: "test-agent",
			},
			verbose: false,
			quiet:   true,
			notExpected: []string{
				"Gibson Attack",
				"Target:",
			},
		},
		{
			name: "target name instead of URL",
			opts: &AttackOptions{
				TargetName: "saved-target",
				AgentName:  "test-agent",
			},
			verbose: false,
			quiet:   false,
			expectedContains: []string{
				"saved-target",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			handler := NewTextOutputHandler(buf, tt.verbose, tt.quiet)
			handler.OnStart(tt.opts)

			output := buf.String()
			for _, expected := range tt.expectedContains {
				assert.Contains(t, output, expected, "Output should contain: %s", expected)
			}
			for _, notExpected := range tt.notExpected {
				assert.NotContains(t, output, notExpected, "Output should not contain: %s", notExpected)
			}
		})
	}
}

func TestTextOutputHandler_OnProgress(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		verbose  bool
		quiet    bool
		expected bool
	}{
		{
			name:     "verbose mode shows progress",
			message:  "Executing payload 1 of 10",
			verbose:  true,
			quiet:    false,
			expected: true,
		},
		{
			name:     "normal mode hides progress",
			message:  "Executing payload 1 of 10",
			verbose:  false,
			quiet:    false,
			expected: false,
		},
		{
			name:     "quiet mode hides progress",
			message:  "Executing payload 1 of 10",
			verbose:  true,
			quiet:    true,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			handler := NewTextOutputHandler(buf, tt.verbose, tt.quiet)
			handler.OnProgress(tt.message)

			output := buf.String()
			if tt.expected {
				assert.Contains(t, output, tt.message)
			} else {
				assert.Empty(t, output)
			}
		})
	}
}

func TestTextOutputHandler_OnFinding(t *testing.T) {
	baseFinding := agent.Finding{
		ID:          types.NewID(),
		Title:       "SQL Injection Vulnerability",
		Description: "The application is vulnerable to SQL injection through user input parameter 'id'.",
		Severity:    agent.SeverityHigh,
		Confidence:  0.95,
		Category:    "injection",
		Evidence: []agent.Evidence{
			{
				Type:        "request",
				Description: "Malicious SQL payload sent",
				Data: map[string]any{
					"payload": "' OR '1'='1",
				},
			},
		},
		CreatedAt: time.Now(),
	}

	enhancedFinding := finding.EnhancedFinding{
		Finding:     baseFinding,
		MissionID:   types.NewID(),
		AgentName:   "sql-injection-agent",
		Subcategory: "blind_sql_injection",
		RiskScore:   8.5,
		Remediation: "Use parameterized queries to prevent SQL injection",
	}
	// Store MITRE ATT&CK mappings in Metadata
	if enhancedFinding.Metadata == nil {
		enhancedFinding.Metadata = make(map[string]any)
	}
	enhancedFinding.Metadata["mitre_attack"] = []finding.SimpleMitreMapping{
		{
			TechniqueID:   "T1190",
			TechniqueName: "Exploit Public-Facing Application",
			Tactic:        "Initial Access",
		},
	}

	tests := []struct {
		name             string
		finding          finding.EnhancedFinding
		verbose          bool
		quiet            bool
		expectedContains []string
		notExpected      []string
	}{
		{
			name:    "normal mode shows full finding",
			finding: enhancedFinding,
			verbose: false,
			quiet:   false,
			expectedContains: []string{
				"[HIGH]",
				"SQL Injection Vulnerability",
				"The application is vulnerable",
				"Category:",
				"injection",
				"blind_sql_injection",
				"Confidence:",
				"95%",
				"Risk Score:",
				"8.5/10.0",
			},
			notExpected: []string{
				"MITRE ATT&CK:",
				"Remediation:",
			},
		},
		{
			name:    "verbose mode shows MITRE and remediation",
			finding: enhancedFinding,
			verbose: true,
			quiet:   false,
			expectedContains: []string{
				"SQL Injection Vulnerability",
				"MITRE ATT&CK:",
				"T1190",
				"Exploit Public-Facing Application",
				"Initial Access",
				"Evidence:",
				"Malicious SQL payload sent",
				"Remediation:",
				"Use parameterized queries",
			},
		},
		{
			name:    "quiet mode shows minimal output",
			finding: enhancedFinding,
			verbose: false,
			quiet:   true,
			expectedContains: []string{
				"[HIGH]",
				"SQL Injection Vulnerability",
			},
			notExpected: []string{
				"The application is vulnerable",
				"Category:",
				"Confidence:",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			handler := NewTextOutputHandler(buf, tt.verbose, tt.quiet)
			handler.OnFinding(tt.finding)

			output := buf.String()
			for _, expected := range tt.expectedContains {
				assert.Contains(t, output, expected, "Output should contain: %s", expected)
			}
			for _, notExpected := range tt.notExpected {
				assert.NotContains(t, output, notExpected, "Output should not contain: %s", notExpected)
			}
		})
	}
}

func TestTextOutputHandler_OnComplete(t *testing.T) {
	missionID := types.NewID()

	tests := []struct {
		name             string
		result           *AttackResult
		quiet            bool
		expectedContains []string
		notExpected      []string
	}{
		{
			name: "successful attack with findings",
			result: func() *AttackResult {
				r := NewAttackResult()
				r.MissionID = &missionID
				r.Persisted = true
				r.Duration = 2 * time.Minute
				r.TurnsUsed = 5
				r.TokensUsed = 1500
				// Add findings using AddFinding to properly populate both arrays
				for i := 0; i < 1; i++ {
					r.AddFinding(finding.EnhancedFinding{
						Finding: agent.Finding{
							ID:       types.NewID(),
							Severity: agent.SeverityCritical,
						},
					})
				}
				for i := 0; i < 2; i++ {
					r.AddFinding(finding.EnhancedFinding{
						Finding: agent.Finding{
							ID:       types.NewID(),
							Severity: agent.SeverityHigh,
						},
					})
				}
				for i := 0; i < 3; i++ {
					r.AddFinding(finding.EnhancedFinding{
						Finding: agent.Finding{
							ID:       types.NewID(),
							Severity: agent.SeverityMedium,
						},
					})
				}
				return r
			}(),
			quiet: false,
			expectedContains: []string{
				"Attack Complete",
				"Status:",
				"findings",
				"Duration:",
				"2m",
				"Turns Used:",
				"5",
				"Tokens Used:",
				"1500",
				"Findings:",
				"6 total",
				"Critical:",
				"1",
				"High:",
				"2",
				"Medium:",
				"3",
				"Mission ID:",
			},
		},
		{
			name: "successful attack with no findings",
			result: &AttackResult{
				Duration:  1 * time.Minute,
				TurnsUsed: 3,
				Status:    AttackStatusSuccess,
				ExitCode:  0,
			},
			quiet: false,
			expectedContains: []string{
				"Attack Complete",
				"Status:",
				"success",
				"Findings:",
				"None discovered",
				"Results not persisted",
			},
		},
		{
			name: "quiet mode with no findings shows nothing",
			result: &AttackResult{
				Duration:  1 * time.Minute,
				TurnsUsed: 3,
				Status:    AttackStatusSuccess,
				ExitCode:  0,
			},
			quiet:       true,
			notExpected: []string{"Attack Complete"},
		},
		{
			name: "quiet mode with findings shows summary",
			result: func() *AttackResult {
				r := NewAttackResult()
				r.Duration = 1 * time.Minute
				r.TurnsUsed = 3
				// Add findings
				for i := 0; i < 2; i++ {
					r.AddFinding(finding.EnhancedFinding{
						Finding: agent.Finding{
							ID:       types.NewID(),
							Severity: agent.SeverityHigh,
						},
					})
				}
				return r
			}(),
			quiet: true,
			expectedContains: []string{
				"Attack Complete",
				"findings",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			handler := NewTextOutputHandler(buf, false, tt.quiet)
			handler.OnComplete(tt.result)

			output := buf.String()
			for _, expected := range tt.expectedContains {
				assert.Contains(t, output, expected, "Output should contain: %s", expected)
			}
			for _, notExpected := range tt.notExpected {
				assert.NotContains(t, output, notExpected, "Output should not contain: %s", notExpected)
			}
		})
	}
}

func TestTextOutputHandler_OnError(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewTextOutputHandler(buf, false, false)

	err := NewAttackError(ErrExecutionFailed, "Target unreachable")
	handler.OnError(err)

	output := buf.String()
	assert.Contains(t, output, "Error:")
	assert.Contains(t, output, "Target unreachable")
}

func TestJSONOutputHandler_Events(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewJSONOutputHandler(buf)

	// Test OnStart
	opts := &AttackOptions{
		TargetURL: "https://api.example.com",
		AgentName: "test-agent",
		MaxTurns:  10,
		Timeout:   5 * time.Minute,
	}
	handler.OnStart(opts)

	// Verify start event
	var startEvent jsonEvent
	decoder := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	err := decoder.Decode(&startEvent)
	require.NoError(t, err)
	assert.Equal(t, "start", startEvent.Type)

	data, ok := startEvent.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "https://api.example.com", data["target"])
	assert.Equal(t, "test-agent", data["agent"])
	assert.Equal(t, "Test goal", data["goal"])

	// Test OnProgress
	buf.Reset()
	handler.OnProgress("Testing payload 1")

	var progressEvent jsonEvent
	decoder = json.NewDecoder(bytes.NewReader(buf.Bytes()))
	err = decoder.Decode(&progressEvent)
	require.NoError(t, err)
	assert.Equal(t, "progress", progressEvent.Type)

	// Test OnFinding
	buf.Reset()
	baseFinding := agent.Finding{
		ID:          types.NewID(),
		Title:       "Test Finding",
		Description: "Test description",
		Severity:    agent.SeverityHigh,
		Confidence:  0.9,
		CreatedAt:   time.Now(),
	}
	enhancedFinding := finding.EnhancedFinding{
		Finding:   baseFinding,
		MissionID: types.NewID(),
		AgentName: "test-agent",
	}
	handler.OnFinding(enhancedFinding)

	var findingEvent jsonEvent
	decoder = json.NewDecoder(bytes.NewReader(buf.Bytes()))
	err = decoder.Decode(&findingEvent)
	require.NoError(t, err)
	assert.Equal(t, "finding", findingEvent.Type)

	// Test OnComplete
	buf.Reset()
	result := &AttackResult{
		Duration:  2 * time.Minute,
		TurnsUsed: 5,
		Status:    AttackStatusSuccess,
		ExitCode:  0,
	}
	handler.OnComplete(result)

	var completeEvent jsonEvent
	decoder = json.NewDecoder(bytes.NewReader(buf.Bytes()))
	err = decoder.Decode(&completeEvent)
	require.NoError(t, err)
	assert.Equal(t, "complete", completeEvent.Type)

	// Test OnError
	buf.Reset()
	handler.OnError(NewAttackError(ErrExecutionFailed, "Test error"))

	var errorEvent jsonEvent
	decoder = json.NewDecoder(bytes.NewReader(buf.Bytes()))
	err = decoder.Decode(&errorEvent)
	require.NoError(t, err)
	assert.Equal(t, "error", errorEvent.Type)
}

func TestSARIFOutputHandler_GenerateValidSARIF(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewSARIFOutputHandler(buf)

	// Add some findings
	baseFinding1 := agent.Finding{
		ID:          types.NewID(),
		Title:       "SQL Injection",
		Description: "SQL injection vulnerability found",
		Severity:    agent.SeverityHigh,
		Confidence:  0.95,
		Category:    "injection",
		CWE:         []string{"CWE-89"},
		CreatedAt:   time.Now(),
	}
	enhancedFinding1 := finding.EnhancedFinding{
		Finding:     baseFinding1,
		MissionID:   types.NewID(),
		AgentName:   "sql-agent",
		Subcategory: "classic_sql_injection",
		RiskScore:   8.5,
		Remediation: "Use parameterized queries",
	}
	// Store MITRE ATT&CK mappings in Metadata
	if enhancedFinding1.Metadata == nil {
		enhancedFinding1.Metadata = make(map[string]any)
	}
	enhancedFinding1.Metadata["mitre_attack"] = []finding.SimpleMitreMapping{
		{
			TechniqueID:   "T1190",
			TechniqueName: "Exploit Public-Facing Application",
			Tactic:        "Initial Access",
		},
	}

	baseFinding2 := agent.Finding{
		ID:          types.NewID(),
		Title:       "Prompt Injection",
		Description: "System prompt was bypassed",
		Severity:    agent.SeverityCritical,
		Confidence:  0.98,
		Category:    "prompt_injection",
		CreatedAt:   time.Now(),
	}
	enhancedFinding2 := finding.EnhancedFinding{
		Finding:   baseFinding2,
		MissionID: types.NewID(),
		AgentName: "prompt-agent",
		RiskScore: 9.0,
	}

	handler.OnFinding(enhancedFinding1)
	handler.OnFinding(enhancedFinding2)

	// Complete the attack
	result := &AttackResult{
		Duration:  2 * time.Minute,
		TurnsUsed: 5,
		Status:    AttackStatusFindings,
		ExitCode:  0,
	}
	handler.OnComplete(result)

	// Parse SARIF output
	var sarif sarifLog
	err := json.Unmarshal(buf.Bytes(), &sarif)
	require.NoError(t, err)

	// Verify SARIF structure
	assert.Equal(t, "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", sarif.Schema)
	assert.Equal(t, "2.1.0", sarif.Version)
	assert.Len(t, sarif.Runs, 1)

	run := sarif.Runs[0]
	assert.Equal(t, "Gibson Attack", run.Tool.Driver.Name)
	assert.Equal(t, "1.0.0", run.Tool.Driver.Version)
	assert.Equal(t, "https://github.com/zero-day-ai/gibson", run.Tool.Driver.InformationUri)

	// Verify rules
	assert.Len(t, run.Tool.Driver.Rules, 2)
	ruleIDs := make(map[string]bool)
	for _, rule := range run.Tool.Driver.Rules {
		ruleIDs[rule.ID] = true
		assert.NotEmpty(t, rule.Name)
		assert.NotEmpty(t, rule.ShortDescription.Text)
	}
	assert.True(t, ruleIDs["INJECTION/CLASSIC_SQL_INJECTION"] || ruleIDs["INJECTION"])
	assert.True(t, ruleIDs["PROMPT_INJECTION"])

	// Verify results
	assert.Len(t, run.Results, 2)
	for _, result := range run.Results {
		assert.NotEmpty(t, result.RuleID)
		assert.Contains(t, []string{"error", "warning", "note"}, result.Level)
		assert.NotEmpty(t, result.Message.Text)
		assert.NotNil(t, result.Properties)

		// Check properties
		assert.NotNil(t, result.Properties["id"])
		assert.NotNil(t, result.Properties["confidence"])
		assert.NotNil(t, result.Properties["risk_score"])
		assert.NotNil(t, result.Properties["category"])
	}

	// Verify severity mapping
	highResult := findResultBySeverity(run.Results, "error")
	assert.NotNil(t, highResult, "Should have error level result")

	criticalResult := findResultBySeverity(run.Results, "error")
	assert.NotNil(t, criticalResult, "Should have error level result for critical")
}

func TestSARIFOutputHandler_ErrorHandling(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewSARIFOutputHandler(buf)

	err := NewAttackError(ErrExecutionFailed, "Test execution failure")
	handler.OnError(err)

	// Parse SARIF output
	var sarif sarifLog
	parseErr := json.Unmarshal(buf.Bytes(), &sarif)
	require.NoError(t, parseErr)

	// Verify error SARIF structure
	assert.Equal(t, "2.1.0", sarif.Version)
	assert.Len(t, sarif.Runs, 1)

	run := sarif.Runs[0]
	assert.Len(t, run.Invocations, 1)
	assert.False(t, run.Invocations[0].ExecutionSuccessful)
	assert.NotNil(t, run.Invocations[0].ExecutionFailure)
	assert.Contains(t, run.Invocations[0].ExecutionFailure.Message.Text, "Test execution failure")
}

func TestSeverityColorMapping(t *testing.T) {
	tests := []struct {
		severity agent.FindingSeverity
		expected string
	}{
		{agent.SeverityCritical, colorRed},
		{agent.SeverityHigh, colorMagenta},
		{agent.SeverityMedium, colorYellow},
		{agent.SeverityLow, colorBlue},
		{agent.SeverityInfo, colorCyan},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			color := getSeverityColor(tt.severity)
			assert.Equal(t, tt.expected, color)
		})
	}
}

func TestWrapText(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		width    int
		prefix   string
		expected string
	}{
		{
			name:     "empty text",
			text:     "",
			width:    80,
			prefix:   "  ",
			expected: "",
		},
		{
			name:     "short text no wrapping",
			text:     "Hello world",
			width:    80,
			prefix:   "  ",
			expected: "  Hello world",
		},
		{
			name:     "text wraps at width",
			text:     "This is a very long line that should wrap at the specified width",
			width:    30,
			prefix:   "  ",
			expected: "  This is a very long line\n  that should wrap at the\n  specified width",
		},
		{
			name:     "preserves multiple spaces between words",
			text:     "Word1 Word2 Word3",
			width:    80,
			prefix:   "",
			expected: "Word1 Word2 Word3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wrapText(tt.text, tt.width, tt.prefix)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetTargetIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		opts     *AttackOptions
		expected string
	}{
		{
			name: "URL takes precedence",
			opts: &AttackOptions{
				TargetURL:  "https://api.example.com",
				TargetName: "saved-target",
			},
			expected: "https://api.example.com",
		},
		{
			name: "falls back to name",
			opts: &AttackOptions{
				TargetName: "saved-target",
			},
			expected: "saved-target",
		},
		{
			name:     "empty when neither set",
			opts:     &AttackOptions{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getTargetIdentifier(tt.opts)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper functions

func typeOf(v interface{}) string {
	return fmt.Sprintf("%T", v)
}

func findResultBySeverity(results []sarifResult, level string) *sarifResult {
	for _, r := range results {
		if r.Level == level {
			return &r
		}
	}
	return nil
}
