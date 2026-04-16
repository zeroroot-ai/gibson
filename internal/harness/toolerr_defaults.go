// Tool-specific recovery hints registered with the SDK's toolerr registry
// at gibson startup.
//
// Per spec decouple-sdk-from-tool-protos, the SDK no longer ships any
// tool-specific recovery defaults — only generic wildcard ("*") fallbacks.
// Gibson registers the per-tool hints here so the orchestrator's
// error-recovery loop continues to surface meaningful alternatives for
// the security tools it commonly orchestrates.
//
// To add a new tool's hints: write a `registerXyzHints()` function below
// and call it from init().

package harness

import "github.com/zero-day-ai/sdk/toolerr"

func init() {
	registerNmapHints()
	registerMasscanHints()
	registerNucleiHints()
	registerHttpxHints()
	registerSubfinderHints()
	registerAmassHints()
}

func registerNmapHints() {
	// Binary not found - suggest alternative port scanners
	toolerr.Register("nmap", toolerr.ErrCodeBinaryNotFound,
		toolerr.RecoveryHint{
			Strategy:    toolerr.StrategyUseAlternative,
			Alternative: "masscan",
			Reason:      "masscan provides similar port scanning capabilities with faster performance",
			Confidence:  0.8,
			Priority:    1,
		},
	)

	// Timeout - suggest parameter adjustments
	toolerr.Register("nmap", toolerr.ErrCodeTimeout,
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyModifyParams,
			Params:     map[string]any{"timing": 2, "scan_type": "connect"},
			Reason:     "slower timing template (T2) and TCP connect scan reduce timeout risk on congested networks",
			Confidence: 0.7,
			Priority:   1,
		},
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyModifyParams,
			Params:     map[string]any{"ports": "22,80,443,8080"},
			Reason:     "scanning only common ports significantly reduces scan time and timeout likelihood",
			Confidence: 0.65,
			Priority:   2,
		},
		toolerr.RecoveryHint{
			Strategy:    toolerr.StrategyUseAlternative,
			Alternative: "masscan",
			Reason:      "masscan is faster and less likely to timeout on large target ranges",
			Confidence:  0.6,
			Priority:    3,
		},
	)

	// Permission denied - suggest non-privileged scan types
	toolerr.Register("nmap", toolerr.ErrCodePermissionDenied,
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyModifyParams,
			Params:     map[string]any{"scan_type": "connect"},
			Reason:     "TCP connect scan (-sT) does not require root/administrator privileges",
			Confidence: 0.9,
			Priority:   1,
		},
	)

	// Network error - suggest retry with backoff
	toolerr.Register("nmap", toolerr.ErrCodeNetworkError,
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyRetryWithBackoff,
			Reason:     "network errors are often transient and resolve after a brief delay",
			Confidence: 0.7,
			Priority:   1,
		},
	)
}
func registerMasscanHints() {
	// Binary not found - suggest nmap as alternative
	toolerr.Register("masscan", toolerr.ErrCodeBinaryNotFound,
		toolerr.RecoveryHint{
			Strategy:    toolerr.StrategyUseAlternative,
			Alternative: "nmap",
			Reason:      "nmap provides similar port scanning functionality with more features",
			Confidence:  0.8,
			Priority:    1,
		},
	)

	// Timeout - suggest rate limiting and alternative
	toolerr.Register("masscan", toolerr.ErrCodeTimeout,
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyModifyParams,
			Params:     map[string]any{"rate": 100},
			Reason:     "reducing scan rate to 100 packets/sec prevents network congestion and timeouts",
			Confidence: 0.75,
			Priority:   1,
		},
		toolerr.RecoveryHint{
			Strategy:    toolerr.StrategyUseAlternative,
			Alternative: "nmap",
			Reason:      "nmap has better timeout handling and adaptive timing for challenging networks",
			Confidence:  0.6,
			Priority:    2,
		},
	)

	// Permission denied - masscan requires root
	toolerr.Register("masscan", toolerr.ErrCodePermissionDenied,
		toolerr.RecoveryHint{
			Strategy:    toolerr.StrategyUseAlternative,
			Alternative: "nmap",
			Reason:      "nmap can operate without privileges using TCP connect scan mode",
			Confidence:  0.85,
			Priority:    1,
		},
	)

	// Network error - suggest retry with backoff
	toolerr.Register("masscan", toolerr.ErrCodeNetworkError,
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyRetryWithBackoff,
			Reason:     "network errors are often transient and resolve after a brief delay",
			Confidence: 0.7,
			Priority:   1,
		},
	)
}
func registerNucleiHints() {
	// Binary not found - suggest alternatives
	toolerr.Register("nuclei", toolerr.ErrCodeBinaryNotFound,
		toolerr.RecoveryHint{
			Strategy:    toolerr.StrategyUseAlternative,
			Alternative: "nmap",
			Reason:      "nmap scripts (NSE) can detect some vulnerabilities, though less comprehensive than nuclei",
			Confidence:  0.5,
			Priority:    1,
		},
	)

	// Timeout - suggest rate limiting
	toolerr.Register("nuclei", toolerr.ErrCodeTimeout,
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyModifyParams,
			Params:     map[string]any{"rate_limit": 50},
			Reason:     "reducing rate limit to 50 requests/second prevents overwhelming target and reduces timeouts",
			Confidence: 0.75,
			Priority:   1,
		},
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyModifyParams,
			Params:     map[string]any{"severity": []string{"critical", "high"}},
			Reason:     "limiting to high-severity templates reduces scan time and timeout risk",
			Confidence: 0.65,
			Priority:   2,
		},
	)

	// Network error - suggest retry with backoff
	toolerr.Register("nuclei", toolerr.ErrCodeNetworkError,
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyRetryWithBackoff,
			Reason:     "network errors are often transient and resolve after a brief delay",
			Confidence: 0.7,
			Priority:   1,
		},
	)

	// Dependency missing - nuclei templates may need updating
	toolerr.Register("nuclei", toolerr.ErrCodeDependencyMissing,
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategySkip,
			Reason:     "nuclei templates may need to be downloaded or updated separately",
			Confidence: 0.6,
			Priority:   1,
		},
	)
}
func registerHttpxHints() {
	// Binary not found - suggest alternatives
	toolerr.Register("httpx", toolerr.ErrCodeBinaryNotFound,
		toolerr.RecoveryHint{
			Strategy:    toolerr.StrategyUseAlternative,
			Alternative: "nmap",
			Reason:      "nmap can probe HTTP services though with less detail than httpx",
			Confidence:  0.6,
			Priority:    1,
		},
	)

	// Timeout - suggest parameter adjustments
	toolerr.Register("httpx", toolerr.ErrCodeTimeout,
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyModifyParams,
			Params:     map[string]any{"timeout": "10s"},
			Reason:     "increasing timeout to 10 seconds allows slow-responding servers to reply",
			Confidence: 0.7,
			Priority:   1,
		},
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyModifyParams,
			Params:     map[string]any{"follow_redirects": false},
			Reason:     "disabling redirect following reduces complexity and timeout risk",
			Confidence: 0.6,
			Priority:   2,
		},
	)

	// Network error - suggest retry with backoff
	toolerr.Register("httpx", toolerr.ErrCodeNetworkError,
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyRetryWithBackoff,
			Reason:     "network errors are often transient and resolve after a brief delay",
			Confidence: 0.7,
			Priority:   1,
		},
	)
}
func registerSubfinderHints() {
	// Binary not found - suggest amass as alternative
	toolerr.Register("subfinder", toolerr.ErrCodeBinaryNotFound,
		toolerr.RecoveryHint{
			Strategy:    toolerr.StrategyUseAlternative,
			Alternative: "amass",
			Reason:      "amass provides comprehensive subdomain enumeration with additional features",
			Confidence:  0.85,
			Priority:    1,
		},
	)

	// Timeout - suggest limiting sources
	toolerr.Register("subfinder", toolerr.ErrCodeTimeout,
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyModifyParams,
			Params:     map[string]any{"all": false},
			Reason:     "disabling all sources and using only fast sources reduces timeout risk",
			Confidence: 0.7,
			Priority:   1,
		},
		toolerr.RecoveryHint{
			Strategy:    toolerr.StrategyUseAlternative,
			Alternative: "amass",
			Reason:      "amass passive mode may complete faster on timeout-prone targets",
			Confidence:  0.6,
			Priority:    2,
		},
	)

	// Network error - suggest retry with backoff
	toolerr.Register("subfinder", toolerr.ErrCodeNetworkError,
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyRetryWithBackoff,
			Reason:     "network errors are often transient and resolve after a brief delay",
			Confidence: 0.7,
			Priority:   1,
		},
	)
}
func registerAmassHints() {
	// Binary not found - suggest subfinder as alternative
	toolerr.Register("amass", toolerr.ErrCodeBinaryNotFound,
		toolerr.RecoveryHint{
			Strategy:    toolerr.StrategyUseAlternative,
			Alternative: "subfinder",
			Reason:      "subfinder provides fast passive subdomain enumeration",
			Confidence:  0.8,
			Priority:    1,
		},
	)

	// Timeout - suggest passive mode
	toolerr.Register("amass", toolerr.ErrCodeTimeout,
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyModifyParams,
			Params:     map[string]any{"mode": "passive"},
			Reason:     "passive enumeration mode is faster and less likely to timeout",
			Confidence: 0.75,
			Priority:   1,
		},
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyModifyParams,
			Params:     map[string]any{"max_depth": 1},
			Reason:     "limiting DNS recursion depth significantly reduces scan time",
			Confidence: 0.7,
			Priority:   2,
		},
		toolerr.RecoveryHint{
			Strategy:    toolerr.StrategyUseAlternative,
			Alternative: "subfinder",
			Reason:      "subfinder is generally faster for basic subdomain enumeration",
			Confidence:  0.65,
			Priority:    3,
		},
	)

	// Network error - suggest retry with backoff
	toolerr.Register("amass", toolerr.ErrCodeNetworkError,
		toolerr.RecoveryHint{
			Strategy:   toolerr.StrategyRetryWithBackoff,
			Reason:     "network errors are often transient and resolve after a brief delay",
			Confidence: 0.7,
			Priority:   1,
		},
	)
}
