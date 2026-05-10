package version

import (
	"fmt"
	"runtime"
)

// Version is the semantic version, injected at build time.
var Version = "dev"

// GitCommit is the git commit hash, injected at build time.
var GitCommit = "unknown"

// BuildTime is the timestamp when the binary was built, injected at build time.
var BuildTime = "unknown"

// String returns a formatted version string containing version, commit, and build time.
func String() string {
	return fmt.Sprintf("Gibson %s (commit: %s, built: %s, go: %s)",
		Version, GitCommit, BuildTime, runtime.Version())
}

// Info returns structured version information.
//
// `build_tag_setec_integration` is added per setec-sandbox-prod-default R1.3:
// operators can read this field to confirm whether a running daemon has the
// Setec sandbox adapter linked in. Value is "on" (production-default) or
// "off" (SDK / dev stub).
func Info() map[string]string {
	return map[string]string{
		"version":                     Version,
		"commit":                      GitCommit,
		"buildTime":                   BuildTime,
		"goVersion":                   runtime.Version(),
		"platform":                    fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		"build_tag_setec_integration": BuildTagSetecIntegration,
	}
}
