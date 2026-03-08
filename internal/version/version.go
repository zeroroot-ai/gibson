package version

import "fmt"

// These are set at build time via ldflags
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

// Info returns full version information
func Info() string {
	return fmt.Sprintf("%s (commit: %s, built: %s)", Version, GitCommit, BuildDate)
}

// Short returns the version string only
func Short() string {
	return Version
}
