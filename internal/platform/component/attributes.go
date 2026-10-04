// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// Component attribute keys for observability.
// Following Gibson's "gibson.component.*" convention for consistency.
const (
	// AttrComponentKind is the type of component (agent, tool, plugin)
	AttrComponentKind = "gibson.component.kind"

	// AttrComponentName is the name of the component
	AttrComponentName = "gibson.component.name"

	// AttrComponentVersion is the version of the component
	AttrComponentVersion = "gibson.component.version"

	// AttrComponentSource is where the component originates from
	AttrComponentSource = "gibson.component.source"

	// AttrComponentStatus is the current runtime status of the component
	AttrComponentStatus = "gibson.component.status"

	// AttrComponentPort is the network port for the component
	AttrComponentPort = "gibson.component.port"

	// AttrComponentPID is the process ID for running components
	AttrComponentPID = "gibson.component.pid"

	// AttrRepoURL is the repository URL for external components
	AttrRepoURL = "gibson.component.repo_url"

	// AttrBuildCommand is the build command used
	AttrBuildCommand = "gibson.component.build_command"

	// AttrBuildDuration is the build duration in milliseconds
	AttrBuildDuration = "gibson.component.build_duration_ms"
)

// Span name constants for component operations.
// Following Gibson's "gibson.component.*" convention.
const (
	// SpanComponentInstall represents a component installation operation
	SpanComponentInstall = "gibson.component.install"

	// SpanComponentBuild represents a component build operation
	SpanComponentBuild = "gibson.component.build"

	// SpanComponentStart represents a component start operation
	SpanComponentStart = "gibson.component.start"

	// SpanComponentStop represents a component stop operation
	SpanComponentStop = "gibson.component.stop"

	// SpanComponentHealth represents a health check operation
	SpanComponentHealth = "gibson.component.health"

	// SpanComponentUninstall represents a component uninstall operation
	SpanComponentUninstall = "gibson.component.uninstall"

	// SpanComponentUpdate represents a component update operation
	SpanComponentUpdate = "gibson.component.update"
)
