package auth

// roleCapabilities maps well-known Gibson roles to their granted capabilities.
//
// The special wildcard entry "*" grants unrestricted access to all resources.
// Capabilities follow the "resource:action" convention used by ParseCapability.
var roleCapabilities = map[string][]string{
	"owner": {"*"},
	"admin": {"*"},
	"operator": {
		"missions:execute",
		"missions:read",
		"findings:read",
		"findings:write",
		"findings:export",
		"graphrag:read",
		"graphrag:write",
		"components:register",
		"components:manage",
		"memory:read",
		"memory:write",
		"llm:complete",
		"tools:execute",
		"agents:delegate",
	},
	"viewer": {
		"missions:read",
		"findings:read",
		"graphrag:read",
		"memory:read",
	},
	"agent": {
		"missions:execute",
		"findings:write",
		"graphrag:read",
		"graphrag:write",
		"components:register",
		"memory:read",
		"memory:write",
		"llm:complete",
		"tools:execute",
		"agents:delegate",
	},
	"tool": {
		"components:register",
		"graphrag:write",
	},
	"tool-executor": {
		"components:register",
		"tools:execute",
		"graphrag:write",
	},
	"agent-executor": {
		"components:register",
		"agents:delegate",
		"tools:execute",
		"llm:complete",
		"memory:read",
		"memory:write",
		"graphrag:read",
		"graphrag:write",
		"findings:write",
		"missions:execute",
	},
	"plugin-executor": {
		"components:register",
	},
}

// resolveCapabilitiesFromRoles maps role names to their capabilities and deduplicates
// the result. If any role maps to the wildcard ["*"], it returns ["*"] immediately.
func resolveCapabilitiesFromRoles(roles []string) []string {
	seen := make(map[string]bool)
	var caps []string

	for _, role := range roles {
		roleCaps, ok := roleCapabilities[role]
		if !ok {
			continue
		}

		for _, c := range roleCaps {
			if c == "*" {
				// Wildcard supersedes all other capabilities.
				return []string{"*"}
			}
			if !seen[c] {
				seen[c] = true
				caps = append(caps, c)
			}
		}
	}

	return caps
}
