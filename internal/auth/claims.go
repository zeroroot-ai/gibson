package auth

import (
	"fmt"
	"strings"
)

// ClaimsMapper extracts and normalizes claims from different OIDC providers.
//
// Handles provider-specific claim formats:
//   - Standard OIDC: groups, email, name
//   - GitHub Actions: repository, ref, workflow
//   - GitLab CI: project_path, ref, pipeline_source
//   - Google: hd (hosted domain)
//   - Azure AD: groups, roles
type ClaimsMapper struct {
	// No state needed - stateless claim extraction
}

// NewClaimsMapper creates a new claims mapper.
func NewClaimsMapper() *ClaimsMapper {
	return &ClaimsMapper{}
}

// ExtractClaims extracts and normalizes claims from a token's claim map.
//
// Applies provider-specific claim extraction logic based on issuer.
// Returns normalized claims suitable for role binding evaluation.
func (m *ClaimsMapper) ExtractClaims(claims map[string]any, issuer string) map[string]any {
	normalized := make(map[string]any)

	// Copy all claims as-is first
	for k, v := range claims {
		normalized[k] = v
	}

	// Apply provider-specific normalization
	switch {
	case strings.Contains(issuer, "token.actions.githubusercontent.com"):
		m.normalizeGitHubActions(claims, normalized)
	case strings.Contains(issuer, "gitlab.com"):
		m.normalizeGitLabCI(claims, normalized)
	case strings.Contains(issuer, "accounts.google.com"):
		m.normalizeGoogle(claims, normalized)
	case strings.Contains(issuer, "login.microsoftonline.com"):
		m.normalizeAzureAD(claims, normalized)
	default:
		// Standard OIDC - already copied
	}

	return normalized
}

// normalizeGitHubActions normalizes GitHub Actions OIDC token claims.
//
// GitHub Actions tokens include:
//   - repository: "org/repo"
//   - ref: "refs/heads/main" or "refs/tags/v1.0.0"
//   - workflow: "CI Pipeline"
//   - actor: GitHub username
//   - repository_owner: Organization or user
func (m *ClaimsMapper) normalizeGitHubActions(claims, normalized map[string]any) {
	// Extract repository (e.g., "myorg/infra")
	if repo, ok := claims["repository"].(string); ok {
		normalized["repo"] = repo
		normalized["repository"] = repo

		// Split into owner/name for convenience
		parts := strings.Split(repo, "/")
		if len(parts) == 2 {
			normalized["repo_owner"] = parts[0]
			normalized["repo_name"] = parts[1]
		}
	}

	// Extract ref (e.g., "refs/heads/main")
	if ref, ok := claims["ref"].(string); ok {
		normalized["ref"] = ref
		normalized["branch"] = ref // Alias for ref

		// Extract just the branch/tag name
		if strings.HasPrefix(ref, "refs/heads/") {
			normalized["branch_name"] = strings.TrimPrefix(ref, "refs/heads/")
		} else if strings.HasPrefix(ref, "refs/tags/") {
			normalized["tag_name"] = strings.TrimPrefix(ref, "refs/tags/")
		}
	}

	// Extract workflow name
	if workflow, ok := claims["workflow"].(string); ok {
		normalized["workflow"] = workflow
	}

	// Extract actor (username)
	if actor, ok := claims["actor"].(string); ok {
		normalized["actor"] = actor
		normalized["username"] = actor // Alias
	}

	// Extract repository owner
	if owner, ok := claims["repository_owner"].(string); ok {
		normalized["repository_owner"] = owner
	}
}

// normalizeGitLabCI normalizes GitLab CI OIDC token claims.
//
// GitLab CI tokens include:
//   - project_path: "group/subgroup/project"
//   - ref: "main" or "feature-branch"
//   - ref_type: "branch" or "tag"
//   - pipeline_source: "push", "merge_request_event", "schedule"
//   - user_login: GitLab username
func (m *ClaimsMapper) normalizeGitLabCI(claims, normalized map[string]any) {
	// Extract project path (e.g., "myorg/security-pipelines")
	if projectPath, ok := claims["project_path"].(string); ok {
		normalized["project"] = projectPath
		normalized["project_path"] = projectPath

		// Split into group/project for convenience
		parts := strings.Split(projectPath, "/")
		if len(parts) >= 2 {
			normalized["group"] = parts[0]
			normalized["project_name"] = parts[len(parts)-1]
		}
	}

	// Extract ref (branch or tag name)
	if ref, ok := claims["ref"].(string); ok {
		normalized["ref"] = ref
		normalized["branch"] = ref // Alias
	}

	// Extract ref type
	if refType, ok := claims["ref_type"].(string); ok {
		normalized["ref_type"] = refType
	}

	// Extract pipeline source
	if pipelineSource, ok := claims["pipeline_source"].(string); ok {
		normalized["pipeline_source"] = pipelineSource
	}

	// Extract user login
	if userLogin, ok := claims["user_login"].(string); ok {
		normalized["username"] = userLogin
	}
}

// normalizeGoogle normalizes Google Workspace OIDC token claims.
//
// Google tokens include:
//   - hd: Hosted domain (e.g., "company.com")
//   - email: User email
//   - email_verified: Boolean
func (m *ClaimsMapper) normalizeGoogle(claims, normalized map[string]any) {
	// Extract hosted domain
	if hd, ok := claims["hd"].(string); ok {
		normalized["domain"] = hd
		normalized["hosted_domain"] = hd
	}

	// Ensure email_verified is boolean
	if emailVerified, ok := claims["email_verified"].(bool); ok {
		normalized["email_verified"] = emailVerified
	}
}

// normalizeAzureAD normalizes Azure AD OIDC token claims.
//
// Azure AD tokens include:
//   - groups: Array of group object IDs or names
//   - roles: Array of application roles
//   - preferred_username: UPN or email
func (m *ClaimsMapper) normalizeAzureAD(claims, normalized map[string]any) {
	// Azure AD groups can be object IDs or names depending on configuration
	if groups, ok := claims["groups"]; ok {
		normalized["groups"] = groups
	}

	// Azure AD application roles
	if roles, ok := claims["roles"]; ok {
		normalized["roles"] = roles
	}

	// Preferred username (UPN format)
	if preferredUsername, ok := claims["preferred_username"].(string); ok {
		normalized["username"] = preferredUsername
	}
}

// ExtractGroups extracts group claims from normalized claims.
//
// Handles both string arrays and single string values.
// Returns empty slice if no groups found.
func (m *ClaimsMapper) ExtractGroups(claims map[string]any) []string {
	groupsClaim, ok := claims["groups"]
	if !ok {
		return []string{}
	}

	switch g := groupsClaim.(type) {
	case []interface{}:
		groups := make([]string, 0, len(g))
		for _, group := range g {
			if groupStr, ok := group.(string); ok {
				groups = append(groups, groupStr)
			}
		}
		return groups
	case []string:
		return g
	case string:
		// Single group as string
		return []string{g}
	default:
		return []string{}
	}
}

// ExtractRepoRef extracts repository reference for CI/CD tokens.
//
// Returns formatted string like "org/repo:refs/heads/main" for role binding.
// Returns empty string if not a CI/CD token or missing required claims.
func (m *ClaimsMapper) ExtractRepoRef(claims map[string]any, issuer string) string {
	switch {
	case strings.Contains(issuer, "token.actions.githubusercontent.com"):
		repo, _ := claims["repository"].(string)
		ref, _ := claims["ref"].(string)
		if repo != "" && ref != "" {
			return fmt.Sprintf("%s:%s", repo, ref)
		}
	case strings.Contains(issuer, "gitlab.com"):
		project, _ := claims["project_path"].(string)
		ref, _ := claims["ref"].(string)
		if project != "" && ref != "" {
			return fmt.Sprintf("%s:%s", project, ref)
		}
	}

	return ""
}
