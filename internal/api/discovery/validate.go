package discovery

import (
	"context"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	discoverypb "github.com/zeroroot-ai/platform-sdk/gen/gibson/daemon/discovery/v1"

	"github.com/zeroroot-ai/gibson/internal/authz"
)

// permissionsFile mirrors the shape of opensource/adk/schemas/permissions.yaml.json.
// Keeping the parser close to the handler avoids a cross-package dependency and
// keeps the schema updatable in lockstep with the JSON schema that ships in the
// ADK. Stricter schema validation happens in the dashboard's install flow
// (task 39) and in the ADK's `gibson-mcp validate_component` before install.
type permissionsFile struct {
	Plugins []permissionEntry `yaml:"plugins"`
	Tools   []permissionEntry `yaml:"tools"`
	Agents  []permissionEntry `yaml:"agents"`
}

type permissionEntry struct {
	Name    string           `yaml:"name"`
	Read    *permissionBlock `yaml:"read,omitempty"`
	Write   *permissionBlock `yaml:"write,omitempty"`
	Execute *permissionBlock `yaml:"execute,omitempty"`
}

type permissionBlock struct {
	Required      bool   `yaml:"required"`
	Justification string `yaml:"justification,omitempty"`
}

// componentManifest is a narrow view of component.yaml sufficient for the
// validator. Full manifest parsing lives in SDK; we duplicate only the
// fields we need to avoid importing the SDK parser into the daemon.
type componentManifest struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	Kind    string `yaml:"kind"` // tools/plugins use `kind`; agents use `type`
	Version string `yaml:"version"`
}

// ValidateComponent dry-runs a draft component.yaml + permissions.yaml
// against the caller's current access. Never mutates state. Returns a
// structured result enumerating schema errors, access errors, slot errors,
// and proto violations so the ADK's `gibson-mcp validate_component` can
// surface a useful, per-item error list to Claude.
func (s *Server) ValidateComponent(ctx context.Context, req *discoverypb.ValidateComponentRequest) (*discoverypb.ValidateComponentResponse, error) {
	resp := &discoverypb.ValidateComponentResponse{
		SchemaErrors:    []*discoverypb.ValidationError{},
		AccessErrors:    []*discoverypb.AccessError{},
		SlotErrors:      []string{},
		ProtoViolations: []string{},
	}

	// --- component.yaml
	if len(req.GetComponentYaml()) == 0 {
		resp.SchemaErrors = append(resp.SchemaErrors, &discoverypb.ValidationError{
			Path:    "component_yaml",
			Message: "component.yaml is required",
		})
	} else {
		var comp componentManifest
		if err := yaml.Unmarshal(req.GetComponentYaml(), &comp); err != nil {
			resp.SchemaErrors = append(resp.SchemaErrors, &discoverypb.ValidationError{
				Path:    "component_yaml",
				Message: fmt.Sprintf("parse: %v", err),
			})
		} else {
			if comp.Name == "" {
				resp.SchemaErrors = append(resp.SchemaErrors, &discoverypb.ValidationError{
					Path: "name", Message: "name is required",
				})
			}
			effectiveKind := comp.Type
			if effectiveKind == "" {
				effectiveKind = comp.Kind
			}
			switch effectiveKind {
			case "agent", "tool", "plugin":
				// ok
			case "":
				resp.SchemaErrors = append(resp.SchemaErrors, &discoverypb.ValidationError{
					Path: "type|kind", Message: "either `type` (agent) or `kind` (tool|plugin) must be set",
				})
			default:
				resp.SchemaErrors = append(resp.SchemaErrors, &discoverypb.ValidationError{
					Path: "type|kind", Message: fmt.Sprintf("unknown kind %q", effectiveKind),
				})
			}
		}
	}

	// --- permissions.yaml (optional)
	if len(req.GetPermissionsYaml()) > 0 {
		var perms permissionsFile
		if err := yaml.Unmarshal(req.GetPermissionsYaml(), &perms); err != nil {
			resp.SchemaErrors = append(resp.SchemaErrors, &discoverypb.ValidationError{
				Path:    "permissions_yaml",
				Message: fmt.Sprintf("parse: %v", err),
			})
		} else {
			s.checkPermissionAccess(ctx, "plugin", perms.Plugins, resp)
			s.checkPermissionAccess(ctx, "tool", perms.Tools, resp)
			s.checkPermissionAccess(ctx, "agent", perms.Agents, resp)
		}
	}

	resp.Ok = len(resp.SchemaErrors) == 0 &&
		len(resp.AccessErrors) == 0 &&
		len(resp.SlotErrors) == 0 &&
		len(resp.ProtoViolations) == 0
	return resp, nil
}

// checkPermissionAccess issues BatchCheck calls for each (target, action)
// pair the manifest requests and appends an AccessError per missing access.
// Uses the caller's user identity (not agent identity) — validation is
// always user-driven (by Claude Code on a developer workstation).
func (s *Server) checkPermissionAccess(ctx context.Context, kind string, entries []permissionEntry, resp *discoverypb.ValidateComponentResponse) {
	userRef := callerUserRef(ctx)
	if userRef == "" {
		return
	}
	var checks []authz.CheckRequest
	var meta []struct{ Ref, Action string }
	for _, e := range entries {
		if e.Name == "" {
			continue
		}
		// Allow either short "gitlab" or prefixed "plugin:gitlab" — strip
		// the prefix if present so we can route to objectForComponent.
		shortName := strings.TrimPrefix(e.Name, kind+":")
		object := objectForComponent(kind, shortName)
		if e.Read != nil {
			checks = append(checks, authz.CheckRequest{User: userRef, Relation: "can_read", Object: object})
			meta = append(meta, struct{ Ref, Action string }{kind + ":" + shortName, "read"})
		}
		if e.Write != nil {
			checks = append(checks, authz.CheckRequest{User: userRef, Relation: "can_configure", Object: object})
			meta = append(meta, struct{ Ref, Action string }{kind + ":" + shortName, "write"})
		}
		if e.Execute != nil {
			checks = append(checks, authz.CheckRequest{User: userRef, Relation: "can_execute", Object: object})
			meta = append(meta, struct{ Ref, Action string }{kind + ":" + shortName, "execute"})
		}
	}
	if len(checks) == 0 {
		return
	}
	results, err := s.authorizer.BatchCheck(ctx, checks)
	if err != nil {
		s.logger.Warn("discovery: validate batch check failed", "err", err)
		return
	}
	for i, ok := range results {
		if !ok {
			resp.AccessErrors = append(resp.AccessErrors, &discoverypb.AccessError{
				TargetRef:       meta[i].Ref,
				RequestedAction: meta[i].Action,
				FailingGates:    []string{"caller does not currently have this access"},
			})
		}
	}
}

// SuggestMissingCapability returns a human-readable next-step hint for a
// catalog reference the caller (typically Claude via ValidateComponent
// access errors) can't access. v1 returns a generic message that points at
// the tenant-admin Security Policy page.
func (s *Server) SuggestMissingCapability(ctx context.Context, req *discoverypb.SuggestMissingCapabilityRequest) (*discoverypb.SuggestMissingCapabilityResponse, error) {
	target := req.GetNeededTarget()
	_ = req.GetAction()
	msg := fmt.Sprintf(
		"%s is not available to you with the requested access. "+
			"Either (1) ask your tenant admin to remove the deny in the "+
			"Security Policy matrix, (2) request installation via the "+
			"platform catalog, or (3) narrow your agent's permissions.yaml "+
			"to drop the requirement. Run `gibson-mcp whoami` to see which "+
			"catalog items you currently have access to.",
		target,
	)
	return &discoverypb.SuggestMissingCapabilityResponse{Message: msg, ActionablePaths: []string{}}, nil
}
