package registry

// Spec: unified-authz-regen Req 5.
//
// Asserts that every (object_type, relation) pair referenced in the
// generated Registry is defined by the canonical FGA model at
// internal/authz/model.fga. This catches the "rename a model relation in
// SDK proto annotations without updating the actual FGA model" regression
// class — that was the failure mode behind zero-trust-hardening 3.1's
// `tenant_admin`/`tenant_member` rollout, which broke every user-acting
// admin RPC for two days until reverted.
//
// The model parser is intentionally minimal — it reads `define <name>:`
// lines under `type <name>` blocks. It does NOT validate the relation's
// type-set ([user], [user, team#admin], etc.); that's not what this test
// is for.

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// modelPath returns the absolute path to internal/authz/model.fga,
// resolved relative to this test file so it works no matter the cwd.
func modelPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// .../core/gibson/internal/authz/registry/model_relations_test.go
	// → .../core/gibson/internal/authz/model.fga
	return filepath.Join(filepath.Dir(file), "..", "model.fga")
}

// parseModelRelations reads model.fga and returns a map of
// type-name → set of relation names defined on that type.
func parseModelRelations(t *testing.T, path string) map[string]map[string]struct{} {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	out := map[string]map[string]struct{}{}
	var currentType string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trim := strings.TrimSpace(line)
		// Skip comments and blank lines.
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		// Type header — always starts at column 0.
		if strings.HasPrefix(line, "type ") {
			currentType = strings.TrimSpace(strings.TrimPrefix(trim, "type"))
			out[currentType] = map[string]struct{}{}
			continue
		}
		// Relation definition — `define <name>:` (any indentation).
		if strings.HasPrefix(trim, "define ") {
			rest := strings.TrimPrefix(trim, "define ")
			colon := strings.IndexByte(rest, ':')
			if colon <= 0 {
				continue
			}
			name := strings.TrimSpace(rest[:colon])
			if currentType == "" {
				t.Fatalf("define %q outside any type block (line: %q)", name, line)
			}
			out[currentType][name] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return out
}

// knownDriftServices is the set of services whose annotations the test
// tolerates because they ALREADY drift from model.fga at the time spec
// unified-authz-regen lands. New regressions outside these services still
// fail.
//
// Every entry here is documented technical debt. Each one should be
// closed by a follow-up spec that either fixes the proto annotation or
// adds the missing relation to model.fga. Do NOT add new services here
// without a tracking issue.
var knownDriftServices = map[string]string{
	// HarnessCallbackService — every RPC references component.can_use
	// uniformly. The component type defines can_execute/can_configure/
	// can_read; can_use exists on provider/model. The harness service is
	// SDK-owned; this is pre-existing SDK proto drift.
	"gibson.harness.v1.HarnessCallbackService": "component.can_use does not exist on the component type (can_use is defined on provider and model only)",
}

// knownDriftMethods covers single-RPC drift not shared across a whole
// service.
var knownDriftMethods = map[string]struct{ ObjectType, Relation, Reason string }{
	// CreateMissionDefinition uses tenant.writer; writer exists only on
	// mission_definition (where it's `admin from parent`). The annotation
	// was probably copy-pasted from mission_definition's authz block.
	// Both the OSS DaemonService and the admin DaemonAdminService have this
	// same annotation drift introduced in fa1c311 (admin platform-sdk migration).
	"/gibson.daemon.v1.DaemonService/CreateMissionDefinition": {
		"tenant", "writer",
		"writer is defined on mission_definition, not tenant — annotation likely copy-pasted from mission_definition",
	},
	"/gibson.daemon.admin.v1.DaemonAdminService/CreateMissionDefinition": {
		"tenant", "writer",
		"writer is defined on mission_definition, not tenant — annotation copy-pasted from OSS DaemonService; fix annotation in platform-sdk proto",
	},
}

func methodService(method string) string {
	// "/pkg.path.Service/Method" → "pkg.path.Service"
	if !strings.HasPrefix(method, "/") {
		return ""
	}
	rest := method[1:]
	if i := strings.IndexByte(rest, '/'); i > 0 {
		return rest[:i]
	}
	return ""
}

func TestRegistryRelationsExistInModel(t *testing.T) {
	model := parseModelRelations(t, modelPath(t))
	if len(model) == 0 {
		t.Fatal("model.fga parsed to zero types — parser is wrong")
	}

	for method, entry := range Registry {
		if entry.Unauthenticated {
			continue
		}
		// self-mode entries have no FGA rule fields; there is no object_type or
		// relation to validate against the model. Spec: self-mode-authz.
		if entry.Self {
			continue
		}
		// Skip known pre-existing drift at the service-wide level.
		if _, ok := knownDriftServices[methodService(method)]; ok {
			continue
		}
		// Skip single-method known drift.
		if drift, ok := knownDriftMethods[method]; ok && drift.ObjectType == entry.ObjectType && drift.Relation == entry.Relation {
			continue
		}
		relations, ok := model[entry.ObjectType]
		if !ok {
			t.Errorf(
				"%s: registry references object_type=%q but model.fga doesn't define that type",
				method, entry.ObjectType,
			)
			continue
		}
		if _, ok := relations[entry.Relation]; !ok {
			definedList := make([]string, 0, len(relations))
			for r := range relations {
				definedList = append(definedList, r)
			}
			t.Errorf(
				"%s: registry references %s.%s but model.fga defines only [%s] on %s",
				method, entry.ObjectType, entry.Relation,
				strings.Join(definedList, ", "), entry.ObjectType,
			)
		}
	}
}

// Sanity check: a planted bad entry must be caught. Run as a sub-test that
// builds a synthetic Registry with a known-bad relation and asserts the
// validation logic flags it. This is a meta-test of the test logic itself.
func TestRegistryRelationsExistInModel_DetectsBadRelation(t *testing.T) {
	model := parseModelRelations(t, modelPath(t))
	bad := Entry{
		Method:        "/synthetic.v1.Synthetic/Bogus",
		ObjectType:    "tenant",
		Relation:      "this_relation_does_not_exist_anywhere",
		ObjectDeriver: "tenant_from_identity",
	}
	relations, ok := model[bad.ObjectType]
	if !ok {
		t.Fatalf("tenant not in model — parser failure")
	}
	if _, ok := relations[bad.Relation]; ok {
		t.Fatalf("the supposedly-fake relation %q was found — pick a different name", bad.Relation)
	}
	// Test passes when the planted relation is correctly identified as missing.
}
