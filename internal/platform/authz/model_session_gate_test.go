// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package authz contains the gibson FGA authorization model and client.
package authz

// TestModel_ActiveSessionGate exercises the token_not_revoked condition and
// active_session relation introduced in gibson#627 Slice 1.
//
// This test runs WITHOUT Docker/testcontainers (no integration build tag) —
// it uses the openfga-language transformer to compile model.fga in-process
// and asserts:
//   - The token_not_revoked condition is present in the compiled model with
//     the two required timestamp parameters: token_issued_at and revoked_at.
//   - The active_session relation is present on the tenant type.
//   - The active_session relation references the token_not_revoked condition
//     (i.e. [user with token_not_revoked]).
//
// Live Check semantics (token_issued_at > revoked_at evaluates correctly in
// CEL) are covered by the FGA integration smoke test (//go:build integration)
// which loads model.fga into an OpenFGA testcontainer. See the integration
// test plan in gibson#627 Slice 2.
//
// Spec: instant-session-revocation (gibson#627).
import (
	"os"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/language/pkg/go/transformer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModel_ActiveSessionGate(t *testing.T) {
	// Read and compile the authoritative model.fga.
	data, err := os.ReadFile("model.fga")
	require.NoError(t, err, "read model.fga")

	model, err := transformer.TransformDSLToProto(string(data))
	require.NoError(t, err, "transformer.TransformDSLToProto: model.fga must parse without errors")

	// ---- Condition assertions -----------------------------------------------

	t.Run("condition_token_not_revoked_exists", func(t *testing.T) {
		cond, ok := model.GetConditions()["token_not_revoked"]
		require.True(t, ok, "model.fga must define condition 'token_not_revoked'")
		require.NotNil(t, cond, "condition must be non-nil")

		// Verify the CEL expression is non-empty and references the expected
		// comparison (the exact expression text is an implementation detail,
		// but must contain the > operator and the parameter names).
		expr := cond.GetExpression()
		assert.NotEmpty(t, expr, "token_not_revoked condition must have a non-empty CEL expression")
		assert.Contains(t, expr, "token_issued_at",
			"condition expression must reference token_issued_at parameter")
		assert.Contains(t, expr, "revoked_at",
			"condition expression must reference revoked_at parameter")
	})

	t.Run("condition_token_not_revoked_has_timestamp_params", func(t *testing.T) {
		cond, ok := model.GetConditions()["token_not_revoked"]
		require.True(t, ok, "token_not_revoked condition must exist")

		params := cond.GetParameters()
		require.NotNil(t, params, "condition must declare parameters")

		assertTimestampParam := func(name string) {
			t.Helper()
			p, found := params[name]
			require.Truef(t, found, "condition must declare parameter %q", name)
			require.NotNilf(t, p, "parameter %q must be non-nil", name)
			// TYPE_NAME_TIMESTAMP is the openfga-language representation for the
			// OpenFGA 1.1 CEL timestamp type.
			require.Equalf(t,
				openfgav1.ConditionParamTypeRef_TYPE_NAME_TIMESTAMP,
				p.GetTypeName(),
				"parameter %q must have type TIMESTAMP", name,
			)
		}

		assertTimestampParam("token_issued_at")
		assertTimestampParam("revoked_at")
	})

	// ---- Relation assertions on tenant type ----------------------------------

	t.Run("tenant_type_has_active_session_relation", func(t *testing.T) {
		tenantDef := findTypeDef(model, "tenant")
		require.NotNil(t, tenantDef, "tenant type must be defined in model.fga")

		relations := tenantDef.GetRelations()
		require.NotNil(t, relations, "tenant type must have relations")

		_, ok := relations["active_session"]
		assert.True(t, ok, "tenant type must define relation 'active_session'")
	})

	t.Run("active_session_references_token_not_revoked_condition", func(t *testing.T) {
		tenantDef := findTypeDef(model, "tenant")
		require.NotNil(t, tenantDef, "tenant type must be defined")

		meta := tenantDef.GetMetadata()
		require.NotNil(t, meta, "tenant type must have metadata (needed for condition reference)")

		relMeta, ok := meta.GetRelations()["active_session"]
		require.True(t, ok, "tenant metadata must include active_session relation")
		require.NotNil(t, relMeta, "active_session metadata must be non-nil")

		directTypes := relMeta.GetDirectlyRelatedUserTypes()
		require.NotEmpty(t, directTypes,
			"active_session must declare directly related user types")

		// Find the user+condition entry. The relation is defined as
		//   define active_session: [user with token_not_revoked]
		// so exactly one entry should have Type="user" and Condition="token_not_revoked".
		found := false
		for _, ref := range directTypes {
			if ref.GetType() == "user" && ref.GetCondition() == "token_not_revoked" {
				found = true
				break
			}
		}
		assert.True(t, found,
			"active_session must be grantable to 'user with token_not_revoked'; "+
				"got directly related user types: %v", directTypes)
	})

	// ---- Zero-blast-radius: existing role hierarchy unaffected ---------------

	t.Run("active_session_not_in_role_hierarchy", func(t *testing.T) {
		tenantDef := findTypeDef(model, "tenant")
		require.NotNil(t, tenantDef)

		relations := tenantDef.GetRelations()

		// active_session must NOT appear as a computed component of member,
		// writer, admin, or owner. A simple check: the userset for each
		// hierarchy relation must not reference active_session via any
		// union/intersection/difference/computed_userset path.
		hierarchyRelations := []string{"owner", "admin", "writer", "member"}
		for _, relName := range hierarchyRelations {
			us, ok := relations[relName]
			if !ok {
				continue
			}
			assert.False(t, usersetReferencesRelation(us, "active_session"),
				"relation %q must NOT reference active_session (would break zero-blast-radius guarantee)",
				relName)
		}

		// Likewise, active_session itself must NOT reference any of the hierarchy
		// relations as a computed union — it is a direct-grant-only relation.
		activeSessionUS, ok := relations["active_session"]
		require.True(t, ok, "active_session relation must exist")
		for _, relName := range hierarchyRelations {
			assert.False(t, usersetReferencesRelation(activeSessionUS, relName),
				"active_session must NOT reference hierarchy relation %q", relName)
		}
	})
}

// TestModel_UserScopedActiveSessionGate pins the USER-SCOPED active_session
// relation added in gibson#1244. It gates tenant-less requests (the sign-in
// bootstrap window) that have no `type tenant` object to check, keyed on the
// caller's own user object under the same token_not_revoked condition.
func TestModel_UserScopedActiveSessionGate(t *testing.T) {
	data, err := os.ReadFile("model.fga")
	require.NoError(t, err, "read model.fga")

	model, err := transformer.TransformDSLToProto(string(data))
	require.NoError(t, err, "transformer.TransformDSLToProto: model.fga must parse without errors")

	t.Run("user_type_has_active_session_relation", func(t *testing.T) {
		userDef := findTypeDef(model, "user")
		require.NotNil(t, userDef, "user type must be defined in model.fga")

		relations := userDef.GetRelations()
		require.NotNil(t, relations, "user type must have relations")

		_, ok := relations["active_session"]
		assert.True(t, ok, "user type must define relation 'active_session' (gibson#1244)")
	})

	t.Run("user_active_session_references_token_not_revoked_condition", func(t *testing.T) {
		userDef := findTypeDef(model, "user")
		require.NotNil(t, userDef, "user type must be defined")

		meta := userDef.GetMetadata()
		require.NotNil(t, meta, "user type must have metadata (needed for condition reference)")

		relMeta, ok := meta.GetRelations()["active_session"]
		require.True(t, ok, "user metadata must include active_session relation")
		require.NotNil(t, relMeta, "active_session metadata must be non-nil")

		directTypes := relMeta.GetDirectlyRelatedUserTypes()
		require.NotEmpty(t, directTypes, "user.active_session must declare directly related user types")

		// The relation is defined as: define active_session: [user with token_not_revoked]
		found := false
		for _, ref := range directTypes {
			if ref.GetType() == "user" && ref.GetCondition() == "token_not_revoked" {
				found = true
				break
			}
		}
		assert.True(t, found,
			"user.active_session must be grantable to 'user with token_not_revoked'; "+
				"got directly related user types: %v", directTypes)
	})
}

// findTypeDef returns the TypeDefinition for the given type name, or nil.
func findTypeDef(model *openfgav1.AuthorizationModel, typeName string) *openfgav1.TypeDefinition {
	for _, td := range model.GetTypeDefinitions() {
		if td.GetType() == typeName {
			return td
		}
	}
	return nil
}

// usersetReferencesRelation reports whether any node in the Userset tree
// names the given relation via ComputedUserset or TupleToUserset.
// This is a shallow structural check — sufficient for the zero-blast-radius
// assertion that active_session is not wired into the role hierarchy.
func usersetReferencesRelation(us *openfgav1.Userset, rel string) bool {
	if us == nil {
		return false
	}
	if cu := us.GetComputedUserset(); cu != nil {
		if cu.GetRelation() == rel {
			return true
		}
	}
	if ttu := us.GetTupleToUserset(); ttu != nil {
		if ttu.GetTupleset().GetRelation() == rel ||
			ttu.GetComputedUserset().GetRelation() == rel {
			return true
		}
	}
	if union := us.GetUnion(); union != nil {
		for _, child := range union.GetChild() {
			if usersetReferencesRelation(child, rel) {
				return true
			}
		}
	}
	if intersection := us.GetIntersection(); intersection != nil {
		for _, child := range intersection.GetChild() {
			if usersetReferencesRelation(child, rel) {
				return true
			}
		}
	}
	if diff := us.GetDifference(); diff != nil {
		if usersetReferencesRelation(diff.GetBase(), rel) ||
			usersetReferencesRelation(diff.GetSubtract(), rel) {
			return true
		}
	}
	return false
}
