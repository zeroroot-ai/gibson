// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"os"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/language/pkg/go/transformer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The mission gate (gibson#1389) is a relation of type mission with the
// condition mission_active. This test compiles model.fga in-process, with no
// Docker, and checks the two pieces.
func TestModel_MissionActiveGate(t *testing.T) {
	data, err := os.ReadFile("model.fga")
	require.NoError(t, err)
	model, err := transformer.TransformDSLToProto(string(data))
	require.NoError(t, err, "model.fga must parse")

	cond, ok := model.GetConditions()[ConditionMissionActive]
	require.True(t, ok, "model.fga must define the condition %s", ConditionMissionActive)
	p, found := cond.GetParameters()[ConditionParamActive]
	require.True(t, found, "the condition must declare the parameter %s", ConditionParamActive)
	assert.Equal(t, openfgav1.ConditionParamTypeRef_TYPE_NAME_BOOL, p.GetTypeName())

	var missionType *openfgav1.TypeDefinition
	for _, td := range model.GetTypeDefinitions() {
		if td.GetType() == "mission" {
			missionType = td
		}
	}
	require.NotNil(t, missionType, "model.fga must define type mission")
	meta := missionType.GetMetadata().GetRelations()[RelationMissionActive]
	require.NotNil(t, meta, "type mission must define the relation %s", RelationMissionActive)
	types := meta.GetDirectlyRelatedUserTypes()
	require.Len(t, types, 1)
	assert.Equal(t, "tenant", types[0].GetType())
	assert.Equal(t, ConditionMissionActive, types[0].GetCondition(),
		"the relation must be restricted to the condition, so a plain tuple cannot open the gate")
}

func TestMissionActiveTuple(t *testing.T) {
	got := MissionActiveTuple("acme", "m-1", true)
	assert.Equal(t, "tenant:acme", got.User)
	assert.Equal(t, "active", got.Relation)
	assert.Equal(t, "mission:m-1", got.Object)
	assert.Equal(t, "mission_active", got.ConditionName)
	assert.Equal(t, map[string]any{"active": true}, got.ConditionContext)
	assert.Equal(t, false, MissionActiveTuple("acme", "m-1", false).ConditionContext["active"])
}
