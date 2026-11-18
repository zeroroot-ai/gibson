// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pgstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

func TestQuery_WhereKeepsValuesOutOfTheStatement(t *testing.T) {
	mission := types.NewID()
	clause, args, err := Query{
		MissionID: mission, Severities: []string{"high"}, Category: "x'; DROP TABLE findings; --", Search: "50%_off",
	}.where()

	require.NoError(t, err)
	assert.NotContains(t, clause, "DROP")
	assert.NotContains(t, clause, "50")
	assert.Contains(t, clause, "mission_id = $1")
	assert.Contains(t, clause, "severity = ANY($2::text[])")
	assert.Contains(t, clause, "lower(document->>'category') = lower($3)")
	assert.Contains(t, clause, "title ILIKE $4")
	require.Len(t, args, 4)
	assert.Equal(t, `%50\%\_off%`, args[3], "wildcards in the search are text")
}

func TestQuery_WhereEmptyAndInvalid(t *testing.T) {
	clause, args, err := Query{}.where()
	require.NoError(t, err)
	assert.Empty(t, clause)
	assert.Empty(t, args)

	_, _, err = Query{MissionID: "not-a-uuid"}.where()
	require.Error(t, err)
	_, _, err = Query{IDs: []types.ID{"nope"}}.where()
	require.Error(t, err)
}

func TestQuery_Page(t *testing.T) {
	l, o := Query{}.page()
	assert.Equal(t, 100, l)
	assert.Equal(t, 0, o)
	l, o = Query{Limit: 5000, Offset: -3}.page()
	assert.Equal(t, MaxPageSize, l)
	assert.Equal(t, 0, o)
}
