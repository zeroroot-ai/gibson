// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/finding/pgstore"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/sdk/auth"
	"github.com/zeroroot-ai/sdk/schema"
)

func TestConvertToSDKSchema_EmptyTypeIsNil(t *testing.T) {
	assert.Nil(t, convertToSDKSchema(schema.JSON{}))
}

func TestConvertToSDKSchema_CopiesNestedFields(t *testing.T) {
	minimum, maximum := 1.5, 9.5
	minLen, maxLen := 2, 8
	in := schema.JSON{
		Type: "object", Description: "top", Required: []string{"name"},
		Properties: map[string]schema.JSON{
			"name": {
				Type: "string", Description: "d", Format: "email", Pattern: "^a", MinLength: &minLen, MaxLength: &maxLen,
				Enum: []any{"a", "b"},
			},
			"score": {Type: "number", Minimum: &minimum, Maximum: &maximum},
			"nested": {
				Type:       "object",
				Properties: map[string]schema.JSON{"n": {Type: "integer"}},
				Required:   []string{"n"},
			},
		},
		Items: &schema.JSON{Type: "array", Items: &schema.JSON{Type: "string"}},
	}

	got := convertToSDKSchema(in)

	require.NotNil(t, got)
	assert.Equal(t, "object", got.Type)
	assert.Equal(t, "top", got.Description)
	assert.Equal(t, []string{"name"}, got.Required)
	name := got.Properties["name"]
	assert.Equal(t, "email", name.Format)
	assert.Equal(t, "^a", name.Pattern)
	assert.Equal(t, &minLen, name.MinLength)
	assert.Equal(t, &maxLen, name.MaxLength)
	assert.Equal(t, []any{"a", "b"}, name.Enum)
	assert.Equal(t, &minimum, got.Properties["score"].Minimum)
	assert.Equal(t, &maximum, got.Properties["score"].Maximum)
	nested := got.Properties["nested"]
	require.Contains(t, nested.Properties, "n")
	assert.Equal(t, "integer", nested.Properties["n"].Type)
	assert.Equal(t, []string{"n"}, nested.Required)
	require.NotNil(t, got.Items)
	require.NotNil(t, got.Items.Items)
	assert.Equal(t, "string", got.Items.Items.Type)
}

func TestStructuredSchema_Refusals(t *testing.T) {
	_, _, err := StructuredSchema(nil)
	require.ErrorContains(t, err, "cannot be nil")

	name, _, err := StructuredSchema(struct{ A string }{})
	require.NoError(t, err)
	assert.Equal(t, "AnonymousType", name)

	_, _, err = StructuredSchema(make(chan int))
	require.ErrorContains(t, err, "has no object schema")
}

func TestStrictSchema_ClosesObjectsInsideArraysAndKeepsOtherTypes(t *testing.T) {
	_, raw, err := StructuredSchema([]struct {
		B int    `json:"b"`
		A string `json:"a"`
	}{})
	require.NoError(t, err)

	text := string(raw)
	assert.Contains(t, text, `"required":["a","b"]`, "the required names are sorted")
	assert.Contains(t, text, `"additionalProperties":false`)
	assert.True(t, strings.HasPrefix(text, `{"type":"array"`), "an array stays an array: %s", text)
}

// poolStub is a data pool whose For returns a fixed error.
type poolStub struct {
	datapool.Pool
	err error
}

func (p poolStub) For(context.Context, auth.TenantID) (*datapool.Conn, error) { return nil, p.err }

func TestPostgresFindingStore_ReportsAPoolThatIsNotReady(t *testing.T) {
	s := NewPostgresFindingStore(func() datapool.Pool { return nil })
	mission := types.NewID()

	err := s.Store(context.Background(), "acme", mission, agent.NewFinding("t", "d", agent.SeverityHigh))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store finding")
	assert.Contains(t, err.Error(), "data pool is not ready")

	got, err := s.Get(context.Background(), "acme", mission, FindingFilter{})
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "list findings of mission "+mission.String())
}

func TestPostgresFindingStore_WrapsThePoolError(t *testing.T) {
	boom := errors.New("pool down")
	var pool pgstore.PoolFunc = func() datapool.Pool { return poolStub{err: boom} }
	s := NewPostgresFindingStore(pool)

	err := s.Store(context.Background(), "acme", types.NewID(), agent.NewFinding("t", "d", agent.SeverityLow))
	require.ErrorIs(t, err, boom)

	_, err = s.Get(context.Background(), "acme", types.NewID(), FindingFilter{})
	require.ErrorIs(t, err, boom)
}

func TestEvidenceRejected(t *testing.T) {
	assert.True(t, evidenceRejected(finding.ErrEvidenceTooLarge))
	assert.True(t, evidenceRejected(errors.Join(errors.New("x"), finding.ErrEvidenceTooLarge)))
	assert.False(t, evidenceRejected(errors.New("other")))
	assert.False(t, evidenceRejected(nil))
}
