// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package missiontest_test

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/mission/missiontest"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

func newClient(t *testing.T) (*redis.Client, *missiontest.Docs) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, missiontest.Attach(rdb)
}

// The fake answers the JSON commands of the mission store from a map, sends the
// rest to the miniredis server, and reports EXISTS for its own documents.
func TestAttach_AnswersTheJSONCommands(t *testing.T) {
	rdb, docs := newClient(t)
	ctx := context.Background()

	require.NoError(t, rdb.Do(ctx, "JSON.SET", "k1", "$", `{"a":1}`).Err())
	assert.True(t, docs.Has("k1"))
	assert.Equal(t, 1, docs.Count())

	got, err := rdb.Do(ctx, "JSON.GET", "k1", "$").Result()
	require.NoError(t, err)
	assert.Equal(t, `[{"a":1}]`, got)

	_, err = rdb.Do(ctx, "JSON.GET", "absent", "$").Result()
	require.ErrorIs(t, err, redis.Nil)

	assert.EqualValues(t, 1, rdb.Exists(ctx, "k1").Val(), "a document is a key that exists")
	assert.EqualValues(t, 0, rdb.Exists(ctx, "absent").Val())

	require.NoError(t, rdb.Do(ctx, "JSON.DEL", "k1", "$").Err())
	assert.False(t, docs.Has("k1"))

	// A command that is not JSON goes to the server.
	require.NoError(t, rdb.Set(ctx, "plain", "v", 0).Err())
	assert.Equal(t, "v", rdb.Get(ctx, "plain").Val())
}

// A pipeline that mixes JSON and plain commands runs both, and a failed JSON.SET
// is the error of the pipeline.
func TestAttach_Pipeline(t *testing.T) {
	rdb, docs := newClient(t)
	ctx := context.Background()

	pipe := rdb.Pipeline()
	pipe.Do(ctx, "JSON.SET", "k2", "$", `{"b":2}`)
	pipe.SAdd(ctx, "set", "m")
	_, err := pipe.Exec(ctx)
	require.NoError(t, err)
	assert.True(t, docs.Has("k2"))
	assert.True(t, rdb.SIsMember(ctx, "set", "m").Val())

	docs.FailSet = true
	pipe = rdb.Pipeline()
	pipe.Do(ctx, "JSON.SET", "k3", "$", `{"c":3}`)
	pipe.SAdd(ctx, "set", "n")
	_, err = pipe.Exec(ctx)
	require.Error(t, err)
	assert.False(t, docs.Has("k3"))

	// A single command fails the same way.
	require.Error(t, rdb.Do(ctx, "JSON.SET", "k4", "$", `{}`).Err())
}

func TestRecorder(t *testing.T) {
	rec := missiontest.NewRecorder()
	ctx := context.Background()
	id := types.NewID()

	require.NoError(t, rec.Record(ctx, "acme", id))
	assert.True(t, rec.Has("acme", id))
	assert.False(t, rec.Has("other", id))

	require.NoError(t, rec.Forget(ctx, "acme", id))
	assert.False(t, rec.Has("acme", id))
	assert.Equal(t, []string{"acme|" + id.String()}, rec.Forgotten)

	rec.Err = errors.New("fga down")
	require.Error(t, rec.Record(ctx, "acme", id))
}
