// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// minLiveIdempotentRequests is the floor of request messages that carry an
// idempotency_key in the binary. The SDK release v0.195.0 added the field to
// its create, run, start and submit requests (sdk#207). A count under the
// floor means the registry scan looked at almost nothing.
const minLiveIdempotentRequests = 8

// idempotentRequestTypes returns each registered gibson request message with
// a string field idempotency_key, sorted by full name.
func idempotentRequestTypes() []protoreflect.MessageType {
	var out []protoreflect.MessageType
	protoregistry.GlobalTypes.RangeMessages(func(mt protoreflect.MessageType) bool {
		d := mt.Descriptor()
		if !strings.HasPrefix(string(d.FullName()), "gibson.") {
			return true
		}
		f := d.Fields().ByName(idempotencyFieldName)
		if f != nil && f.Kind() == protoreflect.StringKind && f.Cardinality() != protoreflect.Repeated {
			out = append(out, mt)
		}
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Descriptor().FullName() < out[j].Descriptor().FullName() })
	return out
}

// withKey returns a new message of type mt with idempotency_key set to key.
func withKey(mt protoreflect.MessageType, key string) proto.Message {
	m := mt.New()
	m.Set(m.Descriptor().Fields().ByName(idempotencyFieldName), protoreflect.ValueOfString(key))
	return m.Interface()
}

// The interceptor is live for each request of the binary that carries an
// idempotency_key (gibson#694): it reads the key of each one. The daemon
// package imports the SDK services it serves, so their requests are in the
// registry.
func TestIdempotency_EachKeyedRequestIsLive(t *testing.T) {
	types := idempotentRequestTypes()
	require.GreaterOrEqual(t, len(types), minLiveIdempotentRequests,
		"the registry holds %d keyed requests; the scan looked at almost nothing", len(types))
	for _, mt := range types {
		name := string(mt.Descriptor().FullName())
		if got := extractIdempotencyKey(withKey(mt, "k-"+name)); got != "k-"+name {
			t.Errorf("%s: the interceptor read %q, want the key that was set", name, got)
		}
	}
}

// liveRedisClient returns a client on the real Redis of the coverage lane.
// That lane sets GIBSON_TEST_REQUIRE_REDIS, so an unreachable Redis fails
// there. Elsewhere an absent Redis skips.
func liveRedisClient(t *testing.T) *goredis.Client {
	t.Helper()
	required := os.Getenv("GIBSON_TEST_REQUIRE_REDIS") != ""
	url := "redis://localhost:6379/14"
	if u := os.Getenv("GIBSON_TEST_REDIS_URL"); u != "" {
		url = u
	}
	opts, err := goredis.ParseURL(url)
	require.NoError(t, err)
	c := goredis.NewClient(opts)
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		if required {
			t.Fatalf("GIBSON_TEST_REQUIRE_REDIS is set, but Redis at %s is unreachable: %v", url, err)
		}
		t.Skipf("Redis not available at %s: %v", url, err)
	}
	return c
}

// With a real Redis, a second call with the same key returns the first
// result, and the work runs one time. A call with no key runs each time.
func TestIdempotency_RealRedis_SecondCallReturnsTheFirstResult(t *testing.T) {
	store := NewRedisIdempotencyStore(liveRedisClient(t), newTestLogger())
	intr := idempotencyUnaryInterceptor(store, time.Minute, newTestLogger())
	types := idempotentRequestTypes()
	require.NotEmpty(t, types)
	mt := types[0]
	method := "/" + string(mt.Descriptor().FullName()) + "/live-test"

	var calls atomic.Int32
	handler := func(context.Context, any) (any, error) {
		return wrapperspb.String("result-" + string(rune('0'+calls.Add(1)))), nil
	}
	ctx := ctxWithTenant(t)
	key := "live-" + time.Now().UTC().Format("20060102T150405.000000000")

	first, err := intr(ctx, withKey(mt, key), info(method), handler)
	require.NoError(t, err)
	second, err := intr(ctx, withKey(mt, key), info(method), handler)
	require.NoError(t, err)
	assert.Equal(t, int32(1), calls.Load(), "the work must run one time for one key")
	assert.True(t, proto.Equal(first.(proto.Message), second.(proto.Message)),
		"the second call returned %v, want the first result %v", second, first)

	_, err = intr(ctx, withKey(mt, ""), info(method), handler)
	require.NoError(t, err)
	_, err = intr(ctx, withKey(mt, ""), info(method), handler)
	require.NoError(t, err)
	assert.Equal(t, int32(3), calls.Load(), "a call with no key runs each time")
}
