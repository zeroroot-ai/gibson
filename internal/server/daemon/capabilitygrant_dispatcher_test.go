// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// TestDispatch_WaitsOnTheWorkIdTheComponentEchoesBack proves the
// capability-grant dispatch round-trip closes on the id the component
// actually claims and delivers a result for. Enqueue returns the Redis
// stream message id, so waiting on the caller's zero-value WorkItem.WorkID
// (a by-value copy that Enqueue never populates) could never be satisfied
// by a component replying with the work id it was handed. See gibson#1249.
func TestDispatch_WaitsOnTheWorkIdTheComponentEchoesBack(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	queue := component.NewRedisWorkQueue(client)
	dispatcher := newWorkQueueDispatcher(queue)

	const tenant, kind, name, consumerID = "tenant-a", "tool", "nmap", "inst-tool"

	// Stand in for the component: claim the work item and answer with the
	// work id it was handed, exactly as a polling component does.
	delivered := make(chan error, 1)
	go func() {
		ctx := context.Background()
		for range 100 {
			item, claimErr := queue.Claim(ctx, tenant, kind, name, consumerID, 100*time.Millisecond)
			if claimErr != nil {
				delivered <- claimErr
				return
			}
			if item == nil {
				continue
			}
			delivered <- queue.DeliverResult(ctx, item.WorkID, component.WorkResult{
				WorkID: item.WorkID,
				Result: []byte(`{"ports":[80]}`),
			})
			return
		}
		delivered <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := dispatcher.Dispatch(ctx, tenant, kind, name, []byte(`{"target":"10.0.0.1"}`))

	require.NoError(t, <-delivered, "the stand-in component must deliver its result")
	require.NoError(t, err, "Dispatch must observe the result the component delivered")
	require.Equal(t, `{"ports":[80]}`, string(result))
}
