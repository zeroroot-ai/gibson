package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/component"
)

// defaultDispatchTimeout is the time budget for a single component dispatch
// round-trip (enqueue + wait for result). It can be overridden per call by
// using a context with a shorter deadline.
const defaultDispatchTimeout = 60 * time.Second

// workQueueDispatcher implements capabilitygrant.ComponentDispatcher using the
// Redis Streams work-queue pattern. It enqueues a WorkItem on the component's
// stream and blocks until the result arrives or the context/timeout expires.
type workQueueDispatcher struct {
	queue component.WorkQueue
}

// newWorkQueueDispatcher constructs a workQueueDispatcher backed by queue.
// queue must be non-nil.
func newWorkQueueDispatcher(queue component.WorkQueue) *workQueueDispatcher {
	return &workQueueDispatcher{queue: queue}
}

// Dispatch enqueues the input payload on the stream for the given component
// (identified by tenant, kind, and name) and waits for the result.
//
// The call respects the deadline already on ctx. When ctx has no deadline,
// defaultDispatchTimeout is used as the wait timeout.
func (d *workQueueDispatcher) Dispatch(ctx context.Context, tenant, kind, name string, input []byte) ([]byte, error) {
	if tenant == "" {
		return nil, fmt.Errorf("capabilitygrant dispatcher: tenant cannot be empty")
	}
	if kind == "" {
		return nil, fmt.Errorf("capabilitygrant dispatcher: kind cannot be empty")
	}
	if name == "" {
		return nil, fmt.Errorf("capabilitygrant dispatcher: name cannot be empty")
	}

	item := component.WorkItem{
		WorkType:  "execute",
		Payload:   input,
		TimeoutMs: defaultDispatchTimeout.Milliseconds(),
	}

	_, err := d.queue.Enqueue(ctx, tenant, kind, name, item)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant dispatcher: enqueue work for %s/%s/%s: %w", tenant, kind, name, err)
	}

	// Determine how long we are willing to wait for the result. Honour any
	// deadline already set on ctx; otherwise fall back to defaultDispatchTimeout.
	waitTimeout := defaultDispatchTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 && remaining < waitTimeout {
			waitTimeout = remaining
		}
	}

	result, err := d.queue.WaitForResult(ctx, item.WorkID, waitTimeout)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant dispatcher: wait for result from %s/%s/%s: %w", tenant, kind, name, err)
	}

	if result.Error != nil {
		return nil, fmt.Errorf("capabilitygrant dispatcher: component %s/%s/%s returned error: [%s] %s",
			tenant, kind, name, result.Error.Code, result.Error.Message)
	}

	return result.Result, nil
}
