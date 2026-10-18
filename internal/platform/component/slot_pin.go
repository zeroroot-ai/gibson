// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// slot_pin.go carries the LLM slot pins of a mission node to the completion
// RPCs of the ComponentService (gibson#1203).
//
// A mission AGENT node can pin a provider and a model for each LLM slot
// (AgentNodeConfig.llm_slots). The harness that dispatches the node puts the
// pins on the agent work item (WorkItem.SlotPins). WorkQueue.Enqueue binds them
// to the work id, the same way it binds the owner and the run, so the pins
// always come from the daemon and never from a component's request. An agent
// served with sdk.ServeAgent calls Complete with the work id, and the
// completion resolves its slot with the pin of the node that dispatched the
// work.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/sdk/auth"
)

// workSlotsKeyPrefix is the Redis key prefix for the work-item → slot pins
// binding.
//
//	gibson:work:slots:{work_id}
const workSlotsKeyPrefix = "gibson:work:slots:"

func workSlotsKey(workID string) string { return workSlotsKeyPrefix + workID }

// bindWorkSlotPins records the slot pins of the work item. A work item with no
// pins writes nothing.
func bindWorkSlotPins(ctx context.Context, client redis.UniversalClient, item WorkItem) error {
	if len(item.SlotPins) == 0 {
		return nil
	}
	raw, err := json.Marshal(item.SlotPins)
	if err != nil {
		return fmt.Errorf("work-context registry: encode the slot pins of work %q: %w", item.WorkID, err)
	}
	if err := client.Set(ctx, workSlotsKey(item.WorkID), raw, workOwnerTTL).Err(); err != nil {
		return fmt.Errorf("work-context registry: bind slot pins of work %q: %w", item.WorkID, err)
	}
	return nil
}

// lookupWorkSlotPin returns the pin bound to workID for slot, or nil when the
// work item has no pins or no pin for that slot.
func lookupWorkSlotPin(ctx context.Context, client redis.UniversalClient, workID, slot string) (*agent.SlotConfig, error) {
	if workID == "" || slot == "" {
		return nil, nil
	}
	raw, err := client.Get(ctx, workSlotsKey(workID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("work-context registry: look up slot pins of work %q: %w", workID, err)
	}
	var pins map[string]agent.SlotConfig
	if err := json.Unmarshal([]byte(raw), &pins); err != nil {
		return nil, fmt.Errorf("work-context registry: parse the slot pins of work %q: %w", workID, err)
	}
	pin, ok := pins[slot]
	if !ok {
		return nil, nil
	}
	return &pin, nil
}

// WorkSlotPin reads the slot pin (see WorkContextRegistry.WorkSlotPin).
func (r *RedisWorkContextRegistry) WorkSlotPin(ctx context.Context, workID, slot string) (*agent.SlotConfig, error) {
	return lookupWorkSlotPin(ctx, r.stateClient.Client(), workID, slot)
}

// slotPinKey is the context key of the slot pin that the completion RPCs hand
// to the LLM adapter.
type slotPinKey struct{}

// withSlotPin returns ctx carrying pin. A nil pin returns ctx unchanged.
func withSlotPin(ctx context.Context, pin *agent.SlotConfig) context.Context {
	if pin == nil {
		return ctx
	}
	return context.WithValue(ctx, slotPinKey{}, pin)
}

// slotPinFrom returns the slot pin in ctx, or nil.
func slotPinFrom(ctx context.Context) *agent.SlotConfig {
	pin, _ := ctx.Value(slotPinKey{}).(*agent.SlotConfig)
	return pin
}

// nodeSlotPin returns the pin of slot for the work item workID.
//
// The pin applies only when the caller is the tenant that owns the work item.
// A pin names a provider of the owning tenant's set, and a completion
// resolves its slot in the caller's set, so a shared (_system) component that
// serves the work of a tenant gets no pin: its completion keeps the _system
// default, as before. A work id with no owner on record, or of another tenant,
// also gives no pin. A failed read is logged, and the slot keeps the default.
// A server with no work-context registry cannot tell whether a pin exists, so
// a completion with a work id is refused, as SubmitResult refuses it.
func (s *ComponentServiceServer) nodeSlotPin(ctx context.Context, tenant, workID, slot string) (*agent.SlotConfig, error) {
	if workID == "" {
		return nil, nil
	}
	if s.workContext == nil {
		s.logger.ErrorContext(ctx, "llm: work-context registry not wired; refusing a completion with a work id",
			slog.String("tenant", tenant), slog.String("work_id", workID))
		return nil, status.Error(codes.FailedPrecondition, "work-context registry is not configured")
	}
	owner, err := s.workContext.WorkOwner(ctx, workID)
	if err != nil {
		if !errors.Is(err, ErrWorkOwnerUnknown) {
			s.logger.WarnContext(ctx, "llm: the owner of the work item could not be read; the slot pin is not applied",
				slog.String("tenant", tenant), slog.String("work_id", workID), slog.String("slot", slot),
				slog.String("error", err.Error()))
		}
		return nil, nil
	}
	if owner != tenant {
		if tenant == auth.SystemTenantString {
			// A shared component resolves in the _system provider set, so a
			// pin of the owning tenant cannot apply. Say so when one exists.
			if pin, perr := s.workContext.WorkSlotPin(ctx, workID, slot); perr == nil && pin != nil {
				s.logger.DebugContext(ctx, "llm: a shared component ignores the slot pin of the tenant's node on Complete",
					slog.String("owner", owner), slog.String("work_id", workID), slog.String("slot", slot))
			}
		}
		return nil, nil
	}
	pin, err := s.workContext.WorkSlotPin(ctx, workID, slot)
	if err != nil {
		s.logger.WarnContext(ctx, "llm: the slot pin of the work item could not be read; the slot pin is not applied",
			slog.String("tenant", tenant), slog.String("work_id", workID), slog.String("slot", slot),
			slog.String("error", err.Error()))
		return nil, nil
	}
	return pin, nil
}
