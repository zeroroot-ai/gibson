// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// slot_pin.go carries the LLM slot pins of a mission node to the completion
// RPCs of the ComponentService (gibson#1203).
//
// A mission AGENT node can pin a provider and a model for each LLM slot
// (AgentNodeConfig.llm_slots). The harness that dispatches the node puts the
// pins on the agent work item (SlotPinsWorkKey). WorkQueue.Enqueue binds them to
// the work id, the same way it binds the owner and the run, so the pins always
// come from the daemon and never from a component's request. An agent served
// with sdk.ServeAgent calls Complete with the work id, and the completion
// resolves its slot with the pin of the node that dispatched the work.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// SlotPinsWorkKey is the work item context key that holds the LLM slot pins of
// the mission node: a JSON object from slot name to agent.SlotConfig.
const SlotPinsWorkKey = "llm_slot_pins"

// workSlotsKeyPrefix is the Redis key prefix for the work-item → slot pins
// binding.
//
//	gibson:work:slots:{work_id}
const workSlotsKeyPrefix = "gibson:work:slots:"

func workSlotsKey(workID string) string { return workSlotsKeyPrefix + workID }

// bindWorkSlotPins records the slot pins of the work item, read from its
// context. A work item with no pins writes nothing. Pins that do not parse are
// an error: the daemon wrote them, so bad pins are a defect and must not pass
// as "no pin".
func bindWorkSlotPins(ctx context.Context, client redis.UniversalClient, item WorkItem) error {
	raw := item.Context[SlotPinsWorkKey]
	if raw == "" {
		return nil
	}
	var pins map[string]agent.SlotConfig
	if err := json.Unmarshal([]byte(raw), &pins); err != nil {
		return fmt.Errorf("work-context registry: parse the slot pins of work %q: %w", item.WorkID, err)
	}
	if len(pins) == 0 {
		return nil
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

// nodeSlotPin returns the pin of slot for the work item workID, when the
// caller's tenant may act on that work item. A work id with no owner on record,
// or owned by another tenant, gives no pin: the slot then resolves to the
// tenant default, as for a call with no work id.
func (s *ComponentServiceServer) nodeSlotPin(ctx context.Context, tenant, workID, slot string) *agent.SlotConfig {
	if workID == "" || s.workContext == nil {
		return nil
	}
	if _, err := s.resolveWorkOwner(ctx, tenant, workID); err != nil {
		return nil
	}
	pin, err := s.workContext.WorkSlotPin(ctx, workID, slot)
	if err != nil {
		s.logger.WarnContext(ctx, "llm: the slot pin of the work item could not be read; using the tenant default",
			slog.String("tenant", tenant),
			slog.String("work_id", workID),
			slog.String("slot", slot),
			slog.String("error", err.Error()),
		)
		return nil
	}
	return pin
}

// slotPinLimits returns the max tokens and the temperature of a pin. Zero means
// the provider default.
func slotPinLimits(pin *agent.SlotConfig) (maxTokens int32, temperature float32) {
	if pin == nil {
		return 0, 0
	}
	if pin.MaxTokens > 0 {
		maxTokens = int32(pin.MaxTokens) //nolint:gosec // a node's max_tokens is a small positive int
	}
	if pin.Temperature > 0 {
		temperature = float32(pin.Temperature)
	}
	return maxTokens, temperature
}
