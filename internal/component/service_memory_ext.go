package component

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/auth"
	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
)

// MemoryDelete removes a key from the specified memory tier.
func (s *ComponentServiceServer) MemoryDelete(ctx context.Context, req *componentpb.MemoryDeleteRequest) (*componentpb.MemoryDeleteResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}

	tier := req.GetTier()
	key := req.GetKey()

	switch tier {
	case memTierWorking:
		if s.memory == nil {
			return nil, status.Error(codes.Unimplemented, "memory not configured")
		}
		s.memory.Working().Delete(key)
	case memTierMission:
		mem, err := s.resolveMissionMemory(ctx, req.GetWorkId(), tenant)
		if err != nil {
			return nil, err
		}
		if err := mem.Delete(ctx, key); err != nil {
			return nil, status.Errorf(codes.Internal, "delete failed: %v", err)
		}
	case memTierLongTerm:
		if s.memory == nil {
			return nil, status.Error(codes.Unimplemented, "memory not configured")
		}
		if err := s.memory.LongTerm().Delete(ctx, key); err != nil {
			return nil, status.Errorf(codes.Internal, "delete failed: %v", err)
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown tier: %s", tier)
	}

	return &componentpb.MemoryDeleteResponse{}, nil
}

// MemoryClear removes all keys from the specified memory tier.
func (s *ComponentServiceServer) MemoryClear(ctx context.Context, req *componentpb.MemoryClearRequest) (*componentpb.MemoryClearResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.memory == nil {
		return nil, status.Error(codes.Unimplemented, "memory not configured")
	}

	tier := req.GetTier()

	switch tier {
	case memTierWorking:
		s.memory.Working().Clear()
	default:
		return nil, status.Errorf(codes.Unimplemented, "clear not supported for tier: %s", tier)
	}

	return &componentpb.MemoryClearResponse{}, nil
}

// MemoryKeys returns all keys in the specified memory tier.
func (s *ComponentServiceServer) MemoryKeys(ctx context.Context, req *componentpb.MemoryKeysRequest) (*componentpb.MemoryKeysResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}

	tier := req.GetTier()

	switch tier {
	case memTierWorking:
		if s.memory == nil {
			return nil, status.Error(codes.Unimplemented, "memory not configured")
		}
		keys := s.memory.Working().List()
		return &componentpb.MemoryKeysResponse{Keys: keys}, nil
	case memTierMission:
		mem, err := s.resolveMissionMemory(ctx, req.GetWorkId(), tenant)
		if err != nil {
			return nil, err
		}
		keys, err := mem.Keys(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "keys failed: %v", err)
		}
		return &componentpb.MemoryKeysResponse{Keys: keys}, nil
	default:
		return nil, status.Errorf(codes.InvalidArgument, "keys not supported for tier: %s", tier)
	}
}

// MemoryHistory returns recent entries from mission memory.
func (s *ComponentServiceServer) MemoryHistory(ctx context.Context, req *componentpb.MemoryHistoryRequest) (*componentpb.MemoryHistoryResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}

	mem, err := s.resolveMissionMemory(ctx, req.GetWorkId(), tenant)
	if err != nil {
		return nil, err
	}
	items, err := mem.History(ctx, int(req.GetLimit()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "history failed: %v", err)
	}
	itemsJSON, err := json.Marshal(items)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal failed: %v", err)
	}
	return &componentpb.MemoryHistoryResponse{ItemsJson: itemsJSON}, nil
}

// MemoryGetPreviousRunValue retrieves a value from the prior mission run.
func (s *ComponentServiceServer) MemoryGetPreviousRunValue(ctx context.Context, req *componentpb.MemoryGetPreviousRunValueRequest) (*componentpb.MemoryGetPreviousRunValueResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}

	mem, err := s.resolveMissionMemory(ctx, req.GetWorkId(), tenant)
	if err != nil {
		return nil, err
	}
	value, err := mem.GetPreviousRunValue(ctx, req.GetKey())
	if err != nil {
		// Not found is not an error — return found=false.
		return &componentpb.MemoryGetPreviousRunValueResponse{Found: false}, nil
	}
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal failed: %v", err)
	}
	return &componentpb.MemoryGetPreviousRunValueResponse{Value: valueJSON, Found: true}, nil
}

// MemoryGetValueHistory returns the history of a key's values across runs.
func (s *ComponentServiceServer) MemoryGetValueHistory(ctx context.Context, req *componentpb.MemoryGetValueHistoryRequest) (*componentpb.MemoryGetValueHistoryResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}

	mem, err := s.resolveMissionMemory(ctx, req.GetWorkId(), tenant)
	if err != nil {
		return nil, err
	}
	history, err := mem.GetValueHistory(ctx, req.GetKey())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "value history failed: %v", err)
	}
	historyJSON, err := json.Marshal(history)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal failed: %v", err)
	}
	return &componentpb.MemoryGetValueHistoryResponse{HistoryJson: historyJSON}, nil
}
