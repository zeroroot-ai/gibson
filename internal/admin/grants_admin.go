// Package admin — grants_admin.go
//
// GrantsAdminServer implements gibson.admin.v1.GrantsAdminService — the
// dashboard's read-only inspector for active capability grants. Pairs with
// secrets_admin.go (secrets), plugin_admin.go (plugin installs), and
// tenant_admin.go (broker config).
//
// CG-JWTs are minted and revoked daemon-internally during mission dispatch;
// this admin surface is read-only in v1. Explicit revocation surfaces are a
// future spec.
//
// Spec: secrets-tenant-lifecycle Requirement 8.1, Requirement 4.
package admin

import (
	"context"
	"errors"
	"sort"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	adminv1 "github.com/zero-day-ai/sdk/api/gen/gibson/admin/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// GrantInfo is the dashboard-shaped view of one active capability grant.
// It mirrors the proto wire-shape but uses native Go types for the
// timestamp fields. The production wiring populates this from the daemon's
// grant store (in-memory or Redis-backed).
type GrantInfo struct {
	JTI                 string
	RecipientInstallID  string
	RecipientClass      string // "agent" | "tool" | "plugin"
	RecipientName       string
	AllowedRPCs         []string
	MissionID           string
	TaskID              string
	IssuedAt            time.Time
	ExpiresAt           time.Time
}

// CapabilityGrantsReader is the narrow read-side contract this handler
// uses against the daemon's grant tracker. The production wiring is
// either a wrapper over the in-memory grant tracker or — when the
// audit-pipeline-backed Redis store lands — a query against that.
type CapabilityGrantsReader interface {
	// ListActive returns active grants for the tenant. The handler
	// applies any further filtering (recipient class, RPC, near-expiry)
	// in Go.
	ListActive(ctx context.Context, tenant auth.TenantID) ([]GrantInfo, error)
}

// GrantsAdminServer implements adminv1.GrantsAdminServiceServer.
type GrantsAdminServer struct {
	adminv1.UnimplementedGrantsAdminServiceServer

	reader CapabilityGrantsReader
	now    func() time.Time
}

// GrantsAdminConfig groups the constructor's required dependencies.
type GrantsAdminConfig struct {
	Reader CapabilityGrantsReader
	Now    func() time.Time
}

// NewGrantsAdminServer constructs a GrantsAdminServer. Reader is required.
func NewGrantsAdminServer(cfg GrantsAdminConfig) (*GrantsAdminServer, error) {
	if cfg.Reader == nil {
		return nil, errors.New("grants admin: Reader is required")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &GrantsAdminServer{reader: cfg.Reader, now: now}, nil
}

// nearExpiryWindow is the window inside which a grant is highlighted as
// nearing expiry per Requirement 4.1. The dashboard renders these rows
// with a warning class.
const nearExpiryWindow = 5 * time.Minute

// ListActiveGrants returns active capability grants for the tenant
// resolved from identity, optionally filtered by recipient class, RPC,
// and near-expiry.
func (s *GrantsAdminServer) ListActiveGrants(ctx context.Context, req *adminv1.ListActiveGrantsRequest) (*adminv1.ListActiveGrantsResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}

	grants, err := s.reader.ListActive(ctx, tenant)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list active grants: %v", err)
	}

	now := s.now()

	// Apply filters in Go.
	classFilter := req.GetRecipientClassFilter()
	rpcFilter := req.GetRpcFilter()
	nearOnly := req.GetIncludeNearExpiryOnly()

	out := make([]*adminv1.CapabilityGrantInfo, 0, len(grants))
	for _, g := range grants {
		// Defense-in-depth: skip expired grants the reader may still return.
		if !g.ExpiresAt.IsZero() && !g.ExpiresAt.After(now) {
			continue
		}

		nearExpiry := false
		if !g.ExpiresAt.IsZero() && g.ExpiresAt.Sub(now) <= nearExpiryWindow {
			nearExpiry = true
		}

		if nearOnly && !nearExpiry {
			continue
		}

		class := classFromString(g.RecipientClass)
		if classFilter != adminv1.RecipientClass_RECIPIENT_CLASS_UNSPECIFIED && class != classFilter {
			continue
		}

		if rpcFilter != "" && !containsString(g.AllowedRPCs, rpcFilter) {
			continue
		}

		out = append(out, &adminv1.CapabilityGrantInfo{
			Jti:                g.JTI,
			RecipientInstallId: g.RecipientInstallID,
			RecipientClass:     class,
			RecipientName:      g.RecipientName,
			AllowedRpcs:        g.AllowedRPCs,
			MissionId:          g.MissionID,
			TaskId:             g.TaskID,
			IssuedAtUnix:       g.IssuedAt.Unix(),
			ExpiresAtUnix:      g.ExpiresAt.Unix(),
			NearExpiry:         nearExpiry,
		})
	}

	// Sort: near-expiry first (dashboard renders them at top), then by
	// expires_at ascending.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].GetNearExpiry() != out[j].GetNearExpiry() {
			return out[i].GetNearExpiry()
		}
		return out[i].GetExpiresAtUnix() < out[j].GetExpiresAtUnix()
	})

	// Apply pagination.
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 100
	}
	offset := int(req.GetOffset())
	if offset < 0 {
		offset = 0
	}
	total := int32(len(out))
	if offset >= len(out) {
		out = out[:0]
	} else {
		end := offset + limit
		if end > len(out) {
			end = len(out)
		}
		out = out[offset:end]
	}

	return &adminv1.ListActiveGrantsResponse{
		Grants: out,
		Total:  total,
	}, nil
}

// classFromString maps the lowercase string class label to the proto enum.
func classFromString(s string) adminv1.RecipientClass {
	switch s {
	case "agent":
		return adminv1.RecipientClass_RECIPIENT_CLASS_AGENT
	case "tool":
		return adminv1.RecipientClass_RECIPIENT_CLASS_TOOL
	case "plugin":
		return adminv1.RecipientClass_RECIPIENT_CLASS_PLUGIN
	default:
		return adminv1.RecipientClass_RECIPIENT_CLASS_UNSPECIFIED
	}
}

// containsString reports whether s appears in xs (exact match).
func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
