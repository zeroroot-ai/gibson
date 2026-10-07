// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ProducedComponentEnroller enrolls a component that an agent produced
// (gibson#33). The daemon wires the tenant-admin server, which owns the
// identity provisioning. It returns gRPC status errors.
type ProducedComponentEnroller interface {
	EnrollProduced(ctx context.Context, tenantID, producer string, c ProducedComponentSpec) (EnrolledProducedComponent, error)
}

// ProducedComponentSpec is the component that the agent produced.
type ProducedComponentSpec struct {
	Kind        string
	Name        string
	Version     string
	Image       string
	Description string
}

// EnrolledProducedComponent is the identity and the one-time credential of
// the new component.
type EnrolledProducedComponent struct {
	PrincipalID    string
	BootstrapToken string
	ExpiresAt      time.Time
}

// WithProducedComponentEnroller wires EnrollComponent. With no enroller the
// RPC is Unavailable.
func (s *ComponentServiceServer) WithProducedComponentEnroller(e ProducedComponentEnroller) *ComponentServiceServer {
	s.producedEnroller = e
	return s
}

// EnrollComponent enrolls a component that the calling agent produced
// (gibson#33). The tenant and the producer come from the verified identity of
// the caller: the subject of its capability-grant JWT is its typed
// principal. The request names neither, so a call cannot reach another
// tenant.
func (s *ComponentServiceServer) EnrollComponent(ctx context.Context, req *componentpb.EnrollComponentRequest) (*componentpb.EnrollComponentResponse, error) {
	if s.producedEnroller == nil {
		return nil, status.Error(codes.Unavailable, "the enrollment of produced components is not configured")
	}
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		return nil, status.Error(codes.Unauthenticated, "missing component identity in context")
	}
	got, err := s.producedEnroller.EnrollProduced(ctx, tenant, id.Subject, ProducedComponentSpec{
		Kind:        req.GetKind(),
		Name:        req.GetName(),
		Version:     req.GetVersion(),
		Image:       req.GetImage(),
		Description: req.GetDescription(),
	})
	if err != nil {
		return nil, err //nolint:wrapcheck // the enroller returns a gRPC status; a wrap hides its code from the caller
	}
	return &componentpb.EnrollComponentResponse{
		PrincipalId:    got.PrincipalID,
		BootstrapToken: got.BootstrapToken,
		ExpiresAt:      timestamppb.New(got.ExpiresAt),
	}, nil
}
