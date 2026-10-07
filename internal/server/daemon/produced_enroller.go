// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// producedEnroller connects ComponentService.EnrollComponent to the identity
// provisioning of the tenant-admin surface (gibson#33). The two packages do
// not import each other.
type producedEnroller struct {
	srv *api.DaemonServer
}

func (p producedEnroller) EnrollProduced(ctx context.Context, tenantID, producer string, c component.ProducedComponentSpec) (component.EnrolledProducedComponent, error) {
	got, err := p.srv.EnrollProducedComponent(ctx, tenantID, producer, api.ProducedComponent{
		Kind:        c.Kind,
		Name:        c.Name,
		Version:     c.Version,
		Image:       c.Image,
		Description: c.Description,
	})
	if err != nil {
		return component.EnrolledProducedComponent{}, err //nolint:wrapcheck // a gRPC status; a wrap hides its code from the caller
	}
	return component.EnrolledProducedComponent{
		PrincipalID:    got.PrincipalID,
		BootstrapToken: got.BootstrapToken,
		ExpiresAt:      got.ExpiresAt,
	}, nil
}
