// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"log/slog"
	"time"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// A cluster can look healthy while its secret plane is dead (hosted#174):
// every pod keeps running on the Secrets that were written earlier, and
// nothing deletes a Secret when its source stops answering. So the health
// surface of the Platform owner asks the source now, every time.

// planeSecret is the name of the secret plane in AdminGetPlatformHealth.
const planeSecret = "secret_plane"

// secretPlaneProbeTimeout bounds one probe. A source that does not answer
// in time is unhealthy: silence must not read as healthy.
const secretPlaneProbeTimeout = 5 * time.Second

// SecretPlaneProbe asks the secret source of the platform to answer. A nil
// error means that the source answered.
type SecretPlaneProbe interface {
	Probe(ctx context.Context) error
}

// WithSecretPlaneProbe wires the probe of AdminGetPlatformHealth.
func (s *DaemonServer) WithSecretPlaneProbe(p SecretPlaneProbe) *DaemonServer {
	s.secretPlaneProbe = p
	return s
}

// AdminGetPlatformHealth implements AdminTenantServiceServer.
//
// gibsoncheck:allow tenant-from-request — AdminTenantService: platform_owner on
// system_tenant at ext-authz. The secret plane belongs to no tenant.
func (s *DaemonServer) AdminGetPlatformHealth(ctx context.Context, _ *tenantv1.AdminGetPlatformHealthRequest) (*tenantv1.AdminGetPlatformHealthResponse, error) {
	return &tenantv1.AdminGetPlatformHealthResponse{
		Planes: []*tenantv1.PlatformPlaneHealth{s.secretPlaneHealth(ctx)},
	}, nil
}

func (s *DaemonServer) secretPlaneHealth(ctx context.Context) *tenantv1.PlatformPlaneHealth {
	out := &tenantv1.PlatformPlaneHealth{Plane: planeSecret, CheckedAtUnix: time.Now().Unix()}
	if s.secretPlaneProbe == nil {
		out.State = tenantv1.PlatformPlaneState_PLATFORM_PLANE_STATE_UNKNOWN
		out.Detail = "the daemon has no secret source to probe"
		return out
	}
	probeCtx, cancel := context.WithTimeout(ctx, secretPlaneProbeTimeout)
	defer cancel()
	if err := s.secretPlaneProbe.Probe(probeCtx); err != nil {
		s.logger.WarnContext(ctx, "platform health: the secret source did not answer",
			slog.String("error", err.Error()))
		out.State = tenantv1.PlatformPlaneState_PLATFORM_PLANE_STATE_UNHEALTHY
		out.Detail = "the secret source did not answer: " + err.Error()
		return out
	}
	out.State = tenantv1.PlatformPlaneState_PLATFORM_PLANE_STATE_HEALTHY
	return out
}
