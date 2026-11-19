// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — server_model_providers_desired.go
//
// DaemonOperatorService.GetTenantModelProviders (gibson#1387, ADR-0172). The
// daemon holds the provider records of a tenant, and it cannot write cluster
// resources (ADR-0023). The tenant operator pulls the records of each tenant and
// reconciles one ModelProvider for each record, as it pulls the desired catalog
// plugins. The reply holds the name of the credential secret, never a value.
package api

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/cabundle"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// The ModelProvider types of the tenant operator (operators/tenant/api).
const (
	gatewayTypeAnthropic        = "anthropic"
	gatewayTypeOpenAI           = "openai"
	gatewayTypeOpenAICompatible = "openai-compatible"
	gatewayTypeBedrock          = "bedrock"
	gatewayTypeGemini           = "gemini"
	gatewayTypeVertexAI         = "vertexai"
)

// gatewayProviderType maps the type of a provider record to the type of a
// ModelProvider. It returns a reason when the gateway has no route for the type.
func gatewayProviderType(t providerconfig.ProviderType) (gwType, skip string) {
	switch t {
	case providerconfig.ProviderAnthropic:
		return gatewayTypeAnthropic, ""
	case providerconfig.ProviderOpenAI:
		return gatewayTypeOpenAI, ""
	case providerconfig.ProviderOpenAICompatible:
		return gatewayTypeOpenAICompatible, ""
	case providerconfig.ProviderBedrock:
		return gatewayTypeBedrock, ""
	case providerconfig.ProviderGoogle:
		return gatewayTypeGemini, ""
	case providerconfig.ProviderVertex:
		return gatewayTypeVertexAI, ""
	case providerconfig.ProviderVoyage:
		return "", "voyage is not a provider type: the model gateway does not accept its reply"
	case providerconfig.ProviderOllama, providerconfig.ProviderCloudflare, providerconfig.ProviderCohere,
		providerconfig.ProviderHuggingFace, providerconfig.ProviderLlamafile, providerconfig.ProviderMistral,
		providerconfig.ProviderCustom, providerconfig.ProviderFoundry, providerconfig.ProviderTEI:
		// The model gateway has no route for these types.
	}
	return "", fmt.Sprintf("the model gateway has no route for the provider type %q", t)
}

// The credential fields that hold no secret and that the ModelProvider needs.
const (
	fieldBaseURL   = "base_url"
	fieldProjectID = "project_id"
	fieldRegion    = "region"
	fieldAWSRegion = "aws_region"
)

// GetTenantModelProviders returns the provider records of one tenant in the
// shape of a ModelProvider.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer allowlist. The operator reads
// the providers of each tenant by design.
func (s *DaemonServer) GetTenantModelProviders(
	ctx context.Context, req *daemonoperatorv1.GetTenantModelProvidersRequest,
) (*daemonoperatorv1.GetTenantModelProvidersResponse, error) {
	if s.providerConfig == nil || s.modelCredStore == nil {
		return nil, status.Error(codes.Unavailable, "provider records are not configured on this daemon")
	}
	if peerSPIFFEID(ctx) != s.modelCredPeer {
		return nil, errNotTheTenantOperator
	}
	tenant, err := auth.NewTenantID(req.GetTenantId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "tenant_id: %v", err)
	}
	records, err := s.providerConfig.List(ctx, tenant.String())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list the provider records: %v", err)
	}
	tctx := auth.WithTenant(ctx, tenant)
	out := &daemonoperatorv1.GetTenantModelProvidersResponse{}
	for _, rec := range records {
		if rec == nil || !rec.Enabled {
			continue
		}
		gw, skip := gatewayProviderType(rec.Type)
		if skip != "" {
			out.Skipped = append(out.Skipped, rec.Name+": "+skip)
			continue
		}
		secret := providerconfig.CredentialSecretName(rec.Name)
		field := func(name string) string {
			v, rerr := s.modelCredStore.Resolve(tctx, providerconfig.CredentialFieldKey(secret, name))
			if rerr != nil {
				return ""
			}
			return strings.TrimSpace(string(v))
		}
		d := &daemonoperatorv1.DesiredModelProvider{
			Name: rec.Name, Type: gw, CredentialSecret: secret, BaseUrl: field(fieldBaseURL),
			CaBundleSecret: field(cabundle.Field),
		}
		switch gw {
		case gatewayTypeBedrock:
			d.Region = field(fieldAWSRegion)
		case gatewayTypeVertexAI:
			d.Region, d.ProjectId = field(fieldRegion), field(fieldProjectID)
		}
		out.Providers = append(out.Providers, d)
	}
	return out, nil
}
