// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package provision

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	operatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// operatorCall is one RPC of the client. op is a word of the error text that
// names the call.
type operatorCall struct {
	name string
	op   string
	call func(c *EntitlementsGRPCClient) error
}

func operatorCalls() []operatorCall {
	ctx := context.Background()
	return []operatorCall{
		{"SetTenantZitadelOrg", "set-tenant-zitadel-org", func(c *EntitlementsGRPCClient) error {
			return c.SetTenantZitadelOrg(ctx, "acme", "org-1")
		}},
		{"ListFeatureTuples", "list-feature-tuples", func(c *EntitlementsGRPCClient) error {
			_, err := c.ListFeatureTuples(ctx, "acme")
			return err
		}},
		{"WriteAccessTuples", "write-tuples", func(c *EntitlementsGRPCClient) error {
			return c.WriteAccessTuples(ctx, []string{"user:a#viewer@doc:1"}, nil, "test")
		}},
		{"SeedCatalogTenantEnabled", "seed-catalog", func(c *EntitlementsGRPCClient) error {
			return c.SeedCatalogTenantEnabled(ctx, "acme")
		}},
		{"ListPendingTenantProvisioning", "list-pending-tenant-provisioning", func(c *EntitlementsGRPCClient) error {
			_, err := c.ListPendingTenantProvisioning(ctx)
			return err
		}},
		{"AckTenantProvisioned", "ack-tenant-provisioned", func(c *EntitlementsGRPCClient) error {
			return c.AckTenantProvisioned(ctx, "acme")
		}},
		{"EnqueueTenantProvisioning", "enqueue-tenant-provisioning", func(c *EntitlementsGRPCClient) error {
			_, err := c.EnqueueTenantProvisioning(ctx, PendingTenant{TenantID: "acme"})
			return err
		}},
		{"ReportTenantStatus", "report-tenant-status", func(c *EntitlementsGRPCClient) error {
			return c.ReportTenantStatus(ctx, TenantStatusReport{TenantID: "acme", Phase: "Ready"})
		}},
		{"ListPendingTenantOps", "list-pending-tenant-ops", func(c *EntitlementsGRPCClient) error {
			_, err := c.ListPendingTenantOps(ctx)
			return err
		}},
		{"AckTenantOp", "ack-tenant-op", func(c *EntitlementsGRPCClient) error {
			return c.AckTenantOp(ctx, "op-1")
		}},
		{"EmitAuditEvent", "emit-audit-event", func(c *EntitlementsGRPCClient) error {
			return c.EmitAuditEvent(ctx, audit.Event{Action: audit.ActionSagaStep, TenantID: "acme"})
		}},
		{"SetAgentEnrollmentLimits", "set agent enrollment limits", func(c *EntitlementsGRPCClient) error {
			return c.SetAgentEnrollmentLimits(ctx, "acme", "scout", time.Minute)
		}},
		{"ModelProviderCredential", "get-model-provider-credential", func(c *EntitlementsGRPCClient) error {
			_, err := c.ModelProviderCredential(ctx, "acme", "key", "anthropic", "")
			return err
		}},
		{"TenantModelProviders", "get-tenant-model-providers", func(c *EntitlementsGRPCClient) error {
			_, _, err := c.TenantModelProviders(ctx, "acme")
			return err
		}},
		{"TenantOutsideAgents", "get-tenant-outside-agents", func(c *EntitlementsGRPCClient) error {
			_, err := c.TenantOutsideAgents(ctx, "acme")
			return err
		}},
		{"OutsideAgentCredential", "get-outside-agent-credential", func(c *EntitlementsGRPCClient) error {
			_, err := c.OutsideAgentCredential(ctx, "acme", "scout")
			return err
		}},
	}
}

// Each call stops before it dials when the token source fails.
func TestEntitlementsGRPC_EachCallStopsWhenTheTokenFails(t *testing.T) {
	c := bufconnClient(t, &captureAuditServer{})
	c.tokens = failingTokens{}
	for _, tt := range operatorCalls() {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(c); !errors.Is(err, errNoToken) {
				t.Fatalf("error = %v, want the token error", err)
			}
		})
	}
}

// Each call turns a refusal of the daemon into an error that names the call.
func TestEntitlementsGRPC_EachCallReportsADaemonRefusal(t *testing.T) {
	// The server answers Unimplemented for each RPC it does not define.
	c := bufconnClient(t, &captureAuditServer{err: status.Error(codes.Internal, "boom")})
	for _, tt := range operatorCalls() {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call(c)
			if err == nil || !strings.Contains(err.Error(), tt.op) {
				t.Fatalf("error = %v, want one that names %q", err, tt.op)
			}
		})
	}
}

// operatorFixture answers the RPCs that the other test files do not define.
type operatorFixture struct {
	operatorv1.UnimplementedDaemonOperatorServiceServer
	err error
}

func (f *operatorFixture) ListFeatureTuples(
	ctx context.Context, _ *operatorv1.ListFeatureTuplesRequest,
) (*operatorv1.ListFeatureTuplesResponse, error) {
	rel := []string{"f1", "f2"}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		rel = append(rel, md.Get("authorization")...)
	}
	return &operatorv1.ListFeatureTuplesResponse{Relations: rel}, f.err
}

func (f *operatorFixture) WriteAccessTuples(
	_ context.Context, req *operatorv1.WriteAccessTuplesRequest,
) (*operatorv1.WriteAccessTuplesResponse, error) {
	if len(req.GetAdd()) != 1 || req.GetAdd()[0].GetUser() != "user:a" || req.GetReason() != "why" {
		return nil, status.Error(codes.InvalidArgument, "unexpected tuples")
	}
	return &operatorv1.WriteAccessTuplesResponse{}, f.err
}

func (f *operatorFixture) EnqueueTenantProvisioning(
	_ context.Context, req *operatorv1.EnqueueTenantProvisioningRequest,
) (*operatorv1.EnqueueTenantProvisioningResponse, error) {
	if req.GetTenantId() != "acme" || req.GetDisplayName() != "Acme" ||
		req.GetOwnerEmail() != "a@x" || req.GetTier() != "pro" {
		return nil, status.Error(codes.InvalidArgument, "unexpected request")
	}
	return &operatorv1.EnqueueTenantProvisioningResponse{AlreadyExisted: true}, f.err
}

func (f *operatorFixture) GetModelProviderCredential(
	_ context.Context, req *operatorv1.GetModelProviderCredentialRequest,
) (*operatorv1.GetModelProviderCredentialResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	if req.GetTenantId() != "acme" || req.GetCredentialSecret() != "key" || req.GetProviderType() != "anthropic" ||
		req.GetCaBundleSecret() != "ca" {
		return nil, status.Error(codes.InvalidArgument, "unexpected request")
	}
	return &operatorv1.GetModelProviderCredentialResponse{
		Secret: &operatorv1.SecretData{Data: map[string][]byte{"Authorization": []byte("k")}},
	}, nil
}

func (f *operatorFixture) GetTenantModelProviders(
	context.Context, *operatorv1.GetTenantModelProvidersRequest,
) (*operatorv1.GetTenantModelProvidersResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &operatorv1.GetTenantModelProvidersResponse{
		Providers: []*operatorv1.DesiredModelProvider{{
			Name: "claude", Type: "anthropic", BaseUrl: "https://b", Region: "r", ProjectId: "p",
			CredentialSecret: "key", CaBundleSecret: "ca",
		}},
		Skipped: []string{"emb: no route"},
	}, nil
}

func (f *operatorFixture) GetTenantOutsideAgents(
	context.Context, *operatorv1.GetTenantOutsideAgentsRequest,
) (*operatorv1.GetTenantOutsideAgentsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &operatorv1.GetTenantOutsideAgentsResponse{Agents: []*operatorv1.DesiredOutsideAgent{{
		Name: "scout", A2AUrl: "https://scout/a2a", CredentialSecret: "key", CaBundleSecret: "ca",
	}}}, nil
}

func (f *operatorFixture) GetOutsideAgentCredential(
	_ context.Context, req *operatorv1.GetOutsideAgentCredentialRequest,
) (*operatorv1.GetOutsideAgentCredentialResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	data := map[string][]byte{"Authorization": []byte(req.GetName())}
	return &operatorv1.GetOutsideAgentCredentialResponse{Secret: &operatorv1.SecretData{Data: data}}, nil
}

func TestEntitlementsGRPC_ReturnsWhatTheDaemonSends(t *testing.T) {
	ctx := context.Background()
	c := bufconnClient(t, &operatorFixture{})

	rel, err := c.ListFeatureTuples(ctx, "acme")
	if err != nil || !reflect.DeepEqual(rel, []string{"f1", "f2"}) {
		t.Errorf("ListFeatureTuples = %v, %v", rel, err)
	}
	if err := c.WriteAccessTuples(ctx, []string{"user:a#viewer@doc:1", "malformed"}, nil, "why"); err != nil {
		t.Errorf("WriteAccessTuples: %v", err)
	}
	existed, err := c.EnqueueTenantProvisioning(ctx, PendingTenant{
		TenantID: "acme", WorkspaceName: "Acme", OwnerEmail: "a@x", Tier: "pro",
	})
	if err != nil || !existed {
		t.Errorf("EnqueueTenantProvisioning = %v, %v", existed, err)
	}
	data, err := c.ModelProviderCredential(ctx, "acme", "key", "anthropic", "ca")
	if err != nil || string(data["Authorization"]) != "k" {
		t.Errorf("ModelProviderCredential = %v, %v", data, err)
	}
	providers, skipped, err := c.TenantModelProviders(ctx, "acme")
	wantProviders := []DesiredModelProvider{{
		Name: "claude", Type: "anthropic", BaseURL: "https://b", Region: "r", ProjectID: "p",
		CredentialSecret: "key", CABundleSecret: "ca",
	}}
	wantSkipped := []string{"emb: no route"}
	if err != nil || !reflect.DeepEqual(providers, wantProviders) || !reflect.DeepEqual(skipped, wantSkipped) {
		t.Errorf("TenantModelProviders = %+v, %v, %v", providers, skipped, err)
	}
	agents, err := c.TenantOutsideAgents(ctx, "acme")
	wantAgents := []DesiredOutsideAgent{{
		Name: "scout", A2AURL: "https://scout/a2a", CredentialSecret: "key", CABundleSecret: "ca",
	}}
	if err != nil || !reflect.DeepEqual(agents, wantAgents) {
		t.Errorf("TenantOutsideAgents = %+v, %v", agents, err)
	}
	data, err = c.OutsideAgentCredential(ctx, "acme", "scout")
	if err != nil || string(data["Authorization"]) != "scout" {
		t.Errorf("OutsideAgentCredential = %v, %v", data, err)
	}
}

// A credential that the daemon does not hold is clients.ErrNotFound, so a
// controller waits for it. Any other failure keeps its class.
func TestEntitlementsGRPC_ACredentialThatDoesNotExistIsNotFound(t *testing.T) {
	ctx := context.Background()
	missing := bufconnClient(t, &operatorFixture{err: status.Error(codes.NotFound, "no such secret")})
	_, err := missing.ModelProviderCredential(ctx, "acme", "key", "anthropic", "")
	if !errors.Is(err, clients.ErrNotFound) {
		t.Errorf("model provider credential error = %v, want ErrNotFound", err)
	}
	if _, err = missing.OutsideAgentCredential(ctx, "acme", "scout"); !errors.Is(err, clients.ErrNotFound) {
		t.Errorf("outside agent credential error = %v, want ErrNotFound", err)
	}
	denied := bufconnClient(t, &operatorFixture{err: status.Error(codes.PermissionDenied, "no")})
	_, err = denied.ModelProviderCredential(ctx, "acme", "key", "anthropic", "")
	if !errors.Is(err, clients.ErrUnauthorized) {
		t.Errorf("denied error = %v, want ErrUnauthorized", err)
	}
}

func TestTranslateGRPCError_MapsEachClass(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{"nil", nil, nil},
		{"not a status", errors.New("socket closed"), clients.ErrUnreachable},
		{"unauthenticated", status.Error(codes.Unauthenticated, "x"), clients.ErrUnauthorized},
		{"invalid argument", status.Error(codes.InvalidArgument, "x"), clients.ErrInvalidInput},
		{"unavailable", status.Error(codes.Unavailable, "x"), clients.ErrUnreachable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := translateGRPCError("op", tt.err)
			if tt.want == nil {
				if got != nil {
					t.Fatalf("error = %v, want nil", got)
				}
				return
			}
			if !errors.Is(got, tt.want) {
				t.Fatalf("error = %v, want %v", got, tt.want)
			}
		})
	}
	other := translateGRPCError("op", status.Error(codes.Internal, "x"))
	if other == nil || errors.Is(other, clients.ErrUnreachable) || errors.Is(other, clients.ErrUnauthorized) ||
		errors.Is(other, clients.ErrInvalidInput) {
		t.Errorf("an internal error got a retry class: %v", other)
	}
}

func TestEntitlementsGRPC_CloseOfANilOrUnconnectedClientIsSafe(t *testing.T) {
	var nilClient *EntitlementsGRPCClient
	if err := nilClient.Close(); err != nil {
		t.Errorf("nil client: %v", err)
	}
	if err := (&EntitlementsGRPCClient{}).Close(); err != nil {
		t.Errorf("client without a transport: %v", err)
	}
}

func TestParseAccessTuples_SkipsMalformedTuples(t *testing.T) {
	got := parseAccessTuples([]string{"user:a#viewer@doc:1", "#r@o", "u#r@", "u@r#o", "plain"})
	if len(got) != 1 || got[0].GetUser() != "user:a" || got[0].GetRelation() != "viewer" || got[0].GetObject() != "doc:1" {
		t.Fatalf("tuples = %v", got)
	}
}

type staticTokens struct{}

func (staticTokens) FetchToken(_ context.Context, audience string) (string, error) {
	return "token-for-" + audience, nil
}

// A token source adds the bearer token of the audience to each call.
func TestEntitlementsGRPC_SendsTheBearerTokenOfTheAudience(t *testing.T) {
	c := bufconnClient(t, &operatorFixture{})
	c.tokens = staticTokens{}
	rel, err := c.ListFeatureTuples(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"f1", "f2", "Bearer token-for-gibson-daemon"}; !reflect.DeepEqual(rel, want) {
		t.Fatalf("relations = %v, want %v", rel, want)
	}
}

// With no SPIRE agent, the constructor fails with a clear error and no client.
func TestNewEntitlementsGRPCClient_NoWorkloadAPIIsAnError(t *testing.T) {
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/no-such-spire-socket-"+t.Name())
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	c, err := NewEntitlementsGRPCClient(ctx, "gibson-workloads:50051", "spiffe://zeroroot.ai/platform/daemon", nil)
	if err == nil || !strings.Contains(err.Error(), "entitlements: daemon-transport:") {
		t.Fatalf("error = %v", err)
	}
	if c != nil {
		t.Error("a client was returned with an error")
	}
}

// twoPageFixture serves each list in two pages. The first token is empty and
// the second is "p2".
type twoPageFixture struct {
	operatorFixture
	sizes  []int32
	tokens []string
}

func (f *twoPageFixture) GetTenantModelProviders(
	_ context.Context, req *operatorv1.GetTenantModelProvidersRequest,
) (*operatorv1.GetTenantModelProvidersResponse, error) {
	f.sizes = append(f.sizes, req.GetPageSize())
	f.tokens = append(f.tokens, req.GetPageToken())
	if req.GetPageToken() == "" {
		return &operatorv1.GetTenantModelProvidersResponse{
			Providers:     []*operatorv1.DesiredModelProvider{{Name: "a"}},
			Skipped:       []string{"x: no route"},
			NextPageToken: "p2",
		}, nil
	}
	return &operatorv1.GetTenantModelProvidersResponse{
		Providers: []*operatorv1.DesiredModelProvider{{Name: "b"}},
		Skipped:   []string{"y: no route"},
	}, nil
}

func (f *twoPageFixture) GetTenantOutsideAgents(
	_ context.Context, req *operatorv1.GetTenantOutsideAgentsRequest,
) (*operatorv1.GetTenantOutsideAgentsResponse, error) {
	f.sizes = append(f.sizes, req.GetPageSize())
	f.tokens = append(f.tokens, req.GetPageToken())
	if req.GetPageToken() == "" {
		return &operatorv1.GetTenantOutsideAgentsResponse{
			Agents: []*operatorv1.DesiredOutsideAgent{{Name: "a"}}, NextPageToken: "p2",
		}, nil
	}
	return &operatorv1.GetTenantOutsideAgentsResponse{Agents: []*operatorv1.DesiredOutsideAgent{{Name: "b"}}}, nil
}

// A sync deletes what the list does not hold, so the client must read each
// page until the next token is empty.
func TestEntitlementsGRPC_TenantListsReadEachPage(t *testing.T) {
	ctx := context.Background()
	fx := &twoPageFixture{}
	c := bufconnClient(t, fx)

	providers, skipped, err := c.TenantModelProviders(ctx, "acme")
	if err != nil || len(providers) != 2 || providers[0].Name != "a" || providers[1].Name != "b" {
		t.Errorf("TenantModelProviders = %+v, %v", providers, err)
	}
	if !reflect.DeepEqual(skipped, []string{"x: no route", "y: no route"}) {
		t.Errorf("skipped = %v, want the skipped of both pages", skipped)
	}
	agents, err := c.TenantOutsideAgents(ctx, "acme")
	if err != nil || len(agents) != 2 || agents[0].Name != "a" || agents[1].Name != "b" {
		t.Errorf("TenantOutsideAgents = %+v, %v", agents, err)
	}
	if !reflect.DeepEqual(fx.tokens, []string{"", "p2", "", "p2"}) {
		t.Errorf("tokens sent = %q", fx.tokens)
	}
	for _, size := range fx.sizes {
		if size != 1000 {
			t.Errorf("page_size = %d, want the largest page", size)
		}
	}
}

// A failure on a later page fails the read. A partial list must never reach a
// sync.
func TestEntitlementsGRPC_TenantListsFailOnALaterPage(t *testing.T) {
	ctx := context.Background()
	c := bufconnClient(t, &failingSecondPage{})
	if providers, _, err := c.TenantModelProviders(ctx, "acme"); err == nil || providers != nil {
		t.Errorf("TenantModelProviders = %v, %v, want an error and no list", providers, err)
	}
	if agents, err := c.TenantOutsideAgents(ctx, "acme"); err == nil || agents != nil {
		t.Errorf("TenantOutsideAgents = %v, %v, want an error and no list", agents, err)
	}
}

type failingSecondPage struct{ operatorFixture }

func (f *failingSecondPage) GetTenantModelProviders(
	_ context.Context, req *operatorv1.GetTenantModelProvidersRequest,
) (*operatorv1.GetTenantModelProvidersResponse, error) {
	if req.GetPageToken() != "" {
		return nil, status.Error(codes.Internal, "boom")
	}
	return &operatorv1.GetTenantModelProvidersResponse{
		Providers: []*operatorv1.DesiredModelProvider{{Name: "a"}}, NextPageToken: "p2",
	}, nil
}

func (f *failingSecondPage) GetTenantOutsideAgents(
	_ context.Context, req *operatorv1.GetTenantOutsideAgentsRequest,
) (*operatorv1.GetTenantOutsideAgentsResponse, error) {
	if req.GetPageToken() != "" {
		return nil, status.Error(codes.Internal, "boom")
	}
	return &operatorv1.GetTenantOutsideAgentsResponse{
		Agents: []*operatorv1.DesiredOutsideAgent{{Name: "a"}}, NextPageToken: "p2",
	}, nil
}
