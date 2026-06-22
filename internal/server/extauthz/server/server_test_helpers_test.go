package server

import (
	"context"
	"log/slog"
	"os"

	openfga "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
)

// tenantMockFGA is a minimal FGAClient stub for tenant cross-check tests.
type tenantMockFGA struct {
	allowed bool
}

func (m *tenantMockFGA) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &tenantMockReq{m: m}
}

type tenantMockReq struct{ m *tenantMockFGA }

func (r *tenantMockReq) Body(_ fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	return r
}
func (r *tenantMockReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}
func (r *tenantMockReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	v := r.m.allowed
	return &fgaclient.ClientCheckResponse{CheckResponse: openfga.CheckResponse{Allowed: &v}}, nil
}
func (r *tenantMockReq) GetAuthorizationModelIdOverride() *string  { return nil }
func (r *tenantMockReq) GetStoreIdOverride() *string               { return nil }
func (r *tenantMockReq) GetContext() context.Context               { return context.Background() }
func (r *tenantMockReq) GetBody() *fgaclient.ClientCheckRequest    { return nil }
func (r *tenantMockReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

// newTestLogger returns a slog.Logger that writes to stderr at Debug level,
// suitable for tests where log output should be visible on failure.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
