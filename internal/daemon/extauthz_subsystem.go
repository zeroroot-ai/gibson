package daemon

import (
	"context"

	"github.com/zero-day-ai/gibson/internal/extauthz"
	"github.com/zero-day-ai/gibson/internal/observability"
)

// extauthzSubsystem owns the lifecycle of the ext_authz gRPC client.
// It constructs the client during daemon bootstrap and closes it when
// the daemon shuts down.
//
// The ext_authz client is lazy-dialing: grpc.NewClient does not actually
// connect until the first RPC call. If the ext_authz service is absent in a
// non-gateway overlay, the first MintCapabilityGrant call will receive
// codes.Unavailable — not a startup failure.
type extauthzSubsystem struct {
	client *extauthz.Client
	logger *observability.Logger
}

// newExtauthzSubsystem constructs the ext_authz client. If construction fails
// (invalid gRPC options — should not happen in practice), it returns nil so
// the daemon can proceed without capability-grant delegation.
func newExtauthzSubsystem(ctx context.Context, logger *observability.Logger) *extauthzSubsystem {
	client, err := extauthz.NewClient(ctx)
	if err != nil {
		// Log warning but do not fail startup — ext_authz is an optional gateway
		// component. In dev/non-gateway overlays it is absent; the daemon degrades
		// gracefully (MintCapabilityGrant returns codes.Unavailable to callers).
		logger.Warn(ctx, "ext_authz client not initialized — capability-grant delegation unavailable",
			"error", err)
		return nil
	}
	return &extauthzSubsystem{client: client, logger: logger}
}

// Client returns the underlying ext_authz client for injection into services
// that need capability-grant delegation.
func (e *extauthzSubsystem) Client() *extauthz.Client {
	if e == nil {
		return nil
	}
	return e.client
}

// Serve blocks until ctx is cancelled, then closes the gRPC connection.
// Returns nil on clean shutdown.
func (e *extauthzSubsystem) Serve(ctx context.Context) error {
	<-ctx.Done()
	if err := e.client.Close(); err != nil {
		e.logger.Warn(ctx, "error closing ext_authz client connection", "error", err)
	}
	return nil
}
