package manifest

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ManifestVersionHeader is the gRPC metadata key SDKs attach to every
// Harness call so the daemon can refuse stale-manifest calls early.
// Lower-case so it matches grpc-go metadata normalization.
const ManifestVersionHeader = "x-gibson-manifest-version"

// DefaultStalenessTolerance is the window (in version deltas) the
// interceptor tolerates before rejecting. K=2 matches design.md — a
// single unpaired invalidation during propagation is survivable.
const DefaultStalenessTolerance uint64 = 2

// StalenessOptions configures the interceptor behavior.
type StalenessOptions struct {
	// Tolerance is the number of versions by which the supplied header
	// may lag current before the interceptor rejects. Default 2.
	Tolerance uint64

	// SkipMethods is the set of fully-qualified gRPC methods that must
	// never be checked — the manifest RPCs themselves and any
	// unauthenticated bootstrap calls.
	SkipMethods map[string]struct{}

	// RequireHeaderForAgentPrincipal forces rejection when an identified
	// agent_principal caller omits the header. Human users and CLI
	// clients are exempt because they do not hold a manifest.
	RequireHeaderForAgentPrincipal bool

	// TenantResolver supplies the tenant for the caller when the
	// interceptor needs to read VersionStore.Current. The daemon passes
	// its existing auth.TenantFromContext here.
	TenantResolver func(ctx context.Context) string

	// SubjectIsAgentPrincipal reports whether the caller is an
	// agent_principal (used by RequireHeaderForAgentPrincipal).
	SubjectIsAgentPrincipal func(ctx context.Context) bool

	// Logger is optional; defaults to slog.Default.
	Logger *slog.Logger
}

// NewStalenessInterceptor returns a grpc.UnaryServerInterceptor that
// validates the x-gibson-manifest-version header against
// VersionStore.Current for the caller's tenant. Insert it BEFORE the
// FGA authz interceptor so the header check runs before the expensive
// FGA round-trip.
func NewStalenessInterceptor(versions VersionStore, opts StalenessOptions) grpc.UnaryServerInterceptor {
	if opts.Tolerance == 0 {
		opts.Tolerance = DefaultStalenessTolerance
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	skip := opts.SkipMethods
	if skip == nil {
		skip = defaultSkipMethods()
	}
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if _, skipIt := skip[info.FullMethod]; skipIt {
			return handler(ctx, req)
		}
		supplied, hasHeader := readManifestVersionMD(ctx)

		isAgent := opts.SubjectIsAgentPrincipal != nil && opts.SubjectIsAgentPrincipal(ctx)
		if !hasHeader {
			if isAgent && opts.RequireHeaderForAgentPrincipal {
				return nil, status.Error(codes.FailedPrecondition,
					"manifest: agent_principal caller must supply "+ManifestVersionHeader)
			}
			// Humans / CLI / dashboard callers — no manifest. Pass through.
			return handler(ctx, req)
		}

		if opts.TenantResolver == nil {
			// Without a resolver we can't check, so pass through with a
			// warn-once log rather than fail random calls.
			opts.Logger.Warn("manifest: staleness interceptor has no TenantResolver; skipping check",
				"method", info.FullMethod)
			return handler(ctx, req)
		}
		tenantID := opts.TenantResolver(ctx)
		if tenantID == "" {
			return handler(ctx, req)
		}
		current, err := versions.Current(ctx, tenantID)
		if err != nil {
			// Cache-miss + Redis outage: return Unavailable so the SDK
			// retries rather than silently executing against stale FGA.
			opts.Logger.Warn("manifest: staleness check version lookup failed",
				"method", info.FullMethod, "tenant", tenantID, "error", err)
			return nil, status.Error(codes.Unavailable, "manifest version lookup failed")
		}
		if current > supplied && current-supplied > opts.Tolerance {
			return nil, buildStalenessError(current, supplied)
		}
		return handler(ctx, req)
	}
}

// defaultSkipMethods are the fully-qualified gRPC methods that never
// get a staleness check — the manifest RPCs themselves and the
// pre-auth bootstrap calls.
func defaultSkipMethods() map[string]struct{} {
	return map[string]struct{}{
		"/gibson.daemon.v1.DaemonService/GetCapabilityManifest":      {},
		"/gibson.daemon.v1.DaemonService/WatchManifestInvalidations": {},
		"/gibson.daemon.v1.DaemonService/Connect":                    {},
		"/gibson.daemon.v1.DaemonService/Ping":                       {},
		"/gibson.daemon.v1.DaemonService/Status":                     {},
	}
}

// readManifestVersionMD reads the x-gibson-manifest-version header from
// the incoming context. Returns (0, false) when the header is missing
// or unparseable.
func readManifestVersionMD(ctx context.Context) (uint64, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return 0, false
	}
	vals := md.Get(ManifestVersionHeader)
	if len(vals) == 0 {
		return 0, false
	}
	raw := strings.TrimSpace(vals[0])
	if raw == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// buildStalenessError renders the FailedPrecondition + structured detail
// the SDK consumes to decide between transparent-retry and surfacing.
// The detail is embedded in the status message as a machine-readable
// prefix so SDKs can parse it without a registered proto ErrorDetail.
func buildStalenessError(current, supplied uint64) error {
	msg := fmt.Sprintf("manifest_version_stale current=%d supplied=%d", current, supplied)
	return status.Error(codes.FailedPrecondition, msg)
}

// ParseStalenessError is the SDK-side counterpart: given a gRPC error,
// returns (current, supplied, true) if it is a manifest-stale error,
// else (_, _, false). Lives daemon-side so both daemon tests and SDK
// tests can import it.
func ParseStalenessError(err error) (current, supplied uint64, ok bool) {
	st, is := status.FromError(err)
	if !is || st.Code() != codes.FailedPrecondition {
		return 0, 0, false
	}
	msg := st.Message()
	const prefix = "manifest_version_stale "
	i := strings.Index(msg, prefix)
	if i < 0 {
		return 0, 0, false
	}
	body := msg[i+len(prefix):]
	parts := strings.Fields(body)
	for _, p := range parts {
		switch {
		case strings.HasPrefix(p, "current="):
			v, perr := strconv.ParseUint(strings.TrimPrefix(p, "current="), 10, 64)
			if perr == nil {
				current = v
			}
		case strings.HasPrefix(p, "supplied="):
			v, perr := strconv.ParseUint(strings.TrimPrefix(p, "supplied="), 10, 64)
			if perr == nil {
				supplied = v
			}
		}
	}
	return current, supplied, true
}
