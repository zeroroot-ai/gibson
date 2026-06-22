// Package authz is the shared authorization client surface for internal
// zeroroot.ai platform services.
//
// Three primitives live here so that ext-authz, the daemon, the
// tenant-operator, and any future internal service consume the same
// implementation:
//
//   - FGAClient: an OpenFGA client wrapper that enforces a per-call
//     timeout floor BELOW Envoy's ext_authz budget (default 5s). This
//     fixes the historical ext-authz behaviour of passing the Envoy
//     context through to the OpenFGA SDK without a local floor — when
//     OpenFGA stalled, the whole ext_authz request would block until
//     Envoy aborted it, leaving no per-call timeout signal in metrics.
//
//   - ValidateIdentityHeaders: HMAC verification for the
//     X-Gibson-Identity-* header bundle that ext-authz emits and the
//     daemon consumes. HMAC is in addition to the SPIFFE-mTLS channel
//     binding; a defense-in-depth layer for callers that want a
//     cryptographic signal independent of the transport.
//
//   - VerifyCapabilityGrant: JWT verification of the
//     daemon-minted capability-grant tokens that agents carry on
//     harness callbacks. Signature + exp + nbf are checked; the caller
//     supplies the JWKS public-key set fetched out-of-band.
//
// Adoption is intentionally NOT performed by this submodule. The
// service-flip slices (see zeroroot-ai/.github#16-19) move ext-authz,
// the daemon, and the tenant-operator over to this package one at a
// time once it ships.
package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sony/gobreaker"
	"github.com/zeroroot-ai/gibson/internal/infra/resilience"
)

// authzCircuitState is the Prometheus gauge tracking the FGA circuit state.
var authzCircuitState = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "gibson_authz_circuit_state",
		Help: "Current state of the authz FGA circuit breaker (0=closed, 1=open, 2=half-open).",
	},
	[]string{"store_id"},
)

// authzStateToFloat converts gobreaker.State to a numeric gauge value.
func authzStateToFloat(s gobreaker.State) float64 {
	switch s {
	case gobreaker.StateClosed:
		return 0
	case gobreaker.StateOpen:
		return 1
	case gobreaker.StateHalfOpen:
		return 2
	default:
		return -1
	}
}

// EnvoyExtAuthzBudgetDefault is the default Envoy ext_authz filter
// timeout. The FGAClient per-call timeout floor MUST be strictly below
// this value so an OpenFGA stall surfaces as a local timeout (with the
// FGAClient's metrics + span) rather than an opaque Envoy
// upstream-timeout error.
const EnvoyExtAuthzBudgetDefault = 5 * time.Second

// DefaultPerCallTimeout is the default per-call timeout the FGAClient
// applies to every Check (and to any other OpenFGA call wired up
// later). 1.5s comfortably fits inside Envoy's 5s budget while leaving
// headroom for derivation, header signing, and the daemon-side HMAC
// validation that follows the ext_authz reply.
const DefaultPerCallTimeout = 1500 * time.Millisecond

// Tuple is the FGA relationship triple (user, relation, object) in
// OpenFGA's colon-notation: user="user:<uuid>", relation="member",
// object="tenant:<slug>".
type Tuple struct {
	User     string
	Relation string
	Object   string
}

// CheckRequest is a single FGA authorization check.
type CheckRequest struct {
	// User is the FGA user reference, e.g. "user:alice" or
	// "tenant:acme#member".
	User string

	// Relation is the relationship name, e.g. "admin", "member",
	// "can_execute".
	Relation string

	// Object is the FGA object reference, e.g. "tenant:zeroroot-ai".
	Object string

	// ContextualTuples are tuples to merge into the FGA store for the
	// duration of this single Check, without persisting them. Used to
	// evaluate hypothetical permissions ("if user were a member, would
	// they have can_execute?") and for header-derived facts that
	// ext-authz wants to feed into the model on a per-request basis.
	ContextualTuples []Tuple
}

// CheckResponse is the result of a single Check call.
type CheckResponse struct {
	// Allowed is the FGA decision. False on any non-allow result,
	// including denials, model errors, and timeouts.
	Allowed bool
}

// FGAClient is the narrow surface of OpenFGA functionality required by
// internal services on the request hot path. Write-side operations
// (tuple writes, model uploads) are not exposed here — those live in
// the daemon's bootstrap path and the tenant-operator's reconcile loop
// and call the upstream SDK directly.
type FGAClient interface {
	// Check evaluates one authorization decision. The call is
	// wrapped in a context.WithTimeout using the configured per-call
	// timeout; if the parent ctx is already shorter, the shorter
	// deadline wins (context.WithTimeout already honours this).
	//
	// Returns ErrFGATimeout when the call exceeds the per-call
	// timeout, ErrFGAUnavailable for transport errors, and the
	// per-call validation error for empty fields.
	Check(ctx context.Context, req CheckRequest) (CheckResponse, error)

	// Close releases any resources the underlying client holds.
	Close() error
}

// FGAClientOptions configures a new FGAClient.
type FGAClientOptions struct {
	// Endpoint is the OpenFGA HTTP endpoint, including the scheme
	// (e.g. "http://gibson-fga:8080"). If the scheme is missing it
	// defaults to http://.
	Endpoint string

	// StoreID is the OpenFGA store ID (ULID format). Required.
	StoreID string

	// ModelID is the OpenFGA authorization model ID (ULID format).
	// Required.
	ModelID string

	// PerCallTimeout is the per-Check timeout floor. Defaults to
	// DefaultPerCallTimeout (1.5s) when zero. Must be strictly less
	// than the Envoy ext_authz budget (default 5s) — the constructor
	// rejects any value at or above EnvoyExtAuthzBudgetDefault.
	PerCallTimeout time.Duration

	// HTTPClient overrides the default HTTP client. If nil, a fresh
	// client with a Timeout = 2 * PerCallTimeout is used (transport
	// timeout slightly above per-call so the per-call context
	// deadline fires first and surfaces as ErrFGATimeout).
	HTTPClient *http.Client

	// Logger is used for structured debug logging. Defaults to
	// slog.Default() when nil.
	Logger *slog.Logger

	// Circuit configures the gobreaker circuit breaker wrapping every
	// Check call. The zero value applies resilience.DefaultCircuitConfig().
	Circuit resilience.CircuitConfig
}

// fgaClient implements FGAClient over the OpenFGA Go SDK.
type fgaClient struct {
	sdk     *fgaclient.OpenFgaClient
	timeout time.Duration
	logger  *slog.Logger
	cb      *gobreaker.CircuitBreaker
}

// NewFGAClient constructs a new FGAClient.
//
// The constructor validates the options and instantiates the OpenFGA
// SDK client. It does NOT make any Check call during construction; the
// FGA reachability probe is the caller's responsibility (the daemon's
// initAuthorizer() / ext-authz's startup self-check).
func NewFGAClient(opts FGAClientOptions) (FGAClient, error) {
	if opts.Endpoint == "" {
		return nil, fmt.Errorf("authz: FGAClientOptions.Endpoint required")
	}
	if opts.StoreID == "" {
		return nil, fmt.Errorf("authz: FGAClientOptions.StoreID required")
	}
	if opts.ModelID == "" {
		return nil, fmt.Errorf("authz: FGAClientOptions.ModelID required")
	}

	timeout := opts.PerCallTimeout
	if timeout <= 0 {
		timeout = DefaultPerCallTimeout
	}
	if timeout >= EnvoyExtAuthzBudgetDefault {
		return nil, fmt.Errorf(
			"authz: PerCallTimeout (%s) must be strictly less than the Envoy ext_authz budget (%s); a per-call timeout at or above the budget defeats the floor",
			timeout, EnvoyExtAuthzBudgetDefault,
		)
	}

	endpoint := opts.Endpoint
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "http://" + endpoint
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 2 * timeout}
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	sdk, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
		ApiUrl:               endpoint,
		StoreId:              opts.StoreID,
		AuthorizationModelId: opts.ModelID,
		HTTPClient:           httpClient,
	})
	if err != nil {
		return nil, fmt.Errorf("authz: construct FGA SDK client for %q: %w", endpoint, err)
	}

	storeID := opts.StoreID
	cb := resilience.NewBreaker(
		"fga/"+storeID,
		opts.Circuit,
		func(_ string, from, to gobreaker.State) {
			logger.Info("authz: FGA circuit state changed",
				"store_id", storeID,
				"from", from.String(),
				"to", to.String(),
			)
			authzCircuitState.WithLabelValues(storeID).Set(authzStateToFloat(to))
		},
	)

	return &fgaClient{
		sdk:     sdk,
		timeout: timeout,
		logger:  logger,
		cb:      cb,
	}, nil
}

// Check evaluates a single FGA authorization decision.
//
// The call is wrapped in the gobreaker circuit breaker; if the breaker is
// open, ErrFGAUnavailable is returned immediately. The per-call timeout
// (DefaultPerCallTimeout) is applied inside Execute so it is preserved
// regardless of circuit state.
func (c *fgaClient) Check(ctx context.Context, req CheckRequest) (CheckResponse, error) {
	if req.User == "" || req.Relation == "" || req.Object == "" {
		return CheckResponse{}, fmt.Errorf(
			"%w: Check: user=%q relation=%q object=%q — all fields must be non-empty",
			ErrInvalidArgument, req.User, req.Relation, req.Object,
		)
	}

	var result CheckResponse
	_, cbErr := c.cb.Execute(func() (interface{}, error) {
		resp, err := c.doCheck(ctx, req)
		result = resp
		return nil, err
	})

	if cbErr == nil {
		return result, nil
	}
	if errors.Is(cbErr, gobreaker.ErrOpenState) || errors.Is(cbErr, gobreaker.ErrTooManyRequests) {
		return CheckResponse{}, fmt.Errorf("%w: circuit open", ErrFGAUnavailable)
	}
	return CheckResponse{}, cbErr
}

// doCheck performs the actual FGA check with the per-call timeout applied.
func (c *fgaClient) doCheck(ctx context.Context, req CheckRequest) (CheckResponse, error) {
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	body := fgaclient.ClientCheckRequest{
		User:     req.User,
		Relation: req.Relation,
		Object:   req.Object,
	}
	if len(req.ContextualTuples) > 0 {
		body.ContextualTuples = make([]fgaclient.ClientContextualTupleKey, 0, len(req.ContextualTuples))
		for _, t := range req.ContextualTuples {
			body.ContextualTuples = append(body.ContextualTuples, fgaclient.ClientContextualTupleKey{
				User:     t.User,
				Relation: t.Relation,
				Object:   t.Object,
			})
		}
	}

	start := time.Now()
	resp, err := c.sdk.Check(callCtx).Body(body).Execute()
	dur := time.Since(start)

	if err != nil {
		return CheckResponse{}, mapFGAError(callCtx, err)
	}

	allowed := resp.GetAllowed()
	c.logger.Debug("authz: Check",
		"user", req.User,
		"relation", req.Relation,
		"object", req.Object,
		"allowed", allowed,
		"duration_ms", dur.Milliseconds(),
	)
	return CheckResponse{Allowed: allowed}, nil
}

// Close releases the SDK client.
func (c *fgaClient) Close() error {
	// The OpenFGA HTTP SDK has no explicit close; the http.Client's
	// transport cleans up via GC. This is a no-op to satisfy the
	// interface contract.
	return nil
}

// Sentinel errors returned by FGAClient.Check and ValidateIdentityHeaders
// / VerifyCapabilityGrant. Callers distinguish ErrFGATimeout from
// ErrFGAUnavailable to decide whether to retry, and from
// ErrInvalidArgument to short-circuit.
var (
	// ErrFGATimeout fires when a Check exceeds the per-call timeout.
	ErrFGATimeout = errors.New("authz: fga call timed out")

	// ErrFGAUnavailable fires when the FGA service is unreachable or
	// returned a transport-class error.
	ErrFGAUnavailable = errors.New("authz: fga service unavailable")

	// ErrInvalidArgument fires for empty user/relation/object or
	// malformed identity / capability inputs.
	ErrInvalidArgument = errors.New("authz: invalid argument")

	// ErrSkewExceeded fires when ValidateIdentityHeaders finds the
	// bundle's IssuedAt is outside the allowed freshness window. It is
	// intentionally distinct from ErrInvalidArgument so callers can
	// emit a replay-specific metric / log line without string-matching.
	ErrSkewExceeded = errors.New("authz: identity bundle outside freshness window")
)

// mapFGAError converts an SDK error into a typed sentinel error.
//
// Context-deadline-exceeded maps to ErrFGATimeout regardless of how
// the SDK surfaced the error (it sometimes wraps it as a generic
// network error). Other transport-class errors map to
// ErrFGAUnavailable.
func mapFGAError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrFGATimeout, err)
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "context deadline exceeded"),
		strings.Contains(msg, "timeout"),
		strings.Contains(msg, "deadline"):
		return fmt.Errorf("%w: %w", ErrFGATimeout, err)
	case strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "no such host"),
		strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "unavailable"),
		strings.Contains(msg, "eof"),
		strings.Contains(msg, "dial"):
		return fmt.Errorf("%w: %w", ErrFGAUnavailable, err)
	default:
		// Conservative fail-closed: any unknown SDK error is treated
		// as transport-class so callers fail closed at the policy
		// boundary.
		return fmt.Errorf("%w: %w", ErrFGAUnavailable, err)
	}
}
