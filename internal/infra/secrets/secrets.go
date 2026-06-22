// Package secrets provides a tenant-scoped secrets broker with per-(tenant,
// provider) circuit breaking and pluggable backend providers.
//
// The Broker interface mirrors the shape used by the Gibson daemon's
// internal secrets stack so platform-clients can serve as a drop-in
// replacement for OSS-SDK-resident broker code. Daemon-side consumers
// resolve a per-tenant Broker via a registry and invoke
// Get/Put/Delete/List/Health/Probe/Capabilities directly.
//
// Provider implementations live under secrets/vault, secrets/aws,
// secrets/gcp, and secrets/azure. The Vault provider is the only fully-
// wired implementation today; AWS, GCP, and Azure remain stubs whose full
// wiring is a follow-up slice.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sony/gobreaker"
	"github.com/zeroroot-ai/gibson/internal/infra/resilience"
	"github.com/zeroroot-ai/sdk/auth"
)

// Sentinel errors returned by Broker methods. Callers compare with errors.Is.
//
// gRPC code mapping — each error maps to a canonical gRPC status code:
//
//	ErrNotFound         → codes.NotFound
//	ErrPermissionDenied → codes.PermissionDenied
//	ErrUnavailable      → codes.Unavailable
//	ErrInvalidArgument  → codes.InvalidArgument
//	ErrUnsupported      → codes.FailedPrecondition
//	ErrTooLarge         → codes.InvalidArgument
var (
	// ErrNotFound is returned by Get when no secret with the requested
	// name exists for the given tenant.
	ErrNotFound = errors.New("secrets: not found")

	// ErrPermissionDenied is returned when the provider rejects the
	// request at its own authorization layer (distinct from FGA denials
	// at the ext-authz layer).
	ErrPermissionDenied = errors.New("secrets: permission denied")

	// ErrUnavailable is returned for transient backend failures: the
	// backend is unreachable, sealed, throttled, or the per-(tenant,
	// provider) circuit breaker is open. Callers should treat this as
	// retryable with appropriate backoff.
	ErrUnavailable = errors.New("secrets: unavailable")

	// ErrInvalidArgument is returned for malformed names or other invalid
	// inputs that would always fail at this provider regardless of system
	// state.
	ErrInvalidArgument = errors.New("secrets: invalid argument")

	// ErrUnsupported is returned when the caller invokes an operation the
	// provider does not declare in Capabilities().
	ErrUnsupported = errors.New("secrets: operation not supported by this provider")

	// ErrTooLarge is returned by Put when len(value) exceeds the
	// provider's declared MaxValueBytes limit.
	ErrTooLarge = errors.New("secrets: value exceeds provider maximum size")
)

// Prometheus metrics for circuit state.
var (
	secretsCircuitOpenTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_secrets_circuit_open_total",
			Help: "Total number of times the secrets circuit breaker transitioned to Open state.",
		},
		[]string{"tenant", "provider"},
	)

	secretsCircuitState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gibson_secrets_circuit_state",
			Help: "Current state of the secrets circuit breaker (0=closed, 1=open, 2=half-open).",
		},
		[]string{"tenant", "provider"},
	)
)

// stateToFloat converts a gobreaker.State to a numeric gauge value.
func stateToFloat(s gobreaker.State) float64 {
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

// Broker is the single abstraction tenant-aware callers use for named-secret
// CRUD across all supported backends. A single Broker instance is shared
// across all tenant operations in a process; tenant isolation is expressed
// through the auth.TenantID argument on each method.
//
// All implementations MUST be safe for concurrent use from multiple
// goroutines.
type Broker interface {
	// Get retrieves the current value of the named secret for tenant.
	// Returns ErrNotFound when no secret with that name exists.
	// The returned slice is a copy owned by the caller; the provider
	// does not retain a reference.
	Get(ctx context.Context, tenant auth.TenantID, name string) ([]byte, error)

	// Put creates or overwrites the named secret for tenant with value.
	// Returns ErrTooLarge when len(value) exceeds Capabilities().MaxValueBytes.
	// Returns ErrUnsupported when Capabilities().CanPut is false.
	Put(ctx context.Context, tenant auth.TenantID, name string, value []byte) error

	// Delete removes the named secret for tenant. Idempotent: deleting a
	// non-existent secret is a no-op. Returns ErrUnsupported when
	// Capabilities().CanDelete is false.
	Delete(ctx context.Context, tenant auth.TenantID, name string) error

	// List returns the names of all secrets for tenant matching filter.
	// Result is not guaranteed to be in any particular order. Returns
	// ErrUnsupported when Capabilities().CanList is false.
	List(ctx context.Context, tenant auth.TenantID, filter Filter) ([]string, error)

	// Health performs a lightweight liveness check against the provider
	// backend. A non-nil return indicates the backend is unavailable.
	Health(ctx context.Context) error

	// Probe performs a write-read-delete round-trip of a transient canary
	// secret to verify full connectivity and authorization. Any error
	// returned MUST be a structured, redacted diagnostic with no plaintext
	// credential values or auth tokens.
	Probe(ctx context.Context) error

	// Capabilities returns the operations this provider supports. The
	// returned struct is immutable for the lifetime of the provider.
	Capabilities() Capabilities
}

// Capabilities describes which Broker operations a particular provider
// implementation supports.
type Capabilities struct {
	// CanPut reports whether the provider supports Put (create + overwrite).
	CanPut bool

	// CanDelete reports whether the provider supports Delete.
	CanDelete bool

	// CanList reports whether the provider supports List.
	CanList bool

	// CanRotate reports whether the provider supports atomic
	// check-and-set rotation via the Rotater extension interface. Callers
	// type-assert on Rotater when this is true.
	CanRotate bool

	// CanProbe reports whether the provider implements a meaningful Probe
	// (a write-read-delete canary). When false, Probe is a no-op that
	// returns nil.
	CanProbe bool

	// SupportsVersion reports whether the provider natively preserves
	// previous versions of a secret (e.g. Vault KV v2). When true, Get
	// returns the latest version by default; explicit version retrieval
	// is outside this interface version's scope.
	SupportsVersion bool

	// MaxValueBytes is the maximum bytes a single secret value may
	// occupy. Zero means the provider imposes no limit. Providers with
	// inherent backend ceilings (e.g. AWS Secrets Manager's 64 KiB)
	// reflect that ceiling here.
	MaxValueBytes int
}

// Filter constrains the results returned by Broker.List. The zero value of
// Filter means "return all secrets up to any provider-imposed default
// limit". All fields are optional.
type Filter struct {
	// Prefix restricts results to names starting with this string.
	Prefix string

	// Limit hints the maximum number of results per call. Zero means
	// "no caller-specified limit"; the provider's own default applies.
	Limit int

	// Offset is the zero-based starting index for pagination, used with
	// Limit to page through a large result set.
	Offset int
}

// Rotater is an optional extension implemented by providers that support
// atomic check-and-set rotation. Callers should declare CanRotate=true in
// Capabilities() when implementing it, and use a type assertion at the
// call-site:
//
//	if r, ok := broker.(secrets.Rotater); ok && broker.Capabilities().CanRotate {
//	    err = r.Rotate(ctx, tenant, name, oldValue, newValue)
//	}
type Rotater interface {
	Rotate(ctx context.Context, tenant auth.TenantID, name string, oldValue, newValue []byte) error
}

// Closer is implemented by providers that hold long-lived resources
// (e.g. token-renewal goroutines, persistent connections). Callers that
// own the provider's lifecycle should invoke Close at shutdown.
type Closer interface {
	Close() error
}

// circuitKey is the map key for per-(tenant, provider) circuit breakers.
type circuitKey struct {
	tenant   string
	provider string
}

// BrokerOptions configures NewBroker.
type BrokerOptions struct {
	// Provider is the backing provider. Required.
	Provider Broker

	// ProviderName is used together with tenant to scope circuit breakers
	// per (tenant, provider). Required.
	ProviderName string

	// CircuitConfig configures the gobreaker circuit breaker. The zero
	// value applies resilience.DefaultCircuitConfig().
	CircuitConfig resilience.CircuitConfig

	// Logger is used for circuit-state change events. If nil, slog.Default().
	Logger *slog.Logger
}

// circuitBroker wraps a Broker with per-(tenant, provider) circuit breaking
// via gobreaker. It implements Broker by delegating to the inner provider
// after routing through the per-key circuit breaker.
type circuitBroker struct {
	inner        Broker
	providerName string
	cfg          resilience.CircuitConfig
	breakers     sync.Map // circuitKey → *gobreaker.CircuitBreaker
	logger       *slog.Logger
}

// NewBroker wraps opts.Provider with a circuit-breaking Broker. The returned
// Broker exposes the same interface as a raw Provider; callers do not need
// to know that breaker logic is interposed.
func NewBroker(opts BrokerOptions) (Broker, error) {
	if opts.Provider == nil {
		return nil, errors.New("secrets.NewBroker: Provider must not be nil")
	}
	if opts.ProviderName == "" {
		return nil, errors.New("secrets.NewBroker: ProviderName must not be empty")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	cfg := opts.CircuitConfig
	if cfg.ConsecutiveFailures == 0 {
		cfg = resilience.DefaultCircuitConfig()
	}

	return &circuitBroker{
		inner:        opts.Provider,
		providerName: opts.ProviderName,
		cfg:          cfg,
		logger:       opts.Logger.With("component", "secrets_broker", "provider", opts.ProviderName),
	}, nil
}

// breaker returns the per-(tenant, provider) gobreaker, creating it lazily.
func (b *circuitBroker) breaker(tenant string) *gobreaker.CircuitBreaker {
	key := circuitKey{tenant: tenant, provider: b.providerName}
	if v, ok := b.breakers.Load(key); ok {
		return v.(*gobreaker.CircuitBreaker)
	}

	// Construct once; Store races are harmless — we always use whatever was
	// stored, never the locally-created copy on a lost race.
	name := fmt.Sprintf("%s/%s", tenant, b.providerName)
	onStateChange := b.makeOnStateChange(tenant)
	cb := resilience.NewBreaker(name, b.cfg, onStateChange)
	actual, _ := b.breakers.LoadOrStore(key, cb)
	return actual.(*gobreaker.CircuitBreaker)
}

// makeOnStateChange returns a gobreaker OnStateChange callback that updates
// Prometheus metrics for the given tenant/provider pair.
func (b *circuitBroker) makeOnStateChange(tenant string) func(string, gobreaker.State, gobreaker.State) {
	provider := b.providerName
	return func(_ string, from, to gobreaker.State) {
		b.logger.Info("secrets circuit state changed",
			slog.String("tenant", tenant),
			slog.String("provider", provider),
			slog.String("from", from.String()),
			slog.String("to", to.String()),
		)
		if to == gobreaker.StateOpen {
			secretsCircuitOpenTotal.WithLabelValues(tenant, provider).Inc()
		}
		secretsCircuitState.WithLabelValues(tenant, provider).Set(stateToFloat(to))
	}
}

// execute routes fn through the per-(tenant) circuit breaker and maps
// gobreaker.ErrOpenState to ErrUnavailable.
func (b *circuitBroker) execute(tenant string, fn func() (interface{}, error)) error {
	cb := b.breaker(tenant)
	_, err := cb.Execute(fn)
	if err == nil {
		return nil
	}
	if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) {
		return fmt.Errorf("circuit open for tenant=%s provider=%s: %w", tenant, b.providerName, ErrUnavailable)
	}
	return err
}

// Get implements Broker.
func (b *circuitBroker) Get(ctx context.Context, tenant auth.TenantID, name string) ([]byte, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name must not be empty", ErrInvalidArgument)
	}
	var val []byte
	err := b.execute(tenant.String(), func() (interface{}, error) {
		v, e := b.inner.Get(ctx, tenant, name)
		val = v
		return nil, e
	})
	return val, err
}

// Put implements Broker.
func (b *circuitBroker) Put(ctx context.Context, tenant auth.TenantID, name string, value []byte) error {
	if name == "" {
		return fmt.Errorf("%w: name must not be empty", ErrInvalidArgument)
	}
	if !b.inner.Capabilities().CanPut {
		return fmt.Errorf("%w: provider %s does not support Put", ErrUnsupported, b.providerName)
	}
	if max := b.inner.Capabilities().MaxValueBytes; max > 0 && len(value) > max {
		return fmt.Errorf("%w: %d bytes (max %d)", ErrTooLarge, len(value), max)
	}
	return b.execute(tenant.String(), func() (interface{}, error) {
		return nil, b.inner.Put(ctx, tenant, name, value)
	})
}

// Delete implements Broker.
func (b *circuitBroker) Delete(ctx context.Context, tenant auth.TenantID, name string) error {
	if name == "" {
		return fmt.Errorf("%w: name must not be empty", ErrInvalidArgument)
	}
	if !b.inner.Capabilities().CanDelete {
		return fmt.Errorf("%w: provider %s does not support Delete", ErrUnsupported, b.providerName)
	}
	return b.execute(tenant.String(), func() (interface{}, error) {
		return nil, b.inner.Delete(ctx, tenant, name)
	})
}

// List implements Broker.
func (b *circuitBroker) List(ctx context.Context, tenant auth.TenantID, filter Filter) ([]string, error) {
	if !b.inner.Capabilities().CanList {
		return nil, fmt.Errorf("%w: provider %s does not support List", ErrUnsupported, b.providerName)
	}
	var names []string
	err := b.execute(tenant.String(), func() (interface{}, error) {
		n, e := b.inner.List(ctx, tenant, filter)
		names = n
		return nil, e
	})
	return names, err
}

// Health implements Broker.
func (b *circuitBroker) Health(ctx context.Context) error {
	return b.inner.Health(ctx)
}

// Probe implements Broker. Probe bypasses the circuit breaker because it
// is itself the diagnostic mechanism for verifying connectivity.
func (b *circuitBroker) Probe(ctx context.Context) error {
	if !b.inner.Capabilities().CanProbe {
		return nil
	}
	return b.inner.Probe(ctx)
}

// Capabilities implements Broker.
func (b *circuitBroker) Capabilities() Capabilities {
	return b.inner.Capabilities()
}

// Close shuts down the inner provider if it implements Closer.
func (b *circuitBroker) Close() error {
	if c, ok := b.inner.(Closer); ok {
		return c.Close()
	}
	return nil
}
