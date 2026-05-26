package secrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sdksecrets "github.com/zeroroot-ai/platform-clients/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// ServiceRegistry is the narrow interface Service needs from the broker
// registry. Production passes *Registry; tests inject a fake.
type ServiceRegistry interface {
	For(ctx context.Context, tenant auth.TenantID) (sdksecrets.Broker, error)
}

// ServiceAuditWriter is the narrow interface Service needs to emit audit
// events. The concrete implementation is *AuditWriter.
type ServiceAuditWriter interface {
	Audit(ctx context.Context, event AuditEvent)
}

// Service is the single entry point that gRPC handlers call for all secrets
// operations. It extracts the tenant from the request context, resolves the
// appropriate SecretsBroker via the registry, enforces the circuit breaker,
// and emits audit events on every operation.
//
// Service is safe for concurrent use.
//
// All methods on Service derive the tenant from the context set by the SDK
// auth interceptor. No method accepts a tenant parameter directly — this
// prevents callers from bypassing tenant isolation.
type Service struct {
	registry ServiceRegistry
	circuit  circuitExecutor
	auditor  ServiceAuditWriter
}

// NewService constructs a Service. All parameters must be non-nil.
func NewService(
	registry ServiceRegistry,
	circuit circuitExecutor,
	auditor ServiceAuditWriter,
) (*Service, error) {
	if registry == nil {
		return nil, errors.New("secrets service: registry must not be nil")
	}
	if circuit == nil {
		return nil, errors.New("secrets service: circuit breaker must not be nil")
	}
	if auditor == nil {
		return nil, errors.New("secrets service: auditor must not be nil")
	}
	return &Service{registry: registry, circuit: circuit, auditor: auditor}, nil
}

// Resolve retrieves the named secret for the tenant extracted from ctx. It
// returns a gRPC status error on failure so callers can forward it directly.
//
// Best-effort plaintext zero: after handing off the returned bytes to the
// gRPC layer (which copies them into the wire buffer), callers should zero
// the slice. This method does NOT zero the slice on return — the gRPC layer
// copies it; zeroing here would race.
func (s *Service) Resolve(ctx context.Context, name string) ([]byte, error) {
	start := time.Now()

	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}

	broker, err := s.registry.For(ctx, tenant)
	if err != nil {
		s.emitAudit(ctx, tenant, name, ActionSecretRead, EffectDeny, false,
			"broker_registry_error", start)
		return nil, toGRPCError(err, "resolve registry")
	}

	pname := providerName(broker)
	var value []byte
	execErr := s.circuit.Execute(tenant.String(), pname, func() error {
		var opErr error
		value, opErr = broker.Get(ctx, tenant, name)
		return opErr
	})

	if execErr != nil {
		if errors.Is(execErr, ErrCircuitOpen) {
			s.emitAuditWithReason(ctx, tenant, name, ActionSecretRead, EffectDeny, false,
				"circuit_open", "circuit_open", start)
			return nil, status.Error(codes.Unavailable, execErr.Error())
		}
		s.emitAuditWithReason(ctx, tenant, name, ActionSecretRead, EffectDeny, false,
			errorClass(execErr), execErr.Error(), start)
		return nil, toGRPCError(execErr, "resolve get")
	}

	s.emitAudit(ctx, tenant, name, ActionSecretRead, EffectAllow, true, "", start)
	return value, nil
}

// Put creates or overwrites the named secret for the tenant from ctx.
func (s *Service) Put(ctx context.Context, name string, value []byte) error {
	start := time.Now()

	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return status.Error(codes.PermissionDenied, "no tenant in context")
	}

	broker, err := s.registry.For(ctx, tenant)
	if err != nil {
		s.emitAudit(ctx, tenant, name, ActionSecretWrite, EffectDeny, false,
			"broker_registry_error", start)
		return toGRPCError(err, "put registry")
	}

	pname := providerName(broker)
	execErr := s.circuit.Execute(tenant.String(), pname, func() error {
		return broker.Put(ctx, tenant, name, value)
	})

	if execErr != nil {
		if errors.Is(execErr, ErrCircuitOpen) {
			s.emitAuditWithReason(ctx, tenant, name, ActionSecretWrite, EffectDeny, false,
				"circuit_open", "circuit_open", start)
			return status.Error(codes.Unavailable, execErr.Error())
		}
		s.emitAuditWithReason(ctx, tenant, name, ActionSecretWrite, EffectDeny, false,
			errorClass(execErr), execErr.Error(), start)
		return toGRPCError(execErr, "put")
	}

	s.emitAudit(ctx, tenant, name, ActionSecretWrite, EffectAllow, true, "", start)
	return nil
}

// Delete removes the named secret for the tenant from ctx.
func (s *Service) Delete(ctx context.Context, name string) error {
	start := time.Now()

	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return status.Error(codes.PermissionDenied, "no tenant in context")
	}

	broker, err := s.registry.For(ctx, tenant)
	if err != nil {
		s.emitAudit(ctx, tenant, name, ActionSecretDelete, EffectDeny, false,
			"broker_registry_error", start)
		return toGRPCError(err, "delete registry")
	}

	pname := providerName(broker)
	execErr := s.circuit.Execute(tenant.String(), pname, func() error {
		return broker.Delete(ctx, tenant, name)
	})

	if execErr != nil {
		if errors.Is(execErr, ErrCircuitOpen) {
			s.emitAuditWithReason(ctx, tenant, name, ActionSecretDelete, EffectDeny, false,
				"circuit_open", "circuit_open", start)
			return status.Error(codes.Unavailable, execErr.Error())
		}
		s.emitAuditWithReason(ctx, tenant, name, ActionSecretDelete, EffectDeny, false,
			errorClass(execErr), execErr.Error(), start)
		return toGRPCError(execErr, "delete")
	}

	s.emitAudit(ctx, tenant, name, ActionSecretDelete, EffectAllow, true, "", start)
	return nil
}

// List returns the names of all secrets for the tenant from ctx that match
// filter.
func (s *Service) List(ctx context.Context, filter sdksecrets.Filter) ([]string, error) {
	start := time.Now()

	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}

	broker, err := s.registry.For(ctx, tenant)
	if err != nil {
		s.emitAudit(ctx, tenant, "*", ActionSecretList, EffectDeny, false,
			"broker_registry_error", start)
		return nil, toGRPCError(err, "list registry")
	}

	pname := providerName(broker)
	var names []string
	execErr := s.circuit.Execute(tenant.String(), pname, func() error {
		var opErr error
		names, opErr = broker.List(ctx, tenant, filter)
		return opErr
	})

	if execErr != nil {
		if errors.Is(execErr, ErrCircuitOpen) {
			s.emitAuditWithReason(ctx, tenant, "*", ActionSecretList, EffectDeny, false,
				"circuit_open", "circuit_open", start)
			return nil, status.Error(codes.Unavailable, execErr.Error())
		}
		s.emitAuditWithReason(ctx, tenant, "*", ActionSecretList, EffectDeny, false,
			errorClass(execErr), execErr.Error(), start)
		return nil, toGRPCError(execErr, "list")
	}

	s.emitAudit(ctx, tenant, "*", ActionSecretList, EffectAllow, true, "", start)
	return names, nil
}

// -------------------------------------------------------------------
// Private helpers
// -------------------------------------------------------------------

// emitAudit emits an allow/deny audit event. resourceURI is derived from the
// tenant and name.
func (s *Service) emitAudit(
	ctx context.Context,
	tenant auth.TenantID,
	name, action, effect string,
	success bool,
	errCode string,
	start time.Time,
) {
	s.emitAuditWithReason(ctx, tenant, name, action, effect, success, errCode, "", start)
}

func (s *Service) emitAuditWithReason(
	ctx context.Context,
	tenant auth.TenantID,
	name, action, effect string,
	success bool,
	errCode, decisionReason string,
	start time.Time,
) {
	decision := "allow"
	if effect == EffectDeny {
		decision = "deny"
	}
	s.auditor.Audit(ctx, AuditEvent{
		ActorTenantID:  tenant.String(),
		Action:         action,
		Effect:         effect,
		ResourceType:   "secret",
		ResourceURI:    fmt.Sprintf("secret:tenant-%s:%s", tenant, name),
		Decision:       decision,
		DecisionReason: decisionReason,
		Success:        success,
		ErrorCode:      errCode,
		LatencyMS:      time.Since(start).Milliseconds(),
		OccurredAt:     time.Now().UTC(),
	})
}

// providerName returns a stable string identifying the provider type for use
// as a circuit breaker key. It introspects the Capabilities to infer the
// name, or falls back to the type name.
func providerName(broker sdksecrets.Broker) string {
	if broker == nil {
		return "unknown"
	}
	// Use a type switch over known provider types. For unknown types (e.g.
	// fakes in tests), we use "unknown" which is still a valid circuit key.
	type named interface{ ProviderName() string }
	if n, ok := broker.(named); ok {
		return n.ProviderName()
	}
	return fmt.Sprintf("%T", broker)
}

// toGRPCError maps secrets package errors to gRPC status codes.
func toGRPCError(err error, op string) error {
	if err == nil {
		return nil
	}
	// Tenant has no row in tenant_secrets_broker_config — the data-plane
	// provisioning saga hasn't seeded credentials for this tenant. This
	// is FailedPrecondition (not Unavailable) so gRPC clients don't
	// retry-loop on a deterministic configuration condition. See
	// gibson#101.
	if errors.Is(err, ErrBrokerConfigNotFound) {
		return status.Errorf(codes.FailedPrecondition, "secrets %s: %v", op, err)
	}
	if errors.Is(err, sdksecrets.ErrNotFound) {
		return status.Errorf(codes.NotFound, "secrets %s: %v", op, err)
	}
	if errors.Is(err, sdksecrets.ErrPermissionDenied) {
		return status.Errorf(codes.PermissionDenied, "secrets %s: %v", op, err)
	}
	if errors.Is(err, sdksecrets.ErrUnavailable) {
		return status.Errorf(codes.Unavailable, "secrets %s: %v", op, err)
	}
	if errors.Is(err, sdksecrets.ErrInvalidArgument) {
		return status.Errorf(codes.InvalidArgument, "secrets %s: %v", op, err)
	}
	if errors.Is(err, sdksecrets.ErrUnsupported) {
		return status.Errorf(codes.FailedPrecondition, "secrets %s: %v", op, err)
	}
	if errors.Is(err, sdksecrets.ErrTooLarge) {
		return status.Errorf(codes.InvalidArgument, "secrets %s: %v", op, err)
	}
	// Default to Unavailable for unclassified errors.
	return status.Errorf(codes.Unavailable, "secrets %s: %v", op, err)
}

// errorClass returns a machine-readable string classifying the error for
// audit DecisionReason / ErrorCode fields.
func errorClass(err error) string {
	if errors.Is(err, sdksecrets.ErrNotFound) {
		return "not_found"
	}
	if errors.Is(err, sdksecrets.ErrPermissionDenied) {
		return "permission_denied"
	}
	if errors.Is(err, sdksecrets.ErrUnavailable) {
		return "unavailable"
	}
	if errors.Is(err, sdksecrets.ErrInvalidArgument) {
		return "invalid_argument"
	}
	if errors.Is(err, sdksecrets.ErrUnsupported) {
		return "unsupported"
	}
	if errors.Is(err, sdksecrets.ErrTooLarge) {
		return "too_large"
	}
	return "internal"
}
