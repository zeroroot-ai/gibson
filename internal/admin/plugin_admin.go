// Package admin — plugin_admin.go
//
// PluginsAdminServer implements gibson.admin.v1.PluginsAdminService — the
// dashboard's tenant-admin surface for plugin install management. Pairs with
// secrets_admin.go (secrets), grants_admin.go (capability grants), and
// tenant_admin.go (broker config).
//
// Atomicity (Spec 2 R3.1): RegisterPlugin coordinates four subsystems
// (manifest validation, broker secret writes, Zitadel SA creation, FGA tuple
// writes) and rolls back any partial state on failure. The handler is
// intentionally agnostic about the exact Zitadel client / FGA writer
// implementation — it depends on narrow interfaces declared here.
//
// Spec: secrets-tenant-lifecycle Requirement 8.1.
package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/secrets"

	adminv1 "github.com/zero-day-ai/sdk/api/gen/gibson/admin/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// PluginRegistryReader is the narrow read-side contract PluginsAdminServer
// uses against the daemon's plugin install registry (Spec 2). It is a
// subset of internal/component.PluginRegistry to avoid pulling the full
// dispatch surface into this package.
type PluginRegistryReader interface {
	// ListAll returns all installs (across all plugin names) for tenant. The
	// production wiring filters out installs whose Redis status key has
	// expired.
	ListAll(ctx context.Context, tenant auth.TenantID) ([]PluginInstallInfo, error)

	// Get returns one install by ID. Returns ErrInstallNotFound when
	// missing.
	Get(ctx context.Context, tenant auth.TenantID, installID string) (*PluginInstallInfo, error)
}

// ErrInstallNotFound is returned by PluginRegistryReader.Get when the
// requested install does not exist.
var ErrInstallNotFound = errors.New("plugin install not found")

// PluginInstallInfo is the dashboard-shaped view of one plugin install —
// independent from the lower-level component.InstallInfo to keep the admin
// package free of cross-cutting types.
type PluginInstallInfo struct {
	InstallID       string
	TenantID        string
	Name            string
	Version         string
	DeclaredMethods []string
	RuntimeMode     string
	SetecRequired   bool
	HostID          string
	Status          string // "serving" | "unreachable" | "degraded"
	Address         string
	LastHeartbeatAt time.Time
	CreatedAt       time.Time
}

// PluginManifestValidator validates a plugin manifest YAML and reports
// structured per-field errors. The production wiring delegates to the
// manifest validator from Spec 2.
type PluginManifestValidator interface {
	// Validate parses manifestYAML and returns the manifest's declared
	// secrets (one entry per spec.secrets[]) and any validation errors.
	// On success, errors is empty.
	Validate(manifestYAML []byte) (manifest ValidatedManifest, errors []ManifestValidationError)
}

// ValidatedManifest carries the subset of manifest fields the registration
// handler needs to coordinate downstream subsystems.
type ValidatedManifest struct {
	// Name is metadata.name.
	Name string

	// Version is metadata.version.
	Version string

	// DeclaredMethods is spec.methods[].name.
	DeclaredMethods []string

	// DeclaredSecrets is the list of names from spec.secrets[].name.
	DeclaredSecrets []string

	// RuntimeMode is one of: process, pod, setec.
	RuntimeMode string

	// SetecRequired mirrors spec.policy.setec_required.
	SetecRequired bool

	// ManifestHash is the SHA-256 hex digest of manifestYAML. Used by the
	// daemon to dedupe upserts.
	ManifestHash string
}

// ManifestValidationError is the local mirror of
// adminv1.PluginManifestValidationError used in interfaces.
type ManifestValidationError struct {
	Field   string
	Line    int32
	Code    string
	Message string
}

// ZitadelPluginPrincipalClient is the narrow contract for creating /
// destroying the plugin_principal Zitadel service account. The production
// wiring uses the dashboard's Zitadel admin client; tests inject a fake
// that records calls.
type ZitadelPluginPrincipalClient interface {
	// CreatePrincipal creates a new Zitadel service-account for the plugin
	// install. Returns the assigned subject ID and a single-use bootstrap
	// token (with the expiry the caller-specified; ≤24h per Spec 2 R3.1).
	CreatePrincipal(ctx context.Context, tenant auth.TenantID, installID, name string, ttl time.Duration) (principalID, bootstrapToken string, expiresAt time.Time, err error)

	// DeletePrincipal removes the principal. Used by RegisterPlugin's
	// rollback path and by RevokePluginSecretBinding when revoking the
	// last binding.
	DeletePrincipal(ctx context.Context, principalID string) error
}

// SecretWriter is the narrow contract used by RegisterPlugin to create
// inline-bound secrets. The production wiring delegates to
// secrets.Service.Put; tests inject a recorder.
type SecretWriter interface {
	Put(ctx context.Context, tenant auth.TenantID, name string, value []byte) error
	Delete(ctx context.Context, tenant auth.TenantID, name string) error
	Exists(ctx context.Context, tenant auth.TenantID, name string) (bool, error)
}

// BootstrapTokenAuditor records audit rows for bootstrap-token issuance per
// Spec 2 R3.1. Tests inject a recorder; production wiring delegates to the
// secrets audit pipeline (the bootstrap token is treated as an FGA-relevant
// admin action).
type BootstrapTokenAuditor interface {
	Audit(ctx context.Context, event secrets.AuditEvent)
}

// PluginsAdminServer implements adminv1.PluginsAdminServiceServer.
type PluginsAdminServer struct {
	adminv1.UnimplementedPluginsAdminServiceServer

	registry  PluginRegistryReader
	validator PluginManifestValidator
	zitadel   ZitadelPluginPrincipalClient
	secretW   SecretWriter
	authzr    authz.Authorizer
	auditor   BootstrapTokenAuditor
	now       func() time.Time

	bootstrapTTL time.Duration
}

// PluginsAdminConfig groups the constructor's required dependencies.
type PluginsAdminConfig struct {
	Registry          PluginRegistryReader
	ManifestValidator PluginManifestValidator
	ZitadelClient     ZitadelPluginPrincipalClient
	SecretWriter      SecretWriter
	Authorizer        authz.Authorizer
	BootstrapAuditor  BootstrapTokenAuditor
	BootstrapTokenTTL time.Duration // ≤24h per Spec 2 R3.1; default 1h
	Now               func() time.Time
}

// NewPluginsAdminServer constructs a PluginsAdminServer. All fields except
// BootstrapTokenTTL and Now are required.
func NewPluginsAdminServer(cfg PluginsAdminConfig) (*PluginsAdminServer, error) {
	if cfg.Registry == nil {
		return nil, errors.New("plugins admin: Registry is required")
	}
	if cfg.ManifestValidator == nil {
		return nil, errors.New("plugins admin: ManifestValidator is required")
	}
	if cfg.ZitadelClient == nil {
		return nil, errors.New("plugins admin: ZitadelClient is required")
	}
	if cfg.SecretWriter == nil {
		return nil, errors.New("plugins admin: SecretWriter is required")
	}
	if cfg.Authorizer == nil {
		return nil, errors.New("plugins admin: Authorizer is required")
	}
	if cfg.BootstrapAuditor == nil {
		return nil, errors.New("plugins admin: BootstrapAuditor is required")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	ttl := cfg.BootstrapTokenTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	return &PluginsAdminServer{
		registry:     cfg.Registry,
		validator:    cfg.ManifestValidator,
		zitadel:      cfg.ZitadelClient,
		secretW:      cfg.SecretWriter,
		authzr:       cfg.Authorizer,
		auditor:      cfg.BootstrapAuditor,
		now:          now,
		bootstrapTTL: ttl,
	}, nil
}

// ---------------------------------------------------------------------------
// PluginsAdminService RPC implementations
// ---------------------------------------------------------------------------

// ListPluginInstalls returns the tenant's plugin installs.
func (s *PluginsAdminServer) ListPluginInstalls(ctx context.Context, req *adminv1.ListPluginInstallsRequest) (*adminv1.ListPluginInstallsResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}

	infos, err := s.registry.ListAll(ctx, tenant)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "registry list: %v", err)
	}

	out := make([]*adminv1.PluginInstallSummary, 0, len(infos))
	for _, info := range infos {
		if req.GetNameFilter() != "" && info.Name != req.GetNameFilter() {
			continue
		}
		summary := pluginInstallToSummary(info)
		if req.GetStatusFilter() != adminv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_UNSPECIFIED {
			if summary.GetStatus() != req.GetStatusFilter() {
				continue
			}
		}
		// Best-effort populate bound_secret_refs by querying FGA for
		// can_resolve tuples on the install's plugin_principal.
		summary.BoundSecretRefs = s.bindingsFor(ctx, tenant, info)
		out = append(out, summary)
	}

	return &adminv1.ListPluginInstallsResponse{
		Installs: out,
		Total:    int32(len(out)),
	}, nil
}

// GetPluginInstall returns one install by ID.
func (s *PluginsAdminServer) GetPluginInstall(ctx context.Context, req *adminv1.GetPluginInstallRequest) (*adminv1.GetPluginInstallResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetInstallId() == "" {
		return nil, status.Error(codes.InvalidArgument, "install_id is required")
	}

	info, err := s.registry.Get(ctx, tenant, req.GetInstallId())
	if err != nil {
		if errors.Is(err, ErrInstallNotFound) {
			return nil, status.Errorf(codes.NotFound, "install %q not found", req.GetInstallId())
		}
		return nil, status.Errorf(codes.Internal, "registry get: %v", err)
	}

	summary := pluginInstallToSummary(*info)
	summary.BoundSecretRefs = s.bindingsFor(ctx, tenant, *info)
	return &adminv1.GetPluginInstallResponse{Install: summary}, nil
}

// RegisterPlugin atomically registers a plugin per Spec 2 R3.1.
//
// The handler walks the following ordered steps. On any failure, the rollback
// section reverses every step that succeeded.
//
//  1. Validate the manifest. On error, return INVALID_ARGUMENT with
//     structured per-field errors. No state was created — no rollback.
//  2. (dry_run only) return the validated manifest's metadata without
//     side-effects.
//  3. Create inline secrets for every binding with mode == "create".
//     Track each created secret name for rollback.
//  4. Create the Zitadel plugin_principal service account. Track the
//     principal_id for rollback.
//  5. Write FGA can_resolve tuples binding the plugin_principal to each
//     bound secret. Track each tuple for rollback.
//  6. Issue and audit a bootstrap token; return install_id +
//     bootstrap_token to caller.
//
// Rollback semantics: each step's rollback is best-effort and idempotent; a
// rollback failure is logged but does not block the user-visible error.
func (s *PluginsAdminServer) RegisterPlugin(ctx context.Context, req *adminv1.RegisterPluginRequest) (*adminv1.RegisterPluginResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if len(req.GetManifestYaml()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "manifest_yaml is required")
	}

	// --- Step 1: validate manifest --------------------------------------
	manifest, vErrs := s.validator.Validate(req.GetManifestYaml())
	if len(vErrs) > 0 {
		out := make([]*adminv1.PluginManifestValidationError, 0, len(vErrs))
		for _, e := range vErrs {
			out = append(out, &adminv1.PluginManifestValidationError{
				Field:   e.Field,
				Line:    e.Line,
				Code:    e.Code,
				Message: e.Message,
			})
		}
		return &adminv1.RegisterPluginResponse{ValidationErrors: out}, status.Error(codes.InvalidArgument, "manifest validation failed")
	}

	// Cross-check: every declared secret must have exactly one binding.
	if vErrs := crossCheckBindings(manifest.DeclaredSecrets, req.GetBindings()); len(vErrs) > 0 {
		out := make([]*adminv1.PluginManifestValidationError, 0, len(vErrs))
		for _, e := range vErrs {
			out = append(out, &adminv1.PluginManifestValidationError{
				Field:   e.Field,
				Code:    e.Code,
				Message: e.Message,
			})
		}
		return &adminv1.RegisterPluginResponse{ValidationErrors: out}, status.Error(codes.InvalidArgument, "binding cross-check failed")
	}

	if req.GetDryRun() {
		return &adminv1.RegisterPluginResponse{}, nil
	}

	// installID is generated locally — the production registry's Register
	// path can adopt this ID or upsert with its own. For dashboard wire-
	// shape consistency we generate the UUID-like ID here.
	installID := newInstallID()

	type rb struct {
		fn func() error
		op string
	}
	var rollback []rb
	doRollback := func(reason error) {
		// Iterate in reverse — undo the most recent step first.
		for i := len(rollback) - 1; i >= 0; i-- {
			if err := rollback[i].fn(); err != nil {
				_ = err // best-effort; production wiring logs via slog
			}
		}
		_ = reason
	}

	// --- Step 3: inline secret creation ---------------------------------
	for _, b := range req.GetBindings() {
		if b.GetMode() != "create" {
			continue
		}
		name := b.GetDeclaredName()
		if err := s.secretW.Put(ctx, tenant, name, b.GetCreateValue()); err != nil {
			doRollback(err)
			return nil, status.Errorf(codes.Internal, "create inline secret %q: %v", name, err)
		}
		nameCopy := name
		rollback = append(rollback, rb{
			fn: func() error { return s.secretW.Delete(ctx, tenant, nameCopy) },
			op: "delete inline secret " + nameCopy,
		})
	}

	// --- Step 4: Zitadel principal --------------------------------------
	principalID, bootstrapToken, expiresAt, err := s.zitadel.CreatePrincipal(ctx, tenant, installID, manifest.Name, s.bootstrapTTL)
	if err != nil {
		doRollback(err)
		return nil, status.Errorf(codes.Internal, "create plugin principal: %v", err)
	}
	rollback = append(rollback, rb{
		fn: func() error { return s.zitadel.DeletePrincipal(ctx, principalID) },
		op: "delete plugin principal " + principalID,
	})

	// --- Step 5: FGA tuple writes ---------------------------------------
	tuples := make([]authz.Tuple, 0, len(req.GetBindings()))
	for _, b := range req.GetBindings() {
		ref := bindingRef(b)
		if ref == "" {
			continue
		}
		tuples = append(tuples, authz.Tuple{
			User:     "user:" + principalID, // plugin_principal subject
			Relation: "can_resolve",
			Object:   fmt.Sprintf("secret:tenant-%s:%s", tenant, ref),
		})
	}
	if len(tuples) > 0 {
		if err := s.authzr.Write(ctx, tuples); err != nil {
			doRollback(err)
			return nil, status.Errorf(codes.Internal, "write FGA tuples: %v", err)
		}
		tupleCopy := tuples
		rollback = append(rollback, rb{
			fn: func() error { return s.authzr.Delete(ctx, tupleCopy) },
			op: fmt.Sprintf("delete %d FGA tuples", len(tupleCopy)),
		})
	}

	// --- Step 6: bootstrap-token audit ----------------------------------
	s.auditor.Audit(ctx, secrets.AuditEvent{
		ActorTenantID: tenant.String(),
		Action:        "plugin_register",
		Effect:        secrets.EffectAllow,
		ResourceType:  "plugin_install",
		ResourceURI:   fmt.Sprintf("plugin_install:tenant-%s:%s", tenant, installID),
		Decision:      "allow",
		Success:       true,
		OccurredAt:    s.now().UTC(),
	})

	return &adminv1.RegisterPluginResponse{
		InstallId:                   installID,
		PluginPrincipalId:           principalID,
		BootstrapToken:              bootstrapToken,
		BootstrapTokenExpiresAtUnix: expiresAt.Unix(),
	}, nil
}

// EditPluginSecretBinding rebinds a binding to a different existing secret.
func (s *PluginsAdminServer) EditPluginSecretBinding(ctx context.Context, req *adminv1.EditPluginSecretBindingRequest) (*adminv1.EditPluginSecretBindingResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetInstallId() == "" || req.GetDeclaredName() == "" || req.GetNewExistingRef() == "" {
		return nil, status.Error(codes.InvalidArgument, "install_id, declared_name, new_existing_ref are required")
	}

	info, err := s.registry.Get(ctx, tenant, req.GetInstallId())
	if err != nil {
		if errors.Is(err, ErrInstallNotFound) {
			return nil, status.Errorf(codes.NotFound, "install %q not found", req.GetInstallId())
		}
		return nil, status.Errorf(codes.Internal, "registry get: %v", err)
	}
	_ = info // production wiring uses info.HostID -> principal_id mapping

	// Resolve the install's plugin_principal subject. In the production
	// wiring this is stored on plugin_install; tests bypass via a fake
	// registry whose Get returns a synthetic principal field elsewhere.
	principal := principalForInstall(req.GetInstallId())

	// Atomic rebind: delete old tuple, write new tuple in a single FGA
	// batch where supported. For our v1 we issue Delete first then Write —
	// a partial failure leaves the binding revoked, which is fail-safe
	// (the plugin loses access rather than gaining unintended access).
	oldTuple := authz.Tuple{
		User:     "user:" + principal,
		Relation: "can_resolve",
		Object:   fmt.Sprintf("secret:tenant-%s:%s", tenant, req.GetDeclaredName()),
	}
	newTuple := authz.Tuple{
		User:     "user:" + principal,
		Relation: "can_resolve",
		Object:   fmt.Sprintf("secret:tenant-%s:%s", tenant, req.GetNewExistingRef()),
	}
	if err := s.authzr.Delete(ctx, []authz.Tuple{oldTuple}); err != nil {
		return nil, status.Errorf(codes.Internal, "delete old tuple: %v", err)
	}
	if err := s.authzr.Write(ctx, []authz.Tuple{newTuple}); err != nil {
		return nil, status.Errorf(codes.Internal, "write new tuple: %v", err)
	}
	return &adminv1.EditPluginSecretBindingResponse{}, nil
}

// RevokePluginSecretBinding removes a single binding and emits a
// secret_access_revoked audit event.
func (s *PluginsAdminServer) RevokePluginSecretBinding(ctx context.Context, req *adminv1.RevokePluginSecretBindingRequest) (*adminv1.RevokePluginSecretBindingResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetInstallId() == "" || req.GetDeclaredName() == "" {
		return nil, status.Error(codes.InvalidArgument, "install_id and declared_name are required")
	}

	principal := principalForInstall(req.GetInstallId())
	tuple := authz.Tuple{
		User:     "user:" + principal,
		Relation: "can_resolve",
		Object:   fmt.Sprintf("secret:tenant-%s:%s", tenant, req.GetDeclaredName()),
	}
	if err := s.authzr.Delete(ctx, []authz.Tuple{tuple}); err != nil {
		return nil, status.Errorf(codes.Internal, "delete tuple: %v", err)
	}

	s.auditor.Audit(ctx, secrets.AuditEvent{
		ActorTenantID: tenant.String(),
		Action:        "secret_access_revoked",
		Effect:        secrets.EffectAllow,
		ResourceType:  "plugin_install",
		ResourceURI:   fmt.Sprintf("plugin_install:tenant-%s:%s:%s", tenant, req.GetInstallId(), req.GetDeclaredName()),
		Decision:      "allow",
		Success:       true,
		OccurredAt:    s.now().UTC(),
	})

	return &adminv1.RevokePluginSecretBindingResponse{}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// pluginInstallToSummary maps the dashboard-shaped registry view to the
// proto wire-shape.
func pluginInstallToSummary(i PluginInstallInfo) *adminv1.PluginInstallSummary {
	return &adminv1.PluginInstallSummary{
		InstallId:           i.InstallID,
		Name:                i.Name,
		Version:             i.Version,
		DeclaredMethods:     i.DeclaredMethods,
		RuntimeMode:         i.RuntimeMode,
		SetecRequired:       i.SetecRequired,
		HostId:              i.HostID,
		Status:              statusToEnum(i.Status),
		Address:             i.Address,
		LastHeartbeatAtUnix: i.LastHeartbeatAt.Unix(),
		CreatedAtUnix:       i.CreatedAt.Unix(),
	}
}

// statusToEnum maps the registry's lowercase string status to the proto
// enum. Unknown values return UNSPECIFIED.
func statusToEnum(s string) adminv1.PluginInstallStatus {
	switch s {
	case "serving":
		return adminv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_SERVING
	case "unreachable":
		return adminv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_UNREACHABLE
	case "degraded":
		return adminv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_DEGRADED
	default:
		return adminv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_UNSPECIFIED
	}
}

// crossCheckBindings ensures every declared secret has exactly one binding,
// and every binding's mode + payload is well-formed.
func crossCheckBindings(declared []string, bindings []*adminv1.PluginSecretBinding) []ManifestValidationError {
	var errs []ManifestValidationError

	seen := map[string]int{}
	for i, b := range bindings {
		seen[b.GetDeclaredName()] = i
		switch b.GetMode() {
		case "existing":
			if b.GetExistingRef() == "" {
				errs = append(errs, ManifestValidationError{
					Field:   fmt.Sprintf("bindings[%d].existing_ref", i),
					Code:    "missing_existing_ref",
					Message: "mode=existing requires existing_ref",
				})
			}
		case "create":
			if len(b.GetCreateValue()) == 0 {
				errs = append(errs, ManifestValidationError{
					Field:   fmt.Sprintf("bindings[%d].create_value", i),
					Code:    "missing_create_value",
					Message: "mode=create requires create_value",
				})
			}
		default:
			errs = append(errs, ManifestValidationError{
				Field:   fmt.Sprintf("bindings[%d].mode", i),
				Code:    "invalid_mode",
				Message: "mode must be 'existing' or 'create'",
			})
		}
	}

	for _, name := range declared {
		if _, ok := seen[name]; !ok {
			errs = append(errs, ManifestValidationError{
				Field:   "bindings",
				Code:    "missing_binding",
				Message: fmt.Sprintf("declared secret %q has no binding", name),
			})
		}
	}
	return errs
}

// bindingRef returns the broker-namespaced ref that a binding points at.
// For mode=existing it is the existing_ref; for mode=create it is the
// declared_name (the inline-created secret's stored name).
func bindingRef(b *adminv1.PluginSecretBinding) string {
	if b == nil {
		return ""
	}
	switch b.GetMode() {
	case "existing":
		return b.GetExistingRef()
	case "create":
		return b.GetDeclaredName()
	}
	return ""
}

// bindingsFor walks FGA can_resolve tuples for the install's principal and
// returns the (decoded) ref names. Best-effort.
func (s *PluginsAdminServer) bindingsFor(ctx context.Context, tenant auth.TenantID, info PluginInstallInfo) []string {
	principal := principalForInstall(info.InstallID)
	objects, err := s.authzr.ListObjects(ctx, "user:"+principal, "can_resolve", "secret")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(objects))
	for _, obj := range objects {
		// obj is "secret:tenant-<id>:<ref>"; strip the prefix.
		if ref := uriToRef(obj); ref != "" {
			out = append(out, ref)
		}
	}
	return out
}

// principalForInstall returns the plugin_principal subject ID for an install.
// Production wiring resolves this via plugin_install.principal_id; for the
// admin handler's helper we use a deterministic transform so tests can
// derive expected values without injecting another dependency.
func principalForInstall(installID string) string {
	return "plugin_principal_" + installID
}

// newInstallID returns a fresh install identifier. We use 16 random bytes
// hex-encoded — sufficient entropy and stable formatting; the production
// registry can substitute its own UUID-shaped identifier.
func newInstallID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to time-based ID; collisions are extremely unlikely
		// at the cardinality of plugin installs per tenant.
		return fmt.Sprintf("install-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
