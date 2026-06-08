package daemon

// plugin_admin_adapters.go wires the concrete daemon dependencies into the
// narrow interfaces declared by internal/admin.PluginsAdminConfig so that
// NewPluginsAdminServer can be called from buildGRPCServer.
//
// Three thin adapters live here:
//
//  1. componentInstallRegistryReaderAdapter — wraps component.ComponentInstallRegistry (which
//     has ListInstalls(tenant, name) and Status) to satisfy the
//     admin.PluginRegistryReader interface (ListAll, Get).
//
//  2. secretWriterAdapter — wraps secrets.Service (tenant extracted from ctx)
//     to satisfy admin.SecretWriter (tenant-explicit Put/Delete/Exists).
//
//  3. idpPluginPrincipalAdapter — wraps idp.AdminClient to satisfy
//     admin.ZitadelPluginPrincipalClient (CreatePrincipal / DeletePrincipal).
//
// No new external dependencies are introduced — every adapter is backed by
// an already-constructed daemon field wired in buildGRPCServer.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/zeroroot-ai/gibson/internal/admin"
	"github.com/zeroroot-ai/gibson/internal/idp"
	"github.com/zeroroot-ai/gibson/internal/secrets"
	sdksecrets "github.com/zeroroot-ai/platform-clients/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// 1. componentInstallRegistryReaderAdapter
// ---------------------------------------------------------------------------

// componentInstallRegistryReaderAdapter adapts the daemon's platformDB (same Postgres
// instance the ComponentInstallRegistry uses) to admin.PluginRegistryReader. We query
// the plugin_install table directly so we can implement the ListAll and Get
// operations needed by the admin surface without extending the
// component.ComponentInstallRegistry interface.
//
// The adapter is read-only and does not touch Redis transient state — the
// admin dashboard cares about install metadata, not live liveness status.
// Status is reported as "serving" for all rows (the liveness model is the
// component.ComponentInstallRegistry's concern).
type componentInstallRegistryReaderAdapter struct {
	db *sql.DB
}

var _ admin.PluginRegistryReader = (*componentInstallRegistryReaderAdapter)(nil)

// ListAll returns all plugin_install rows for the given tenant. It does not
// check Redis transient state — the admin surface needs the full list including
// installs whose hosts are currently offline.
func (a *componentInstallRegistryReaderAdapter) ListAll(ctx context.Context, tenant auth.TenantID) ([]admin.ComponentInstallInfo, error) {
	const q = `
SELECT id, tenant_id, plugin_name, version, declared_methods,
       runtime_mode, setec_required, created_at
FROM   plugin_install
WHERE  tenant_id = $1
ORDER BY created_at`

	rows, err := a.db.QueryContext(ctx, q, tenant.String())
	if err != nil {
		return nil, fmt.Errorf("plugin registry reader: list all for tenant %s: %w", tenant, err)
	}
	defer rows.Close() //nolint:errcheck

	var out []admin.ComponentInstallInfo
	for rows.Next() {
		var (
			info        admin.ComponentInstallInfo
			tenantIDStr string
			methodsJSON []byte
			createdAt   time.Time
		)
		if err := rows.Scan(
			&info.InstallID, &tenantIDStr, &info.Name, &info.Version,
			&methodsJSON, &info.RuntimeMode, &info.SetecRequired, &createdAt,
		); err != nil {
			return nil, fmt.Errorf("plugin registry reader: scan row: %w", err)
		}
		info.TenantID = tenantIDStr
		info.CreatedAt = createdAt
		// Status is best-effort from the admin surface; mark as serving
		// (liveness is the component surface's concern).
		info.Status = "serving"
		if len(methodsJSON) > 0 {
			if jsonErr := json.Unmarshal(methodsJSON, &info.DeclaredMethods); jsonErr != nil {
				// Non-fatal: log by returning an empty methods slice.
				info.DeclaredMethods = nil
			}
		}
		out = append(out, info)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("plugin registry reader: iterate rows: %w", err)
	}
	return out, nil
}

// Get returns a single plugin_install row by install ID and tenant.
func (a *componentInstallRegistryReaderAdapter) Get(ctx context.Context, tenant auth.TenantID, installID string) (*admin.ComponentInstallInfo, error) {
	const q = `
SELECT id, tenant_id, plugin_name, version, declared_methods,
       runtime_mode, setec_required, created_at
FROM   plugin_install
WHERE  tenant_id  = $1
AND    id         = $2
LIMIT 1`

	var (
		info        admin.ComponentInstallInfo
		tenantIDStr string
		methodsJSON []byte
		createdAt   time.Time
	)
	err := a.db.QueryRowContext(ctx, q, tenant.String(), installID).Scan(
		&info.InstallID, &tenantIDStr, &info.Name, &info.Version,
		&methodsJSON, &info.RuntimeMode, &info.SetecRequired, &createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, admin.ErrInstallNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("plugin registry reader: get install %s: %w", installID, err)
	}
	info.TenantID = tenantIDStr
	info.CreatedAt = createdAt
	info.Status = "serving"
	if len(methodsJSON) > 0 {
		_ = json.Unmarshal(methodsJSON, &info.DeclaredMethods)
	}
	return &info, nil
}

// ---------------------------------------------------------------------------
// 2. secretWriterAdapter
// ---------------------------------------------------------------------------

// secretWriterAdapter wraps secrets.Service to satisfy admin.SecretWriter.
// secrets.Service extracts the tenant from the context; our adapter injects
// the explicit tenant parameter into the context before forwarding the call.
type secretWriterAdapter struct {
	svc *secrets.Service
}

var _ admin.SecretWriter = (*secretWriterAdapter)(nil)

func (a *secretWriterAdapter) Put(ctx context.Context, tenant auth.TenantID, name string, value []byte) error {
	return a.svc.Put(auth.WithTenant(ctx, tenant), name, value)
}

func (a *secretWriterAdapter) Delete(ctx context.Context, tenant auth.TenantID, name string) error {
	return a.svc.Delete(auth.WithTenant(ctx, tenant), name)
}

// Exists checks whether a named secret exists by listing the tenant's secrets
// and scanning for the name. This is best-effort — the admin surface declares
// the Exists method but the RegisterPlugin handler does not call it for the
// happy path; it is available for completeness.
func (a *secretWriterAdapter) Exists(ctx context.Context, tenant auth.TenantID, name string) (bool, error) {
	names, err := a.svc.List(auth.WithTenant(ctx, tenant), sdksecrets.Filter{})
	if err != nil {
		return false, err
	}
	for _, n := range names {
		if n == name {
			return true, nil
		}
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// 3. idpPluginPrincipalAdapter
// ---------------------------------------------------------------------------

// idpPluginPrincipalAdapter adapts idp.AdminClient to
// admin.ZitadelPluginPrincipalClient. CreatePrincipal calls
// CreateServiceAccount then MintClientSecret to obtain the bootstrap token;
// DeletePrincipal calls DeleteServiceAccount.
//
// The bootstrap token TTL passed to CreatePrincipal is honoured at the
// caller's discretion — the Zitadel client secret mechanism does not natively
// support TTL-bound secrets. We record the expected expiry and return it to
// the handler so it can be surfaced to the dashboard.
type idpPluginPrincipalAdapter struct {
	client idp.AdminClient
}

var _ admin.ZitadelPluginPrincipalClient = (*idpPluginPrincipalAdapter)(nil)

// CreatePrincipal creates a plugin service-account and mints a one-time
// bootstrap token. The principalID is the IdP-assigned machine-user ID;
// bootstrapToken is the client secret.
func (a *idpPluginPrincipalAdapter) CreatePrincipal(
	ctx context.Context,
	tenant auth.TenantID,
	installID, name string,
	ttl time.Duration,
) (principalID, bootstrapToken string, expiresAt time.Time, err error) {
	saName := fmt.Sprintf("plugin-%s-%s", tenant.String(), installID)
	sa, err := a.client.CreateServiceAccount(ctx, idp.CreateServiceAccountRequest{
		Name:        saName,
		Description: fmt.Sprintf("plugin principal for install %s (%s)", installID, name),
		Role:        idp.RolePlugin,
	})
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("create plugin principal: %w", err)
	}

	// Plugins authenticate via the capability-grant bootstrap (not a raw
	// client_credentials grant), so the loginName-based clientID is not needed
	// here; the principalID stays the user id. Revisit under gibson#643 if the
	// plugin SDK ever does client_credentials.
	_, secret, err := a.client.MintClientSecret(ctx, sa.AccountID)
	if err != nil {
		// Best-effort cleanup — if DeleteServiceAccount fails, the orphaned
		// account will be cleaned up by the rollback path in RegisterPlugin.
		_ = a.client.DeleteServiceAccount(ctx, sa.AccountID)
		return "", "", time.Time{}, fmt.Errorf("mint client secret for plugin principal: %w", err)
	}

	return sa.AccountID, secret, time.Now().UTC().Add(ttl), nil
}

// DeletePrincipal removes the plugin service account from the IdP.
func (a *idpPluginPrincipalAdapter) DeletePrincipal(ctx context.Context, principalID string) error {
	if err := a.client.DeleteServiceAccount(ctx, principalID); err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			return nil // idempotent — already gone
		}
		return fmt.Errorf("delete plugin principal %s: %w", principalID, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// 4. pluginManifestValidator
// ---------------------------------------------------------------------------

// pluginManifestValidator implements admin.PluginManifestValidator by parsing
// the plugin manifest YAML format understood by the daemon (same schema as
// internal/component/testdata/debug-plugin.yaml). It validates required fields
// and returns structured per-field errors on failure.
//
// Expected YAML shape:
//
//	apiVersion: plugin.gibson.zeroroot.ai/v1
//	kind: Plugin
//	metadata:
//	  name: <string>
//	  version: <semver>
//	spec:
//	  runtime: process | pod | setec
//	  methods:
//	    - name: <string>
//	  secrets:          # optional
//	    - name: <string>
//	  policy:           # optional
//	    setec_required: true | false
type pluginManifestValidator struct{}

var _ admin.PluginManifestValidator = (*pluginManifestValidator)(nil)

// pluginManifestYAML mirrors the YAML structure for parsing.
type pluginManifestYAML struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name    string `yaml:"name"`
		Version string `yaml:"version"`
	} `yaml:"metadata"`
	Spec struct {
		Runtime string `yaml:"runtime"`
		Methods []struct {
			Name string `yaml:"name"`
		} `yaml:"methods"`
		Secrets []struct {
			Name string `yaml:"name"`
		} `yaml:"secrets"`
		Policy struct {
			SetecRequired bool `yaml:"setec_required"`
		} `yaml:"policy"`
	} `yaml:"spec"`
}

// Validate parses manifestYAML and returns the validated manifest fields and
// any per-field validation errors.
func (v *pluginManifestValidator) Validate(manifestYAML []byte) (admin.ValidatedManifest, []admin.ManifestValidationError) {
	var raw pluginManifestYAML
	if err := yaml.Unmarshal(manifestYAML, &raw); err != nil {
		return admin.ValidatedManifest{}, []admin.ManifestValidationError{{
			Field:   "manifest",
			Line:    0,
			Code:    "parse_error",
			Message: fmt.Sprintf("failed to parse manifest YAML: %v", err),
		}}
	}

	var errs []admin.ManifestValidationError

	if raw.Metadata.Name == "" {
		errs = append(errs, admin.ManifestValidationError{
			Field:   "metadata.name",
			Code:    "required",
			Message: "metadata.name is required",
		})
	}
	if raw.Metadata.Version == "" {
		errs = append(errs, admin.ManifestValidationError{
			Field:   "metadata.version",
			Code:    "required",
			Message: "metadata.version is required",
		})
	}
	if raw.Spec.Runtime == "" {
		errs = append(errs, admin.ManifestValidationError{
			Field:   "spec.runtime",
			Code:    "required",
			Message: "spec.runtime is required (process | pod | setec)",
		})
	} else {
		switch raw.Spec.Runtime {
		case "process", "pod", "setec":
		default:
			errs = append(errs, admin.ManifestValidationError{
				Field:   "spec.runtime",
				Code:    "invalid_value",
				Message: fmt.Sprintf("spec.runtime must be 'process', 'pod', or 'setec'; got %q", raw.Spec.Runtime),
			})
		}
	}

	if len(raw.Spec.Methods) == 0 {
		errs = append(errs, admin.ManifestValidationError{
			Field:   "spec.methods",
			Code:    "required",
			Message: "spec.methods must declare at least one method",
		})
	}
	for i, m := range raw.Spec.Methods {
		if m.Name == "" {
			errs = append(errs, admin.ManifestValidationError{
				Field:   fmt.Sprintf("spec.methods[%d].name", i),
				Code:    "required",
				Message: "method name is required",
			})
		}
	}

	if len(errs) > 0 {
		return admin.ValidatedManifest{}, errs
	}

	methods := make([]string, 0, len(raw.Spec.Methods))
	for _, m := range raw.Spec.Methods {
		methods = append(methods, m.Name)
	}
	declaredSecrets := make([]string, 0, len(raw.Spec.Secrets))
	for _, s := range raw.Spec.Secrets {
		declaredSecrets = append(declaredSecrets, s.Name)
	}

	hash := sha256.Sum256(manifestYAML)
	return admin.ValidatedManifest{
		Name:            raw.Metadata.Name,
		Version:         raw.Metadata.Version,
		DeclaredMethods: methods,
		DeclaredSecrets: declaredSecrets,
		RuntimeMode:     raw.Spec.Runtime,
		SetecRequired:   raw.Spec.Policy.SetecRequired,
		ManifestHash:    hex.EncodeToString(hash[:]),
	}, nil
}
