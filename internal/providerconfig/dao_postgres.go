package providerconfig

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/types"
)

const (
	metaKeyDefault = "__default"
)

// providerConfigDAO is an unexported Postgres DAO for provider config metadata.
// It operates against provider_configs and provider_config_meta tables (migration 007).
// It does NOT handle credentials — those flow through secrets.Service.
type providerConfigDAO struct {
	pg *pgxpool.Pool
}

func newProviderConfigDAO(pg *pgxpool.Pool) *providerConfigDAO {
	return &providerConfigDAO{pg: pg}
}

func (d *providerConfigDAO) insert(ctx context.Context, tenantID string, input *ProviderConfigInput) (*ProviderConfig, error) {
	now := time.Now().UTC()
	id := types.NewID()

	_, err := d.pg.Exec(ctx,
		`INSERT INTO provider_configs (id, name, type, default_model, is_default, enabled, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		string(id), input.Name, string(input.Type), input.DefaultModel,
		input.SetAsDefault, input.Enabled, now, now,
	)
	if err != nil {
		if isPgUniqueViolation(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("dao: insert provider config %q: %w", input.Name, err)
	}

	return &ProviderConfig{
		ID:           id,
		TenantID:     tenantID,
		Name:         input.Name,
		Type:         input.Type,
		DefaultModel: input.DefaultModel,
		IsDefault:    input.SetAsDefault,
		Enabled:      input.Enabled,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// insertMigrated inserts a provider config row from migrated legacy data.
// ON CONFLICT DO NOTHING so repeated migration attempts are idempotent.
func (d *providerConfigDAO) insertMigrated(ctx context.Context, tenantID, name string, p *legacyProviderPayload) (*ProviderConfig, error) {
	id := types.NewID()
	_, err := d.pg.Exec(ctx,
		`INSERT INTO provider_configs (id, name, type, default_model, is_default, enabled, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (name) DO NOTHING`,
		string(id), name, p.Type, p.DefaultModel, p.IsDefault, p.Enabled, p.CreatedAt, p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("dao: migrate insert %q: %w", name, err)
	}
	return &ProviderConfig{
		ID:           id,
		TenantID:     tenantID,
		Name:         name,
		Type:         llm.ProviderType(p.Type),
		DefaultModel: p.DefaultModel,
		IsDefault:    p.IsDefault,
		Enabled:      p.Enabled,
		CreatedAt:    p.CreatedAt,
		UpdatedAt:    p.UpdatedAt,
	}, nil
}

func (d *providerConfigDAO) get(ctx context.Context, tenantID, name string) (*ProviderConfig, error) {
	var id, typ, defaultModel string
	var isDefault, enabled bool
	var createdAt, updatedAt time.Time

	err := d.pg.QueryRow(ctx,
		`SELECT id, type, default_model, is_default, enabled, created_at, updated_at
		 FROM provider_configs WHERE name = $1`, name,
	).Scan(&id, &typ, &defaultModel, &isDefault, &enabled, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("dao: get provider config %q: %w", name, err)
	}

	parsedID, _ := types.ParseID(id)
	return &ProviderConfig{
		ID:           parsedID,
		TenantID:     tenantID,
		Name:         name,
		Type:         llm.ProviderType(typ),
		DefaultModel: defaultModel,
		IsDefault:    isDefault,
		Enabled:      enabled,
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
	}, nil
}

func (d *providerConfigDAO) list(ctx context.Context, tenantID string) ([]*ProviderConfig, error) {
	rows, err := d.pg.Query(ctx,
		`SELECT id, name, type, default_model, is_default, enabled, created_at, updated_at
		 FROM provider_configs ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("dao: list provider configs: %w", err)
	}
	defer rows.Close()

	var configs []*ProviderConfig
	for rows.Next() {
		var id, name, typ, defaultModel string
		var isDefault, enabled bool
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&id, &name, &typ, &defaultModel, &isDefault, &enabled, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("dao: scan provider config row: %w", err)
		}
		parsedID, _ := types.ParseID(id)
		configs = append(configs, &ProviderConfig{
			ID:           parsedID,
			TenantID:     tenantID,
			Name:         name,
			Type:         llm.ProviderType(typ),
			DefaultModel: defaultModel,
			IsDefault:    isDefault,
			Enabled:      enabled,
			CreatedAt:    createdAt,
			UpdatedAt:    updatedAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dao: iterate provider configs: %w", err)
	}
	return configs, nil
}

func (d *providerConfigDAO) update(ctx context.Context, tenantID, name string, input *ProviderConfigInput) (*ProviderConfig, error) {
	now := time.Now().UTC()

	var id string
	var createdAt time.Time
	err := d.pg.QueryRow(ctx,
		`UPDATE provider_configs
		 SET type = $1, default_model = $2, is_default = $3, enabled = $4, updated_at = $5
		 WHERE name = $6
		 RETURNING id, created_at`,
		string(input.Type), input.DefaultModel, input.SetAsDefault, input.Enabled, now, name,
	).Scan(&id, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("dao: update provider config %q: %w", name, err)
	}

	parsedID, _ := types.ParseID(id)
	return &ProviderConfig{
		ID:           parsedID,
		TenantID:     tenantID,
		Name:         name,
		Type:         input.Type,
		DefaultModel: input.DefaultModel,
		IsDefault:    input.SetAsDefault,
		Enabled:      input.Enabled,
		CreatedAt:    createdAt,
		UpdatedAt:    now,
	}, nil
}

func (d *providerConfigDAO) delete(ctx context.Context, name string) error {
	tag, err := d.pg.Exec(ctx, `DELETE FROM provider_configs WHERE name = $1`, name)
	if err != nil {
		return fmt.Errorf("dao: delete provider config %q: %w", name, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *providerConfigDAO) getMetaValue(ctx context.Context, key string) (string, error) {
	var value string
	err := d.pg.QueryRow(ctx,
		`SELECT value FROM provider_config_meta WHERE key = $1`, key,
	).Scan(&value)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("dao: get meta %q: %w", key, err)
	}
	return value, nil
}

func (d *providerConfigDAO) setMetaValue(ctx context.Context, key, value string) error {
	_, err := d.pg.Exec(ctx,
		`INSERT INTO provider_config_meta (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("dao: set meta %q: %w", key, err)
	}
	return nil
}

func (d *providerConfigDAO) getDefault(ctx context.Context) (string, error) {
	return d.getMetaValue(ctx, metaKeyDefault)
}

func (d *providerConfigDAO) setDefault(ctx context.Context, name string) error {
	// Keep the meta pointer (legacy path + GetDefault).
	if err := d.setMetaValue(ctx, metaKeyDefault, name); err != nil {
		return err
	}
	// Also sync provider_configs.is_default so list() returns the right value.
	_, err := d.pg.Exec(ctx,
		`UPDATE provider_configs SET is_default = (name = $1)`,
		name,
	)
	if err != nil {
		return fmt.Errorf("dao: sync is_default column: %w", err)
	}
	return nil
}

// legacyProviderNames returns provider names that still exist in tenant_secrets
// under the old "provider_config:<name>" key format. Meta keys are excluded.
func (d *providerConfigDAO) legacyProviderNames(ctx context.Context) ([]string, error) {
	rows, err := d.pg.Query(ctx,
		`SELECT name FROM tenant_secrets
		 WHERE starts_with(name, 'provider_config:')
		   AND name != 'provider_config:__default'
		 ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("dao: list legacy provider names: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("dao: scan legacy key: %w", err)
		}
		names = append(names, strings.TrimPrefix(key, "provider_config:"))
	}
	return names, rows.Err()
}

// deleteLegacyRow removes the old tenant_secrets row for the provider.
func (d *providerConfigDAO) deleteLegacyRow(ctx context.Context, name string) error {
	_, err := d.pg.Exec(ctx, `DELETE FROM tenant_secrets WHERE name = $1`, "provider_config:"+name)
	return err
}

// isPgUniqueViolation reports whether err is a Postgres unique constraint
// violation (SQLSTATE 23505).
func isPgUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	type pgError interface{ SQLState() string }
	var pe pgError
	if errors.As(err, &pe) {
		return pe.SQLState() == "23505"
	}
	return false
}

// legacyProviderPayload is the JSON blob from old tenant_secrets rows written
// by store_postgres.go (now deleted). Used only in the lazy migration path.
type legacyProviderPayload struct {
	Type         string            `json:"type"`
	DefaultModel string            `json:"default_model"`
	IsDefault    bool              `json:"is_default"`
	Enabled      bool              `json:"enabled"`
	Credentials  map[string]string `json:"credentials"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}
