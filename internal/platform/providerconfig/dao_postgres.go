// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providerconfig

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// providerConfigDAO is an unexported Postgres DAO for provider config metadata.
// It operates against the provider_configs tables (migration 007).
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
		`INSERT INTO provider_configs (id, name, type, default_model, is_default, enabled, capabilities, default_embedding_model, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		string(id), input.Name, string(input.Type), input.DefaultModel,
		input.SetAsDefault, input.Enabled, capabilitiesParam(input.Capabilities), input.DefaultEmbeddingModel, now, now,
	)
	if err != nil {
		if isPgUniqueViolation(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("dao: insert provider config %q: %w", input.Name, err)
	}

	return &ProviderConfig{
		ID:                    id,
		TenantID:              tenantID,
		Name:                  input.Name,
		Type:                  input.Type,
		DefaultModel:          input.DefaultModel,
		IsDefault:             input.SetAsDefault,
		Enabled:               input.Enabled,
		Capabilities:          normalizeCapabilities(input.Capabilities),
		DefaultEmbeddingModel: input.DefaultEmbeddingModel,
		CreatedAt:             now,
		UpdatedAt:             now,
	}, nil
}

func (d *providerConfigDAO) get(ctx context.Context, tenantID, name string) (*ProviderConfig, error) {
	var id, typ, defaultModel, defaultEmbeddingModel string
	var isDefault, enabled bool
	var capabilities []string
	var createdAt, updatedAt time.Time

	err := d.pg.QueryRow(ctx,
		`SELECT id, type, default_model, is_default, enabled, capabilities, default_embedding_model, created_at, updated_at
		 FROM provider_configs WHERE name = $1`, name,
	).Scan(&id, &typ, &defaultModel, &isDefault, &enabled, &capabilities, &defaultEmbeddingModel, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("dao: get provider config %q: %w", name, err)
	}

	parsedID, _ := types.ParseID(id)
	return &ProviderConfig{
		ID:                    parsedID,
		TenantID:              tenantID,
		Name:                  name,
		Type:                  llm.ProviderType(typ),
		DefaultModel:          defaultModel,
		IsDefault:             isDefault,
		Enabled:               enabled,
		Capabilities:          normalizeCapabilities(capabilities),
		DefaultEmbeddingModel: defaultEmbeddingModel,
		CreatedAt:             createdAt,
		UpdatedAt:             updatedAt,
	}, nil
}

func (d *providerConfigDAO) list(ctx context.Context, tenantID string) ([]*ProviderConfig, error) {
	rows, err := d.pg.Query(ctx,
		`SELECT id, name, type, default_model, is_default, enabled, capabilities, default_embedding_model, created_at, updated_at
		 FROM provider_configs ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("dao: list provider configs: %w", err)
	}
	defer rows.Close()

	var configs []*ProviderConfig
	for rows.Next() {
		var id, name, typ, defaultModel, defaultEmbeddingModel string
		var isDefault, enabled bool
		var capabilities []string
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&id, &name, &typ, &defaultModel, &isDefault, &enabled, &capabilities, &defaultEmbeddingModel, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("dao: scan provider config row: %w", err)
		}
		parsedID, _ := types.ParseID(id)
		configs = append(configs, &ProviderConfig{
			ID:                    parsedID,
			TenantID:              tenantID,
			Name:                  name,
			Type:                  llm.ProviderType(typ),
			DefaultModel:          defaultModel,
			IsDefault:             isDefault,
			Enabled:               enabled,
			Capabilities:          normalizeCapabilities(capabilities),
			DefaultEmbeddingModel: defaultEmbeddingModel,
			CreatedAt:             createdAt,
			UpdatedAt:             updatedAt,
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
		 SET type = $1, default_model = $2, is_default = $3, enabled = $4, capabilities = $5, default_embedding_model = $6, updated_at = $7
		 WHERE name = $8
		 RETURNING id, created_at`,
		string(input.Type), input.DefaultModel, input.SetAsDefault, input.Enabled,
		capabilitiesParam(input.Capabilities), input.DefaultEmbeddingModel, now, name,
	).Scan(&id, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("dao: update provider config %q: %w", name, err)
	}

	parsedID, _ := types.ParseID(id)
	return &ProviderConfig{
		ID:                    parsedID,
		TenantID:              tenantID,
		Name:                  name,
		Type:                  input.Type,
		DefaultModel:          input.DefaultModel,
		IsDefault:             input.SetAsDefault,
		Enabled:               input.Enabled,
		Capabilities:          normalizeCapabilities(input.Capabilities),
		DefaultEmbeddingModel: input.DefaultEmbeddingModel,
		CreatedAt:             createdAt,
		UpdatedAt:             now,
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

// getDefault returns the name of the provider flagged is_default. The column
// is the one source: the provider_config_meta key/value pointer that used to
// shadow it left with gibson#505 (tenant migration 012).
func (d *providerConfigDAO) getDefault(ctx context.Context) (string, error) {
	var name string
	err := d.pg.QueryRow(ctx,
		`SELECT name FROM provider_configs WHERE is_default ORDER BY updated_at DESC LIMIT 1`,
	).Scan(&name)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("dao: get default: %w", err)
	}
	return name, nil
}

func (d *providerConfigDAO) setDefault(ctx context.Context, name string) error {
	_, err := d.pg.Exec(ctx,
		`UPDATE provider_configs SET is_default = (name = $1)`,
		name,
	)
	if err != nil {
		return fmt.Errorf("dao: sync is_default column: %w", err)
	}
	return nil
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

// normalizeCapabilities lower-cases, trims, de-duplicates and drops empty
// capability strings. A nil/empty input yields nil, which means chat-only,
// so round-tripping a provider with no declared capabilities is a no-op
// rather than persisting an empty array.
func normalizeCapabilities(caps []string) []string {
	if len(caps) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(caps))
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// capabilitiesParam returns the normalized capabilities as the value bound to a
// Postgres text[] column. pgx encodes a Go []string as text[]; a nil slice
// becomes an empty array, which scans back as nil via normalizeCapabilities.
func capabilitiesParam(caps []string) []string {
	n := normalizeCapabilities(caps)
	if n == nil {
		return []string{}
	}
	return n
}
