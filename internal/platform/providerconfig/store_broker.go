// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providerconfig

import (
	"context"
	"errors"
	"fmt"
	"strings"

	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
)

// secretsServiceIface is the narrow slice of secrets.Service that
// brokerBackedStore needs. Production passes *secrets.Service; tests inject a
// fake. The interface is defined here (not in the secrets package) to keep the
// providerconfig package free of a concrete import cycle.
type secretsServiceIface interface {
	Put(ctx context.Context, name string, value []byte) error
	Resolve(ctx context.Context, name string) ([]byte, error)
	Delete(ctx context.Context, name string) error
	List(ctx context.Context, filter sdksecrets.Filter) ([]string, error)
}

// brokerBackedStore implements ProviderConfigStore by routing:
//   - plaintext metadata (type, model, flags, timestamps) to the per-tenant
//     provider_configs Postgres table via providerConfigDAO.
//   - credentials to the secrets broker (secrets.Service) under keys
//     "provider_cred:<name>:<field>", one key per credential field.
type brokerBackedStore struct {
	pool datapool.Pool
	svc  secretsServiceIface
}

// NewBrokerBackedStore constructs a ProviderConfigStore that stores metadata in
// Postgres and credentials via the secrets broker. Both arguments must be
// non-nil; the function panics on nil so misconfiguration is caught at startup.
func NewBrokerBackedStore(pool datapool.Pool, svc secretsServiceIface) ProviderConfigStore {
	if pool == nil {
		panic("providerconfig: NewBrokerBackedStore: pool must not be nil")
	}
	if svc == nil {
		panic("providerconfig: NewBrokerBackedStore: secretsService must not be nil")
	}
	return &brokerBackedStore{pool: pool, svc: svc}
}

var _ ProviderConfigStore = (*brokerBackedStore)(nil)

// credKeyPrefix returns the secrets-broker key prefix for all credential fields
// of a named provider. Format: "provider_cred:<name>:".
func credKeyPrefix(name string) string {
	return "provider_cred:" + name + ":"
}

// credKey returns the secrets-broker key for a single credential field.
// Format: "provider_cred:<name>:<field>".
func credKey(name, field string) string {
	return credKeyPrefix(name) + field
}

// withTenant injects tenantID into ctx so secrets.Service can extract it.
func withTenant(ctx context.Context, tenantID string) context.Context {
	return auth.ContextWithTenantString(ctx, tenantID)
}

// acquireConn acquires a per-tenant Conn from the pool.
func (s *brokerBackedStore) acquireConn(ctx context.Context, tenantID string) (*datapool.Conn, error) {
	tid, err := auth.NewTenantID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("providerconfig: invalid tenant %q: %w", tenantID, err)
	}
	conn, err := s.pool.For(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("providerconfig: acquire conn for %s: %w", tenantID, err)
	}
	return conn, nil
}

// putCredentials writes each credential field to the secrets broker.
func (s *brokerBackedStore) putCredentials(ctx context.Context, tenantID, name string, creds map[string]string) error {
	tctx := withTenant(ctx, tenantID)
	for field, val := range creds {
		if err := s.svc.Put(tctx, credKey(name, field), []byte(val)); err != nil {
			return fmt.Errorf("providerconfig: put credential %q field %q: %w", name, field, err)
		}
	}
	return nil
}

// getCredentials lists and resolves all credential fields for the provider from
// the secrets broker. Returns an empty (non-nil) map when no credentials exist.
func (s *brokerBackedStore) getCredentials(ctx context.Context, tenantID, name string) (map[string]string, error) {
	tctx := withTenant(ctx, tenantID)
	prefix := credKeyPrefix(name)
	keys, err := s.svc.List(tctx, sdksecrets.Filter{Prefix: prefix})
	if err != nil {
		return nil, fmt.Errorf("providerconfig: list credentials for %q: %w", name, err)
	}
	creds := make(map[string]string, len(keys))
	for _, key := range keys {
		val, err := s.svc.Resolve(tctx, key)
		if err != nil {
			return nil, fmt.Errorf("providerconfig: resolve credential %q: %w", key, err)
		}
		creds[strings.TrimPrefix(key, prefix)] = string(val)
	}
	return creds, nil
}

// deleteCredentials removes all credential fields for the provider from the broker.
func (s *brokerBackedStore) deleteCredentials(ctx context.Context, tenantID, name string) error {
	tctx := withTenant(ctx, tenantID)
	prefix := credKeyPrefix(name)
	keys, err := s.svc.List(tctx, sdksecrets.Filter{Prefix: prefix})
	if err != nil {
		return fmt.Errorf("providerconfig: list credentials for delete %q: %w", name, err)
	}
	for _, key := range keys {
		if err := s.svc.Delete(tctx, key); err != nil {
			return fmt.Errorf("providerconfig: delete credential %q: %w", key, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Lazy migration helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ProviderConfigStore implementation
// ---------------------------------------------------------------------------

func (s *brokerBackedStore) List(ctx context.Context, tenantID string) ([]*ProviderConfig, error) {
	conn, err := s.acquireConn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	dao := newProviderConfigDAO(conn.Postgres)
	metas, err := dao.list(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	result := make([]*ProviderConfig, 0, len(metas))
	for _, meta := range metas {
		creds, err := s.getCredentials(ctx, tenantID, meta.Name)
		if err != nil {
			return nil, err
		}
		result = append(result, AsRecord(meta, creds))
	}
	return result, nil
}

func (s *brokerBackedStore) Get(ctx context.Context, tenantID, name string) (*ProviderConfig, error) {
	conn, err := s.acquireConn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	dao := newProviderConfigDAO(conn.Postgres)
	meta, err := dao.get(ctx, tenantID, name)
	if errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("provider %q: %w", name, ErrNotFound)
	}
	if err != nil {
		return nil, err
	}

	creds, err := s.getCredentials(ctx, tenantID, name)
	if err != nil {
		return nil, err
	}
	return AsRecord(meta, creds), nil
}

func (s *brokerBackedStore) Create(ctx context.Context, tenantID string, input *ProviderConfigInput) (*ProviderConfig, error) {
	if err := validateType(input.Type); err != nil {
		return nil, err
	}

	conn, err := s.acquireConn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	dao := newProviderConfigDAO(conn.Postgres)
	meta, err := dao.insert(ctx, tenantID, input)
	if err != nil {
		return nil, err
	}

	if err := s.putCredentials(ctx, tenantID, input.Name, input.Credentials); err != nil {
		_ = dao.delete(ctx, input.Name) // best-effort rollback of metadata row
		return nil, err
	}

	if input.SetAsDefault {
		_ = dao.setDefault(ctx, input.Name)
	}

	return AsRecord(meta, input.Credentials), nil
}

func (s *brokerBackedStore) Update(ctx context.Context, tenantID, name string, input *ProviderConfigInput) (*ProviderConfig, error) {
	if err := validateType(input.Type); err != nil {
		return nil, err
	}

	conn, err := s.acquireConn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	dao := newProviderConfigDAO(conn.Postgres)
	meta, err := dao.update(ctx, tenantID, name, input)
	if err != nil {
		return nil, err
	}

	if err := s.putCredentials(ctx, tenantID, name, input.Credentials); err != nil {
		return nil, err
	}

	if input.SetAsDefault {
		_ = dao.setDefault(ctx, name)
	}

	return AsRecord(meta, input.Credentials), nil
}

func (s *brokerBackedStore) Delete(ctx context.Context, tenantID, name string) error {
	conn, err := s.acquireConn(ctx, tenantID)
	if err != nil {
		return err
	}
	defer conn.Release()

	dao := newProviderConfigDAO(conn.Postgres)
	if err := dao.delete(ctx, name); err != nil {
		return err
	}

	return s.deleteCredentials(ctx, tenantID, name)
}

func (s *brokerBackedStore) GetDefault(ctx context.Context, tenantID string) (*ProviderConfig, error) {
	conn, err := s.acquireConn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	name, daoErr := newProviderConfigDAO(conn.Postgres).getDefault(ctx)
	conn.Release()
	if daoErr != nil {
		return nil, ErrNotFound
	}
	return s.Get(ctx, tenantID, name)
}

func (s *brokerBackedStore) SetDefault(ctx context.Context, tenantID, name string) error {
	// Verify the provider exists before setting default.
	if _, err := s.Get(ctx, tenantID, name); err != nil {
		return err
	}

	conn, err := s.acquireConn(ctx, tenantID)
	if err != nil {
		return err
	}
	defer conn.Release()

	return newProviderConfigDAO(conn.Postgres).setDefault(ctx, name)
}

func (s *brokerBackedStore) Resolve(ctx context.Context, tenantID, name string) (*DecryptedConfig, error) {
	conn, err := s.acquireConn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	dao := newProviderConfigDAO(conn.Postgres)
	meta, err := dao.get(ctx, tenantID, name)
	if errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("provider %q: %w", name, ErrNotFound)
	}
	if err != nil {
		return nil, err
	}

	creds, err := s.getCredentials(ctx, tenantID, name)
	if err != nil {
		return nil, err
	}

	masked := AsRecord(meta, creds)
	return &DecryptedConfig{
		ProviderConfig: *masked,
		Credentials:    creds,
	}, nil
}
