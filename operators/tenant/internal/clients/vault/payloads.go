/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// payloads.go: typed per-store credential writers + deletes peering the
// existing WriteInfraNeo4j/DeleteInfraNeo4j pattern in namespace.go.
//
// Each writer marshals a typed payload struct from
// gibson/pkg/platform/dataplane and POSTs to the canonical Vault path
// (secret/data/<VaultPathPrefix>/<infra-suffix>). Idempotent.
//
// Spec: tenant-provisioning-unification-phase2 Requirement 1 +
// design.md Component 4.

package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// kvWritePayload wraps a base64-encoded value blob in Vault KV v2's
// `{"data": {"value": "..."}}` envelope. We use the same single-`value`
// field shape the SDK secrets broker's Vault provider reads from
// (core/sdk/secrets/providers/vault/provider.go:127), so the daemon can
// fetch operator-written credentials via broker.Get without any custom
// Vault parsing.
type kvWritePayload struct {
	Data struct {
		Value string `json:"value"`
	} `json:"data"`
}

// writeInfraSecret marshals payload to JSON, base64-encodes it, and
// writes `{"data":{"value":"<base64>"}}` to the canonical Vault path.
// The daemon-side broker.Get returns the raw JSON bytes (after
// base64-decoding the value) for the caller to unmarshal back into a
// pdataplane.*Credentials struct.
//
// The single-blob shape (rather than splaying fields into separate KV
// keys) gives us atomic writes — operator failure mid-call cannot
// produce partial credentials.
func (c *httpClient) writeInfraSecret(ctx context.Context, tenantID, infraSuffix string, payload any) error {
	if err := validateTenantID(tenantID); err != nil {
		return err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("vault: marshal credentials payload: %w", err)
	}
	var body kvWritePayload
	body.Data.Value = base64.StdEncoding.EncodeToString(raw)

	ns := joinNamespace(c.cfg.RootNamespace, tenantNamespacePath(tenantID))
	return c.do(ctx, http.MethodPost, "/v1/secret/data/"+infraSuffix, ns, body, nil)
}

// deleteInfraSecret is the shared delete path. 404 is success
// (idempotent — secret already gone).
func (c *httpClient) deleteInfraSecret(ctx context.Context, tenantID, infraSuffix string) error {
	if err := validateTenantID(tenantID); err != nil {
		return err
	}
	ns := joinNamespace(c.cfg.RootNamespace, tenantNamespacePath(tenantID))
	err := c.do(ctx, http.MethodDelete, "/v1/secret/metadata/"+infraSuffix, ns, nil, nil)
	if err == nil || errors.Is(err, clients.ErrNotFound) {
		return nil
	}
	return err
}

// WriteInfraPostgres writes the per-tenant Postgres credentials to
// tenant/<id>/infra/postgres. Idempotent.
func (c *httpClient) WriteInfraPostgres(ctx context.Context, tenantID string, creds pdataplane.PostgresCredentials) error {
	return c.writeInfraSecret(ctx, tenantID, pdataplane.VaultPathInfraPostgres, creds)
}

// DeleteInfraPostgres removes the per-tenant Postgres credentials.
// Idempotent.
func (c *httpClient) DeleteInfraPostgres(ctx context.Context, tenantID string) error {
	return c.deleteInfraSecret(ctx, tenantID, pdataplane.VaultPathInfraPostgres)
}

// WriteInfraRedis writes the per-tenant Redis credentials to
// tenant/<id>/infra/redis. Idempotent.
func (c *httpClient) WriteInfraRedis(ctx context.Context, tenantID string, creds pdataplane.RedisCredentials) error {
	return c.writeInfraSecret(ctx, tenantID, pdataplane.VaultPathInfraRedis, creds)
}

// DeleteInfraRedis removes the per-tenant Redis credentials. Idempotent.
func (c *httpClient) DeleteInfraRedis(ctx context.Context, tenantID string) error {
	return c.deleteInfraSecret(ctx, tenantID, pdataplane.VaultPathInfraRedis)
}

// WriteInfraVector writes the per-tenant Qdrant credentials to
// tenant/<id>/infra/vector. Idempotent.
func (c *httpClient) WriteInfraVector(ctx context.Context, tenantID string, creds pdataplane.VectorCredentials) error {
	return c.writeInfraSecret(ctx, tenantID, pdataplane.VaultPathInfraVector, creds)
}

// DeleteInfraVector removes the per-tenant Qdrant credentials.
// Idempotent.
func (c *httpClient) DeleteInfraVector(ctx context.Context, tenantID string) error {
	return c.deleteInfraSecret(ctx, tenantID, pdataplane.VaultPathInfraVector)
}

// WriteInfraNeo4jCredentials writes the typed Neo4jCredentials payload
// (BoltURI + Username + Password) to tenant/<id>/infra/neo4j. The
// daemon reads this with a single broker.Get and unmarshals into the
// matching struct — no registry-table lookup needed for bolt URI.
// Spec tenant-provisioning-unification-phase2 Requirement 1.7.
func (c *httpClient) WriteInfraNeo4jCredentials(ctx context.Context, tenantID string, creds pdataplane.Neo4jCredentials) error {
	return c.writeInfraSecret(ctx, tenantID, pdataplane.VaultPathInfraNeo4j, creds)
}

