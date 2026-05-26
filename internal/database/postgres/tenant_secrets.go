package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeroroot-ai/gibson/internal/datapool/envelope"
)

// TenantSecretsOps provides encrypted opaque-value storage in the per-tenant
// Postgres database against the unified tenant_secrets table.
//
// Each value is wrapped under the per-tenant KEK via envelope encryption
// (AES Key Wrap DEK + AES-256-GCM). The table is name-keyed with no tenant_id
// column — tenant isolation is implicit in which database the pool connects to.
//
// AAD format: "secret:<name>" — ties the envelope to the logical record so a
// row cannot be renamed without decryption failing.
//
// This type replaces the deleted CredentialOps and PostgresCredentialDAO and
// is the only Postgres DAO for tenant secrets going forward.
//
// Spec: secrets-broker, Phase 2, Task 4.2.
// Requirements: 2.2, 2.6.
type TenantSecretsOps struct {
	pg     *pgxpool.Pool
	kek    []byte
	tenant string // used for metric labels; not a security boundary
}

// NewTenantSecretsOps constructs a TenantSecretsOps bound to the given Postgres
// pool, per-tenant KEK, and tenant label. The caller is responsible for zeroing
// kek after use (the Conn.Release path does this automatically when constructed
// from a Conn).
func NewTenantSecretsOps(pool *pgxpool.Pool, kek []byte, tenant string) *TenantSecretsOps {
	return &TenantSecretsOps{pg: pool, kek: kek, tenant: tenant}
}

// secretAAD returns the additional authenticated data for the named secret.
// AAD ties the ciphertext to the record identity so that rows cannot be
// renamed without decryption failing.
func secretAAD(name string) []byte {
	return []byte("secret:" + name)
}

// ErrTenantSecretNotFound is returned by Get and Delete when the named secret
// does not exist in the tenant's database.
var ErrTenantSecretNotFound = errors.New("tenant secret not found")

// ErrTenantSecretTooLarge is returned by Put when the value exceeds the 1 MiB
// limit declared by ProviderCapabilities.MaxValueBytes. The provider layer maps
// this to secrets.ErrTooLarge.
var ErrTenantSecretTooLarge = errors.New("tenant secret: value too large")

// crossTenantSecretError wraps a cross-tenant decrypt failure. The provider
// layer maps this to secrets.ErrUnavailable and increments the
// gibson_xtenant_decrypt_attempt_total metric.
type crossTenantSecretError struct {
	name  string
	cause error
}

func (e *crossTenantSecretError) Error() string {
	return fmt.Sprintf("secret %q: cross-tenant decrypt failure", e.name)
}

func (e *crossTenantSecretError) Unwrap() error { return e.cause }

// IsCrossTenantSecretError reports whether the error originated from an
// AES-Unwrap authentication failure — the canonical indicator that the Conn's
// KEK does not match the KEK used when the secret was stored.
//
// The broker layer uses this predicate to map the error to secrets.ErrUnavailable
// and increment the gibson_xtenant_decrypt_attempt_total metric.
func IsCrossTenantSecretError(err error) bool {
	var e *crossTenantSecretError
	return errors.As(err, &e)
}

// Put encrypts value under the per-tenant KEK and stores it in tenant_secrets.
// If a secret with the given name already exists it is overwritten (upsert
// semantics). Put enforces the 1 MiB max value size consistent with
// ProviderCapabilities.MaxValueBytes.
func (o *TenantSecretsOps) Put(ctx context.Context, name string, value []byte) error {
	if name == "" {
		return fmt.Errorf("tenant secret: name must not be empty")
	}
	if len(value) == 0 {
		return fmt.Errorf("tenant secret: value must not be empty")
	}
	const maxBytes = 1 << 20 // 1 MiB
	if len(value) > maxBytes {
		return fmt.Errorf("tenant secret: value exceeds 1 MiB limit (%d bytes): %w", len(value), ErrTenantSecretTooLarge)
	}

	env, err := envelope.Encrypt(o.kek, value, secretAAD(name))
	if err != nil {
		return fmt.Errorf("tenant secret: encrypt %q: %w", name, err)
	}

	_, err = o.pg.Exec(ctx,
		`INSERT INTO tenant_secrets (name, envelope, created_at, updated_at)
		 VALUES ($1, $2, now(), now())
		 ON CONFLICT (name) DO UPDATE
		   SET envelope   = EXCLUDED.envelope,
		       updated_at = now()`,
		name, env,
	)
	if err != nil {
		return fmt.Errorf("tenant secret: upsert %q: %w", name, err)
	}
	return nil
}

// Get decrypts and returns the value stored under name.
// Returns ErrTenantSecretNotFound when no secret with that name exists.
// Returns a *crossTenantSecretError when IsCrossTenantDecryptError detects
// a KEK mismatch. Callers (the provider layer) must check IsCrossTenantSecretError
// before returning to the broker so the metric can be incremented.
func (o *TenantSecretsOps) Get(ctx context.Context, name string) ([]byte, error) {
	if name == "" {
		return nil, fmt.Errorf("tenant secret: name must not be empty")
	}

	var env []byte
	err := o.pg.QueryRow(ctx,
		`SELECT envelope FROM tenant_secrets WHERE name = $1`, name,
	).Scan(&env)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("secret %q: %w", name, ErrTenantSecretNotFound)
		}
		return nil, fmt.Errorf("tenant secret: query %q: %w", name, err)
	}

	plaintext, err := envelope.Decrypt(o.kek, env, secretAAD(name))
	if err != nil {
		if envelope.IsCrossTenantDecryptError(err) {
			// Increment the metric here so the detection is co-located with
			// the storage DAO. The tenant label is safe — it is the caller's
			// own tenant, not the tenant that originally encrypted the row.
			recordXTenantDecryptAttempt(o.tenant)
			return nil, &crossTenantSecretError{name: name, cause: err}
		}
		return nil, fmt.Errorf("tenant secret: decrypt %q: %w", name, err)
	}
	return plaintext, nil
}

// Delete removes the secret named name.
// Returns ErrTenantSecretNotFound when no such secret exists.
func (o *TenantSecretsOps) Delete(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("tenant secret: name must not be empty")
	}

	tag, err := o.pg.Exec(ctx,
		`DELETE FROM tenant_secrets WHERE name = $1`, name,
	)
	if err != nil {
		return fmt.Errorf("tenant secret: delete %q: %w", name, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("secret %q: %w", name, ErrTenantSecretNotFound)
	}
	return nil
}

// SecretFilter constrains the results returned by ListNames. It mirrors the
// shape of the secrets.Filter type in the SDK but is defined locally to avoid
// importing the SDK from the database layer.
type SecretFilter struct {
	// Prefix restricts the result to names that start with the given string.
	// An empty Prefix matches all names.
	Prefix string

	// Limit is the maximum number of results to return. Zero means use the
	// default of 100.
	Limit int

	// Offset is the zero-based starting index for pagination.
	Offset int
}

// ListNames returns the names of all secrets in the tenant's database that
// match the supplied filter (applied in-memory for prefix; Limit/Offset are
// pushed down to Postgres). The scan does not decrypt any secrets.
func (o *TenantSecretsOps) ListNames(ctx context.Context, filter *SecretFilter) ([]string, error) {
	limit := 100
	offset := 0
	prefix := ""
	if filter != nil {
		if filter.Limit > 0 {
			limit = filter.Limit
		}
		if filter.Offset > 0 {
			offset = filter.Offset
		}
		prefix = filter.Prefix
	}

	var rows pgx.Rows
	var err error
	if prefix != "" {
		rows, err = o.pg.Query(ctx,
			`SELECT name FROM tenant_secrets WHERE name LIKE $1 ORDER BY name LIMIT $2 OFFSET $3`,
			prefix+"%", limit, offset,
		)
	} else {
		rows, err = o.pg.Query(ctx,
			`SELECT name FROM tenant_secrets ORDER BY name LIMIT $1 OFFSET $2`,
			limit, offset,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("tenant secret: list names: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("tenant secret: scan name: %w", err)
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tenant secret: iterate names: %w", err)
	}
	return names, nil
}
