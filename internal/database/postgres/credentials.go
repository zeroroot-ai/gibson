package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time" // for time.Time in credentialMeta

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zero-day-ai/gibson/internal/datapool/envelope"
	"github.com/zero-day-ai/gibson/internal/types"
)

// CredentialOps provides encrypted credential storage in the per-tenant
// Postgres database. Each secret is wrapped under the per-tenant KEK via
// envelope encryption (AES Key Wrap DEK + AES-256-GCM).
//
// This is the Phase C data-plane model: storage is per-tenant Postgres,
// scoped implicitly by which database the pool connects to. There is no
// tenant_id column.
//
// AAD format: "credential:<name>" — ties the envelope to the logical record
// so a row cannot be moved between tables or renamed without decryption failing.
type CredentialOps struct {
	pg     *pgxpool.Pool
	kek    []byte
	tenant string // used for metric labels; not a security boundary
}

// NewCredentialOps constructs a CredentialOps bound to the given Postgres pool
// and per-tenant KEK. The caller is responsible for zeroing kek after use (the
// Conn.Release path does this automatically when constructed from a Conn).
func NewCredentialOps(pg *pgxpool.Pool, kek []byte) *CredentialOps {
	return &CredentialOps{pg: pg, kek: kek}
}

// NewCredentialOpsWithTenant is like NewCredentialOps but also carries the
// tenant string for metric labels on cross-tenant decrypt failures.
func NewCredentialOpsWithTenant(pg *pgxpool.Pool, kek []byte, tenant string) *CredentialOps {
	return &CredentialOps{pg: pg, kek: kek, tenant: tenant}
}

// credentialAAD returns the additional authenticated data for the named
// credential. AAD ties the ciphertext to the record identity so that rows
// cannot be renamed or moved between tables without decryption failing.
func credentialAAD(name string) []byte {
	return []byte("credential:" + name)
}

// Put encrypts secret under the per-tenant KEK and stores it in Postgres.
// If a credential with the given name already exists it is overwritten
// (upsert semantics).
func (o *CredentialOps) Put(ctx context.Context, name string, secret []byte) error {
	if name == "" {
		return errors.New("credential name must not be empty")
	}
	if len(secret) == 0 {
		return errors.New("credential secret must not be empty")
	}

	env, err := envelope.Encrypt(o.kek, secret, credentialAAD(name))
	if err != nil {
		return fmt.Errorf("credential: encrypt: %w", err)
	}

	_, err = o.pg.Exec(ctx,
		`INSERT INTO credentials (name, envelope, created_at, updated_at)
		 VALUES ($1, $2, now(), now())
		 ON CONFLICT (name) DO UPDATE
		   SET envelope   = EXCLUDED.envelope,
		       updated_at = now()`,
		name, env,
	)
	if err != nil {
		return fmt.Errorf("credential: upsert: %w", err)
	}
	return nil
}

// Get decrypts and returns the secret stored under name.
// Returns ErrCredentialNotFound when no credential with that name exists.
// Returns ErrCredentialDecrypt (wrapping envelope.ErrDecrypt) on AEAD failure.
// When IsCrossTenantDecryptError is true the caller should increment the
// gibson_xtenant_decrypt_attempt_total metric.
func (o *CredentialOps) Get(ctx context.Context, name string) ([]byte, error) {
	if name == "" {
		return nil, errors.New("credential name must not be empty")
	}

	var env []byte
	err := o.pg.QueryRow(ctx,
		`SELECT envelope FROM credentials WHERE name = $1`, name,
	).Scan(&env)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("credential %q: %w", name, ErrCredentialNotFound)
		}
		return nil, fmt.Errorf("credential: query: %w", err)
	}

	plaintext, err := envelope.Decrypt(o.kek, env, credentialAAD(name))
	if err != nil {
		if envelope.IsCrossTenantDecryptError(err) {
			// Requirement 6.5: increment metric and return generic error.
			// The tenant label is safe to include — it's the caller's own tenant,
			// not the target tenant (which is unknown from the failure alone).
			recordXTenantDecryptAttempt(o.tenant)
			return nil, &credentialDecryptError{name: name, crossTenant: true, cause: err}
		}
		return nil, &credentialDecryptError{name: name, crossTenant: false, cause: err}
	}
	return plaintext, nil
}

// Delete removes the credential named name.
// Returns ErrCredentialNotFound when no such credential exists.
func (o *CredentialOps) Delete(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("credential name must not be empty")
	}

	tag, err := o.pg.Exec(ctx,
		`DELETE FROM credentials WHERE name = $1`, name,
	)
	if err != nil {
		return fmt.Errorf("credential: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("credential %q: %w", name, ErrCredentialNotFound)
	}
	return nil
}

// -------------------------------------------------------------------
// Sentinel errors
// -------------------------------------------------------------------

// ErrCredentialNotFound is returned when a Get or Delete targets a name
// that does not exist in the tenant's database.
var ErrCredentialNotFound = errors.New("credential not found")

// credentialDecryptError wraps an envelope decryption failure and exposes
// the cross-tenant flag to DAO callers.
type credentialDecryptError struct {
	name        string
	crossTenant bool
	cause       error
}

func (e *credentialDecryptError) Error() string {
	return fmt.Sprintf("credential %q: decryption failed", e.name)
}

func (e *credentialDecryptError) Unwrap() error { return e.cause }

// IsCrossTenantCredentialError reports whether the error was produced by an
// AES-Unwrap failure — the canonical indicator that the Conn's KEK does not
// match the KEK used when the credential was stored.
func IsCrossTenantCredentialError(err error) bool {
	var de *credentialDecryptError
	if errors.As(err, &de) {
		return de.crossTenant
	}
	return false
}

// ListNames returns the names of all credentials in the tenant's database,
// applying a limit/offset from the provided filter if non-nil. This is a
// lightweight scan that does not decrypt any credentials; it is used by
// CredentialHandler.List to enumerate names for the dashboard API.
func (o *CredentialOps) ListNames(ctx context.Context, filter *types.CredentialFilter) ([]string, error) {
	limit := 100
	offset := 0
	if filter != nil {
		if filter.Limit > 0 {
			limit = filter.Limit
		}
		if filter.Offset > 0 {
			offset = filter.Offset
		}
	}

	rows, err := o.pg.Query(ctx,
		`SELECT name FROM credentials ORDER BY name LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("credential: list names: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("credential: scan name: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("credential: iterate names: %w", err)
	}
	return names, nil
}

// -------------------------------------------------------------------
// CredentialDAO adapter — satisfies the existing interface
// -------------------------------------------------------------------

// credentialMeta is the JSON structure stored in the credential secret for
// the legacy CredentialDAO model. The CredentialOps layer treats the secret
// as an opaque blob; this struct allows PostgresCredentialDAO to encode
// both the plaintext secret value and the non-sensitive metadata in a single
// envelope without needing additional Postgres columns.
type credentialMeta struct {
	PlainValue        string                   `json:"plain_value"`
	Type              string                   `json:"type"`
	Provider          string                   `json:"provider,omitempty"`
	Status            string                   `json:"status"`
	Description       string                   `json:"description,omitempty"`
	Tags              []string                 `json:"tags"`
	Rotation          types.CredentialRotation `json:"rotation"`
	Usage             types.CredentialUsage    `json:"usage"`
	CreatedAt         time.Time                `json:"created_at"`
	UpdatedAt         time.Time                `json:"updated_at"`
	LastUsed          *time.Time               `json:"last_used,omitempty"`
}

// PostgresCredentialDAO wraps CredentialOps to satisfy the legacy CredentialDAO
// interface. This allows existing call sites (DaemonCredentialStore,
// CredentialHandler) to keep working unchanged while the storage layer migrates
// from Redis to per-tenant Postgres with envelope encryption.
//
// The plaintext API key and all metadata are JSON-encoded and stored as the
// "secret" in CredentialOps — a single envelope per credential. This is a
// bridge implementation; Phase D will replace the rich CredentialDAO call sites
// with direct CredentialOps usage.
type PostgresCredentialDAO struct {
	ops *CredentialOps
}

// NewPostgresCredentialDAO constructs a PostgresCredentialDAO.
func NewPostgresCredentialDAO(pg *pgxpool.Pool, kek []byte) *PostgresCredentialDAO {
	return &PostgresCredentialDAO{ops: NewCredentialOps(pg, kek)}
}

// Ensure PostgresCredentialDAO implements CredentialDAO.
var _ CredentialDAO = (*PostgresCredentialDAO)(nil)

func (d *PostgresCredentialDAO) marshalMeta(cred *types.Credential, plainValue string) ([]byte, error) {
	meta := &credentialMeta{
		PlainValue:  plainValue,
		Type:        cred.Type.String(),
		Provider:    cred.Provider,
		Status:      cred.Status.String(),
		Description: cred.Description,
		Tags:        cred.Tags,
		Rotation:    cred.Rotation,
		Usage:       cred.Usage,
		CreatedAt:   cred.CreatedAt,
		UpdatedAt:   cred.UpdatedAt,
		LastUsed:    cred.LastUsed,
	}
	if meta.Tags == nil {
		meta.Tags = []string{}
	}
	return json.Marshal(meta)
}

func (d *PostgresCredentialDAO) unmarshalMeta(name string, data []byte) (*types.Credential, string, error) {
	var meta credentialMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, "", fmt.Errorf("unmarshal credential meta for %q: %w", name, err)
	}
	var credType types.CredentialType
	if err := json.Unmarshal([]byte(`"`+meta.Type+`"`), &credType); err != nil {
		return nil, "", fmt.Errorf("parse credential type %q: %w", meta.Type, err)
	}
	var status types.CredentialStatus
	if err := json.Unmarshal([]byte(`"`+meta.Status+`"`), &status); err != nil {
		return nil, "", fmt.Errorf("parse credential status %q: %w", meta.Status, err)
	}
	cred := &types.Credential{
		ID:          types.NewID(),
		Name:        name,
		Type:        credType,
		Provider:    meta.Provider,
		Status:      status,
		Description: meta.Description,
		Tags:        meta.Tags,
		Rotation:    meta.Rotation,
		Usage:       meta.Usage,
		CreatedAt:   meta.CreatedAt,
		UpdatedAt:   meta.UpdatedAt,
		LastUsed:    meta.LastUsed,
	}
	if cred.Tags == nil {
		cred.Tags = []string{}
	}
	return cred, meta.PlainValue, nil
}

// Create implements CredentialDAO.
func (d *PostgresCredentialDAO) Create(ctx context.Context, cred *types.Credential) error {
	// Validate — but the old validation requires EncryptedValue/IV/Salt which
	// we no longer need. We only require Name and Type.
	if cred.Name == "" {
		return fmt.Errorf("credential name cannot be empty")
	}
	if !cred.Type.IsValid() {
		return fmt.Errorf("invalid credential type: %s", cred.Type)
	}

	// Check for existing credential.
	_, err := d.ops.Get(ctx, cred.Name)
	if err == nil {
		return fmt.Errorf("credential with name %q already exists", cred.Name)
	}
	if !errors.Is(err, ErrCredentialNotFound) {
		return fmt.Errorf("existence check: %w", err)
	}

	// The plaintext value is in EncryptedValue field — it was passed pre-encrypted
	// by the legacy callers, but we store the raw bytes directly since our envelope
	// handles encryption. For bridge compatibility we detect if EncryptedValue
	// is set and treat it as the opaque secret bytes to store.
	// Legacy callers set EncryptedValue+IV+Salt; new callers will use Put directly.
	secret := cred.EncryptedValue
	if len(secret) == 0 {
		// No encrypted value — store metadata only with empty plain value.
		secret = []byte("")
	}

	meta, err := d.marshalMeta(cred, string(secret))
	if err != nil {
		return fmt.Errorf("marshal credential: %w", err)
	}

	return d.ops.Put(ctx, cred.Name, meta)
}

// Get implements CredentialDAO. Returns a credential by a synthetic ID search
// (name-based since we don't have a separate ID index in the simple schema).
func (d *PostgresCredentialDAO) Get(ctx context.Context, id types.ID) (*types.Credential, error) {
	// The simple Postgres schema uses name as the primary key. Since we don't
	// have an ID index, we implement Get(id) as a scan — this is a bridge
	// implementation. Phase D will replace this call site.
	// For now, return not-found since there's no way to look up by ID.
	_ = id
	return nil, fmt.Errorf("credential: lookup by ID is not supported in Postgres store; use GetByName")
}

// GetByName implements CredentialDAO.
func (d *PostgresCredentialDAO) GetByName(ctx context.Context, name string) (*types.Credential, error) {
	data, err := d.ops.Get(ctx, name)
	if err != nil {
		if errors.Is(err, ErrCredentialNotFound) {
			return nil, fmt.Errorf("credential not found: %s", name)
		}
		return nil, fmt.Errorf("get credential: %w", err)
	}
	cred, plainValue, err := d.unmarshalMeta(name, data)
	if err != nil {
		return nil, err
	}
	// Restore EncryptedValue so legacy callers (DaemonCredentialStore.GetCredential)
	// can call their own Decrypt path if they need it. We store the plain value
	// in EncryptedValue as raw bytes; the legacy callers will receive it correctly.
	cred.EncryptedValue = []byte(plainValue)
	return cred, nil
}

// List implements CredentialDAO. Scans all credential names from Postgres.
func (d *PostgresCredentialDAO) List(ctx context.Context, filter *types.CredentialFilter) ([]*types.Credential, error) {
	limit := 100
	if filter != nil && filter.Limit > 0 {
		limit = filter.Limit
	}
	offset := 0
	if filter != nil && filter.Offset > 0 {
		offset = filter.Offset
	}

	rows, err := d.ops.pg.Query(ctx,
		`SELECT name, envelope FROM credentials ORDER BY name LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	defer rows.Close()

	var results []*types.Credential
	for rows.Next() {
		var name string
		var env []byte
		if err := rows.Scan(&name, &env); err != nil {
			return nil, fmt.Errorf("scan credential row: %w", err)
		}
		data, err := envelope.Decrypt(d.ops.kek, env, credentialAAD(name))
		if err != nil {
			// Skip rows that cannot be decrypted rather than failing the whole list.
			continue
		}
		cred, _, err := d.unmarshalMeta(name, data)
		if err != nil {
			continue
		}

		// Apply in-memory filters.
		if filter != nil {
			if filter.Type != nil && cred.Type != *filter.Type {
				continue
			}
			if filter.Status != nil && cred.Status != *filter.Status {
				continue
			}
			if filter.Provider != nil && cred.Provider != *filter.Provider {
				continue
			}
		}

		results = append(results, cred)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credentials: %w", err)
	}
	return results, nil
}

// Update implements CredentialDAO.
func (d *PostgresCredentialDAO) Update(ctx context.Context, cred *types.Credential) error {
	if cred.Name == "" {
		return fmt.Errorf("credential name cannot be empty")
	}
	secret := cred.EncryptedValue
	if len(secret) == 0 {
		// No new secret — preserve existing by fetching current.
		existing, err := d.GetByName(ctx, cred.Name)
		if err != nil {
			return err
		}
		secret = existing.EncryptedValue
	}
	meta, err := d.marshalMeta(cred, string(secret))
	if err != nil {
		return fmt.Errorf("marshal credential: %w", err)
	}
	return d.ops.Put(ctx, cred.Name, meta)
}

// Delete implements CredentialDAO.
func (d *PostgresCredentialDAO) Delete(ctx context.Context, id types.ID) error {
	// The simple Postgres schema uses name as the primary key; ID-based delete
	// is not supported in this bridge implementation. Phase D replaces callers.
	_ = id
	return fmt.Errorf("credential: delete by ID is not supported in Postgres store; use DeleteByName")
}

// DeleteByName implements CredentialDAO.
func (d *PostgresCredentialDAO) DeleteByName(ctx context.Context, name string) error {
	return d.ops.Delete(ctx, name)
}

// Exists implements CredentialDAO.
func (d *PostgresCredentialDAO) Exists(ctx context.Context, name string) (bool, error) {
	var count int
	err := d.ops.pg.QueryRow(ctx,
		`SELECT count(*) FROM credentials WHERE name = $1`, name,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("exists check: %w", err)
	}
	return count > 0, nil
}

