package database

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// RedisCredentialDAO provides Redis-based storage for Credential entities.
// It uses RedisJSON for document storage and RediSearch for efficient querying.
//
// Key naming convention:
//   - Credential document: "gibson:credential:{id}"
//   - Name lookup: "gibson:credential:by_name:{name}" -> ID
//
// Security considerations:
//   - Encrypted fields (EncryptedValue, EncryptionIV, KeyDerivationSalt) are stored as base64-encoded strings
//   - These encrypted fields are NEVER indexed in RediSearch
//   - Name uniqueness is enforced using a separate lookup key
//   - All operations use pipelines for atomicity where required
type RedisCredentialDAO struct {
	client *state.StateClient
}

// credentialDocument represents the JSON structure stored in Redis.
// Binary encrypted fields are base64-encoded for JSON compatibility.
type credentialDocument struct {
	ID                string                   `json:"id"`
	Name              string                   `json:"name"`
	Type              string                   `json:"type"`
	Provider          string                   `json:"provider,omitempty"`
	Status            string                   `json:"status"`
	Description       string                   `json:"description,omitempty"`
	EncryptedValue    string                   `json:"encrypted_value"`     // base64 encoded
	EncryptionIV      string                   `json:"encryption_iv"`       // base64 encoded
	KeyDerivationSalt string                   `json:"key_derivation_salt"` // base64 encoded
	Tags              []string                 `json:"tags,omitempty"`
	Rotation          types.CredentialRotation `json:"rotation"`
	Usage             types.CredentialUsage    `json:"usage"`
	CreatedAt         int64                    `json:"created_at"`          // Unix milliseconds for RediSearch numeric indexing
	UpdatedAt         int64                    `json:"updated_at"`          // Unix milliseconds
	LastUsed          *int64                   `json:"last_used,omitempty"` // Unix milliseconds, nullable
}

// NewRedisCredentialDAO creates a new Redis-based credential DAO.
func NewRedisCredentialDAO(client *state.StateClient) *RedisCredentialDAO {
	return &RedisCredentialDAO{
		client: client,
	}
}

// Ensure RedisCredentialDAO implements CredentialDAO interface
var _ CredentialDAO = (*RedisCredentialDAO)(nil)

// credentialKey returns the Redis key for a credential document by ID.
func credentialKey(id types.ID) string {
	return fmt.Sprintf("gibson:credential:%s", id.String())
}

// credentialNameKey returns the Redis key for name-to-ID lookup.
func credentialNameKey(name string) string {
	return fmt.Sprintf("gibson:credential:by_name:%s", name)
}

// toDocument converts a types.Credential to a credentialDocument for Redis storage.
func toDocument(cred *types.Credential) *credentialDocument {
	doc := &credentialDocument{
		ID:                cred.ID.String(),
		Name:              cred.Name,
		Type:              cred.Type.String(),
		Provider:          cred.Provider,
		Status:            cred.Status.String(),
		Description:       cred.Description,
		EncryptedValue:    base64.StdEncoding.EncodeToString(cred.EncryptedValue),
		EncryptionIV:      base64.StdEncoding.EncodeToString(cred.EncryptionIV),
		KeyDerivationSalt: base64.StdEncoding.EncodeToString(cred.KeyDerivationSalt),
		Tags:              cred.Tags,
		Rotation:          cred.Rotation,
		Usage:             cred.Usage,
		CreatedAt:         cred.CreatedAt.UnixMilli(),
		UpdatedAt:         cred.UpdatedAt.UnixMilli(),
	}

	if cred.LastUsed != nil {
		lastUsedMs := cred.LastUsed.UnixMilli()
		doc.LastUsed = &lastUsedMs
	}

	// Ensure Tags is not nil for JSON consistency
	if doc.Tags == nil {
		doc.Tags = []string{}
	}

	return doc
}

// fromDocument converts a credentialDocument from Redis to a types.Credential.
func fromDocument(doc *credentialDocument) (*types.Credential, error) {
	// Parse ID
	id, err := types.ParseID(doc.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential ID: %w", err)
	}

	// Parse type
	var credType types.CredentialType
	if err := json.Unmarshal([]byte(fmt.Sprintf(`"%s"`, doc.Type)), &credType); err != nil {
		return nil, fmt.Errorf("failed to parse credential type: %w", err)
	}

	// Parse status
	var status types.CredentialStatus
	if err := json.Unmarshal([]byte(fmt.Sprintf(`"%s"`, doc.Status)), &status); err != nil {
		return nil, fmt.Errorf("failed to parse credential status: %w", err)
	}

	// Decode base64 encrypted fields
	encryptedValue, err := base64.StdEncoding.DecodeString(doc.EncryptedValue)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted value: %w", err)
	}

	encryptionIV, err := base64.StdEncoding.DecodeString(doc.EncryptionIV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption IV: %w", err)
	}

	keyDerivationSalt, err := base64.StdEncoding.DecodeString(doc.KeyDerivationSalt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key derivation salt: %w", err)
	}

	cred := &types.Credential{
		ID:                id,
		Name:              doc.Name,
		Type:              credType,
		Provider:          doc.Provider,
		Status:            status,
		Description:       doc.Description,
		EncryptedValue:    encryptedValue,
		EncryptionIV:      encryptionIV,
		KeyDerivationSalt: keyDerivationSalt,
		Tags:              doc.Tags,
		Rotation:          doc.Rotation,
		Usage:             doc.Usage,
		CreatedAt:         time.UnixMilli(doc.CreatedAt),
		UpdatedAt:         time.UnixMilli(doc.UpdatedAt),
	}

	if doc.LastUsed != nil {
		lastUsed := time.UnixMilli(*doc.LastUsed)
		cred.LastUsed = &lastUsed
	}

	// Ensure Tags is not nil
	if cred.Tags == nil {
		cred.Tags = []string{}
	}

	return cred, nil
}

// Create inserts a new credential into Redis.
// Uses a Lua script to atomically create both the document and name lookup,
// ensuring name uniqueness even under concurrent operations.
// This prevents race conditions where two creates with the same name both succeed.
func (dao *RedisCredentialDAO) Create(ctx context.Context, cred *types.Credential) error {
	// Validate credential including encrypted fields
	if err := cred.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Convert to document
	doc := toDocument(cred)

	// Marshal to JSON for Lua script
	docJSON, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal credential document: %w", err)
	}

	// Use atomic Lua script to create credential with name uniqueness check
	err = dao.client.CreateCredentialAtomic(ctx, cred.ID.String(), cred.Name, string(docJSON))
	if err != nil {
		// Check if it's an already exists error
		if errors.Is(err, state.ErrAlreadyExists) {
			return fmt.Errorf("credential with name %q already exists", cred.Name)
		}
		return fmt.Errorf("failed to create credential: %w", err)
	}

	return nil
}

// Get retrieves a credential by ID.
func (dao *RedisCredentialDAO) Get(ctx context.Context, id types.ID) (*types.Credential, error) {
	key := credentialKey(id)

	var doc credentialDocument
	err := dao.client.JSONGet(ctx, key, "$", &doc)
	if err != nil {
		if err == state.ErrNotFound || err == redis.Nil {
			return nil, fmt.Errorf("credential not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}

	// JSONPath $ returns array, extract first element
	var docs []credentialDocument
	if err := json.Unmarshal([]byte(fmt.Sprintf("%v", doc)), &docs); err == nil && len(docs) > 0 {
		return fromDocument(&docs[0])
	}

	return fromDocument(&doc)
}

// GetByName retrieves a credential by name.
// First looks up the ID via the name index, then fetches the document.
func (dao *RedisCredentialDAO) GetByName(ctx context.Context, name string) (*types.Credential, error) {
	nameKey := credentialNameKey(name)

	// Get ID from name lookup
	idStr, err := dao.client.Client().Get(ctx, nameKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("credential not found: %s", name)
		}
		return nil, fmt.Errorf("failed to lookup credential by name: %w", err)
	}

	// Parse ID
	id, err := types.ParseID(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential ID: %w", err)
	}

	// Fetch the credential document
	return dao.Get(ctx, id)
}

// List retrieves credentials with optional filtering using RediSearch.
func (dao *RedisCredentialDAO) List(ctx context.Context, filter *types.CredentialFilter) ([]*types.Credential, error) {
	// Build search query
	query := "*" // Match all by default
	filters := []string{}

	if filter != nil {
		if filter.Type != nil {
			escapedType := state.EscapeTag(filter.Type.String())
			filters = append(filters, fmt.Sprintf("@type:{%s}", escapedType))
		}

		if filter.Provider != nil {
			escapedProvider := state.EscapeTag(*filter.Provider)
			filters = append(filters, fmt.Sprintf("@provider:{%s}", escapedProvider))
		}

		if filter.Status != nil {
			escapedStatus := state.EscapeTag(filter.Status.String())
			filters = append(filters, fmt.Sprintf("@status:{%s}", escapedStatus))
		}

		// Tag filtering - credential must have all specified tags
		for _, tag := range filter.Tags {
			escapedTag := state.EscapeTag(tag)
			filters = append(filters, fmt.Sprintf("@tags:{%s}", escapedTag))
		}
	}

	// Combine filters with AND logic
	if len(filters) > 0 {
		query = strings.Join(filters, " ")
	}

	// Configure search options
	opts := &state.SearchOptions{
		Limit:   10, // Default limit
		Offset:  0,
		SortBy:  "name",
		SortAsc: true,
	}

	if filter != nil {
		if filter.Limit > 0 {
			opts.Limit = filter.Limit
		}
		if filter.Offset > 0 {
			opts.Offset = filter.Offset
		}
	}

	// Execute search
	result, err := dao.client.Search(ctx, "gibson:idx:credentials", query, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to search credentials: %w", err)
	}

	// Parse results
	credentials := make([]*types.Credential, 0, len(result.Documents))
	for _, searchDoc := range result.Documents {
		var doc credentialDocument
		if err := json.Unmarshal(searchDoc.JSON, &doc); err != nil {
			return nil, fmt.Errorf("failed to unmarshal credential document: %w", err)
		}

		cred, err := fromDocument(&doc)
		if err != nil {
			return nil, fmt.Errorf("failed to convert credential document: %w", err)
		}

		credentials = append(credentials, cred)
	}

	return credentials, nil
}

// Update updates an existing credential.
// If the name changed, updates both the document and the name lookup keys atomically.
func (dao *RedisCredentialDAO) Update(ctx context.Context, cred *types.Credential) error {
	if err := cred.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Get existing credential to check if name changed
	existing, err := dao.Get(ctx, cred.ID)
	if err != nil {
		return fmt.Errorf("credential not found: %w", err)
	}

	key := credentialKey(cred.ID)
	doc := toDocument(cred)

	// If name changed, we need to update the name lookup
	if existing.Name != cred.Name {
		// Check new name doesn't exist
		newNameKey := credentialNameKey(cred.Name)
		exists, err := dao.client.Client().Exists(ctx, newNameKey).Result()
		if err != nil {
			return fmt.Errorf("failed to check name uniqueness: %w", err)
		}
		if exists > 0 {
			return fmt.Errorf("credential with name %q already exists", cred.Name)
		}

		// Use pipeline to update document and swap name lookup atomically
		pipe := dao.client.Client().Pipeline()

		// Update the document
		if err := dao.client.JSONSet(ctx, key, "$", doc); err != nil {
			return fmt.Errorf("failed to update credential document: %w", err)
		}

		// Delete old name lookup
		oldNameKey := credentialNameKey(existing.Name)
		pipe.Del(ctx, oldNameKey)

		// Set new name lookup
		pipe.Set(ctx, newNameKey, cred.ID.String(), 0)

		// Execute pipeline
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("failed to execute update pipeline: %w", err)
		}
	} else {
		// Name didn't change, just update the document
		if err := dao.client.JSONSet(ctx, key, "$", doc); err != nil {
			return fmt.Errorf("failed to update credential document: %w", err)
		}
	}

	return nil
}

// UpdateLastUsed updates only the last_used timestamp of a credential.
// This is optimized to update just the specific field rather than the entire document.
func (dao *RedisCredentialDAO) UpdateLastUsed(ctx context.Context, id types.ID, lastUsed time.Time) error {
	key := credentialKey(id)

	// Check if credential exists
	exists, err := dao.client.Client().Exists(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to check credential existence: %w", err)
	}
	if exists == 0 {
		return fmt.Errorf("credential not found: %s", id)
	}

	// Update just the last_used field using JSONPath
	lastUsedMs := lastUsed.UnixMilli()
	if err := dao.client.JSONSet(ctx, key, "$.last_used", lastUsedMs); err != nil {
		return fmt.Errorf("failed to update last_used: %w", err)
	}

	// Also update updated_at
	updatedAtMs := time.Now().UnixMilli()
	if err := dao.client.JSONSet(ctx, key, "$.updated_at", updatedAtMs); err != nil {
		return fmt.Errorf("failed to update updated_at: %w", err)
	}

	return nil
}

// Delete deletes a credential by ID.
// Removes both the document and the name lookup key atomically.
func (dao *RedisCredentialDAO) Delete(ctx context.Context, id types.ID) error {
	// Get the credential to find its name
	cred, err := dao.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("credential not found: %w", err)
	}

	key := credentialKey(id)
	nameKey := credentialNameKey(cred.Name)

	// Use pipeline for atomic deletion
	pipe := dao.client.Client().Pipeline()

	// Delete the JSON document
	if err := dao.client.JSONDel(ctx, key, "$"); err != nil {
		return fmt.Errorf("failed to delete credential document: %w", err)
	}

	// Delete name lookup
	pipe.Del(ctx, nameKey)

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to execute delete pipeline: %w", err)
	}

	return nil
}

// DeleteByName deletes a credential by name.
func (dao *RedisCredentialDAO) DeleteByName(ctx context.Context, name string) error {
	// First lookup the ID
	cred, err := dao.GetByName(ctx, name)
	if err != nil {
		return err
	}

	// Use the regular Delete method
	return dao.Delete(ctx, cred.ID)
}

// Exists checks if a credential with the given name exists.
func (dao *RedisCredentialDAO) Exists(ctx context.Context, name string) (bool, error) {
	nameKey := credentialNameKey(name)
	exists, err := dao.client.Client().Exists(ctx, nameKey).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check credential existence: %w", err)
	}
	return exists > 0, nil
}
