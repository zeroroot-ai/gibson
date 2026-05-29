package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/state"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// RedisTargetDAO provides Redis-based storage for Target entities.
// It uses RedisJSON for document storage and RediSearch for efficient querying.
//
// Key naming convention:
//   - Target document: "gibson:target:{id}"
//   - Name lookup: "gibson:target:by_name:{name}" -> ID
//
// The DAO ensures name uniqueness across all targets and provides
// efficient filtering by provider, type, status, and tags using RediSearch.
type RedisTargetDAO struct {
	client *state.StateClient
}

// targetDocument represents the JSON structure stored in Redis.
// It matches the types.Target structure but with timestamps as Unix milliseconds
// for RediSearch numeric indexing.
type targetDocument struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	TenantID     string                 `json:"tenant_id,omitempty"`
	Type         string                 `json:"type"`
	Provider     string                 `json:"provider,omitempty"`
	Connection   map[string]any         `json:"connection,omitempty"`
	Model        string                 `json:"model,omitempty"`
	Config       map[string]interface{} `json:"config,omitempty"`
	Capabilities []string               `json:"capabilities,omitempty"`
	AuthType     string                 `json:"auth_type,omitempty"`
	CredentialID *string                `json:"credential_id,omitempty"` // String pointer for nullable FK
	Status       string                 `json:"status"`
	Description  string                 `json:"description,omitempty"`
	Tags         []string               `json:"tags,omitempty"`
	Timeout      int                    `json:"timeout"`
	CreatedAt    int64                  `json:"created_at"` // Unix milliseconds for RediSearch numeric indexing
	UpdatedAt    int64                  `json:"updated_at"` // Unix milliseconds

	// Deprecated fields for backward compatibility
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// NewRedisTargetDAO creates a new Redis-based target DAO.
func NewRedisTargetDAO(client *state.StateClient) *RedisTargetDAO {
	return &RedisTargetDAO{
		client: client,
	}
}

// targetKey returns the Redis key for a target document by ID.
func targetKey(id types.ID) string {
	return fmt.Sprintf("gibson:target:%s", id.String())
}

// targetNameKey returns the Redis key for name-to-ID lookup.
func targetNameKey(name string) string {
	return fmt.Sprintf("gibson:target:by_name:%s", name)
}

// toTargetDocument converts a types.Target to a targetDocument for Redis storage.
func toTargetDocument(target *types.Target) *targetDocument {
	doc := &targetDocument{
		ID:           target.ID.String(),
		Name:         target.Name,
		TenantID:     target.TenantID,
		Type:         target.Type,
		Provider:     target.Provider.String(),
		Connection:   target.Connection,
		Model:        target.Model,
		Config:       target.Config,
		Capabilities: target.Capabilities,
		AuthType:     target.AuthType.String(),
		Status:       target.Status.String(),
		Description:  target.Description,
		Tags:         target.Tags,
		Timeout:      target.Timeout,
		CreatedAt:    target.CreatedAt.UnixMilli(),
		UpdatedAt:    target.UpdatedAt.UnixMilli(),
		URL:          target.URL,
		Headers:      target.Headers,
	}

	// Convert credential ID if present
	if target.CredentialID != nil {
		credID := target.CredentialID.String()
		doc.CredentialID = &credID
	}

	// Ensure non-nil maps and slices for JSON consistency
	if doc.Connection == nil {
		doc.Connection = make(map[string]any)
	}
	if doc.Config == nil {
		doc.Config = make(map[string]interface{})
	}
	if doc.Capabilities == nil {
		doc.Capabilities = []string{}
	}
	if doc.Tags == nil {
		doc.Tags = []string{}
	}
	if doc.Headers == nil {
		doc.Headers = make(map[string]string)
	}

	return doc
}

// fromTargetDocument converts a targetDocument from Redis to a types.Target.
func fromTargetDocument(doc *targetDocument) (*types.Target, error) {
	// Parse ID
	id, err := types.ParseID(doc.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target ID: %w", err)
	}

	target := &types.Target{
		ID:           id,
		Name:         doc.Name,
		TenantID:     doc.TenantID,
		Type:         doc.Type,
		Provider:     types.Provider(doc.Provider),
		Connection:   doc.Connection,
		Model:        doc.Model,
		Config:       doc.Config,
		Capabilities: doc.Capabilities,
		AuthType:     types.AuthType(doc.AuthType),
		Status:       types.TargetStatus(doc.Status),
		Description:  doc.Description,
		Tags:         doc.Tags,
		Timeout:      doc.Timeout,
		CreatedAt:    time.UnixMilli(doc.CreatedAt),
		UpdatedAt:    time.UnixMilli(doc.UpdatedAt),
		URL:          doc.URL,
		Headers:      doc.Headers,
	}

	// Parse credential ID if present
	if doc.CredentialID != nil {
		credID, err := types.ParseID(*doc.CredentialID)
		if err != nil {
			return nil, fmt.Errorf("failed to parse credential ID: %w", err)
		}
		target.CredentialID = &credID
	}

	// Ensure non-nil maps and slices
	if target.Connection == nil {
		target.Connection = make(map[string]any)
	}
	if target.Config == nil {
		target.Config = make(map[string]interface{})
	}
	if target.Capabilities == nil {
		target.Capabilities = []string{}
	}
	if target.Tags == nil {
		target.Tags = []string{}
	}
	if target.Headers == nil {
		target.Headers = make(map[string]string)
	}

	return target, nil
}

// Create inserts a new target into Redis.
// It ensures name uniqueness by checking the name lookup key first.
// Uses a pipeline for atomic creation of both the document and name lookup.
func (dao *RedisTargetDAO) Create(ctx context.Context, target *types.Target) error {
	if err := target.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Check name uniqueness first
	nameKey := targetNameKey(target.Name)
	exists, err := dao.client.Client().Exists(ctx, nameKey).Result()
	if err != nil {
		return fmt.Errorf("failed to check name uniqueness: %w", err)
	}
	if exists > 0 {
		return fmt.Errorf("target with name %q already exists", target.Name)
	}

	// Convert to document
	doc := toTargetDocument(target)
	key := targetKey(target.ID)

	// Use pipeline for atomic creation
	pipe := dao.client.Client().Pipeline()

	// Set the JSON document
	if err := dao.client.JSONSet(ctx, key, "$", doc); err != nil {
		return fmt.Errorf("failed to create target document: %w", err)
	}

	// Set name lookup key (maps name -> ID)
	pipe.Set(ctx, nameKey, target.ID.String(), 0)

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to execute create pipeline: %w", err)
	}

	return nil
}

// Get retrieves a target by ID.
func (dao *RedisTargetDAO) Get(ctx context.Context, id types.ID) (*types.Target, error) {
	key := targetKey(id)

	var doc targetDocument
	err := dao.client.JSONGet(ctx, key, "$", &doc)
	if err != nil {
		if err == state.ErrNotFound || err == goredis.Nil {
			return nil, fmt.Errorf("target not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get target: %w", err)
	}

	// JSONPath $ returns array, extract first element
	var docs []targetDocument
	if err := json.Unmarshal([]byte(fmt.Sprintf("%v", doc)), &docs); err == nil && len(docs) > 0 {
		return fromTargetDocument(&docs[0])
	}

	return fromTargetDocument(&doc)
}

// GetByName retrieves a target by name.
// First looks up the ID via the name index, then fetches the document.
func (dao *RedisTargetDAO) GetByName(ctx context.Context, name string) (*types.Target, error) {
	nameKey := targetNameKey(name)

	// Get ID from name lookup
	idStr, err := dao.client.Client().Get(ctx, nameKey).Result()
	if err != nil {
		if err == goredis.Nil {
			return nil, fmt.Errorf("target not found: %s", name)
		}
		return nil, fmt.Errorf("failed to lookup target by name: %w", err)
	}

	// Parse ID
	id, err := types.ParseID(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target ID: %w", err)
	}

	// Fetch the target document
	return dao.Get(ctx, id)
}

// List retrieves targets with optional filtering using RediSearch.
func (dao *RedisTargetDAO) List(ctx context.Context, filter *types.TargetFilter) ([]*types.Target, error) {
	// Build search query
	query := "*" // Match all by default
	filters := []string{}

	if filter != nil {
		if filter.Provider != nil {
			escapedProvider := state.EscapeTag(filter.Provider.String())
			filters = append(filters, fmt.Sprintf("@provider:{%s}", escapedProvider))
		}

		if filter.Type != nil {
			escapedType := state.EscapeTag(*filter.Type)
			filters = append(filters, fmt.Sprintf("@type:{%s}", escapedType))
		}

		if filter.Status != nil {
			escapedStatus := state.EscapeTag(filter.Status.String())
			filters = append(filters, fmt.Sprintf("@status:{%s}", escapedStatus))
		}

		// Tag filtering - target must have all specified tags
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
		Limit:   100, // Default limit
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
	result, err := dao.client.Search(ctx, "gibson:idx:targets", query, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to search targets: %w", err)
	}

	// Parse results
	targets := make([]*types.Target, 0, len(result.Documents))
	for _, searchDoc := range result.Documents {
		var doc targetDocument
		if err := json.Unmarshal(searchDoc.JSON, &doc); err != nil {
			return nil, fmt.Errorf("failed to unmarshal target document: %w", err)
		}

		target, err := fromTargetDocument(&doc)
		if err != nil {
			return nil, fmt.Errorf("failed to convert target document: %w", err)
		}

		targets = append(targets, target)
	}

	return targets, nil
}

// Update updates an existing target.
// If the name changed, updates both the document and the name lookup keys atomically.
func (dao *RedisTargetDAO) Update(ctx context.Context, target *types.Target) error {
	if err := target.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Get existing target to check if name changed
	existing, err := dao.Get(ctx, target.ID)
	if err != nil {
		return fmt.Errorf("target not found: %w", err)
	}

	// Update timestamp
	target.UpdatedAt = time.Now()

	key := targetKey(target.ID)
	doc := toTargetDocument(target)

	// If name changed, we need to update the name lookup
	if existing.Name != target.Name {
		// Check new name doesn't exist
		newNameKey := targetNameKey(target.Name)
		exists, err := dao.client.Client().Exists(ctx, newNameKey).Result()
		if err != nil {
			return fmt.Errorf("failed to check name uniqueness: %w", err)
		}
		if exists > 0 {
			return fmt.Errorf("target with name %q already exists", target.Name)
		}

		// Use pipeline to update document and swap name lookup atomically
		pipe := dao.client.Client().Pipeline()

		// Update the document
		if err := dao.client.JSONSet(ctx, key, "$", doc); err != nil {
			return fmt.Errorf("failed to update target document: %w", err)
		}

		// Delete old name lookup
		oldNameKey := targetNameKey(existing.Name)
		pipe.Del(ctx, oldNameKey)

		// Set new name lookup
		pipe.Set(ctx, newNameKey, target.ID.String(), 0)

		// Execute pipeline
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("failed to execute update pipeline: %w", err)
		}
	} else {
		// Name didn't change, just update the document
		if err := dao.client.JSONSet(ctx, key, "$", doc); err != nil {
			return fmt.Errorf("failed to update target document: %w", err)
		}
	}

	return nil
}

// Delete deletes a target by ID.
// Removes both the document and the name lookup key atomically.
func (dao *RedisTargetDAO) Delete(ctx context.Context, id types.ID) error {
	// Get the target to find its name
	target, err := dao.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("target not found: %w", err)
	}

	key := targetKey(id)
	nameKey := targetNameKey(target.Name)

	// Use pipeline for atomic deletion
	pipe := dao.client.Client().Pipeline()

	// Delete the JSON document
	if err := dao.client.JSONDel(ctx, key, "$"); err != nil {
		return fmt.Errorf("failed to delete target document: %w", err)
	}

	// Delete name lookup
	pipe.Del(ctx, nameKey)

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to execute delete pipeline: %w", err)
	}

	return nil
}

// Exists checks if a target with the given name exists (implements TargetDAO interface).
func (dao *RedisTargetDAO) Exists(ctx context.Context, name string) (bool, error) {
	nameKey := targetNameKey(name)
	exists, err := dao.client.Client().Exists(ctx, nameKey).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check target existence: %w", err)
	}
	return exists > 0, nil
}

// ExistsByID checks if a target exists by ID (helper method, not part of interface).
func (dao *RedisTargetDAO) ExistsByID(ctx context.Context, id types.ID) (bool, error) {
	key := targetKey(id)
	exists, err := dao.client.Client().Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check target existence by ID: %w", err)
	}
	return exists > 0, nil
}

// DeleteByName deletes a target by name.
// First looks up the ID via the name index, then deletes the target.
func (dao *RedisTargetDAO) DeleteByName(ctx context.Context, name string) error {
	// First lookup the ID
	target, err := dao.GetByName(ctx, name)
	if err != nil {
		return err
	}

	// Use the regular Delete method
	return dao.Delete(ctx, target.ID)
}
