package graphrag

import (
	"fmt"
	"strings"
)

// GraphRAGConfig contains the top-level configuration for GraphRAG integration.
// GraphRAG is a required core component of Gibson - there is no disabled state.
// Supports multiple graph providers (Neo4j, AWS Neptune, etc.) with vector search
// and embeddings for hybrid retrieval combining graph traversal and semantic search.
type GraphRAGConfig struct {
	Provider string         `yaml:"provider" json:"provider" mapstructure:"provider"` // neo4j, neptune, memgraph (required)
	Neo4j    Neo4jConfig    `yaml:"neo4j" json:"neo4j" mapstructure:"neo4j"`
	Vector   VectorConfig   `yaml:"vector" json:"vector" mapstructure:"vector"`
	Embedder EmbedderConfig `yaml:"embedder" json:"embedder" mapstructure:"embedder"`
	Cloud    CloudConfig    `yaml:"cloud" json:"cloud" mapstructure:"cloud"`
	Query    QueryConfig    `yaml:"query" json:"query" mapstructure:"query"`
}

// Neo4jConfig contains Neo4j graph database configuration.
// Supports connection pooling, authentication, and database selection.
type Neo4jConfig struct {
	URI      string `yaml:"uri" json:"uri" mapstructure:"uri"` // bolt://localhost:7687
	Username string `yaml:"username" json:"username" mapstructure:"username"`
	Password string `yaml:"password" json:"password" mapstructure:"password"`
	Database string `yaml:"database" json:"database" mapstructure:"database"`    // Default: neo4j
	PoolSize int    `yaml:"pool_size" json:"pool_size" mapstructure:"pool_size"` // Max connections
}

// VectorConfig contains vector search configuration.
// Vector search is always enabled as part of GraphRAG's hybrid retrieval.
// Used for combining graph structure and semantic similarity.
type VectorConfig struct {
	IndexType  string `yaml:"index_type" json:"index_type" mapstructure:"index_type"` // hnsw, ivfflat
	Dimensions int    `yaml:"dimensions" json:"dimensions" mapstructure:"dimensions"` // Embedding dimensions
	Metric     string `yaml:"metric" json:"metric" mapstructure:"metric"`             // cosine, euclidean, dot
}

// EmbedderConfig contains embeddings configuration for vector search.
// Supports multiple embedding providers (OpenAI, HuggingFace, local models).
type EmbedderConfig struct {
	Provider   string `yaml:"provider" json:"provider" mapstructure:"provider"`       // openai, huggingface, local
	Model      string `yaml:"model" json:"model" mapstructure:"model"`                // text-embedding-ada-002, etc.
	Dimensions int    `yaml:"dimensions" json:"dimensions" mapstructure:"dimensions"` // Must match VectorConfig.Dimensions
	APIKey     string `yaml:"api_key" json:"api_key" mapstructure:"api_key"`
	Endpoint   string `yaml:"endpoint" json:"endpoint" mapstructure:"endpoint"` // For custom/local embedders
}

// CloudConfig contains cloud provider-specific configuration.
// Used for managed graph services like AWS Neptune, Azure Cosmos DB, etc.
type CloudConfig struct {
	Provider string `yaml:"provider" json:"provider" mapstructure:"provider"` // aws, azure, gcp
	Region   string `yaml:"region" json:"region" mapstructure:"region"`
	Endpoint string `yaml:"endpoint" json:"endpoint" mapstructure:"endpoint"` // For Neptune, Cosmos DB, etc.

	// AWS-specific
	AWSAccessKeyID     string `yaml:"aws_access_key_id" json:"aws_access_key_id" mapstructure:"aws_access_key_id"`
	AWSSecretAccessKey string `yaml:"aws_secret_access_key" json:"aws_secret_access_key" mapstructure:"aws_secret_access_key"`

	// Azure-specific
	AzureSubscriptionID string `yaml:"azure_subscription_id" json:"azure_subscription_id" mapstructure:"azure_subscription_id"`
	AzureTenantID       string `yaml:"azure_tenant_id" json:"azure_tenant_id" mapstructure:"azure_tenant_id"`
}

// QueryConfig contains default query configuration for GraphRAG operations.
// Controls hybrid search behavior, scoring weights, and traversal limits.
type QueryConfig struct {
	DefaultTopK    int     `yaml:"default_top_k" json:"default_top_k" mapstructure:"default_top_k"`          // Default number of results
	DefaultMaxHops int     `yaml:"default_max_hops" json:"default_max_hops" mapstructure:"default_max_hops"` // Max graph traversal depth
	MinScore       float64 `yaml:"min_score" json:"min_score" mapstructure:"min_score"`                      // Minimum similarity threshold
	VectorWeight   float64 `yaml:"vector_weight" json:"vector_weight" mapstructure:"vector_weight"`          // Weight for vector similarity (0-1)
	GraphWeight    float64 `yaml:"graph_weight" json:"graph_weight" mapstructure:"graph_weight"`             // Weight for graph proximity (0-1)
}

// Validate validates the GraphRAGConfig fields.
// GraphRAG is a required core component - validation always runs.
// Returns an error if Provider is invalid, required fields are missing,
// or configuration values are out of valid ranges.
func (c *GraphRAGConfig) Validate() error {
	// Provider is required (GraphRAG is a core component)
	if c.Provider == "" {
		return fmt.Errorf("graphrag provider is required (must be one of: neo4j, neptune, memgraph)")
	}

	// Validate provider
	validProviders := []string{"neo4j", "neptune", "memgraph"}
	provider := strings.ToLower(c.Provider)
	isValid := false
	for _, valid := range validProviders {
		if provider == valid {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid graphrag provider: %s (must be one of: %s)", c.Provider, strings.Join(validProviders, ", "))
	}

	// Validate provider-specific config
	switch provider {
	case "neo4j":
		if err := c.Neo4j.Validate(); err != nil {
			return fmt.Errorf("neo4j config validation failed: %w", err)
		}
	case "neptune":
		if err := c.Cloud.Validate(); err != nil {
			return fmt.Errorf("cloud config validation failed: %w", err)
		}
	}

	// Validate vector config (always enabled as part of GraphRAG)
	if err := c.Vector.Validate(); err != nil {
		return fmt.Errorf("vector config validation failed: %w", err)
	}
	if err := c.Embedder.Validate(); err != nil {
		return fmt.Errorf("embedder config validation failed: %w", err)
	}
	// Ensure dimensions match
	if c.Vector.Dimensions != c.Embedder.Dimensions {
		return fmt.Errorf("vector dimensions (%d) must match embedder dimensions (%d)",
			c.Vector.Dimensions, c.Embedder.Dimensions)
	}

	// Validate query config
	if err := c.Query.Validate(); err != nil {
		return fmt.Errorf("query config validation failed: %w", err)
	}

	return nil
}

// ApplyDefaults applies default values to the GraphRAGConfig.
// Call this before Validate() to ensure sensible defaults.
func (c *GraphRAGConfig) ApplyDefaults() {
	if c.Provider == "" {
		c.Provider = "neo4j"
	}

	c.Neo4j.ApplyDefaults()
	c.Vector.ApplyDefaults()
	c.Embedder.ApplyDefaults()
	c.Query.ApplyDefaults()
}

// Validate validates the Neo4jConfig fields.
// Returns an error if required fields are missing or values are invalid.
func (n *Neo4jConfig) Validate() error {
	if n.URI == "" {
		return fmt.Errorf("neo4j URI is required")
	}
	if n.Username == "" {
		return fmt.Errorf("neo4j username is required")
	}
	if n.Password == "" {
		return fmt.Errorf("neo4j password is required")
	}
	if n.PoolSize < 1 || n.PoolSize > 1000 {
		return fmt.Errorf("neo4j pool_size must be between 1 and 1000, got %d", n.PoolSize)
	}
	return nil
}

// ApplyDefaults applies default values to the Neo4jConfig.
func (n *Neo4jConfig) ApplyDefaults() {
	if n.Database == "" {
		n.Database = "neo4j"
	}
	if n.PoolSize == 0 {
		n.PoolSize = 50
	}
}

// Validate validates the VectorConfig fields.
// Vector search is always enabled as part of GraphRAG.
// Returns an error if index type is invalid or dimensions are out of range.
func (v *VectorConfig) Validate() error {
	// Validate index type
	validIndexTypes := []string{"hnsw", "ivfflat"}
	indexType := strings.ToLower(v.IndexType)
	isValid := false
	for _, valid := range validIndexTypes {
		if indexType == valid {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid vector index_type: %s (must be one of: %s)", v.IndexType, strings.Join(validIndexTypes, ", "))
	}

	// Validate dimensions
	if v.Dimensions < 1 || v.Dimensions > 4096 {
		return fmt.Errorf("vector dimensions must be between 1 and 4096, got %d", v.Dimensions)
	}

	// Validate metric
	validMetrics := []string{"cosine", "euclidean", "dot"}
	metric := strings.ToLower(v.Metric)
	isValid = false
	for _, valid := range validMetrics {
		if metric == valid {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid vector metric: %s (must be one of: %s)", v.Metric, strings.Join(validMetrics, ", "))
	}

	return nil
}

// ApplyDefaults applies default values to the VectorConfig.
func (v *VectorConfig) ApplyDefaults() {
	if v.IndexType == "" {
		v.IndexType = "hnsw"
	}
	if v.Dimensions == 0 {
		v.Dimensions = 384 // Native embedder (all-MiniLM-L6-v2) default
	}
	if v.Metric == "" {
		v.Metric = "cosine"
	}
}

// Validate validates the EmbedderConfig fields.
// Returns an error if provider is invalid or required fields are missing.
func (e *EmbedderConfig) Validate() error {
	// Validate provider
	validProviders := []string{"native", "openai", "huggingface", "local"}
	provider := strings.ToLower(e.Provider)
	isValid := false
	for _, valid := range validProviders {
		if provider == valid {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid embedder provider: %s (must be one of: %s)", e.Provider, strings.Join(validProviders, ", "))
	}

	// Native embedder doesn't require model or API key - it's embedded
	if provider == "native" {
		// Native embedder (all-MiniLM-L6-v2) has fixed 384 dimensions
		if e.Dimensions != 0 && e.Dimensions != 384 {
			return fmt.Errorf("native embedder produces 384 dimensions, got %d", e.Dimensions)
		}
		return nil
	}

	// Validate model for non-native providers
	if e.Model == "" {
		return fmt.Errorf("embedder model is required")
	}

	// Validate dimensions
	if e.Dimensions < 1 || e.Dimensions > 4096 {
		return fmt.Errorf("embedder dimensions must be between 1 and 4096, got %d", e.Dimensions)
	}

	// Provider-specific validation
	switch provider {
	case "openai":
		if e.APIKey == "" {
			return fmt.Errorf("openai embedder requires api_key")
		}
	case "local":
		if e.Endpoint == "" {
			return fmt.Errorf("local embedder requires endpoint")
		}
	}

	return nil
}

// ApplyDefaults applies default values to the EmbedderConfig.
func (e *EmbedderConfig) ApplyDefaults() {
	if e.Provider == "" {
		e.Provider = "native" // Use offline native embedder by default (all-MiniLM-L6-v2)
	}
	if e.Provider == "native" {
		e.Dimensions = 384 // Native embedder produces 384-dimensional vectors
		e.Model = "all-MiniLM-L6-v2"
	} else if e.Model == "" && e.Provider == "openai" {
		e.Model = "text-embedding-ada-002"
		if e.Dimensions == 0 {
			e.Dimensions = 1536 // OpenAI ada-002 default
		}
	}
}

// Validate validates the CloudConfig fields.
// Returns an error if cloud provider is invalid or required credentials are missing.
func (c *CloudConfig) Validate() error {
	if c.Provider == "" {
		return nil // Cloud config is optional
	}

	// Validate provider
	validProviders := []string{"aws", "azure", "gcp"}
	provider := strings.ToLower(c.Provider)
	isValid := false
	for _, valid := range validProviders {
		if provider == valid {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid cloud provider: %s (must be one of: %s)", c.Provider, strings.Join(validProviders, ", "))
	}

	// Provider-specific validation
	switch provider {
	case "aws":
		if c.Region == "" {
			return fmt.Errorf("aws region is required")
		}
		if c.Endpoint == "" {
			return fmt.Errorf("aws endpoint is required for Neptune")
		}
		// AWS credentials can come from environment, so we don't strictly require them
	case "azure":
		if c.Endpoint == "" {
			return fmt.Errorf("azure endpoint is required for Cosmos DB")
		}
	}

	return nil
}

// QueryConfig.Validate validates the QueryConfig fields.
// Returns an error if values are out of valid ranges.
func (q *QueryConfig) Validate() error {
	if q.DefaultTopK < 1 || q.DefaultTopK > 1000 {
		return fmt.Errorf("default_top_k must be between 1 and 1000, got %d", q.DefaultTopK)
	}
	if q.DefaultMaxHops < 1 || q.DefaultMaxHops > 10 {
		return fmt.Errorf("default_max_hops must be between 1 and 10, got %d", q.DefaultMaxHops)
	}
	if q.MinScore < 0.0 || q.MinScore > 1.0 {
		return fmt.Errorf("min_score must be between 0.0 and 1.0, got %f", q.MinScore)
	}
	if q.VectorWeight < 0.0 || q.VectorWeight > 1.0 {
		return fmt.Errorf("vector_weight must be between 0.0 and 1.0, got %f", q.VectorWeight)
	}
	if q.GraphWeight < 0.0 || q.GraphWeight > 1.0 {
		return fmt.Errorf("graph_weight must be between 0.0 and 1.0, got %f", q.GraphWeight)
	}

	// Weights should sum to approximately 1.0 for proper hybrid scoring
	weightSum := q.VectorWeight + q.GraphWeight
	if weightSum < 0.99 || weightSum > 1.01 {
		return fmt.Errorf("vector_weight and graph_weight should sum to 1.0, got %f", weightSum)
	}

	return nil
}

// ApplyDefaults applies default values to the QueryConfig.
func (q *QueryConfig) ApplyDefaults() {
	if q.DefaultTopK == 0 {
		q.DefaultTopK = 10
	}
	if q.DefaultMaxHops == 0 {
		q.DefaultMaxHops = 3
	}
	if q.MinScore == 0.0 {
		q.MinScore = 0.7
	}
	if q.VectorWeight == 0.0 && q.GraphWeight == 0.0 {
		q.VectorWeight = 0.6
		q.GraphWeight = 0.4
	}
}
