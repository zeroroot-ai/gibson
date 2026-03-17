package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/cmd/gibson/internal"
	"github.com/zero-day-ai/gibson/internal/knowledge"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/memory/embedder"
	"github.com/zero-day-ai/gibson/internal/memory/vector"
	"github.com/zero-day-ai/gibson/internal/state"
)

var knowledgeCmd = &cobra.Command{
	Use:   "knowledge",
	Short: "Manage knowledge store",
	Long:  `Ingest, search, and manage Gibson's local knowledge store for attack techniques and research`,
}

var knowledgeIngestCmd = &cobra.Command{
	Use:   "ingest",
	Short: "Ingest content into knowledge store",
	Long: `Ingest content from various sources into Gibson's local knowledge store.

The knowledge store provides semantic search over attack research, papers, and technique documentation.
All content is chunked, embedded, and stored locally using sqlite-vec.

Examples:
  # Ingest a PDF research paper
  gibson knowledge ingest --from-pdf ./papers/attack-research.pdf

  # Ingest content from a blog post URL
  gibson knowledge ingest --from-url https://example.com/llm-attacks

  # Batch ingest all PDFs from a directory
  gibson knowledge ingest --from-dir ./papers

  # Ingest markdown files matching a pattern
  gibson knowledge ingest --from-dir ./docs --pattern "*.md"

  # Force overwrite existing content
  gibson knowledge ingest --from-pdf paper.pdf --force`,
	RunE: runKnowledgeIngest,
}

var knowledgeSearchCmd = &cobra.Command{
	Use:   "search QUERY",
	Short: "Search the knowledge store",
	Long: `Search the knowledge store using semantic similarity.

Returns chunks of knowledge that are semantically similar to the query,
ranked by similarity score. Results include the original text, source,
similarity score, and metadata.

Examples:
  # Basic search
  gibson knowledge search "SQL injection techniques"

  # Limit results
  gibson knowledge search "jailbreak methods" --limit 5

  # Filter by minimum similarity threshold
  gibson knowledge search "prompt injection" --threshold 0.8

  # Filter by source
  gibson knowledge search "XSS attacks" --source "owasp-guide.pdf"

  # JSON output for scripting
  gibson knowledge search "RCE payloads" --output json`,
	Args: cobra.ExactArgs(1),
	RunE: runKnowledgeSearch,
}

var knowledgeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List ingested knowledge sources",
	Long: `List all sources that have been ingested into the knowledge store,
showing chunk counts and ingest timestamps.

Examples:
  # List all sources
  gibson knowledge list

  # JSON output for scripting
  gibson knowledge list --output json`,
	RunE: runKnowledgeList,
}

var knowledgeStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show knowledge store statistics",
	Long: `Display statistics about the knowledge store including:
  - Total number of sources
  - Total number of chunks
  - Storage size
  - Last ingest timestamp

Examples:
  # Show statistics
  gibson knowledge stats

  # JSON output for scripting
  gibson knowledge stats --output json`,
	RunE: runKnowledgeStats,
}

var knowledgeDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete knowledge from store",
	Long: `Delete knowledge chunks from the store by source or delete all content.

WARNING: Deletion is permanent and cannot be undone.

Examples:
  # Delete chunks from a specific source
  gibson knowledge delete --source "research-paper.pdf"

  # Delete all knowledge (requires confirmation)
  gibson knowledge delete --all

  # Force deletion without confirmation
  gibson knowledge delete --all --force`,
	RunE: runKnowledgeDelete,
}

var knowledgeSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync knowledge with Zero Day AI cloud",
	Long: `Sync local knowledge store with Zero Day AI cloud service.

This feature is part of the paid tier and is not yet available.
Use 'gibson knowledge ingest' to add content to your local store.

The sync command will be enabled when:
  1. Cloud integration is implemented
  2. Your Gibson configuration includes Zero Day AI API credentials
  3. You have an active Zero Day AI subscription

Examples:
  # Attempt to sync (currently returns stub message)
  gibson knowledge sync`,
	RunE: runKnowledgeSync,
}

// Flags for ingest command
var (
	ingestFromPDF   string
	ingestFromURL   string
	ingestFromDir   string
	ingestPattern   string
	ingestForce     bool
	ingestChunkSize int
	ingestOverlap   int
)

// Flags for search command
var (
	searchLimit     int
	searchThreshold float64
	searchSource    string
	searchOutput    string
)

// Flags for list/stats commands
var (
	knowledgeListOutput  string
	knowledgeStatsOutput string
)

// Flags for delete command
var (
	knowledgeDeleteSource string
	knowledgeDeleteAll    bool
	knowledgeDeleteForce  bool
)

func init() {
	// Ingest command flags
	knowledgeIngestCmd.Flags().StringVar(&ingestFromPDF, "from-pdf", "", "Path to PDF file to ingest")
	knowledgeIngestCmd.Flags().StringVar(&ingestFromURL, "from-url", "", "URL to fetch and ingest")
	knowledgeIngestCmd.Flags().StringVar(&ingestFromDir, "from-dir", "", "Directory path to recursively ingest files from")
	knowledgeIngestCmd.Flags().StringVar(&ingestPattern, "pattern", "*.pdf", "Glob pattern for filtering files (used with --from-dir)")
	knowledgeIngestCmd.Flags().BoolVar(&ingestForce, "force", false, "Force overwrite if source already exists")
	knowledgeIngestCmd.Flags().IntVar(&ingestChunkSize, "chunk-size", 512, "Tokens per chunk")
	knowledgeIngestCmd.Flags().IntVar(&ingestOverlap, "chunk-overlap", 50, "Overlap tokens between chunks")

	// Search command flags
	knowledgeSearchCmd.Flags().IntVar(&searchLimit, "limit", 10, "Maximum number of results to return")
	knowledgeSearchCmd.Flags().Float64Var(&searchThreshold, "threshold", 0.0, "Minimum similarity threshold (0.0-1.0)")
	knowledgeSearchCmd.Flags().StringVar(&searchSource, "source", "", "Filter results by source")
	knowledgeSearchCmd.Flags().StringVar(&searchOutput, "output", "text", "Output format (text, json)")

	// List command flags
	knowledgeListCmd.Flags().StringVar(&knowledgeListOutput, "output", "text", "Output format (text, json)")

	// Stats command flags
	knowledgeStatsCmd.Flags().StringVar(&knowledgeStatsOutput, "output", "text", "Output format (text, json)")

	// Delete command flags
	knowledgeDeleteCmd.Flags().StringVar(&knowledgeDeleteSource, "source", "", "Source to delete chunks from")
	knowledgeDeleteCmd.Flags().BoolVar(&knowledgeDeleteAll, "all", false, "Delete all knowledge (requires confirmation)")
	knowledgeDeleteCmd.Flags().BoolVar(&knowledgeDeleteForce, "force", false, "Skip confirmation prompt")

	// Add subcommands
	knowledgeCmd.AddCommand(knowledgeIngestCmd)
	knowledgeCmd.AddCommand(knowledgeSearchCmd)
	knowledgeCmd.AddCommand(knowledgeListCmd)
	knowledgeCmd.AddCommand(knowledgeStatsCmd)
	knowledgeCmd.AddCommand(knowledgeDeleteCmd)
	knowledgeCmd.AddCommand(knowledgeSyncCmd)
}

// knowledgeContext holds initialized resources for knowledge commands
type knowledgeContext struct {
	stateClient *state.StateClient
	manager     knowledge.KnowledgeManager
	ltm         memory.LongTermMemory
	store       vector.VectorStore
}

// initKnowledgeContext initializes the knowledge manager and related resources.
// The caller is responsible for calling Close() on the returned context.
func initKnowledgeContext() (*knowledgeContext, error) {
	// Get Gibson home directory
	homeDir := os.Getenv("GIBSON_HOME")
	if homeDir == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}
		homeDir = filepath.Join(userHome, ".gibson")
	}

	// Ensure home directory exists
	if err := os.MkdirAll(homeDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create Gibson home directory: %w", err)
	}

	// Load configuration to get Redis settings
	cfg, err := loadGlobalConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Create StateClient for Redis state stores
	stateCfg := &state.Config{
		URL:         cfg.Redis.URL,
		Database:    cfg.Redis.Database,
		Password:    cfg.Redis.Password,
		PoolSize:    cfg.Redis.PoolSize,
		DialTimeout: cfg.Redis.ConnectTimeout,
		ReadTimeout: cfg.Redis.ReadTimeout,
	}
	stateCfg.ApplyDefaults()

	stateClient, err := state.NewStateClient(stateCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create state client: %w", err)
	}

	// Initialize native embedder
	emb, err := embedder.CreateNativeEmbedder()
	if err != nil {
		stateClient.Close()
		return nil, fmt.Errorf("failed to create embedder: %w", err)
	}

	// Get embedding dimensions
	dims := emb.Dimensions()

	// Initialize vector store using Redis
	store := vector.NewRedisVectorStore(stateClient, dims)

	// Initialize long-term memory
	ltm := memory.NewLongTermMemory(store, emb)

	// Initialize knowledge manager with Redis-backed storage
	// Note: KnowledgeManager will need to be updated to use StateClient instead of sql.DB
	// For now, we'll pass nil and handle this in a follow-up if needed
	manager := knowledge.NewKnowledgeManager(ltm, nil)

	return &knowledgeContext{
		stateClient: stateClient,
		manager:     manager,
		ltm:         ltm,
		store:       store,
	}, nil
}

// Close releases all resources held by the knowledge context.
func (kc *knowledgeContext) Close() error {
	var errs []error

	if kc.store != nil {
		if err := kc.store.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close vector store: %w", err))
		}
	}

	if kc.stateClient != nil {
		if err := kc.stateClient.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close state client: %w", err))
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// checkKnowledgeConfig validates that knowledge storage configuration is valid.
// Returns an error with a helpful message if the configuration is invalid.
//
// The knowledge system currently uses Redis as the vector store backend.
// Future versions may support additional storage backends (embedded, Qdrant, Milvus).
func checkKnowledgeConfig(cmd *cobra.Command) error {
	// Load global config
	cfg, err := loadGlobalConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Check Redis configuration (currently the only supported backend)
	if cfg.Redis.URL == "" {
		return fmt.Errorf("knowledge commands require Redis configuration\n\n"+
			"Configure Redis URL with:\n"+
			"  gibson config set redis.url redis://localhost:6379\n\n"+
			"Or set in config file (~/.gibson/config.yaml):\n"+
			"  redis:\n"+
			"    url: redis://localhost:6379")
	}

	return nil
}

// runKnowledgeIngest handles the knowledge ingest command
func runKnowledgeIngest(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Check knowledge config before proceeding
	if err := checkKnowledgeConfig(cmd); err != nil {
		return err
	}

	// Validate that exactly one source flag is provided
	sourceCount := 0
	if ingestFromPDF != "" {
		sourceCount++
	}
	if ingestFromURL != "" {
		sourceCount++
	}
	if ingestFromDir != "" {
		sourceCount++
	}

	if sourceCount == 0 {
		return internal.WrapError(internal.ExitConfigError,
			"no source specified: use --from-pdf, --from-url, or --from-dir", nil)
	}
	if sourceCount > 1 {
		return internal.WrapError(internal.ExitConfigError,
			"multiple sources specified: use only one of --from-pdf, --from-url, or --from-dir", nil)
	}

	// Parse global flags for verbose output
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to parse flags", err)
	}

	verbose := flags.IsVerbose()

	// Initialize knowledge context
	kc, err := initKnowledgeContext()
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to initialize knowledge store", err)
	}
	defer kc.Close()

	// Create chunk processor and ingester
	processor := knowledge.NewChunkProcessor()
	ingester := knowledge.NewIngester(processor, kc.manager)

	opts := knowledge.IngestOptions{
		Force:        ingestForce,
		ChunkSize:    ingestChunkSize,
		ChunkOverlap: ingestOverlap,
	}

	var result *knowledge.IngestResult

	if ingestFromPDF != "" {
		if verbose {
			fmt.Fprintf(cmd.OutOrStdout(), "Ingesting PDF: %s\n", ingestFromPDF)
		}
		result, err = ingester.IngestPDF(ctx, ingestFromPDF, opts)
	} else if ingestFromURL != "" {
		if verbose {
			fmt.Fprintf(cmd.OutOrStdout(), "Ingesting URL: %s\n", ingestFromURL)
		}
		result, err = ingester.IngestURL(ctx, ingestFromURL, opts)
	} else if ingestFromDir != "" {
		if verbose {
			fmt.Fprintf(cmd.OutOrStdout(), "Ingesting directory: %s (pattern: %s)\n", ingestFromDir, ingestPattern)
		}
		result, err = ingester.IngestDirectory(ctx, ingestFromDir, ingestPattern, opts)
	}

	if err != nil {
		return internal.WrapError(internal.ExitError, "ingestion failed", err)
	}

	// Display results
	if result.ChunksSkipped > 0 && result.ChunksAdded == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "Source already ingested (%d chunks). Use --force to overwrite.\n", result.ChunksSkipped)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Ingested %d chunks from %s in %dms\n",
			result.ChunksAdded, result.Source, result.DurationMs)
	}

	if len(result.Errors) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "\nWarnings:\n")
		for _, e := range result.Errors {
			fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", e)
		}
	}

	return nil
}

// runKnowledgeSearch handles the knowledge search command
func runKnowledgeSearch(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	query := args[0]

	// Check knowledge config before proceeding
	if err := checkKnowledgeConfig(cmd); err != nil {
		return err
	}

	// Initialize knowledge context
	kc, err := initKnowledgeContext()
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to initialize knowledge store", err)
	}
	defer kc.Close()

	// Build search options
	opts := knowledge.SearchOptions{
		Limit:     searchLimit,
		Threshold: searchThreshold,
	}
	if searchSource != "" {
		opts.Source = searchSource
	}

	// Perform search
	results, err := kc.manager.Search(ctx, query, opts)
	if err != nil {
		return internal.WrapError(internal.ExitError, "search failed", err)
	}

	// Output results
	if searchOutput == "json" {
		return outputKnowledgeSearchJSON(cmd, query, results)
	}

	return outputKnowledgeSearchText(cmd, query, results)
}

// outputKnowledgeSearchJSON outputs search results as JSON
func outputKnowledgeSearchJSON(cmd *cobra.Command, query string, results []knowledge.KnowledgeResult) error {
	output := struct {
		Query   string                      `json:"query"`
		Results []knowledge.KnowledgeResult `json:"results"`
		Count   int                         `json:"count"`
	}{
		Query:   query,
		Results: results,
		Count:   len(results),
	}

	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// outputKnowledgeSearchText outputs search results as text
func outputKnowledgeSearchText(cmd *cobra.Command, query string, results []knowledge.KnowledgeResult) error {
	if len(results) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "No results found for query: %s\n", query)
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Found %d results for: %s\n\n", len(results), query)

	for i, r := range results {
		fmt.Fprintf(cmd.OutOrStdout(), "--- Result %d (score: %.4f) ---\n", i+1, r.Score)
		fmt.Fprintf(cmd.OutOrStdout(), "Source: %s\n", r.Chunk.Source)

		// Truncate text for display
		text := r.Chunk.Text
		if len(text) > 500 {
			text = text[:500] + "..."
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Text:\n%s\n\n", text)
	}

	return nil
}

// runKnowledgeList handles the knowledge list command
func runKnowledgeList(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Check knowledge config before proceeding
	if err := checkKnowledgeConfig(cmd); err != nil {
		return err
	}

	// Initialize knowledge context
	kc, err := initKnowledgeContext()
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to initialize knowledge store", err)
	}
	defer kc.Close()

	// Get list of sources
	sources, err := kc.manager.ListSources(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to list sources", err)
	}

	// Output results
	if knowledgeListOutput == "json" {
		return outputKnowledgeListJSON(cmd, sources)
	}

	return outputKnowledgeListText(cmd, sources)
}

// outputKnowledgeListJSON outputs source list as JSON
func outputKnowledgeListJSON(cmd *cobra.Command, sources []knowledge.KnowledgeSource) error {
	output := struct {
		Sources []knowledge.KnowledgeSource `json:"sources"`
		Count   int                         `json:"count"`
	}{
		Sources: sources,
		Count:   len(sources),
	}

	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// outputKnowledgeListText outputs source list as text
func outputKnowledgeListText(cmd *cobra.Command, sources []knowledge.KnowledgeSource) error {
	if len(sources) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "No knowledge sources found. Use 'gibson knowledge ingest' to add content.\n")
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SOURCE\tTYPE\tCHUNKS\tINGESTED")
	fmt.Fprintln(w, "------\t----\t------\t--------")

	for _, s := range sources {
		ingestedAt := s.IngestedAt.Format("2006-01-02 15:04")
		// Truncate long source names
		source := s.Source
		if len(source) > 50 {
			source = "..." + source[len(source)-47:]
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", source, s.SourceType, s.ChunkCount, ingestedAt)
	}
	w.Flush()

	fmt.Fprintf(cmd.OutOrStdout(), "\nTotal: %d sources\n", len(sources))
	return nil
}

// runKnowledgeStats handles the knowledge stats command
func runKnowledgeStats(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Check knowledge config before proceeding
	if err := checkKnowledgeConfig(cmd); err != nil {
		return err
	}

	// Initialize knowledge context
	kc, err := initKnowledgeContext()
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to initialize knowledge store", err)
	}
	defer kc.Close()

	// Get stats
	stats, err := kc.manager.GetStats(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to get stats", err)
	}

	// Output results
	if knowledgeStatsOutput == "json" {
		return outputKnowledgeStatsJSON(cmd, stats)
	}

	return outputKnowledgeStatsText(cmd, stats)
}

// outputKnowledgeStatsJSON outputs stats as JSON
func outputKnowledgeStatsJSON(cmd *cobra.Command, stats knowledge.KnowledgeStats) error {
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(stats)
}

// outputKnowledgeStatsText outputs stats as text
func outputKnowledgeStatsText(cmd *cobra.Command, stats knowledge.KnowledgeStats) error {
	fmt.Fprintln(cmd.OutOrStdout(), "Knowledge Store Statistics")
	fmt.Fprintln(cmd.OutOrStdout(), "==========================")

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Total Sources:\t%d\n", stats.TotalSources)
	fmt.Fprintf(w, "Total Chunks:\t%d\n", stats.TotalChunks)
	fmt.Fprintf(w, "Storage Size:\t%s\n", formatBytes(stats.StorageBytes))

	if !stats.LastIngestTime.IsZero() {
		fmt.Fprintf(w, "Last Ingest:\t%s\n", stats.LastIngestTime.Format(time.RFC3339))
	} else {
		fmt.Fprintf(w, "Last Ingest:\t(none)\n")
	}

	if len(stats.SourcesByType) > 0 {
		fmt.Fprintln(w, "\nSources by Type:")
		for typ, count := range stats.SourcesByType {
			fmt.Fprintf(w, "  %s:\t%d\n", typ, count)
		}
	}
	w.Flush()

	return nil
}

// runKnowledgeDelete handles the knowledge delete command
func runKnowledgeDelete(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Check knowledge config before proceeding
	if err := checkKnowledgeConfig(cmd); err != nil {
		return err
	}

	// Validate that exactly one deletion target is specified
	if knowledgeDeleteSource == "" && !knowledgeDeleteAll {
		return internal.WrapError(internal.ExitConfigError,
			"no deletion target specified: use --source <name> or --all", nil)
	}
	if knowledgeDeleteSource != "" && knowledgeDeleteAll {
		return internal.WrapError(internal.ExitConfigError,
			"cannot specify both --source and --all", nil)
	}

	// Confirmation prompt for --all (unless --force is set)
	if knowledgeDeleteAll && !knowledgeDeleteForce {
		fmt.Fprintf(cmd.OutOrStdout(), "WARNING: This will delete ALL knowledge from the store.\n")
		fmt.Fprintf(cmd.OutOrStdout(), "This action CANNOT be undone.\n\n")
		fmt.Fprintf(cmd.OutOrStdout(), "Type 'yes' to confirm: ")

		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return internal.WrapError(internal.ExitError, "failed to read confirmation", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "yes" {
			fmt.Fprintf(cmd.OutOrStdout(), "Deletion cancelled\n")
			return nil
		}
	}

	// Initialize knowledge context
	kc, err := initKnowledgeContext()
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to initialize knowledge store", err)
	}
	defer kc.Close()

	if knowledgeDeleteAll {
		if err := kc.manager.DeleteAll(ctx); err != nil {
			return internal.WrapError(internal.ExitError, "failed to delete all knowledge", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "All knowledge deleted successfully.\n")
	} else {
		if err := kc.manager.DeleteBySource(ctx, knowledgeDeleteSource); err != nil {
			return internal.WrapError(internal.ExitError, "failed to delete source", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Deleted knowledge from source: %s\n", knowledgeDeleteSource)
	}

	return nil
}

// runKnowledgeSync handles the knowledge sync command (stub for cloud integration)
func runKnowledgeSync(cmd *cobra.Command, args []string) error {
	// Parse global flags to check for config
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to parse flags", err)
	}

	verbose := flags.IsVerbose()

	if verbose {
		fmt.Fprintf(cmd.OutOrStdout(), "Checking cloud sync configuration...\n\n")
	}

	// Note: Cloud sync feature not yet implemented.
	// Currently only local/Redis storage is supported.
	// Future versions may add cloud provider integration.
	configuredProvider := "local"

	if configuredProvider == "zero-day-ai" {
		// Cloud provider configured but not implemented yet
		fmt.Fprintf(cmd.OutOrStdout(), "Zero Day AI cloud integration coming soon.\n")
		fmt.Fprintf(cmd.OutOrStdout(), "\nYour configuration includes Zero Day AI provider, but cloud sync is not yet implemented.\n")
		fmt.Fprintf(cmd.OutOrStdout(), "Use 'gibson knowledge ingest' to add content to your local store.\n")
		return nil
	}

	// Local provider or no provider configured
	fmt.Fprintf(cmd.OutOrStdout(), "Cloud sync not configured. Use 'gibson knowledge ingest' to add content locally.\n")
	fmt.Fprintf(cmd.OutOrStdout(), "\nTo enable cloud sync in the future:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  1. Configure Zero Day AI provider in ~/.gibson/config.yaml:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "     knowledge:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "       provider: zero-day-ai\n")
	fmt.Fprintf(cmd.OutOrStdout(), "       api_key: <your-api-key>\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  2. Subscribe to Zero Day AI paid tier\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  3. Run 'gibson knowledge sync' to sync local and cloud knowledge\n")

	return nil
}
