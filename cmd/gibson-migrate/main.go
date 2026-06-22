// gibson-migrate applies and queries schema migrations across all provisioned
// tenant databases (Postgres and Neo4j).
//
// Usage:
//
//	gibson-migrate up [--tenant <id>] [--all] [--dry-run] [--store postgres|neo4j|all]
//	gibson-migrate status [--tenant <id>] [--all]
//	gibson-migrate down --tenant <id> --to <migration_id> [--confirm]
//
// Environment variables required when connecting to tenant databases:
//
//	POSTGRES_ADMIN_DSN       — admin postgres:// DSN (no database component required)
//	NEO4J_ADMIN_URI          — bolt:// or neo4j:// URI
//	NEO4J_ADMIN_USER         — Neo4j admin username
//	NEO4J_ADMIN_PASSWORD     — Neo4j admin password
//	GIBSON_MIGRATIONS_DIR    — absolute path to the gibson/migrations directory
//	                           (defaults to ./migrations relative to the binary)
//	KUBECONFIG               — path to kubeconfig for Tenant CRD enumeration
//	                           (optional; falls back to in-cluster service account)
//
// Spec: database-per-tenant-data-plane, Phase G, task 7.1.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	neo4j "github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/zeroroot-ai/gibson/cmd/gibson-migrate/internal/runner"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool/admin"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point. Returns an exit code:
//
//	0 — success
//	1 — hard configuration error (missing flags, env vars, etc.)
//	2 — partial success: at least one tenant failed but others succeeded
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 1
	}

	subcommand := args[0]
	rest := args[1:]

	switch subcommand {
	case "up":
		return cmdUp(ctx, rest, stdout, stderr)
	case "status":
		return cmdStatus(ctx, rest, stdout, stderr)
	case "down":
		return cmdDown(ctx, rest, stdout, stderr)
	case "platform":
		// `gibson-migrate platform {up|down|status}` operates on the
		// dashboard / control-plane Postgres DB via the embedded
		// platform migration set. Spec gibson-postgres-migrations
		// Requirement 2.4 + design Component 3.
		return runPlatform(ctx, rest, stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "error: unknown subcommand %q\n\n", subcommand)
		printUsage(stderr)
		return 1
	}
}

// ---------------------------------------------------------------------------
// Subcommand: up
// ---------------------------------------------------------------------------

func cmdUp(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(stderr)

	tenant := fs.String("tenant", "", "target a single tenant by ID")
	all := fs.Bool("all", false, "iterate all provisioned tenants")
	dryRun := fs.Bool("dry-run", false, "list pending migrations without applying them")
	store := fs.String("store", "all", "store to migrate: postgres, neo4j, or all")
	asJSON := fs.Bool("json", false, "emit machine-parseable JSON output")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if !*all && *tenant == "" {
		fmt.Fprintln(stderr, "error: one of --all or --tenant is required")
		fs.Usage()
		return 1
	}
	if *all && *tenant != "" {
		fmt.Fprintln(stderr, "error: --all and --tenant are mutually exclusive")
		return 1
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	neo4jDriver, err := newNeo4jDriver(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "error: neo4j driver: %v\n", err)
		return 1
	}
	if neo4jDriver != nil {
		defer neo4jDriver.Close(ctx)
	}

	tenants, err := resolveTenants(ctx, *tenant, *all, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "error: resolve tenants: %v\n", err)
		return 1
	}

	type tenantResult struct {
		Tenant  string   `json:"tenant"`
		Store   string   `json:"store"`
		Status  string   `json:"status"`
		From    uint     `json:"from"`
		To      uint     `json:"to"`
		Applied []string `json:"applied,omitempty"`
		Error   string   `json:"error,omitempty"`
	}

	var results []tenantResult
	hadErrors := false

	for _, tid := range tenants {
		select {
		case <-ctx.Done():
			fmt.Fprintln(stderr, "interrupted")
			return 1
		default:
		}

		if *store == "postgres" || *store == "all" {
			pg := &runner.PostgresRunner{
				DSN:           buildPostgresDSN(cfg, tid),
				MigrationsDir: filepath.Join(cfg.MigrationsDir, "postgres"),
			}

			if *dryRun {
				st, err := pg.Status(ctx)
				if err != nil {
					hadErrors = true
					results = append(results, tenantResult{Tenant: tid, Store: "postgres", Status: "error", Error: err.Error()})
					continue
				}
				pending := make([]string, 0, len(st.Pending))
				for _, p := range st.Pending {
					pending = append(pending, p.Name)
				}
				results = append(results, tenantResult{Tenant: tid, Store: "postgres", Status: "dry-run", From: st.Current, To: st.Target, Applied: pending})
			} else {
				cur, tgt, applied, err := pg.Apply(ctx)
				if err != nil {
					hadErrors = true
					results = append(results, tenantResult{Tenant: tid, Store: "postgres", Status: "error", From: cur, Error: err.Error()})
				} else {
					results = append(results, tenantResult{Tenant: tid, Store: "postgres", Status: "ok", From: cur, To: tgt, Applied: applied})
				}
			}
		}

		if (*store == "neo4j" || *store == "all") && neo4jDriver != nil {
			nr := &runner.Neo4jRunner{
				Driver:        neo4jDriver,
				DatabaseName:  tenantDBName(tid),
				MigrationsDir: filepath.Join(cfg.MigrationsDir, "neo4j"),
			}

			if *dryRun {
				st, err := nr.Status(ctx)
				if err != nil {
					hadErrors = true
					results = append(results, tenantResult{Tenant: tid, Store: "neo4j", Status: "error", Error: err.Error()})
					continue
				}
				pending := make([]string, 0, len(st.Pending))
				for _, p := range st.Pending {
					pending = append(pending, p.Name)
				}
				results = append(results, tenantResult{Tenant: tid, Store: "neo4j", Status: "dry-run", From: st.CurrentVersion, To: st.Target, Applied: pending})
			} else {
				_, cur, applied, err := nr.Apply(ctx)
				if err != nil {
					hadErrors = true
					results = append(results, tenantResult{Tenant: tid, Store: "neo4j", Status: "error", Error: err.Error()})
				} else {
					var fromVer uint
					if cur != "" {
						// resolveVersion not needed — just report last applied name
					}
					_ = fromVer
					results = append(results, tenantResult{Tenant: tid, Store: "neo4j", Status: "ok", Applied: applied})
				}
			}
		}
	}

	printResults(stdout, results, *asJSON)

	if hadErrors {
		return 2
	}
	return 0
}

// ---------------------------------------------------------------------------
// Subcommand: status
// ---------------------------------------------------------------------------

func cmdStatus(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)

	tenant := fs.String("tenant", "", "target a single tenant by ID")
	all := fs.Bool("all", false, "iterate all provisioned tenants")
	asJSON := fs.Bool("json", false, "emit machine-parseable JSON output")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if !*all && *tenant == "" {
		fmt.Fprintln(stderr, "error: one of --all or --tenant is required")
		fs.Usage()
		return 1
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	neo4jDriver, err := newNeo4jDriver(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "warning: neo4j driver unavailable: %v\n", err)
	}
	if neo4jDriver != nil {
		defer neo4jDriver.Close(ctx)
	}

	tenants, err := resolveTenants(ctx, *tenant, *all, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "error: resolve tenants: %v\n", err)
		return 1
	}

	type statusResult struct {
		Tenant         string   `json:"tenant"`
		Store          string   `json:"store"`
		CurrentVersion uint     `json:"current_version"`
		TargetVersion  uint     `json:"target_version"`
		Dirty          bool     `json:"dirty,omitempty"`
		Pending        []string `json:"pending,omitempty"`
		Error          string   `json:"error,omitempty"`
	}

	var results []statusResult

	for _, tid := range tenants {
		pg := &runner.PostgresRunner{
			DSN:           buildPostgresDSN(cfg, tid),
			MigrationsDir: filepath.Join(cfg.MigrationsDir, "postgres"),
		}
		st, err := pg.Status(ctx)
		if err != nil {
			results = append(results, statusResult{Tenant: tid, Store: "postgres", Error: err.Error()})
		} else {
			pending := make([]string, 0, len(st.Pending))
			for _, p := range st.Pending {
				pending = append(pending, p.Name)
			}
			results = append(results, statusResult{
				Tenant:         tid,
				Store:          "postgres",
				CurrentVersion: st.Current,
				TargetVersion:  st.Target,
				Dirty:          st.Dirty,
				Pending:        pending,
			})
		}

		if neo4jDriver != nil {
			nr := &runner.Neo4jRunner{
				Driver:        neo4jDriver,
				DatabaseName:  tenantDBName(tid),
				MigrationsDir: filepath.Join(cfg.MigrationsDir, "neo4j"),
			}
			nst, err := nr.Status(ctx)
			if err != nil {
				results = append(results, statusResult{Tenant: tid, Store: "neo4j", Error: err.Error()})
			} else {
				pending := make([]string, 0, len(nst.Pending))
				for _, p := range nst.Pending {
					pending = append(pending, p.Name)
				}
				results = append(results, statusResult{
					Tenant:         tid,
					Store:          "neo4j",
					CurrentVersion: nst.CurrentVersion,
					TargetVersion:  nst.Target,
					Pending:        pending,
				})
			}
		}
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return 0
	}

	for _, r := range results {
		if r.Error != "" {
			fmt.Fprintf(stdout, "%-20s %-8s ERROR: %s\n", r.Tenant, r.Store, r.Error)
			continue
		}
		pendingStr := "none"
		if len(r.Pending) > 0 {
			pendingStr = strings.Join(r.Pending, ", ")
		}
		dirtyStr := ""
		if r.Dirty {
			dirtyStr = " [DIRTY]"
		}
		fmt.Fprintf(stdout, "%-20s %-8s current=%-4d target=%-4d pending=[%s]%s\n",
			r.Tenant, r.Store, r.CurrentVersion, r.TargetVersion, pendingStr, dirtyStr)
	}
	return 0
}

// ---------------------------------------------------------------------------
// Subcommand: down
// ---------------------------------------------------------------------------

func cmdDown(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	fs.SetOutput(stderr)

	tenant := fs.String("tenant", "", "target tenant ID (required)")
	toVer := fs.Uint("to", 0, "migrate down to this version (required)")
	confirm := fs.Bool("confirm", false, "actually apply the down migration (otherwise dry-run)")
	store := fs.String("store", "all", "store to roll back: postgres, neo4j, or all")
	asJSON := fs.Bool("json", false, "emit machine-parseable JSON output")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if *tenant == "" {
		fmt.Fprintln(stderr, "error: --tenant is required for down migrations")
		fs.Usage()
		return 1
	}
	// Allow 0 explicitly to mean "roll back all" — no validation needed here.

	if !*confirm {
		fmt.Fprintln(stdout, "[dry-run] The following migrations would be rolled back (pass --confirm to execute):")
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	neo4jDriver, err := newNeo4jDriver(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "warning: neo4j driver unavailable: %v\n", err)
	}
	if neo4jDriver != nil {
		defer neo4jDriver.Close(ctx)
	}

	type downResult struct {
		Tenant     string   `json:"tenant"`
		Store      string   `json:"store"`
		ToVersion  uint     `json:"to_version"`
		RolledBack []string `json:"rolled_back,omitempty"`
		DryRun     bool     `json:"dry_run"`
		Error      string   `json:"error,omitempty"`
	}

	var results []downResult

	if *store == "postgres" || *store == "all" {
		pg := &runner.PostgresRunner{
			DSN:           buildPostgresDSN(cfg, *tenant),
			MigrationsDir: filepath.Join(cfg.MigrationsDir, "postgres"),
		}

		if !*confirm {
			// Dry-run: show what would be rolled back.
			st, err := pg.Status(ctx)
			if err != nil {
				results = append(results, downResult{Tenant: *tenant, Store: "postgres", ToVersion: *toVer, DryRun: true, Error: err.Error()})
			} else {
				var pending []string
				for _, a := range st.Applied {
					if a > *toVer {
						pending = append(pending, fmt.Sprintf("version %d", a))
					}
				}
				results = append(results, downResult{Tenant: *tenant, Store: "postgres", ToVersion: *toVer, DryRun: true, RolledBack: pending})
			}
		} else {
			rb, err := pg.Down(ctx, *toVer)
			if err != nil {
				results = append(results, downResult{Tenant: *tenant, Store: "postgres", ToVersion: *toVer, Error: err.Error()})
			} else {
				results = append(results, downResult{Tenant: *tenant, Store: "postgres", ToVersion: *toVer, RolledBack: rb})
			}
		}
	}

	if (*store == "neo4j" || *store == "all") && neo4jDriver != nil {
		nr := &runner.Neo4jRunner{
			Driver:        neo4jDriver,
			DatabaseName:  tenantDBName(*tenant),
			MigrationsDir: filepath.Join(cfg.MigrationsDir, "neo4j"),
		}

		if !*confirm {
			st, err := nr.Status(ctx)
			if err != nil {
				results = append(results, downResult{Tenant: *tenant, Store: "neo4j", ToVersion: *toVer, DryRun: true, Error: err.Error()})
			} else {
				var pending []string
				for _, p := range st.Pending {
					if p.Version > *toVer {
						pending = append(pending, p.Name)
					}
				}
				_ = pending
				results = append(results, downResult{Tenant: *tenant, Store: "neo4j", ToVersion: *toVer, DryRun: true})
			}
		} else {
			rb, err := nr.Down(ctx, *toVer)
			if err != nil {
				results = append(results, downResult{Tenant: *tenant, Store: "neo4j", ToVersion: *toVer, Error: err.Error()})
			} else {
				results = append(results, downResult{Tenant: *tenant, Store: "neo4j", ToVersion: *toVer, RolledBack: rb})
			}
		}
	}

	printResults(stdout, results, *asJSON)

	for _, r := range results {
		if r.Error != "" {
			return 2
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// Config and environment
// ---------------------------------------------------------------------------

type cliConfig struct {
	// PostgresAdminDSN is the admin DSN without a database component.
	// Tenant database name is appended per-tenant.
	PostgresAdminDSN string

	// Neo4jURI, Neo4jUser, Neo4jPassword are admin Neo4j credentials.
	Neo4jURI      string
	Neo4jUser     string
	Neo4jPassword string

	// MigrationsDir is the root of the migrations/ directory tree.
	// Subdirectories "postgres" and "neo4j" are expected.
	MigrationsDir string

	// Kubeconfig is optional; empty means in-cluster service-account.
	Kubeconfig string
}

func loadConfig() (*cliConfig, error) {
	cfg := &cliConfig{
		PostgresAdminDSN: os.Getenv("POSTGRES_ADMIN_DSN"),
		Neo4jURI:         os.Getenv("NEO4J_ADMIN_URI"),
		Neo4jUser:        os.Getenv("NEO4J_ADMIN_USER"),
		Neo4jPassword:    os.Getenv("NEO4J_ADMIN_PASSWORD"),
		Kubeconfig:       os.Getenv("KUBECONFIG"),
	}

	dir := os.Getenv("GIBSON_MIGRATIONS_DIR")
	if dir == "" {
		// Default: migrations/ relative to the binary's working directory.
		dir = "migrations"
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve migrations dir: %w", err)
	}
	cfg.MigrationsDir = abs

	return cfg, nil
}

// newNeo4jDriver creates a Neo4j driver from environment config.
// Returns nil (not an error) if no URI is configured, so callers can skip
// Neo4j gracefully when not configured.
func newNeo4jDriver(cfg *cliConfig) (neo4j.DriverWithContext, error) {
	if cfg.Neo4jURI == "" {
		return nil, nil
	}
	auth := neo4j.BasicAuth(cfg.Neo4jUser, cfg.Neo4jPassword, "")
	driver, err := neo4j.NewDriverWithContext(cfg.Neo4jURI, auth)
	if err != nil {
		return nil, fmt.Errorf("neo4j.NewDriverWithContext: %w", err)
	}
	return driver, nil
}

// resolveTenants returns the list of tenant IDs to operate on based on the
// --tenant / --all flags. When --all is true it enumerates Tenant CRDs from
// the Kubernetes API. When --tenant is set it returns a single-element slice.
func resolveTenants(ctx context.Context, tenantFlag string, allFlag bool, cfg *cliConfig) ([]string, error) {
	if tenantFlag != "" {
		return []string{tenantFlag}, nil
	}

	// Build a Kubernetes client for tenant enumeration.
	var k8sCfg *rest.Config
	var err error
	if cfg.Kubeconfig != "" {
		k8sCfg, err = clientcmd.BuildConfigFromFlags("", cfg.Kubeconfig)
	} else {
		k8sCfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("kubernetes config: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(k8sCfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes dynamic client: %w", err)
	}

	lister := admin.NewK8sLister(dynClient, "")
	tids, err := lister.ListTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}

	_ = allFlag
	result := make([]string, 0, len(tids))
	for _, tid := range tids {
		result = append(result, tid.String())
	}
	return result, nil
}

// tenantGVR is the GroupVersionResource for the Tenant CRD.
var tenantGVR = schema.GroupVersionResource{
	Group:    "gibson.zeroroot.ai",
	Version:  "v1alpha1",
	Resource: "tenants",
}

// listAllTenants is a fallback for environments without the admin package.
func listAllTenants(ctx context.Context, dynClient dynamic.Interface) ([]string, error) {
	list, err := dynClient.Resource(tenantGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var tenants []string
	for _, item := range list.Items {
		meta, ok := item.Object["metadata"].(map[string]any)
		if !ok {
			continue
		}
		name, _ := meta["name"].(string)
		if name != "" {
			tenants = append(tenants, name)
		}
	}
	return tenants, nil
}

// buildPostgresDSN constructs a per-tenant Postgres DSN from the admin DSN by
// appending the tenant database name. The admin DSN is expected to be of the
// form postgres://user:pass@host:port/admin_db or similar. We replace the
// database component with tenant_<sanitized>.
func buildPostgresDSN(cfg *cliConfig, tenantID string) string {
	dbName := "tenant_" + sanitizeTenantID(tenantID)
	dsn := cfg.PostgresAdminDSN

	// Replace the last path segment of the DSN with the tenant DB name.
	// Handles both postgres://user:pass@host/admin and
	// postgres://user:pass@host:5432/admin forms.
	if idx := strings.LastIndex(dsn, "/"); idx >= 0 {
		// Check that the slash is after the "://" part.
		if idx > strings.Index(dsn, "://") {
			dsn = dsn[:idx+1] + dbName
		}
	}
	return dsn
}

// tenantDBName returns the Neo4j database name for a tenant.
func tenantDBName(tenantID string) string {
	return "tenant_" + sanitizeTenantID(tenantID)
}

// sanitizeTenantID returns a sanitized form of the tenant ID safe for use in
// database names and role names. Only alphanumeric characters and underscores
// are retained; all other characters are replaced with underscores.
func sanitizeTenantID(id string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(id) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

func printResults(w io.Writer, results any, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return
	}
	// Human-readable: reflect on the concrete type.
	// Use fmt.Fprintf for simplicity; the JSON encoding above handles the
	// structured case.
	fmt.Fprintf(w, "%+v\n", results)
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, "gibson-migrate — apply schema migrations across all tenant databases\n\nUsage:\n"+
		"  gibson-migrate up [--tenant <id>] [--all] [--dry-run] [--store postgres|neo4j|all] [--json]\n"+
		"  gibson-migrate status [--tenant <id>] [--all] [--json]\n"+
		"  gibson-migrate down --tenant <id> --to <version> [--store postgres|neo4j|all] [--confirm] [--json]\n\n"+
		"Environment variables:\n"+
		"  POSTGRES_ADMIN_DSN      Admin postgres DSN (postgres://user:pass@host/admin)\n"+
		"  NEO4J_ADMIN_URI         Neo4j bolt URI (bolt://neo4j:7687)\n"+
		"  NEO4J_ADMIN_USER        Neo4j admin username\n"+
		"  NEO4J_ADMIN_PASSWORD    Neo4j admin password\n"+
		"  GIBSON_MIGRATIONS_DIR   Path to migrations/ directory (default: ./migrations)\n"+
		"  KUBECONFIG              Path to kubeconfig (default: in-cluster)\n\n"+
		"Exit codes:\n"+
		"  0   All operations succeeded\n"+
		"  1   Hard configuration error\n"+
		"  2   Partial success: at least one tenant failed\n\n"+
		"Note: migration SQL and Cypher files are authored by Phase D (task 4.8/4.9).\n"+
		"      The runner machinery works on an empty migration set — it is a no-op.\n")
}
