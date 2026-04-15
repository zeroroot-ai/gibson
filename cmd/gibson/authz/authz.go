// Package authz provides the `gibson authz` CLI subcommand for interacting
// with the OpenFGA authorization service.
//
// Subcommands:
//
//	check       — evaluate a single authorization check (user, relation, object)
//	write       — write a relationship tuple to the FGA store
//	model-info  — display the active store ID and authorization model ID
package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/config"
)

// Cmd is the root `gibson authz` command.
var Cmd = &cobra.Command{
	Use:   "authz",
	Short: "Interact with the OpenFGA authorization service",
	Long: `The authz subcommand provides direct access to the OpenFGA authorization
service for debugging, auditing, and operational tasks.

Commands require authz.enabled=true in the Gibson config file (or environment
variables) and a reachable FGA endpoint.

Examples:

  # Check whether alice is a member of the acme tenant
  gibson authz check user:alice member tenant:acme

  # Write a platform_operator tuple for a user
  gibson authz write user:root platform_operator system_tenant:_system

  # Display active store and model IDs
  gibson authz model-info`,
	// No RunE - shows help when no subcommand is given
}

func init() {
	Cmd.AddCommand(checkCmd)
	Cmd.AddCommand(writeCmd)
	Cmd.AddCommand(modelInfoCmd)
	Cmd.AddCommand(newInspectRpcCmd())
	Cmd.AddCommand(newListRpcsCmd())
}

// newAuthorizerFromConfig constructs an FGA authorizer from the loaded config.
// Returns an error if authz is disabled or if the FGA client cannot be constructed.
func newAuthorizerFromConfig(ctx context.Context, cfg config.AuthzConfig) (authz.Authorizer, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("authz is disabled (authz.enabled=false) — enable it in config to use authz commands")
	}

	storeID, modelID, err := authz.ResolveStoreAndModelIDs(ctx, authz.IDConfig{
		StoreID: cfg.Fga.StoreID,
		ModelID: cfg.Fga.ModelID,
	}, nil) // nil → auto-detect in-cluster config; falls through to env vars
	if err != nil {
		return nil, fmt.Errorf("failed to resolve FGA store/model IDs: %w", err)
	}

	a, err := authz.NewFgaAuthorizer(ctx, authz.FgaConfig{
		Endpoint:   cfg.Fga.Endpoint,
		StoreID:    storeID,
		ModelID:    modelID,
		TimeoutMs:  cfg.Fga.TimeoutMs,
		TLSEnabled: cfg.Fga.TLS.Enabled,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to construct FGA authorizer: %w", err)
	}

	return a, nil
}

// loadAuthzConfig loads the daemon config and returns the AuthzConfig section.
// Uses GIBSON_HOME and GIBSON_CONFIG env vars for config file resolution.
func loadAuthzConfig(cmd *cobra.Command) (config.AuthzConfig, error) {
	homeDir := os.Getenv("GIBSON_HOME")
	if homeDir == "" {
		homeDir = config.DefaultHomeDir()
	}

	configFilePath := os.Getenv("GIBSON_CONFIG")
	if configFilePath == "" {
		configFilePath = config.DefaultConfigPath(homeDir)
	}

	loader := config.NewConfigLoader(config.NewValidator())
	cfg, err := loader.LoadWithDefaults(configFilePath)
	if err != nil {
		// Return default config so env vars still work
		cfg = config.DefaultConfig()
	}

	return cfg.Authz, nil
}

// --- `gibson authz check` ---

var checkCmd = &cobra.Command{
	Use:   "check <user> <relation> <object>",
	Short: "Evaluate a single FGA authorization check",
	Long: `Evaluate whether <user> has <relation> on <object> in the FGA store.

Both true (allowed) and false (denied) are valid outcomes. A non-zero exit code
indicates a communication error with the FGA service, not a permission denial.

Examples:

  # Check if alice is admin of the acme tenant
  gibson authz check user:alice admin tenant:acme

  # Check if root has platform_operator on the system singleton
  gibson authz check user:root platform_operator system_tenant:_system`,
	Args: cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		user, relation, object := args[0], args[1], args[2]

		authzCfg, err := loadAuthzConfig(cmd)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
		defer cancel()

		a, err := newAuthorizerFromConfig(ctx, authzCfg)
		if err != nil {
			return err
		}
		defer a.Close()

		allowed, err := a.Check(ctx, user, relation, object)
		if err != nil {
			return fmt.Errorf("FGA check failed: %w", err)
		}

		result := map[string]interface{}{
			"user":     user,
			"relation": relation,
			"object":   object,
			"allowed":  allowed,
		}

		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)

		if !allowed {
			cmd.PrintErrln("Result: DENIED")
		} else {
			cmd.PrintErrln("Result: ALLOWED")
		}

		return nil
	},
}

// --- `gibson authz write` ---

var writeCmd = &cobra.Command{
	Use:   "write <user> <relation> <object>",
	Short: "Write a relationship tuple to the FGA store",
	Long: `Write a relationship tuple (user, relation, object) to the FGA store.

Writing is idempotent — writing a tuple that already exists succeeds silently.

Examples:

  # Grant alice admin rights on the acme tenant
  gibson authz write user:alice admin tenant:acme

  # Grant root platform_operator privilege
  gibson authz write user:root platform_operator system_tenant:_system`,
	Args: cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		user, relation, object := args[0], args[1], args[2]

		authzCfg, err := loadAuthzConfig(cmd)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
		defer cancel()

		a, err := newAuthorizerFromConfig(ctx, authzCfg)
		if err != nil {
			return err
		}
		defer a.Close()

		tuples := []authz.Tuple{
			{User: user, Relation: relation, Object: object},
		}

		if err := a.Write(ctx, tuples); err != nil {
			return fmt.Errorf("FGA write failed: %w", err)
		}

		result := map[string]interface{}{
			"written": tuples,
			"status":  "ok",
		}

		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)

		cmd.PrintErrln("Tuple written successfully.")
		return nil
	},
}

// --- `gibson authz model-info` ---

var modelInfoCmd = &cobra.Command{
	Use:   "model-info",
	Short: "Display the active FGA store ID and authorization model ID",
	Long: `Print the resolved FGA store ID and authorization model ID from the
current configuration. Useful for verifying which store and model the daemon
will use after the gibson-fga-init Job runs.

Sources checked (in priority order):
  1. Config file (authz.fga.store_id / authz.fga.model_id)
  2. Kubernetes ConfigMap gibson/gibson-fga-config
  3. Environment variables GIBSON_AUTHZ_FGA_STORE_ID / GIBSON_AUTHZ_FGA_MODEL_ID`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		authzCfg, err := loadAuthzConfig(cmd)
		if err != nil {
			return err
		}

		if !authzCfg.Enabled {
			cmd.PrintErrln("Warning: authz.enabled=false — showing configured IDs only (FGA not active)")
		}

		ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
		defer cancel()

		storeID, modelID, resolveErr := authz.ResolveStoreAndModelIDs(ctx, authz.IDConfig{
			StoreID: authzCfg.Fga.StoreID,
			ModelID: authzCfg.Fga.ModelID,
		}, nil)

		info := map[string]interface{}{
			"enabled":  authzCfg.Enabled,
			"provider": authzCfg.Provider,
			"endpoint": authzCfg.Fga.Endpoint,
			"store_id": storeID,
			"model_id": modelID,
		}

		if resolveErr != nil {
			info["resolve_error"] = resolveErr.Error()
		}

		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		_ = enc.Encode(info)

		if resolveErr != nil {
			return fmt.Errorf("could not fully resolve FGA IDs: %w", resolveErr)
		}

		return nil
	},
}
