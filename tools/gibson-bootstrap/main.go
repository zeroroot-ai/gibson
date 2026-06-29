// Package main is the entry point for gibson-bootstrap, a single-purpose CLI
// invoked by the chart's bootstrap-secrets Job to provision Zitadel resources
// during helm install / upgrade.
//
// All operations are idempotent. Output is a single line of compact JSON on
// stdout. All log output goes to stderr. Exit code is 0 on success, non-zero
// on any error.
//
// Subcommands:
//
//	gibson-bootstrap zitadel-ensure-org <name>
//	gibson-bootstrap zitadel-mint-oidc-client <client-name>
//	gibson-bootstrap zitadel-mint-user-pat <username> [--rotate] [--roles=<list>]
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	// Catch SIGINT/SIGTERM so in-flight HTTP calls can finish cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "gibson-bootstrap: %v\n", err)
		os.Exit(1)
	}
}

// run dispatches to the appropriate subcommand handler.
func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: gibson-bootstrap <subcommand> [args...]\n\nSubcommands:\n  zitadel-ensure-org <name>\n  zitadel-ensure-project <name>\n  zitadel-mint-oidc-client <client-name>\n  zitadel-mint-user-pat <username> [--rotate] [--roles=<list>]\n  seed-first-admin")
	}

	subcommand := args[0]
	rest := args[1:]

	switch subcommand {
	case "zitadel-ensure-org":
		return cmdEnsureOrg(ctx, rest)
	case "zitadel-ensure-project":
		return cmdEnsureProject(ctx, rest)
	case "zitadel-mint-oidc-client":
		return cmdMintOIDCClient(ctx, rest)
	case "zitadel-mint-user-pat":
		return cmdMintUserPAT(ctx, rest)
	case "seed-first-admin":
		return cmdSeedFirstAdmin(ctx, rest)
	default:
		return fmt.Errorf("unknown subcommand %q; valid subcommands: zitadel-ensure-org, zitadel-ensure-project, zitadel-mint-oidc-client, zitadel-mint-user-pat, seed-first-admin", subcommand)
	}
}

// cmdMintUserPAT handles the zitadel-mint-user-pat subcommand.
//
// Required env:
//
//	ZITADEL_ISSUER    — Zitadel base URL
//	ZITADEL_ADMIN_PAT — Personal access token with IAM_OWNER scope
//
// Args: <username> [--rotate] [--roles=<role1,role2,...>]
//
// Output: {"user_id":"<id>","pat":"<token>","rotated":true|false}
//
// Idempotently ensures a Zitadel service user, optionally grants IAM roles,
// and emits a PAT. See user_pat.go for the rotation contract — when the
// user already has an active PAT, --rotate must be passed (Zitadel's list
// API does not return PAT secrets).
func cmdMintUserPAT(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "" {
		return fmt.Errorf("usage: gibson-bootstrap zitadel-mint-user-pat <username> [--rotate] [--roles=<list>]")
	}

	username := args[0]
	rotate := false
	var roles []string
	for _, a := range args[1:] {
		switch {
		case a == "--rotate":
			rotate = true
		case strings.HasPrefix(a, "--roles="):
			raw := strings.TrimPrefix(a, "--roles=")
			for _, r := range strings.Split(raw, ",") {
				r = strings.TrimSpace(r)
				if r != "" {
					roles = append(roles, r)
				}
			}
		default:
			return fmt.Errorf("unknown flag %q", a)
		}
	}

	cfg, err := loadPATClientConfig()
	if err != nil {
		return err
	}

	c := newPATClient(cfg)
	result, err := c.MintUserPAT(ctx, MintUserPATRequest{
		Username: username,
		Roles:    roles,
		Rotate:   rotate,
	})
	if err != nil {
		return fmt.Errorf("zitadel-mint-user-pat: %w", err)
	}

	return writeJSON(result)
}

// cmdEnsureOrg handles the zitadel-ensure-org subcommand.
//
// Required env:
//
//	ZITADEL_ISSUER    — Zitadel base URL (e.g. http://gibson-zitadel.gibson.svc.cluster.local:8080)
//	ZITADEL_ADMIN_PAT — Personal access token with org-create scope
//
// Args: <name>
//
// Output: {"org_id":"<id>","created":true|false}
func cmdEnsureOrg(ctx context.Context, args []string) error {
	if len(args) != 1 || args[0] == "" {
		return fmt.Errorf("usage: gibson-bootstrap zitadel-ensure-org <name>")
	}
	name := args[0]

	cfg, err := loadPATClientConfig()
	if err != nil {
		return err
	}

	c := newPATClient(cfg)
	result, err := c.EnsureOrg(ctx, name)
	if err != nil {
		return fmt.Errorf("zitadel-ensure-org: %w", err)
	}

	return writeJSON(result)
}

// cmdEnsureProject handles the zitadel-ensure-project subcommand.
//
// Required env:
//
//	ZITADEL_ISSUER    — Zitadel base URL
//	ZITADEL_ADMIN_PAT — Personal access token with project-create scope
//	ZITADEL_ORG_ID    — Organisation ID under which the project is created
//
// Args: <name>
//
// Output: {"project_id":"<id>","created":true|false}
func cmdEnsureProject(ctx context.Context, args []string) error {
	if len(args) != 1 || args[0] == "" {
		return fmt.Errorf("usage: gibson-bootstrap zitadel-ensure-project <name>")
	}
	name := args[0]

	cfg, err := loadPATClientConfig()
	if err != nil {
		return err
	}

	orgID := os.Getenv("ZITADEL_ORG_ID")
	if orgID == "" {
		return fmt.Errorf("ZITADEL_ORG_ID env must be set")
	}

	c := newPATClient(cfg)
	result, err := c.EnsureProject(ctx, orgID, name)
	if err != nil {
		return fmt.Errorf("zitadel-ensure-project: %w", err)
	}

	return writeJSON(result)
}

// cmdMintOIDCClient handles the zitadel-mint-oidc-client subcommand.
//
// Required env:
//
//	ZITADEL_ISSUER     — Zitadel base URL
//	ZITADEL_ADMIN_PAT  — Personal access token with application-create scope
//	ZITADEL_ORG_ID     — Organisation ID in which the project lives
//	ZITADEL_PROJECT_ID — Project ID in which the OIDC client will be created
//
// Optional flags (must appear after the positional <client-name>):
//
//	--rotate-secret    — Regenerate the client secret even if the app already exists
//
// Args: <client-name> [--rotate-secret]
//
// Output: {"client_id":"<id>","client_secret":"<secret>","rotated":true|false}
func cmdMintOIDCClient(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "" {
		return fmt.Errorf("usage: gibson-bootstrap zitadel-mint-oidc-client <client-name> [--rotate-secret]")
	}

	clientName := args[0]
	rotateSecret := false
	for _, a := range args[1:] {
		if a == "--rotate-secret" {
			rotateSecret = true
		} else {
			return fmt.Errorf("unknown flag %q", a)
		}
	}

	cfg, err := loadPATClientConfig()
	if err != nil {
		return err
	}

	orgID := os.Getenv("ZITADEL_ORG_ID")
	if orgID == "" {
		return fmt.Errorf("ZITADEL_ORG_ID env must be set")
	}

	projectID := os.Getenv("ZITADEL_PROJECT_ID")
	if projectID == "" {
		return fmt.Errorf("ZITADEL_PROJECT_ID env must be set")
	}

	c := newPATClient(cfg)
	result, err := c.MintOIDCClient(ctx, MintOIDCClientRequest{
		ClientName:   clientName,
		OrgID:        orgID,
		ProjectID:    projectID,
		RotateSecret: rotateSecret,
	})
	if err != nil {
		return fmt.Errorf("zitadel-mint-oidc-client: %w", err)
	}

	return writeJSON(result)
}
