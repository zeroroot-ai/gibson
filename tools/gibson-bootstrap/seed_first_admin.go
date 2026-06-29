package main

// seed_first_admin.go implements the seed-first-admin subcommand for
// gibson-bootstrap.
//
// This subcommand is the bootstrap mechanism for fresh self-hosted installs
// (deploy ADR-0006, gibson#1088). When SIGNUP_SELF_SERVE is unset, the only
// way to create the initial principal is via AdminTenantService.AdminProvisionTenant.
// This subcommand calls that RPC from a helm post-install Job (or on-demand CLI)
// using the daemon's gRPC endpoint, seeding the first admin user + tenant.
//
// # Idempotency
//
// AdminProvisionTenant is idempotent on tenant_id: if a provision op for the
// slug is already pending, the call returns an empty op_id and this command
// treats it as a no-op success. Callers must not panic on already_existed=true.
//
// # Required env vars
//
//	GIBSON_DAEMON_ADDR      — daemon gRPC address (e.g. gibson-daemon:50051)
//	BOOTSTRAP_ADMIN_EMAIL   — email address for the first admin user
//	BOOTSTRAP_TENANT_ID     — tenant slug (e.g. "default" or "acme")
//	BOOTSTRAP_TENANT_DISPLAY_NAME — human-readable workspace name
//
// # Optional env vars
//
//	BOOTSTRAP_ADMIN_TIER    — plan tier; defaults to "team"
//
// # Output
//
//	{"tenant_id":"...","op_id":"...","already_existed":true|false}
//
// When already_existed=true the op_id is empty (idempotent de-dup).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// seedFirstAdminConfig holds the configuration for the seed-first-admin command.
type seedFirstAdminConfig struct {
	// DaemonAddr is the gRPC address of the gibson daemon (host:port).
	DaemonAddr string

	// AdminEmail is the email of the first admin user to associate with the tenant.
	AdminEmail string

	// TenantID is the tenant slug (e.g. "default" or derived from the workspace name).
	TenantID string

	// TenantDisplayName is the human-readable workspace name.
	TenantDisplayName string

	// Tier is the plan tier. Defaults to "team" when empty.
	Tier string

	// TLSCertFile / TLSKeyFile / TLSCAFile are optional mTLS credentials.
	// When all three are empty, the command uses insecure transport (suitable
	// for in-cluster Jobs where the mTLS sidecar handles transport encryption).
	TLSCertFile string
	TLSKeyFile  string
	TLSCAFile   string
}

// seedFirstAdminResult is the JSON output of the seed-first-admin command.
type seedFirstAdminResult struct {
	TenantID       string `json:"tenant_id"`
	OpID           string `json:"op_id"`
	AlreadyExisted bool   `json:"already_existed"`
}

// loadSeedFirstAdminConfig reads the seed-first-admin configuration from
// environment variables. Returns an error if any required variable is missing.
func loadSeedFirstAdminConfig() (seedFirstAdminConfig, error) {
	daemonAddr := os.Getenv("GIBSON_DAEMON_ADDR")
	if daemonAddr == "" {
		return seedFirstAdminConfig{}, errors.New("GIBSON_DAEMON_ADDR env must be set (e.g. gibson-daemon:50051)")
	}

	adminEmail := os.Getenv("BOOTSTRAP_ADMIN_EMAIL")
	if adminEmail == "" {
		return seedFirstAdminConfig{}, errors.New("BOOTSTRAP_ADMIN_EMAIL env must be set")
	}

	tenantID := os.Getenv("BOOTSTRAP_TENANT_ID")
	if tenantID == "" {
		return seedFirstAdminConfig{}, errors.New("BOOTSTRAP_TENANT_ID env must be set (e.g. 'default')")
	}

	displayName := os.Getenv("BOOTSTRAP_TENANT_DISPLAY_NAME")
	if displayName == "" {
		return seedFirstAdminConfig{}, errors.New("BOOTSTRAP_TENANT_DISPLAY_NAME env must be set")
	}

	tier := os.Getenv("BOOTSTRAP_ADMIN_TIER")
	if tier == "" {
		tier = "team"
	}

	return seedFirstAdminConfig{
		DaemonAddr:        daemonAddr,
		AdminEmail:        adminEmail,
		TenantID:          tenantID,
		TenantDisplayName: displayName,
		Tier:              tier,
		TLSCertFile:       os.Getenv("GIBSON_BOOTSTRAP_MTLS_CERT"),
		TLSKeyFile:        os.Getenv("GIBSON_BOOTSTRAP_MTLS_KEY"),
		TLSCAFile:         os.Getenv("GIBSON_BOOTSTRAP_MTLS_CA"),
	}, nil
}

// cmdSeedFirstAdmin handles the seed-first-admin subcommand.
//
// It calls AdminTenantService.AdminProvisionTenant on the daemon to enqueue
// the first tenant for operator-pull provisioning. This is idempotent: if the
// tenant is already in the queue, it is a no-op success.
func cmdSeedFirstAdmin(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("seed-first-admin takes no positional arguments; configure via env vars")
	}

	cfg, err := loadSeedFirstAdminConfig()
	if err != nil {
		return err
	}

	// Build gRPC dial options.
	dialOpt, err := buildDialOpts(cfg)
	if err != nil {
		return fmt.Errorf("building gRPC dial options: %w", err)
	}

	conn, err := grpc.NewClient(cfg.DaemonAddr, dialOpt)
	if err != nil {
		return fmt.Errorf("dialing daemon at %s: %w", cfg.DaemonAddr, err)
	}
	defer conn.Close() //nolint:errcheck // Close is best-effort on a dialled connection

	client := tenantv1.NewAdminTenantServiceClient(conn)

	resp, err := client.AdminProvisionTenant(ctx, &tenantv1.AdminProvisionTenantRequest{
		TenantId:    cfg.TenantID,
		DisplayName: cfg.TenantDisplayName,
		OwnerEmail:  cfg.AdminEmail,
		Tier:        cfg.Tier,
	})
	if err != nil {
		return fmt.Errorf("AdminProvisionTenant: %w", err)
	}

	alreadyExisted := resp.GetOpId() == ""

	return writeJSON(seedFirstAdminResult{
		TenantID:       cfg.TenantID,
		OpID:           resp.GetOpId(),
		AlreadyExisted: alreadyExisted,
	})
}

// buildDialOpts constructs the gRPC dial options from the config.
// When mTLS cert/key/CA are all provided, mutual TLS is used.
// When they are all absent, insecure transport is used (in-cluster Job pattern).
// Partial configuration (some but not all three set) is an error.
func buildDialOpts(cfg seedFirstAdminConfig) (grpc.DialOption, error) {
	hasCert := cfg.TLSCertFile != ""
	hasKey := cfg.TLSKeyFile != ""
	hasCA := cfg.TLSCAFile != ""

	// No TLS configured: use insecure (in-cluster Job pattern — mTLS handled
	// at the sidecar/service-mesh layer, not this binary).
	if !hasCert && !hasKey && !hasCA {
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	}

	// Partial mTLS config is a misconfiguration.
	if !hasCert || !hasKey || !hasCA {
		return nil, errors.New("mTLS requires all three env vars: GIBSON_BOOTSTRAP_MTLS_CERT, GIBSON_BOOTSTRAP_MTLS_KEY, GIBSON_BOOTSTRAP_MTLS_CA")
	}

	// Load the client cert+key pair.
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading mTLS client cert/key: %w", err)
	}

	// Load the CA cert pool.
	caPEM, err := os.ReadFile(cfg.TLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("reading mTLS CA file %s: %w", cfg.TLSCAFile, err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse mTLS CA certificate from %s", cfg.TLSCAFile)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}
	return grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)), nil
}
