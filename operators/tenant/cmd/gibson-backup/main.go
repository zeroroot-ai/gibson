/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// gibson-backup is a per-tenant backup and restore CLI for the Gibson
// data plane. It fans out across the four per-tenant stores (Postgres, Neo4j,
// Redis, vector), encrypts each backup blob with a fresh DEK wrapped by
// the tenant KEK (HKDF from master KEK), and writes a manifest to
// S3-compatible object storage.
//
// Subcommands:
//
//	create   --tenant <id> [--store all|postgres|neo4j|redis|vector] [--note "..."]
//	list     [--tenant <id>] [--limit N]
//	restore  --tenant <id> --backup-id <id> [--store ...] [--target-tenant <id>] [--confirm]
//	verify   --tenant <id> --backup-id <id>
//
// Configuration via environment variables:
//
//	MASTER_KEK          — hex-encoded 32-byte master KEK (required)
//	S3_BUCKET           — target bucket (required)
//	S3_ACCESS_KEY       — S3 access key (required)
//	S3_SECRET_KEY       — S3 secret key (required)
//	S3_ENDPOINT         — optional; empty means AWS S3
//	S3_REGION           — optional; defaults to us-east-1
//	S3_USE_SSL          — optional; defaults to true
//	PG_ADMIN_DSN        — Postgres admin DSN (required for postgres store)
//	NEO4J_URI           — Neo4j bolt URI, e.g. bolt://host:7687 (required for neo4j store)
//	NEO4J_USERNAME      — Neo4j admin username
//	NEO4J_PASSWORD      — Neo4j admin password
//	REDIS_ADDR          — Redis address host:port (required for redis store)
//	REDIS_PASSWORD      — Redis auth password
//	REDIS_DB_INDEX      — override the tenant's logical DB index (default 1)
//	VECTOR_REDIS_ADDR   — Redis address host:port for the vector store (required for vector store)
//	VECTOR_REDIS_PASSWORD — optional Redis password for the vector store
//	VECTOR_REDIS_DB     — Redis DB index for the vector store (default 0)
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/hkdf"

	"github.com/zeroroot-ai/gibson/operators/tenant/cmd/gibson-backup/internal/envelope"
	"github.com/zeroroot-ai/gibson/operators/tenant/cmd/gibson-backup/internal/manifest"
	s3client "github.com/zeroroot-ai/gibson/operators/tenant/cmd/gibson-backup/internal/s3"
	"github.com/zeroroot-ai/gibson/operators/tenant/cmd/gibson-backup/internal/store"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// globalFlags holds flags shared across subcommands.
type globalFlags struct {
	jsonOutput bool
}

func newRootCmd() *cobra.Command {
	gf := &globalFlags{}

	root := &cobra.Command{
		Use:   "gibson-backup",
		Short: "Per-tenant backup and restore for the Gibson data plane",
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if gf.jsonOutput {
				slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
			}
			return nil
		},
	}
	root.PersistentFlags().BoolVar(&gf.jsonOutput, "json", false, "emit machine-parseable JSON progress lines to stderr")

	root.AddCommand(
		newCreateCmd(gf),
		newListCmd(gf),
		newRestoreCmd(gf),
		newVerifyCmd(),
	)
	return root
}

// --------------------------------------------------------------------------
// create
// --------------------------------------------------------------------------

func newCreateCmd(gf *globalFlags) *cobra.Command {
	var tenantID, note string
	var storeNames []string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a per-tenant backup",
		Example: `  gibson-backup create --tenant acme
  gibson-backup create --tenant acme --store postgres --store neo4j --note "pre-migration"`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCreate(cmd.Context(), gf, tenantID, storeNames, note)
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID to back up (required)")
	cmd.Flags().StringArrayVar(&storeNames, "store", []string{"all"}, "stores to include: all|postgres|neo4j|redis|vector")
	cmd.Flags().StringVar(&note, "note", "", "optional human-readable label")
	_ = cmd.MarkFlagRequired("tenant")
	return cmd
}

func runCreate(ctx context.Context, gf *globalFlags, tenantID string, storeNames []string, note string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	targets := resolveStores(storeNames)
	backupID := manifest.BackupIDFromTime(time.Now().UTC())

	emit(gf, "create_start", map[string]any{
		"tenant":    tenantID,
		"backup_id": backupID,
		"stores":    targets,
	})

	kek, err := deriveTenantKEK(cfg.masterKEK, tenantID)
	if err != nil {
		return fmt.Errorf("derive KEK: %w", err)
	}
	defer zeroSlice(kek)

	s3, err := s3client.New(cfg.s3)
	if err != nil {
		return fmt.Errorf("s3 client: %w", err)
	}

	m := &manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion,
		BackupID:      backupID,
		TenantID:      tenantID,
		CreatedAt:     time.Now().UTC(),
		Note:          note,
	}

	for _, sn := range targets {
		emit(gf, "store_start", map[string]any{"store": sn})

		blobKey := manifest.BlobPath(tenantID, backupID, sn)
		plaintextSize, digest, err := backupAndUpload(ctx, cfg, kek, sn, tenantID, s3, blobKey)
		if err != nil {
			if errors.Is(err, store.ErrNeo4jAPOCNotAvailable) {
				slog.WarnContext(ctx, "neo4j store skipped: APOC not available",
					"store", sn, "tenant", tenantID)
				emit(gf, "store_skipped", map[string]any{"store": sn, "reason": err.Error()})
				continue
			}
			return fmt.Errorf("backup %q: %w", sn, err)
		}

		m.Blobs = append(m.Blobs, manifest.BlobEntry{
			Store:     sn,
			Path:      blobKey,
			SizeBytes: plaintextSize,
			SHA256:    digest,
		})
		emit(gf, "store_done", map[string]any{
			"store":      sn,
			"size_bytes": plaintextSize,
			"sha256":     digest,
		})
	}

	// Write manifest.
	var buf bytes.Buffer
	if err := manifest.Encode(&buf, m); err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	if _, err := s3.PutObject(ctx, manifest.ManifestPath(tenantID, backupID), &buf, int64(buf.Len())); err != nil {
		return fmt.Errorf("upload manifest: %w", err)
	}

	fmt.Printf("backup_id=%s\n", backupID)
	return nil
}

// backupAndUpload runs the per-store backup, wraps it in an envelope, and
// streams to S3. Returns the plaintext byte count and its SHA-256 hex digest.
func backupAndUpload(
	ctx context.Context,
	cfg *runtimeConfig,
	kek []byte,
	sn manifest.StoreName,
	tenantID string,
	s3 *s3client.Client,
	blobKey string,
) (int64, string, error) {
	var plainBuf bytes.Buffer
	h := sha256.New()
	plainWriter := io.MultiWriter(&plainBuf, h)

	switch sn {
	case manifest.StorePostgres:
		if _, _, err := store.PostgresBackup(ctx, buildPostgresDSN(cfg, tenantID), plainWriter); err != nil {
			return 0, "", err
		}
	case manifest.StoreNeo4j:
		if _, _, err := store.Neo4jBackup(ctx, buildNeo4jDSN(cfg, tenantID), plainWriter); err != nil {
			return 0, "", err
		}
	case manifest.StoreRedis:
		if _, _, err := store.RedisBackup(ctx, buildRedisDSN(cfg, tenantID), plainWriter); err != nil {
			return 0, "", err
		}
	case manifest.StoreVector:
		if _, _, err := store.VectorBackup(ctx, buildVectorDSN(cfg, tenantID), plainWriter); err != nil {
			return 0, "", err
		}
	default:
		return 0, "", fmt.Errorf("unknown store %q", sn)
	}

	plaintextSize := int64(plainBuf.Len())
	digest := hex.EncodeToString(h.Sum(nil))

	var encBuf bytes.Buffer
	if _, err := envelope.Seal(&encBuf, &plainBuf, kek); err != nil {
		return 0, "", fmt.Errorf("seal: %w", err)
	}

	if _, err := s3.PutObject(ctx, blobKey, &encBuf, int64(encBuf.Len())); err != nil {
		return 0, "", fmt.Errorf("upload: %w", err)
	}
	return plaintextSize, digest, nil
}

// --------------------------------------------------------------------------
// list
// --------------------------------------------------------------------------

func newListCmd(gf *globalFlags) *cobra.Command {
	var tenantID string
	var limit int

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List backups",
		Example: `  gibson-backup list
  gibson-backup list --tenant acme --limit 5`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runList(cmd.Context(), gf, tenantID, limit)
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant", "", "filter by tenant ID (optional)")
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum number of results")
	return cmd
}

func runList(ctx context.Context, gf *globalFlags, tenantID string, limit int) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	s3, err := s3client.New(cfg.s3)
	if err != nil {
		return fmt.Errorf("s3 client: %w", err)
	}

	prefix := ""
	if tenantID != "" {
		prefix = tenantID + "/"
	}
	objects, err := s3.ListObjects(ctx, prefix)
	if err != nil {
		return fmt.Errorf("list objects: %w", err)
	}

	var mfObjs []minio.ObjectInfo
	for _, obj := range objects {
		if strings.HasSuffix(obj.Key, "/manifest.json") {
			mfObjs = append(mfObjs, obj)
		}
	}
	sort.Slice(mfObjs, func(i, j int) bool { return mfObjs[i].Key > mfObjs[j].Key })
	if limit > 0 && len(mfObjs) > limit {
		mfObjs = mfObjs[:limit]
	}

	if gf.jsonOutput {
		for _, obj := range mfObjs {
			rc, err := s3.GetObject(ctx, obj.Key)
			if err != nil {
				slog.WarnContext(ctx, "fetch manifest failed", "key", obj.Key, "error", err)
				continue
			}
			m, decErr := manifest.Decode(rc)
			_ = rc.Close()
			if decErr != nil {
				slog.WarnContext(ctx, "decode manifest failed", "key", obj.Key, "error", decErr)
				continue
			}
			b, _ := json.Marshal(m)
			fmt.Println(string(b))
		}
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "BACKUP ID\tTENANT\tCREATED\tSTORES\tSIZE")
	for _, obj := range mfObjs {
		rc, err := s3.GetObject(ctx, obj.Key)
		if err != nil {
			slog.WarnContext(ctx, "fetch manifest failed", "key", obj.Key, "error", err)
			continue
		}
		m, decErr := manifest.Decode(rc)
		_ = rc.Close()
		if decErr != nil {
			slog.WarnContext(ctx, "decode manifest failed", "key", obj.Key, "error", decErr)
			continue
		}
		var storeList []string
		var totalSize int64
		for _, b := range m.Blobs {
			storeList = append(storeList, string(b.Store))
			totalSize += b.SizeBytes
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			m.BackupID,
			m.TenantID,
			m.CreatedAt.UTC().Format(time.RFC3339),
			strings.Join(storeList, ","),
			humanBytes(totalSize),
		)
	}
	return tw.Flush()
}

// --------------------------------------------------------------------------
// restore
// --------------------------------------------------------------------------

func newRestoreCmd(gf *globalFlags) *cobra.Command {
	var tenantID, backupID, targetTenant string
	var storeNames []string
	var confirm bool

	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore a backup into a tenant",
		Example: `  gibson-backup restore --tenant acme --backup-id 2026-04-26T12-00-00Z
  gibson-backup restore --tenant acme --backup-id 2026-04-26T12-00-00Z \
    --target-tenant acme-staging --confirm`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRestore(cmd.Context(), gf, tenantID, backupID, storeNames, targetTenant, confirm)
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant", "", "source tenant ID (required)")
	cmd.Flags().StringVar(&backupID, "backup-id", "", "backup ID to restore (required)")
	cmd.Flags().StringArrayVar(&storeNames, "store", []string{"all"}, "stores to restore")
	cmd.Flags().StringVar(&targetTenant, "target-tenant", "", "restore into a different tenant (default: same as source)")
	cmd.Flags().BoolVar(&confirm, "confirm", false, "required when --target-tenant is set")
	_ = cmd.MarkFlagRequired("tenant")
	_ = cmd.MarkFlagRequired("backup-id")
	return cmd
}

func runRestore(
	ctx context.Context,
	gf *globalFlags,
	tenantID, backupID string,
	storeNames []string,
	targetTenant string,
	confirm bool,
) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	dest := tenantID
	if targetTenant != "" {
		if !confirm {
			return fmt.Errorf("--confirm is required when --target-tenant is set")
		}
		dest = targetTenant
	}

	targets := resolveStores(storeNames)

	s3, err := s3client.New(cfg.s3)
	if err != nil {
		return fmt.Errorf("s3 client: %w", err)
	}

	rc, err := s3.GetObject(ctx, manifest.ManifestPath(tenantID, backupID))
	if err != nil {
		return fmt.Errorf("fetch manifest: %w", err)
	}
	m, err := manifest.Decode(rc)
	_ = rc.Close()
	if err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}

	// KEK is derived from the source tenant (backup was encrypted with source KEK).
	kek, err := deriveTenantKEK(cfg.masterKEK, tenantID)
	if err != nil {
		return fmt.Errorf("derive KEK: %w", err)
	}
	defer zeroSlice(kek)

	for _, sn := range targets {
		var blob *manifest.BlobEntry
		for i := range m.Blobs {
			if m.Blobs[i].Store == sn {
				blob = &m.Blobs[i]
				break
			}
		}
		if blob == nil {
			slog.WarnContext(ctx, "store not in backup manifest; skipping", "store", sn)
			continue
		}

		emit(gf, "restore_start", map[string]any{"store": sn, "target_tenant": dest})

		if err := downloadAndRestore(ctx, cfg, kek, sn, dest, s3, blob.Path); err != nil {
			return fmt.Errorf("restore %q: %w", sn, err)
		}

		emit(gf, "restore_done", map[string]any{"store": sn})
	}

	fmt.Printf("restore complete: tenant=%s backup_id=%s\n", dest, backupID)
	return nil
}

func downloadAndRestore(
	ctx context.Context,
	cfg *runtimeConfig,
	kek []byte,
	sn manifest.StoreName,
	targetTenant string,
	s3 *s3client.Client,
	blobKey string,
) error {
	rc, err := s3.GetObject(ctx, blobKey)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer func() { _ = rc.Close() }()

	var plainBuf bytes.Buffer
	if err := envelope.Open(&plainBuf, rc, kek); err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	switch sn {
	case manifest.StorePostgres:
		return store.PostgresRestore(ctx, buildPostgresDSN(cfg, targetTenant), &plainBuf)
	case manifest.StoreNeo4j:
		return store.Neo4jRestore(ctx, buildNeo4jDSN(cfg, targetTenant), &plainBuf)
	case manifest.StoreRedis:
		return store.RedisRestore(ctx, buildRedisDSN(cfg, targetTenant), &plainBuf)
	case manifest.StoreVector:
		return store.VectorRestore(ctx, buildVectorDSN(cfg, targetTenant), &plainBuf)
	default:
		return fmt.Errorf("unknown store %q", sn)
	}
}

// --------------------------------------------------------------------------
// verify
// --------------------------------------------------------------------------

func newVerifyCmd() *cobra.Command {
	var tenantID, backupID string

	cmd := &cobra.Command{
		Use:     "verify",
		Short:   "Download, decrypt, and checksum each backup blob without restoring",
		Example: `  gibson-backup verify --tenant acme --backup-id 2026-04-26T12-00-00Z`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVerify(cmd.Context(), tenantID, backupID)
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID (required)")
	cmd.Flags().StringVar(&backupID, "backup-id", "", "backup ID to verify (required)")
	_ = cmd.MarkFlagRequired("tenant")
	_ = cmd.MarkFlagRequired("backup-id")
	return cmd
}

// runVerify previously accepted *globalFlags; the gf param was never
// read. Drop it. If a future verify command needs flag access, re-add
// the param.
func runVerify(ctx context.Context, tenantID, backupID string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	s3, err := s3client.New(cfg.s3)
	if err != nil {
		return fmt.Errorf("s3 client: %w", err)
	}

	rc, err := s3.GetObject(ctx, manifest.ManifestPath(tenantID, backupID))
	if err != nil {
		return fmt.Errorf("fetch manifest: %w", err)
	}
	m, err := manifest.Decode(rc)
	_ = rc.Close()
	if err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}

	kek, err := deriveTenantKEK(cfg.masterKEK, tenantID)
	if err != nil {
		return fmt.Errorf("derive KEK: %w", err)
	}
	defer zeroSlice(kek)

	allPass := true
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "STORE\tSTATUS\tSIZE\tSHA256")

	for _, blob := range m.Blobs {
		status, size, digest := verifyBlob(ctx, s3, kek, blob)
		if !strings.HasPrefix(status, "PASS") {
			allPass = false
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", blob.Store, status, humanBytes(size), digest)
	}
	tw.Flush() //nolint:errcheck

	if !allPass {
		return fmt.Errorf("verify failed for one or more blobs")
	}
	fmt.Println("verify OK")
	return nil
}

func verifyBlob(
	ctx context.Context,
	s3 *s3client.Client,
	kek []byte,
	blob manifest.BlobEntry,
) (status string, size int64, digest string) {
	rc, err := s3.GetObject(ctx, blob.Path)
	if err != nil {
		return fmt.Sprintf("FAIL (download: %v)", err), 0, ""
	}
	defer func() { _ = rc.Close() }()

	var plainBuf bytes.Buffer
	if err := envelope.Open(&plainBuf, rc, kek); err != nil {
		return fmt.Sprintf("FAIL (decrypt: %v)", err), 0, ""
	}

	h := sha256.New()
	n, _ := io.Copy(h, &plainBuf)
	got := hex.EncodeToString(h.Sum(nil))

	if got != blob.SHA256 {
		return fmt.Sprintf("FAIL (checksum mismatch: got %s want %s)", got, blob.SHA256), n, got
	}
	return "PASS", n, got
}

// --------------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------------

type runtimeConfig struct {
	masterKEK []byte
	s3        s3client.Config

	pgAdminDSN    string
	neo4jURI      string
	neo4jUsername string
	neo4jPassword string
	redisAddr     string
	redisPassword string
	redisDBIndex  int

	// vector store — Redis-backed (hash-scan NDJSON export/import)
	vectorRedisAddr     string
	vectorRedisPassword string
	vectorRedisDB       int
}

func loadConfig() (*runtimeConfig, error) {
	masterKEKHex := os.Getenv("MASTER_KEK")
	if masterKEKHex == "" {
		return nil, fmt.Errorf("MASTER_KEK environment variable is required")
	}
	masterKEK, err := hex.DecodeString(masterKEKHex)
	if err != nil {
		return nil, fmt.Errorf("MASTER_KEK: invalid hex: %w", err)
	}
	if len(masterKEK) < 32 {
		return nil, fmt.Errorf("MASTER_KEK must be at least 32 bytes (64 hex chars), got %d bytes", len(masterKEK))
	}

	s3cfg, err := s3client.ConfigFromEnv()
	if err != nil {
		return nil, err
	}

	redisDBIndex := 1
	if v := os.Getenv("REDIS_DB_INDEX"); v != "" {
		if idx, err := strconv.Atoi(v); err == nil {
			redisDBIndex = idx
		}
	}

	vectorRedisDB := 0
	if v := os.Getenv("VECTOR_REDIS_DB"); v != "" {
		if idx, err := strconv.Atoi(v); err == nil {
			vectorRedisDB = idx
		}
	}

	return &runtimeConfig{
		masterKEK:           masterKEK,
		s3:                  s3cfg,
		pgAdminDSN:          os.Getenv("PG_ADMIN_DSN"),
		neo4jURI:            os.Getenv("NEO4J_URI"),
		neo4jUsername:       os.Getenv("NEO4J_USERNAME"),
		neo4jPassword:       os.Getenv("NEO4J_PASSWORD"),
		redisAddr:           os.Getenv("REDIS_ADDR"),
		redisPassword:       os.Getenv("REDIS_PASSWORD"),
		redisDBIndex:        redisDBIndex,
		vectorRedisAddr:     os.Getenv("VECTOR_REDIS_ADDR"),
		vectorRedisPassword: os.Getenv("VECTOR_REDIS_PASSWORD"),
		vectorRedisDB:       vectorRedisDB,
	}, nil
}

// --------------------------------------------------------------------------
// DSN builders
// --------------------------------------------------------------------------

// sanitize returns the lowercase alphanumeric-plus-underscore form of id.
func sanitize(id string) string {
	s := strings.ToLower(id)
	var b strings.Builder
	for _, ch := range s {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9', ch == '_':
			b.WriteRune(ch)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

func tenantDBName(tenantID string) string {
	return "tenant_" + sanitize(tenantID)
}

func buildPostgresDSN(cfg *runtimeConfig, tenantID string) string {
	if cfg.pgAdminDSN == "" {
		return ""
	}
	dbName := tenantDBName(tenantID)
	dsn := cfg.pgAdminDSN
	// Replace the database name component (after the last / before any ?).
	if idx := strings.LastIndex(dsn, "/"); idx >= 0 {
		base := dsn[:idx+1]
		rest := dsn[idx+1:]
		if q := strings.Index(rest, "?"); q >= 0 {
			return base + dbName + rest[q:]
		}
		return base + dbName
	}
	return dsn
}

func buildNeo4jDSN(cfg *runtimeConfig, tenantID string) string {
	if cfg.neo4jURI == "" {
		return ""
	}
	dbName := tenantDBName(tenantID)
	uri := cfg.neo4jURI

	// Normalise scheme.
	scheme := "bolt"
	hostPart := uri
	switch {
	case strings.HasPrefix(uri, "neo4j://"):
		scheme = "neo4j"
		hostPart = uri[len("neo4j://"):]
	case strings.HasPrefix(uri, "bolt://"):
		hostPart = uri[len("bolt://"):]
	}
	// Strip any existing path.
	if idx := strings.Index(hostPart, "/"); idx >= 0 {
		hostPart = hostPart[:idx]
	}
	return fmt.Sprintf("%s://%s:%s@%s/%s",
		scheme, cfg.neo4jUsername, cfg.neo4jPassword, hostPart, dbName)
}

func buildRedisDSN(cfg *runtimeConfig, tenantID string) string {
	if cfg.redisAddr == "" {
		return ""
	}
	_ = tenantID // DB index is resolved at startup via REDIS_DB_INDEX env
	if cfg.redisPassword != "" {
		return fmt.Sprintf("redis://:%s@%s/%d", cfg.redisPassword, cfg.redisAddr, cfg.redisDBIndex)
	}
	return fmt.Sprintf("redis://%s/%d", cfg.redisAddr, cfg.redisDBIndex)
}

func buildVectorDSN(cfg *runtimeConfig, tenantID string) string {
	if cfg.vectorRedisAddr == "" {
		return ""
	}
	indexName := "vector_idx:" + tenantDBName(tenantID)
	if cfg.vectorRedisPassword != "" {
		return fmt.Sprintf("redis://:%s@%s/%d?index=%s",
			cfg.vectorRedisPassword, cfg.vectorRedisAddr, cfg.vectorRedisDB, indexName)
	}
	return fmt.Sprintf("redis://%s/%d?index=%s",
		cfg.vectorRedisAddr, cfg.vectorRedisDB, indexName)
}

// --------------------------------------------------------------------------
// KEK derivation (mirrors internal/dataplane/kek.go)
// --------------------------------------------------------------------------

const (
	hkdfInfo = "gibson/v1/tenant-kek"
	kekLen   = 32
)

func deriveTenantKEK(masterKEK []byte, tenantID string) ([]byte, error) {
	if len(masterKEK) < kekLen {
		return nil, fmt.Errorf("master KEK too short: need %d bytes, got %d", kekLen, len(masterKEK))
	}
	r := hkdf.New(sha256.New, masterKEK, []byte(tenantID), []byte(hkdfInfo))
	kek := make([]byte, kekLen)
	if _, err := io.ReadFull(r, kek); err != nil {
		return nil, fmt.Errorf("HKDF expand: %w", err)
	}
	return kek, nil
}

func zeroSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// --------------------------------------------------------------------------
// Utilities
// --------------------------------------------------------------------------

func resolveStores(names []string) []manifest.StoreName {
	if slices.Contains(names, "all") {
		return manifest.AllStores
	}
	seen := map[manifest.StoreName]bool{}
	var out []manifest.StoreName
	for _, n := range names {
		sn := manifest.StoreName(n)
		if !seen[sn] {
			seen[sn] = true
			out = append(out, sn)
		}
	}
	return out
}

// emit writes a structured progress line to stderr (human-readable) or stdout
// (JSON with --json). Progress lines are informational and do not affect
// machine-parseable output from the subcommands.
func emit(gf *globalFlags, event string, fields map[string]any) {
	if gf.jsonOutput {
		fields["event"] = event
		fields["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
		b, _ := json.Marshal(fields)
		fmt.Fprintln(os.Stderr, string(b))
		return
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString("[")
	sb.WriteString(event)
	sb.WriteString("] ")
	for i, k := range keys {
		if i > 0 {
			sb.WriteString(" ")
		}
		fmt.Fprintf(&sb, "%s=%v", k, fields[k])
	}
	fmt.Fprintln(os.Stderr, sb.String())
}

func humanBytes(n int64) string {
	const (
		kb = 1 << 10
		mb = 1 << 20
		gb = 1 << 30
	)
	switch {
	case n >= gb:
		return fmt.Sprintf("%.1f GiB", float64(n)/float64(gb))
	case n >= mb:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(mb))
	case n >= kb:
		return fmt.Sprintf("%.1f KiB", float64(n)/float64(kb))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
