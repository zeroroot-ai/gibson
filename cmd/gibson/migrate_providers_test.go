package main

// migrate_providers_test.go covers the `gibson migrate-providers` subcommand.
//
// Test strategy:
//   - Fake K8s clientset (k8s.io/client-go/kubernetes/fake) for Secrets API.
//   - Fake gRPC server (net.Listener + grpc.NewServer) recording CreateProvider calls.
//   - Miniredis for the distributed migration lock.
//
// Sub-tests:
//   1. TestMigrateProviders_Happy — verifies the 5-record scenario from the spec:
//        2 anthropic + 1 openai + 1 aws_bedrock + 1 azure_openai
//        → 4 CreateProvider RPCs, 1 skipped WARN, Secret annotated.
//   2. TestMigrateProviders_Idempotency — second run on already-annotated Secret
//        → 0 new CreateProvider RPCs.
//   3. TestMigrateProviders_BedrockFieldMapping — bedrock Extra fields
//        carry aws_region / aws_access_key_id / aws_secret_access_key.
//   4. TestMigrateProviders_MissingSecret — no Secret in namespace → no error, 0 calls.
//   5. TestMigrateProviders_NamespaceFallback — no labeled namespaces → fallback
//        to tenant- prefix works.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	adminapi "github.com/zero-day-ai/gibson/internal/daemon/api"
)

// ─────────────────────────────────────────────────────────────────────────────
// Fake gRPC server for DaemonAdminService
// ─────────────────────────────────────────────────────────────────────────────

// fakeAdminServer records every CreateProvider call and returns success.
type fakeAdminServer struct {
	adminapi.UnimplementedDaemonAdminServiceServer

	mu    sync.Mutex
	calls []*adminapi.CreateProviderRequest
}

func (s *fakeAdminServer) CreateProvider(_ context.Context, req *adminapi.CreateProviderRequest) (*adminapi.CreateProviderResponse, error) {
	s.mu.Lock()
	s.calls = append(s.calls, req)
	s.mu.Unlock()
	return &adminapi.CreateProviderResponse{}, nil
}

func (s *fakeAdminServer) CallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *fakeAdminServer) AllCalls() []*adminapi.CreateProviderRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]*adminapi.CreateProviderRequest, len(s.calls))
	copy(cp, s.calls)
	return cp
}

// startFakeGRPC starts a real gRPC server on a random port and returns
// (serverAddr, fakeServer, cleanup).
func startFakeGRPC(t *testing.T) (string, *fakeAdminServer, func()) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer()
	fake := &fakeAdminServer{}
	adminapi.RegisterDaemonAdminServiceServer(srv, fake)

	go srv.Serve(lis) //nolint:errcheck

	cleanup := func() { srv.Stop() }
	return lis.Addr().String(), fake, cleanup
}

// buildTestAdminClient creates a DaemonAdminServiceClient connected to addr.
func buildTestAdminClient(t *testing.T, addr string) adminapi.DaemonAdminServiceClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, addr, //nolint:staticcheck
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck
	return adminapi.NewDaemonAdminServiceClient(conn)
}

// ─────────────────────────────────────────────────────────────────────────────
// Fake gRPC server that always returns AlreadyExists
// ─────────────────────────────────────────────────────────────────────────────

type alreadyExistsAdminServer struct {
	adminapi.UnimplementedDaemonAdminServiceServer
	mu    sync.Mutex
	calls int
}

func (s *alreadyExistsAdminServer) CreateProvider(_ context.Context, _ *adminapi.CreateProviderRequest) (*adminapi.CreateProviderResponse, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return nil, status.Error(codes.AlreadyExists, "already exists")
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers: build a Secret payload
// ─────────────────────────────────────────────────────────────────────────────

// buildProvidersSecret constructs a K8s Secret containing the given records
// encoded as a JSON array (no base64 — fake.NewSimpleClientset returns
// Secret.Data already decoded like the real API does).
func buildProvidersSecret(t *testing.T, namespace string, records []legacyProviderRecord, annotations map[string]string) *corev1.Secret {
	t.Helper()
	raw, err := json.Marshal(records)
	require.NoError(t, err)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        llmProvidersSecretName,
			Namespace:   namespace,
			Annotations: annotations,
		},
		Data: map[string][]byte{
			"providers": raw,
		},
	}
}

// buildTestNamespace returns a Namespace object with the Gibson managed-by label.
func buildTestNamespace(name string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "gibson",
			},
		},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 5-record fixture
// ─────────────────────────────────────────────────────────────────────────────

func fiveRecordFixture() []legacyProviderRecord {
	return []legacyProviderRecord{
		{Name: "anthropic-prod", Type: "anthropic", APIKey: "sk-ant-api03-AAAA", Model: "claude-3-5-sonnet", Enabled: true, CreatedAt: "2025-01-01T00:00:00Z"},
		{Name: "anthropic-test", Type: "anthropic", APIKey: "sk-ant-api03-BBBB", Model: "claude-3-haiku", Enabled: true, CreatedAt: "2025-01-02T00:00:00Z"},
		{Name: "openai-prod", Type: "openai", APIKey: "sk-openai-CCCC", Model: "gpt-4o", Enabled: true},
		{
			Name:               "aws-bedrock-main",
			Type:               "aws_bedrock",
			Model:              "anthropic.claude-3-5-sonnet-20241022-v2:0",
			Enabled:            true,
			AWSRegion:          "us-east-1",
			AWSAccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			AWSSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		{Name: "azure-main", Type: "azure_openai", APIKey: "az-key-EEEE", Model: "gpt-4", Enabled: true},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test log capture helper
// ─────────────────────────────────────────────────────────────────────────────

// logCapture wraps a bytes.Buffer to capture slog output.
type logCapture struct {
	buf *bytes.Buffer
}

func newLogCapture() (*logCapture, *slog.Logger) {
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &logCapture{buf: buf}, logger
}

func (lc *logCapture) Contains(needle string) bool {
	return bytes.Contains(lc.buf.Bytes(), []byte(needle))
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMigrateProviders_Happy
// ─────────────────────────────────────────────────────────────────────────────

func TestMigrateProviders_Happy(t *testing.T) {
	const ns = "tenant-acme"

	// ── Fake K8s ────────────────────────────────────────────────────────────
	secret := buildProvidersSecret(t, ns, fiveRecordFixture(), nil)
	k8sClient := k8sfake.NewSimpleClientset(buildTestNamespace(ns), secret)

	// ── Fake gRPC ────────────────────────────────────────────────────────────
	_, fakeServer, cleanup := startFakeGRPC(t)
	defer cleanup()

	// ── Miniredis lock ───────────────────────────────────────────────────────
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() }) //nolint:errcheck

	// ── Log capture ──────────────────────────────────────────────────────────
	lc, logger := newLogCapture()
	_ = logger // will be used implicitly

	// ── Run migration directly on migrateTenant ──────────────────────────────
	// Re-use the fake admin client built from the started fake server.
	grpcAddr, _, cleanup2 := startFakeGRPC(t)
	defer cleanup2()
	// Replace fakeServer with a second instance for direct use.
	_ = fakeServer

	fakeAddr, srv2, cleanup3 := startFakeGRPC(t)
	defer cleanup3()

	adminClient := buildTestAdminClient(t, fakeAddr)
	ctx := context.Background()

	m, s, e := migrateTenant(ctx, logger, k8sClient, adminClient, ns, false)

	// ── Assertions ───────────────────────────────────────────────────────────
	assert.Equal(t, 4, m, "migrated count: anthropic×2 + openai + bedrock")
	assert.Equal(t, 1, s, "skipped count: azure_openai")
	assert.Equal(t, 0, e, "error count")

	assert.Equal(t, 4, srv2.CallCount(), "4 CreateProvider RPCs should have been made")

	// Verify WARN for azure_openai appears in logs.
	assert.True(t, lc.Contains("azure_openai"), "expected WARN log for azure_openai")
	assert.True(t, lc.Contains("not supported by daemon post-spec-25"), "expected skip reason in logs")

	// Verify structured audit log line (slog JSON format uses key:value pairs).
	assert.True(t, lc.Contains("migrate-providers"), "expected audit log event")
	assert.True(t, lc.Contains(`"migrated_count":4`), "expected migrated_count:4 in audit line")
	assert.True(t, lc.Contains(`"skipped_count":1`), "expected skipped_count:1 in audit line")
	assert.True(t, lc.Contains(`"spec":"25"`), "expected spec:25 in audit line")

	// Verify Secret was annotated.
	updatedSecret, err := k8sClient.CoreV1().Secrets(ns).Get(ctx, llmProvidersSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, migrationAnnotationVal, updatedSecret.Annotations[migrationAnnotationKey],
		"Secret should be annotated after successful migration")

	// Suppress unused variable warning.
	_ = grpcAddr
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMigrateProviders_Idempotency
// ─────────────────────────────────────────────────────────────────────────────

func TestMigrateProviders_Idempotency(t *testing.T) {
	const ns = "tenant-acme"

	// Secret already annotated as migrated.
	secret := buildProvidersSecret(t, ns, fiveRecordFixture(), map[string]string{
		migrationAnnotationKey: migrationAnnotationVal,
	})
	k8sClient := k8sfake.NewSimpleClientset(buildTestNamespace(ns), secret)

	fakeAddr, srv, cleanup := startFakeGRPC(t)
	defer cleanup()
	adminClient := buildTestAdminClient(t, fakeAddr)

	_, logger := newLogCapture()
	ctx := context.Background()

	m, s, e := migrateTenant(ctx, logger, k8sClient, adminClient, ns, false)

	// Already annotated → no calls, no errors.
	assert.Equal(t, 0, m)
	assert.Equal(t, 0, s)
	assert.Equal(t, 0, e)
	assert.Equal(t, 0, srv.CallCount(), "0 CreateProvider RPCs on idempotent re-run")
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMigrateProviders_BedrockFieldMapping
// ─────────────────────────────────────────────────────────────────────────────

func TestMigrateProviders_BedrockFieldMapping(t *testing.T) {
	const ns = "tenant-bedrock"

	records := []legacyProviderRecord{
		{
			Name:               "bedrock-main",
			Type:               "aws_bedrock",
			Model:              "anthropic.claude-3-5-sonnet-20241022-v2:0",
			Enabled:            true,
			AWSRegion:          "us-west-2",
			AWSAccessKeyID:     "AKIATEST123",
			AWSSecretAccessKey: "supersecret/KEY+test",
		},
	}

	secret := buildProvidersSecret(t, ns, records, nil)
	k8sClient := k8sfake.NewSimpleClientset(buildTestNamespace(ns), secret)

	fakeAddr, srv, cleanup := startFakeGRPC(t)
	defer cleanup()
	adminClient := buildTestAdminClient(t, fakeAddr)

	_, logger := newLogCapture()
	ctx := context.Background()

	m, _, e := migrateTenant(ctx, logger, k8sClient, adminClient, ns, false)

	require.Equal(t, 1, m, "1 bedrock record migrated")
	require.Equal(t, 0, e)
	require.Equal(t, 1, srv.CallCount())

	calls := srv.AllCalls()
	require.Len(t, calls, 1)
	req := calls[0]

	// Provider type renamed.
	assert.Equal(t, "bedrock", req.Input.Type)
	assert.Equal(t, "bedrock-main", req.Input.Name)

	// Credential fields mapped correctly.
	creds := req.Input.Credentials
	assert.Equal(t, "us-west-2", creds["aws_region"])
	assert.Equal(t, "AKIATEST123", creds["aws_access_key_id"])
	assert.Equal(t, "supersecret/KEY+test", creds["aws_secret_access_key"])

	// No api_key for Bedrock.
	_, hasAPIKey := creds["api_key"]
	assert.False(t, hasAPIKey, "Bedrock record should not include api_key credential")
}

// TestMigrateProviders_BedrockNestedAWSFields verifies the nested aws sub-object schema.
func TestMigrateProviders_BedrockNestedAWSFields(t *testing.T) {
	const ns = "tenant-bedrock2"

	records := []legacyProviderRecord{
		{
			Name:    "bedrock-nested",
			Type:    "aws_bedrock",
			Model:   "amazon.titan-text-lite-v1",
			Enabled: true,
			AWS: &legacyAWSFields{
				Region:          "eu-west-1",
				AccessKeyID:     "AKIA_NESTED",
				SecretAccessKey: "nested_secret",
			},
		},
	}

	secret := buildProvidersSecret(t, ns, records, nil)
	k8sClient := k8sfake.NewSimpleClientset(buildTestNamespace(ns), secret)

	fakeAddr, srv, cleanup := startFakeGRPC(t)
	defer cleanup()
	adminClient := buildTestAdminClient(t, fakeAddr)

	_, logger := newLogCapture()
	ctx := context.Background()

	m, _, e := migrateTenant(ctx, logger, k8sClient, adminClient, ns, false)
	require.Equal(t, 1, m)
	require.Equal(t, 0, e)

	calls := srv.AllCalls()
	require.Len(t, calls, 1)
	creds := calls[0].Input.Credentials

	assert.Equal(t, "eu-west-1", creds["aws_region"])
	assert.Equal(t, "AKIA_NESTED", creds["aws_access_key_id"])
	assert.Equal(t, "nested_secret", creds["aws_secret_access_key"])
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMigrateProviders_MissingSecret
// ─────────────────────────────────────────────────────────────────────────────

func TestMigrateProviders_MissingSecret(t *testing.T) {
	const ns = "tenant-empty"

	// Namespace exists but has no llm-providers Secret.
	k8sClient := k8sfake.NewSimpleClientset(buildTestNamespace(ns))

	fakeAddr, srv, cleanup := startFakeGRPC(t)
	defer cleanup()
	adminClient := buildTestAdminClient(t, fakeAddr)

	_, logger := newLogCapture()
	ctx := context.Background()

	m, s, e := migrateTenant(ctx, logger, k8sClient, adminClient, ns, false)

	assert.Equal(t, 0, m)
	assert.Equal(t, 0, s)
	assert.Equal(t, 0, e)
	assert.Equal(t, 0, srv.CallCount())
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMigrateProviders_NamespaceFallback
// ─────────────────────────────────────────────────────────────────────────────

func TestMigrateProviders_NamespaceFallback(t *testing.T) {
	// Namespace has NO managed-by label — should be picked up by the
	// tenant- prefix fallback in listTenantNamespaces.
	const ns = "tenant-unlabeled"
	unlabeled := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: ns},
	}

	records := []legacyProviderRecord{
		{Name: "openai-1", Type: "openai", APIKey: "sk-test", Model: "gpt-4o", Enabled: true},
	}
	secret := buildProvidersSecret(t, ns, records, nil)
	k8sClient := k8sfake.NewSimpleClientset(unlabeled, secret)

	ctx := context.Background()

	// listTenantNamespaces: primary selector returns empty → fallback.
	nsList, err := listTenantNamespaces(ctx, k8sClient)
	require.NoError(t, err)
	assert.Contains(t, nsList, ns, "unlabeled tenant- namespace should appear via fallback")
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMigrateProviders_SkippedTypesWarn
// ─────────────────────────────────────────────────────────────────────────────

func TestMigrateProviders_SkippedTypesWarn(t *testing.T) {
	const ns = "tenant-mixed"

	records := []legacyProviderRecord{
		{Name: "ernie-1", Type: "ernie", APIKey: "key", Model: "ernie-4", Enabled: true},
		{Name: "maritaca-1", Type: "maritaca", APIKey: "key", Model: "sabia", Enabled: true},
		{Name: "watsonx-1", Type: "watsonx", APIKey: "key", Model: "ibm-model", Enabled: true},
		{Name: "local-1", Type: "local", Model: "llama3", Enabled: true},
		{Name: "anthropic-ok", Type: "anthropic", APIKey: "sk-ant-ok", Model: "claude-3-haiku", Enabled: true},
	}

	secret := buildProvidersSecret(t, ns, records, nil)
	k8sClient := k8sfake.NewSimpleClientset(buildTestNamespace(ns), secret)

	fakeAddr, srv, cleanup := startFakeGRPC(t)
	defer cleanup()
	adminClient := buildTestAdminClient(t, fakeAddr)

	lc, logger := newLogCapture()
	ctx := context.Background()

	m, s, e := migrateTenant(ctx, logger, k8sClient, adminClient, ns, false)

	assert.Equal(t, 1, m, "only anthropic-ok migrated")
	assert.Equal(t, 4, s, "4 unsupported types skipped")
	assert.Equal(t, 0, e)
	assert.Equal(t, 1, srv.CallCount())

	// Each skipped type should appear in logs.
	for _, skip := range []string{"ernie", "maritaca", "watsonx", "local"} {
		assert.True(t, lc.Contains(skip), "expected %s in WARN log", skip)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMigrateProviders_DryRun
// ─────────────────────────────────────────────────────────────────────────────

func TestMigrateProviders_DryRun(t *testing.T) {
	const ns = "tenant-dryrun"

	records := []legacyProviderRecord{
		{Name: "anthropic-prod", Type: "anthropic", APIKey: "sk-ant-DRY", Model: "claude-3-5-sonnet", Enabled: true},
	}
	secret := buildProvidersSecret(t, ns, records, nil)
	k8sClient := k8sfake.NewSimpleClientset(buildTestNamespace(ns), secret)

	fakeAddr, srv, cleanup := startFakeGRPC(t)
	defer cleanup()
	adminClient := buildTestAdminClient(t, fakeAddr)

	_, logger := newLogCapture()
	ctx := context.Background()

	m, _, e := migrateTenant(ctx, logger, k8sClient, adminClient, ns, true /* dryRun */)

	assert.Equal(t, 1, m, "dry-run reports as migrated")
	assert.Equal(t, 0, e)
	// No RPC calls in dry-run.
	assert.Equal(t, 0, srv.CallCount(), "dry-run must not call CreateProvider")

	// Secret must NOT be annotated in dry-run.
	updatedSecret, err := k8sClient.CoreV1().Secrets(ns).Get(ctx, llmProvidersSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Empty(t, updatedSecret.Annotations[migrationAnnotationKey], "Secret must not be annotated in dry-run")
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMigrateProviders_RPCError
// ─────────────────────────────────────────────────────────────────────────────

func TestMigrateProviders_RPCError(t *testing.T) {
	const ns = "tenant-grpcfail"

	records := []legacyProviderRecord{
		{Name: "anthropic-fail", Type: "anthropic", APIKey: "sk-ant-FAIL", Model: "claude-3-haiku", Enabled: true},
	}
	secret := buildProvidersSecret(t, ns, records, nil)
	k8sClient := k8sfake.NewSimpleClientset(buildTestNamespace(ns), secret)

	// Use AlreadyExists server — the current error handling logs and counts an error.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	grpcSrv := grpc.NewServer()
	aeServer := &alreadyExistsAdminServer{}
	adminapi.RegisterDaemonAdminServiceServer(grpcSrv, aeServer)
	go grpcSrv.Serve(lis) //nolint:errcheck
	defer grpcSrv.Stop()

	adminClient := buildTestAdminClient(t, lis.Addr().String())

	_, logger := newLogCapture()
	ctx := context.Background()

	m, _, e := migrateTenant(ctx, logger, k8sClient, adminClient, ns, false)

	// RPC returned an error (AlreadyExists is treated as error for migration).
	assert.Equal(t, 0, m)
	assert.Equal(t, 1, e, "failed RPC increments error count")

	// Secret must NOT be annotated when there were errors.
	updatedSecret, err2 := k8sClient.CoreV1().Secrets(ns).Get(ctx, llmProvidersSecretName, metav1.GetOptions{})
	require.NoError(t, err2)
	assert.Empty(t, updatedSecret.Annotations[migrationAnnotationKey],
		"Secret must not be annotated when migration had errors")
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMigrateProviders_LockAcquisition
// ─────────────────────────────────────────────────────────────────────────────

func TestMigrateProviders_LockAcquisition(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx := context.Background()
	const lockKey = "migration:providers:testlock"

	// First acquisition must succeed.
	release1, err := acquireMigrationLock(ctx, mr.Addr(), lockKey)
	require.NoError(t, err, "first acquisition should succeed")

	// Second acquisition must fail (lock held).
	_, err2 := acquireMigrationLock(ctx, mr.Addr(), lockKey)
	assert.Error(t, err2, "second acquisition should fail while lock is held")
	assert.Contains(t, err2.Error(), "held by another migration runner")

	// Release and verify the key is gone.
	release1()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() }) //nolint:errcheck
	exists, err := rdb.Exists(ctx, lockKey).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists, "lock key should be deleted after release")
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMigrateProviders_DecodeProviderSecret
// ─────────────────────────────────────────────────────────────────────────────

func TestMigrateProviders_DecodeProviderSecret(t *testing.T) {
	t.Run("valid_payload", func(t *testing.T) {
		secret := buildProvidersSecret(t, "test-ns", fiveRecordFixture(), nil)
		records, err := decodeProviderSecret(secret)
		require.NoError(t, err)
		assert.Len(t, records, 5)
		assert.Equal(t, "anthropic", records[0].Type)
		assert.Equal(t, "aws_bedrock", records[3].Type)
	})

	t.Run("missing_key", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "llm-providers", Namespace: "ns"},
			Data:       map[string][]byte{},
		}
		records, err := decodeProviderSecret(secret)
		require.NoError(t, err)
		assert.Nil(t, records)
	})

	t.Run("corrupted_json", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "llm-providers", Namespace: "ns"},
			Data:       map[string][]byte{"providers": []byte("{ NOT JSON !!!")},
		}
		_, err := decodeProviderSecret(secret)
		assert.Error(t, err)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMigrateProviders_ExtractBedrockCredentials
// ─────────────────────────────────────────────────────────────────────────────

func TestMigrateProviders_ExtractBedrockCredentials(t *testing.T) {
	t.Run("flat_fields", func(t *testing.T) {
		rec := &legacyProviderRecord{
			AWSRegion:          "us-east-1",
			AWSAccessKeyID:     "AKIA_FLAT",
			AWSSecretAccessKey: "flat_secret",
		}
		r, k, s := extractBedrockCredentials(rec)
		assert.Equal(t, "us-east-1", r)
		assert.Equal(t, "AKIA_FLAT", k)
		assert.Equal(t, "flat_secret", s)
	})

	t.Run("nested_aws_object", func(t *testing.T) {
		rec := &legacyProviderRecord{
			AWS: &legacyAWSFields{
				Region:          "ap-southeast-1",
				AccessKeyID:     "AKIA_NESTED",
				SecretAccessKey: "nested_secret",
			},
		}
		r, k, s := extractBedrockCredentials(rec)
		assert.Equal(t, "ap-southeast-1", r)
		assert.Equal(t, "AKIA_NESTED", k)
		assert.Equal(t, "nested_secret", s)
	})

	t.Run("nested_overrides_flat", func(t *testing.T) {
		rec := &legacyProviderRecord{
			AWSRegion:          "us-east-1",   // flat
			AWSAccessKeyID:     "AKIA_FLAT",   // flat
			AWSSecretAccessKey: "flat_secret", // flat
			AWS: &legacyAWSFields{
				Region:          "eu-west-1",     // nested wins
				AccessKeyID:     "AKIA_OVERRIDE", // nested wins
				SecretAccessKey: "override_key",  // nested wins
			},
		}
		r, k, s := extractBedrockCredentials(rec)
		assert.Equal(t, "eu-west-1", r)
		assert.Equal(t, "AKIA_OVERRIDE", k)
		assert.Equal(t, "override_key", s)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMigrateProviders_AuditLogStructure
// ─────────────────────────────────────────────────────────────────────────────

func TestMigrateProviders_AuditLogStructure(t *testing.T) {
	const ns = "tenant-audit"

	records := []legacyProviderRecord{
		{Name: "anthropic-1", Type: "anthropic", APIKey: "sk-ant-AUDIT", Model: "claude-3-5-sonnet", Enabled: true},
		{Name: "azure-skip", Type: "azure_openai", APIKey: "az-key", Model: "gpt-4", Enabled: true},
	}
	secret := buildProvidersSecret(t, ns, records, nil)
	k8sClient := k8sfake.NewSimpleClientset(buildTestNamespace(ns), secret)

	fakeAddr, _, cleanup := startFakeGRPC(t)
	defer cleanup()
	adminClient := buildTestAdminClient(t, fakeAddr)

	lc, logger := newLogCapture()
	ctx := context.Background()

	migrateTenant(ctx, logger, k8sClient, adminClient, ns, false)

	// The audit log line is emitted as structured slog fields at the end of migrateTenant.
	// slog JSON handler writes each field as a separate key-value pair in the JSON object.
	raw := lc.buf.String()
	assert.Contains(t, raw, `"migrated_count":1`)
	assert.Contains(t, raw, `"skipped_count":1`)
	assert.Contains(t, raw, `"errors_count":0`)
	assert.Contains(t, raw, `"spec":"25"`)
	assert.Contains(t, raw, fmt.Sprintf(`"tenant_namespace":"%s"`, ns))
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMigrateProviders_TypeMapping
// ─────────────────────────────────────────────────────────────────────────────

func TestMigrateProviders_TypeMapping(t *testing.T) {
	// Verify every pass-through type keeps its api_key.
	passThrough := []string{"anthropic", "openai", "google", "ollama", "cohere", "mistral", "cloudflare", "huggingface", "llamafile"}

	for _, pt := range passThrough {
		pt := pt
		t.Run(pt, func(t *testing.T) {
			ns := "tenant-type-" + pt
			records := []legacyProviderRecord{
				{Name: pt + "-test", Type: pt, APIKey: "sk-test-KEY", Model: "model-1", BaseURL: "https://api.example.com", Enabled: true},
			}
			secret := buildProvidersSecret(t, ns, records, nil)
			k8sClient := k8sfake.NewSimpleClientset(buildTestNamespace(ns), secret)

			fakeAddr, srv, cleanup := startFakeGRPC(t)
			defer cleanup()
			adminClient := buildTestAdminClient(t, fakeAddr)

			_, logger := newLogCapture()
			m, _, e := migrateTenant(context.Background(), logger, k8sClient, adminClient, ns, false)

			assert.Equal(t, 1, m)
			assert.Equal(t, 0, e)
			require.Equal(t, 1, srv.CallCount())

			calls := srv.AllCalls()
			req := calls[0]
			assert.Equal(t, pt, req.Input.Type, "type should pass through unchanged for %s", pt)
			assert.Equal(t, "sk-test-KEY", req.Input.Credentials["api_key"])
			assert.Equal(t, "https://api.example.com", req.Input.Credentials["base_url"])
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMigrateProviders_MultiTenantIsolation
// ─────────────────────────────────────────────────────────────────────────────

func TestMigrateProviders_MultiTenantIsolation(t *testing.T) {
	// Two tenants, each with their own Secret. Errors in one should not affect the other.
	const ns1 = "tenant-alpha"
	const ns2 = "tenant-beta"

	recordsA := []legacyProviderRecord{
		{Name: "alpha-openai", Type: "openai", APIKey: "sk-alpha", Model: "gpt-4o", Enabled: true},
	}
	recordsB := []legacyProviderRecord{
		{Name: "beta-anthropic", Type: "anthropic", APIKey: "sk-beta", Model: "claude-3-haiku", Enabled: true},
	}

	secretA := buildProvidersSecret(t, ns1, recordsA, nil)
	secretB := buildProvidersSecret(t, ns2, recordsB, nil)

	k8sClient := k8sfake.NewSimpleClientset(
		buildTestNamespace(ns1),
		buildTestNamespace(ns2),
		secretA,
		secretB,
	)

	fakeAddr, srv, cleanup := startFakeGRPC(t)
	defer cleanup()
	adminClient := buildTestAdminClient(t, fakeAddr)

	_, logger := newLogCapture()
	ctx := context.Background()

	// Migrate both tenants.
	for _, ns := range []string{ns1, ns2} {
		migrateTenant(ctx, logger, k8sClient, adminClient, ns, false)
	}

	// Both providers should have been created.
	assert.Equal(t, 2, srv.CallCount())

	// Both Secrets should be annotated.
	for _, ns := range []string{ns1, ns2} {
		s, err := k8sClient.CoreV1().Secrets(ns).Get(ctx, llmProvidersSecretName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, migrationAnnotationVal, s.Annotations[migrationAnnotationKey],
			"Secret in %s should be annotated", ns)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMigrateProviders_IsDefaultPassthrough
// ─────────────────────────────────────────────────────────────────────────────

func TestMigrateProviders_IsDefaultPassthrough(t *testing.T) {
	const ns = "tenant-default"

	records := []legacyProviderRecord{
		{Name: "primary", Type: "openai", APIKey: "sk-key", Model: "gpt-4o", IsDefault: true, Enabled: true},
		{Name: "secondary", Type: "openai", APIKey: "sk-key2", Model: "gpt-3.5-turbo", IsDefault: false, Enabled: true},
	}

	secret := buildProvidersSecret(t, ns, records, nil)
	k8sClient := k8sfake.NewSimpleClientset(buildTestNamespace(ns), secret)

	fakeAddr, srv, cleanup := startFakeGRPC(t)
	defer cleanup()
	adminClient := buildTestAdminClient(t, fakeAddr)

	_, logger := newLogCapture()
	migrateTenant(context.Background(), logger, k8sClient, adminClient, ns, false)

	require.Equal(t, 2, srv.CallCount())
	calls := srv.AllCalls()

	// Find primary and secondary.
	var primary, secondary *adminapi.CreateProviderRequest
	for _, c := range calls {
		switch c.Input.Name {
		case "primary":
			primary = c
		case "secondary":
			secondary = c
		}
	}

	require.NotNil(t, primary)
	require.NotNil(t, secondary)
	assert.True(t, primary.Input.SetAsDefault, "primary should have SetAsDefault=true")
	assert.False(t, secondary.Input.SetAsDefault, "secondary should have SetAsDefault=false")
}
