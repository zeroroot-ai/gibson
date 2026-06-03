//go:build integration

// Package testhelpers provides shared test scaffolding for gibson integration
// tests. The postgres_tls helper here exists because of the workspace-wide
// directive that deletes the `disable` SSL mode from every DSN
// (spec: first-deploy-unblock-and-ha, Requirement 7). Every Postgres
// testcontainer in the daemon must connect with `sslmode=require` (or
// stronger) — the `disable` branch is forbidden anywhere in the source tree.
//
// StartPostgresTLS spins up a Postgres testcontainer with TLS enabled,
// generates a fresh self-signed CA + server keypair into the test's
// temp directory, mounts the cert/key into the container, and rewrites
// the container's entrypoint to chown the key to the postgres user
// before exec-ing the upstream `docker-entrypoint.sh`.
//
// The returned DSN already contains `sslmode=require`. When a test wants
// stronger verification, call StartPostgresTLSVerify which wires the
// generated CA bundle and yields a DSN with `sslmode=verify-ca`.
package testhelpers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	dockercontainer "github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// PostgresTLS is the bundle of artefacts returned by StartPostgresTLS.
// All fields are filled before the helper returns; the caller must use
// DSN to build a connection string and may use CAPath for stronger
// verification modes.
type PostgresTLS struct {
	// Container is the running Postgres testcontainer. The caller does
	// not need to terminate it — t.Cleanup will do that.
	Container testcontainers.Container

	// Host is the docker-side host (typically "localhost").
	Host string

	// Port is the docker-mapped port for 5432/tcp.
	Port string

	// User, Password, Database are the credentials the container was
	// started with.
	User     string
	Password string
	Database string

	// DSN is a libpq-style key/value DSN suitable for `database/sql`
	// (lib/pq) and pgx. It already contains `sslmode=require` (or
	// `sslmode=verify-ca` if BuildVerifyCADSN was called).
	DSN string

	// URL is a postgres://… URL form of the same connection. Some
	// drivers (e.g. golang-migrate) require URL form.
	URL string

	// CAPath is the absolute filesystem path to the test CA cert
	// (PEM). Pass it as `sslrootcert=` to a libpq DSN to use
	// `sslmode=verify-ca` or `verify-full`.
	CAPath string
}

// PostgresOptions controls the testcontainer setup. Zero-value works:
// User=testuser, Password=testpass, Database=testdb, Image=postgres:15-alpine.
type PostgresOptions struct {
	User     string
	Password string
	Database string
	Image    string
}

func (o PostgresOptions) withDefaults() PostgresOptions {
	if o.User == "" {
		o.User = "testuser"
	}
	if o.Password == "" {
		o.Password = "testpass"
	}
	if o.Database == "" {
		o.Database = "testdb"
	}
	if o.Image == "" {
		o.Image = "postgres:15-alpine"
	}
	return o
}

// StartPostgresTLS launches an ephemeral Postgres container with TLS
// enabled. The returned DSN uses `sslmode=require`. Tests that need
// chain verification can rebuild the DSN with PostgresTLS.BuildVerifyCADSN.
//
// The function calls t.Skip when Docker is unavailable so it is safe to
// invoke from any test gated behind `//go:build integration`.
//
// Per first-deploy-unblock-and-ha:R7.13–R7.17, this helper is the only
// supported way to obtain a Postgres connection in a test fixture —
// hand-rolled testcontainers that pass the `disable` SSL mode are
// forbidden.
func StartPostgresTLS(t *testing.T, opts PostgresOptions) *PostgresTLS {
	t.Helper()
	opts = opts.withDefaults()

	ctx := context.Background()

	// Skip gracefully when Docker is unavailable — matches the previous
	// behaviour of the per-test setup helpers we replaced.
	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		t.Skipf("Docker not available, skipping Postgres TLS integration test: %v", err)
		return nil
	}
	if healthErr := provider.Health(ctx); healthErr != nil {
		t.Skipf("Docker not running, skipping Postgres TLS integration test: %v", healthErr)
		return nil
	}

	// 1. Mint a self-signed CA + server cert with SANs that match every
	//    address a client might reach the container by.
	certDir := t.TempDir()
	caCertPath, caKeyPath, serverCertPath, serverKeyPath := writeSelfSignedTLS(t, certDir)

	// 2. Read the server materials so we can mount them into the
	//    container as in-memory copies (the temp directory is good
	//    enough to keep them around for the lifetime of the test, but
	//    bytes.Reader gives us deterministic ordering).
	serverCertPEM, err := os.ReadFile(serverCertPath)
	if err != nil {
		t.Fatalf("read server cert: %v", err)
	}
	serverKeyPEM, err := os.ReadFile(serverKeyPath)
	if err != nil {
		t.Fatalf("read server key: %v", err)
	}

	// 3. Build the container request.
	//    - Files are mounted as root:root inside the container.
	//    - The Postgres process must be able to read the key, but the
	//      key file ownership must be the running Postgres uid (or
	//      root) and its mode must be 0600 (or stricter). To satisfy
	//      both constraints we override the entrypoint with a tiny
	//      bash wrapper that chowns/chmods the cert files to the
	//      postgres user before exec-ing docker-entrypoint.sh.
	//    - Cmd carries `-c ssl=on -c ssl_cert_file=… -c ssl_key_file=…`
	//      so postgres listens for TLS on every connection.
	const certInContainer = "/etc/postgresql/tls/server.crt"
	const keyInContainer = "/etc/postgresql/tls/server.key"

	req := testcontainers.ContainerRequest{
		Image: opts.Image,
		Env: map[string]string{
			"POSTGRES_USER":     opts.User,
			"POSTGRES_PASSWORD": opts.Password,
			"POSTGRES_DB":       opts.Database,
		},
		ExposedPorts: []string{"5432/tcp"},
		Files: []testcontainers.ContainerFile{
			{
				Reader:            bytes.NewReader(serverCertPEM),
				ContainerFilePath: certInContainer,
				FileMode:          0o644,
			},
			{
				Reader:            bytes.NewReader(serverKeyPEM),
				ContainerFilePath: keyInContainer,
				FileMode:          0o600,
			},
		},
		ConfigModifier: func(cfg *dockercontainer.Config) {
			// Wrap the upstream entrypoint with a chown shim. The
			// upstream image's docker-entrypoint.sh is the
			// canonical path that handles initdb, role creation,
			// and exec-ing postgres — we keep it intact and only
			// fix file ownership/permissions before it runs.
			cfg.Entrypoint = []string{
				"bash", "-c",
				`set -euo pipefail
chown postgres:postgres ` + certInContainer + ` ` + keyInContainer + `
chmod 0644 ` + certInContainer + `
chmod 0600 ` + keyInContainer + `
exec docker-entrypoint.sh "$@"`,
				"--",
			}
		},
		Cmd: []string{
			"postgres",
			"-c", "ssl=on",
			"-c", "ssl_cert_file=" + certInContainer,
			"-c", "ssl_key_file=" + keyInContainer,
		},
		WaitingFor: wait.ForAll(
			wait.ForLog("database system is ready to accept connections"),
			wait.ForListeningPort("5432/tcp"),
		).WithDeadline(90 * time.Second),
	}

	pgC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start Postgres TLS container: %v", err)
	}
	t.Cleanup(func() {
		termCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if termErr := pgC.Terminate(termCtx); termErr != nil {
			t.Logf("warning: failed to terminate Postgres TLS container: %v", termErr)
		}
	})

	host, err := pgC.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	mappedPort, err := pgC.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("container port: %v", err)
	}
	port := mappedPort.Port()

	// 4. Build the default DSN (libpq key/value form, sslmode=require).
	//    `require` mandates TLS without verifying the chain — the right
	//    knob for tests that don't want to plumb the CA through the
	//    driver. Tests that DO want chain verification can rebuild
	//    with BuildVerifyCADSN.
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=require",
		host, port, opts.User, opts.Password, opts.Database,
	)
	url := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=require",
		opts.User, opts.Password, host, port, opts.Database,
	)

	// We don't need caKeyPath at the call site, but stash it so the
	// linter doesn't complain.
	_ = caKeyPath

	return &PostgresTLS{
		Container: pgC,
		Host:      host,
		Port:      port,
		User:      opts.User,
		Password:  opts.Password,
		Database:  opts.Database,
		DSN:       dsn,
		URL:       url,
		CAPath:    caCertPath,
	}
}

// BuildVerifyCADSN returns a libpq-style DSN with `sslmode=verify-ca`
// and the test CA wired in via `sslrootcert=`. Use this when a test
// needs to assert that chain verification succeeds end-to-end.
//
// The cert we issue covers the SANs `localhost`, `127.0.0.1`, and `::1`,
// so verify-full will match for `host=localhost`. For the docker-mapped
// host the helper tries to detect localhost; if the testcontainer host
// is anything else, the caller should stick to verify-ca.
func (p *PostgresTLS) BuildVerifyCADSN() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=verify-ca sslrootcert=%s",
		p.Host, p.Port, p.User, p.Password, p.Database, p.CAPath,
	)
}

// writeSelfSignedTLS mints a CA + server cert+key, writes them as PEM
// into dir, and returns the four absolute paths
// (caCert, caKey, serverCert, serverKey). The cert covers the SANs
// `localhost`, `127.0.0.1`, and `::1`, which is what a docker-mapped
// host resolves to in the testcontainers setup.
func writeSelfSignedTLS(t *testing.T, dir string) (caCertPath, caKeyPath, serverCertPath, serverKeyPath string) {
	t.Helper()

	// --- CA ---
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gibson-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	// --- Server leaf ---
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "gibson-test-postgres"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "gibson-test-postgres"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	// --- Marshal to PEM ---
	caCertPath = filepath.Join(dir, "ca.crt")
	caKeyPath = filepath.Join(dir, "ca.key")
	serverCertPath = filepath.Join(dir, "server.crt")
	serverKeyPath = filepath.Join(dir, "server.key")

	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}

	writePEM(t, caCertPath, "CERTIFICATE", caDER, 0o644)
	writePEM(t, caKeyPath, "EC PRIVATE KEY", caKeyDER, 0o600)
	writePEM(t, serverCertPath, "CERTIFICATE", serverDER, 0o644)
	writePEM(t, serverKeyPath, "EC PRIVATE KEY", serverKeyDER, 0o600)

	return caCertPath, caKeyPath, serverCertPath, serverKeyPath
}

func writePEM(t *testing.T, path, blockType string, der []byte, mode os.FileMode) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("encode PEM %s: %v", path, err)
	}
}

