package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
	"github.com/zeroroot-ai/gibson/internal/platform/authz/registry"
)

// The authz-registry endpoint lets ext-authz fetch the daemon's compiled-in
// authz policy at runtime instead of pulling a separately-versioned OCI
// artifact (deploy#852). The daemon is the single source of truth: registry.go
// (its own enforcement view) and the embedded registry.yaml are generated
// together, so ext-authz always sees exactly the policy the running daemon
// expects — the version-pin skew that silently default-denied newly-added RPCs
// (e.g. SetSignupProgress) is structurally gone.
//
// SECURITY: this is served over SPIFFE mTLS, NOT the plain-HTTP native-login
// bootstrap port. The registry is the source of truth for enforcement, so a
// reader that trusts it must be certain of its origin; a plain-HTTP fetch
// would let any in-cluster MITM/impersonator feed ext-authz a poisoned policy
// (e.g. flipping admin RPCs to unauthenticated). mTLS pins both directions:
// ext-authz verifies the daemon's SVID before trusting a byte, and the daemon
// only serves to an explicit reader allow-list. The registry holds no secrets
// (authz schema only), but its integrity is critical.
const (
	envAuthzRegistryPort     = "GIBSON_AUTHZ_REGISTRY_PORT"
	envAuthzRegistryReaders  = "GIBSON_AUTHZ_REGISTRY_READER_SVIDS"
	defaultAuthzRegistryPort = "8086"
	authzRegistryPath        = "/authz/registry.yaml"
)

// authzRegistrySubsystem owns the mTLS HTTPS listener that serves the embedded
// authz registry to allow-listed platform peers (ext-authz). Its Serve(ctx)
// signature matches the other daemon subsystems.
type authzRegistrySubsystem struct {
	srv    *http.Server
	logger *observability.Logger
	addr   string
}

// newAuthzRegistrySubsystem builds the subsystem. Returns (nil, nil) — meaning
// "skip, do not launch" — when SPIFFE mTLS is not available, because the
// registry MUST NOT be served without transport authentication (see the
// SECURITY note above). Returns an error only on misconfiguration that should
// fail the daemon (e.g. an unparseable reader SVID).
func newAuthzRegistrySubsystem(
	x509Source *workloadapi.X509Source,
	logger *observability.Logger,
) (*authzRegistrySubsystem, error) {
	if x509Source == nil {
		// No SPIFFE source → cannot secure the endpoint → do not start it.
		// ext-authz falls back to its file path in non-SPIFFE/test setups.
		return nil, nil
	}

	readers, err := parseAuthzRegistryReaders(os.Getenv(envAuthzRegistryReaders))
	if err != nil {
		return nil, err
	}
	if len(readers) == 0 {
		// Fail closed: an mTLS server with no authorized reader would accept
		// no one, so a missing allow-list is a configuration error, not a
		// silently-open endpoint.
		return nil, fmt.Errorf(
			"%s is required when SPIFFE mTLS is configured: it is the closed "+
				"set of SVIDs (e.g. the ext-authz SVID) allowed to read the authz registry",
			envAuthzRegistryReaders)
	}

	port := os.Getenv(envAuthzRegistryPort)
	if port == "" {
		port = defaultAuthzRegistryPort
	}

	tlsCfg := tlsconfig.MTLSServerConfig(x509Source, x509Source, tlsconfig.AuthorizeOneOf(readers...))

	mux := http.NewServeMux()
	mux.HandleFunc(authzRegistryPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(registry.YAML())
	})

	addr := ":" + port
	return &authzRegistrySubsystem{
		srv: &http.Server{
			Addr:              addr,
			Handler:           mux,
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 5 * time.Second,
		},
		logger: logger,
		addr:   addr,
	}, nil
}

// parseAuthzRegistryReaders parses a whitespace/comma-separated list of SPIFFE
// IDs into the reader allow-list.
func parseAuthzRegistryReaders(raw string) ([]spiffeid.ID, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	ids := make([]spiffeid.ID, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		id, err := spiffeid.FromString(f)
		if err != nil {
			return nil, fmt.Errorf("%s entry %q is not a parseable SPIFFE ID: %w", envAuthzRegistryReaders, f, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// Serve starts the mTLS listener and blocks until ctx is cancelled, then
// performs a graceful stop. Like the native-login and health subsystems, a
// listener failure is logged but non-fatal — the daemon must not go down
// because this endpoint did. (ext-authz retries the fetch, and a hard failure
// surfaces there as a refusal to load a stale policy, not a silent bypass.)
func (a *authzRegistrySubsystem) Serve(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		// TLSConfig is set on the server; certs come from the SPIFFE source.
		if err := a.srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	a.logger.Info(ctx, "authz-registry mTLS server started", "addr", a.addr, "path", authzRegistryPath)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		a.logger.Warn(ctx, "authz-registry mTLS server failed (non-fatal)", "error", err)
		return nil
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.srv.Shutdown(shutdownCtx); err != nil {
		a.logger.Warn(ctx, "authz-registry mTLS server shutdown error", "error", err)
	}
	return nil
}
