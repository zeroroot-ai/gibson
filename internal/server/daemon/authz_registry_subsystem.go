// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
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
//
// The Capability-Grant per-kid key route is served here for the same reason
// (deploy#1187). ext-authz already fetches the registry from this listener; the
// keys it verifies every component signature against deserve the same
// authenticated transport, so both halves of an ext-authz decision — the policy
// and the key that binds a caller to a principal — come from a daemon whose
// SVID the reader has verified.
//
// What mTLS buys here is server authentication and integrity in transit, not
// caller gating: the key route deliberately imposes no application-level
// authorization. ext-authz IS the authenticator, and it must be able to fetch a
// key before any caller identity exists. The documents are public keys, so the
// exposure that matters is substitution, not disclosure.
//
// The same route stays mounted on the plain-HTTP :8085 bootstrap listener while
// deployed ext-authz instances still point there. That duplication is
// transitional and must be removed once the chart repoints — see
// bootstrap_subsystem.go.
const (
	envAuthzRegistryPort     = "GIBSON_AUTHZ_REGISTRY_PORT"
	envAuthzRegistryReaders  = "GIBSON_AUTHZ_REGISTRY_READER_SVIDS"
	defaultAuthzRegistryPort = "8086"
	authzRegistryPath        = "/authz/registry.yaml"
)

// authzRegistryMuxPaths is what the mTLS listener answers on, for the startup
// log line. Package-level so the log cannot drift from the mux.
var authzRegistryMuxPaths = []string{authzRegistryPath, capabilityGrantKeysPath}

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
//
// cgMinter and cgSvc are the Capability-Grant key sources for the per-kid key
// route. They are taken as concrete pointers, not interfaces, so a nil daemon
// field stays a nil check: assigning a typed nil pointer into an interface
// produces a non-nil interface, which would mount a route that panics instead
// of one that is absent.
func newAuthzRegistrySubsystem(
	x509Source *workloadapi.X509Source,
	logger *observability.Logger,
	cgMinter *capabilitygrant.Minter,
	cgSvc *capabilitygrant.CapabilityGrantService,
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

	mux := authzRegistryMux(cgKeySources(cgMinter, cgSvc))

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

// cgKeySources narrows the daemon's concrete Capability-Grant pointers to the
// interfaces the key route consumes, mapping a nil pointer to a nil interface.
//
// The conversion is explicit because assigning a typed nil pointer into an
// interface yields a NON-nil interface. Passing the pointers straight through
// would therefore mount a key route on a nil receiver — a route that panics
// under load instead of one that is cleanly absent.
func cgKeySources(m *capabilitygrant.Minter, s *capabilitygrant.CapabilityGrantService) (cgKeyMinter, cgAgentKeyLookup) {
	var (
		minter cgKeyMinter
		lookup cgAgentKeyLookup
	)
	if m != nil {
		minter = m
	}
	if s != nil {
		lookup = s
	}
	return minter, lookup
}

// authzRegistryMux builds the route table the mTLS listener serves. It is split
// from the subsystem constructor because the constructor needs a real SPIFFE
// X509Source, which a unit test cannot produce — the routes are testable, the
// listener is not.
//
// The Capability-Grant key route mounts only when both key sources are present,
// matching the pre-auth listener: a missing source yields an absent route and a
// clean 404 rather than a route that answers 503 forever.
func authzRegistryMux(minter cgKeyMinter, lookup cgAgentKeyLookup) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(authzRegistryPath, authzRegistryHandler)
	if minter != nil && lookup != nil {
		mux.HandleFunc(capabilityGrantKeysPath, capabilityGrantKeysHandler(minter, lookup))
	}
	return mux
}

// authzRegistryHandler writes the embedded authz registry document.
func authzRegistryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(registry.YAML())
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
	a.logger.Info(ctx, "authz-registry mTLS server started", "addr", a.addr, "paths", authzRegistryMuxPaths)

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
