/*
Copyright 2026 Hack the Planet LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Command spiffe-jwks-exporter is a sidecar that fetches the SPIFFE JWT
// trust bundle from a SPIRE agent's Workload API and exposes it as a JWKS
// document. Non-Go workloads (e.g. Next.js) in the same pod verify
// incoming JWT-SVIDs against this document using any standard JOSE library.
//
// The sidecar runs two things concurrently:
//  1. A JWTSource watching the Workload API for bundle updates.
//  2. An HTTP handler on /jwks that serialises the latest JWT bundles as
//     a JWKS JSON document ({"keys":[...]}).
//
// Why a sidecar and not direct workload API calls from Next.js: SPIRE's
// workload API is gRPC only, and mature Node.js clients don't exist. This
// sidecar is small and trades one Go binary for avoiding all of that
// Node.js gRPC plumbing.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/zeroroot-ai/gibson/internal/infra/otelinit"
	"github.com/zeroroot-ai/gibson/internal/infra/readiness"
)

const serviceName = "spiffe-jwks-exporter"

func main() {
	var (
		socket = flag.String("socket", envOr("SPIFFE_ENDPOINT_SOCKET", "unix:///run/spire/sockets/agent.sock"), "SPIRE agent workload API socket")
		td     = flag.String("trust-domain", envOr("SPIFFE_TRUST_DOMAIN", "zeroroot.ai"), "expected trust domain")
		addr   = flag.String("listen", envOr("LISTEN_ADDR", "127.0.0.1:9091"), "HTTP listen address")
	)
	flag.Parse()

	obs, err := otelinit.Init(context.Background(), serviceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "observability init failed: %v\n", err)
		os.Exit(1)
	}
	log := obs.Logger.With("component", serviceName)

	trustDomain, err := spiffeid.TrustDomainFromString(*td)
	if err != nil {
		log.Error("invalid trust domain",
			otelinit.TenantIDField, "",
			"trust_domain", *td,
			"err", err,
		)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	initCtx, initCancel := context.WithTimeout(ctx, 30*time.Second)
	source, err := workloadapi.NewJWTSource(initCtx, workloadapi.WithClientOptions(workloadapi.WithAddr(*socket)))
	initCancel()
	if err != nil {
		log.Error("workload API JWTSource init failed", "socket", *socket, "err", err)
		os.Exit(1)
	}
	defer func() { _ = source.Close() }()
	log.Info("JWTSource ready", "socket", *socket, "trust_domain", trustDomain.String())

	// Readiness aggregator: SPIFFE Workload API reachable + SVID fetchable.
	agg := readiness.NewAggregator()
	agg.Register(&spiffeProbe{source: source, trustDomain: trustDomain})

	exp := &exporter{source: source, trustDomain: trustDomain, log: log}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", exp.serveJWKS)
	mux.Handle("/readyz", agg.ReadyHandler())
	mux.Handle("/healthz", agg.LivenessHandler())

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Info("serving", "addr", *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("listen failed", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)

	flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer flushCancel()
	_ = obs.Shutdown(flushCtx)

	log.Info("stopped")
}

// spiffeProbe implements readiness.Probe. It verifies the SPIFFE Workload API
// is reachable and that a JWT bundle for the configured trust domain can be
// fetched and is non-empty.
type spiffeProbe struct {
	source      *workloadapi.JWTSource
	trustDomain spiffeid.TrustDomain
}

func (p *spiffeProbe) Name() string { return "spiffe-workload-api" }

func (p *spiffeProbe) Check(_ context.Context) error {
	bundle, err := p.source.GetJWTBundleForTrustDomain(p.trustDomain)
	if err != nil {
		return fmt.Errorf("GetJWTBundleForTrustDomain: %w", err)
	}
	if bundle == nil || bundle.Empty() {
		return fmt.Errorf("JWT bundle for %s is empty", p.trustDomain)
	}
	return nil
}

type exporter struct {
	source      *workloadapi.JWTSource
	trustDomain spiffeid.TrustDomain
	log         interface {
		Error(msg string, args ...any)
	}

	mu     sync.Mutex
	cached []byte
	at     time.Time
}

// serveJWKS emits the current JWT bundle for the configured trust domain as
// a JWKS document: {"keys": [...]}. Re-marshals at most once per second.
func (e *exporter) serveJWKS(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	fresh := time.Since(e.at) < time.Second && e.cached != nil
	body := e.cached
	e.mu.Unlock()

	if !fresh {
		bundle, err := e.source.GetJWTBundleForTrustDomain(e.trustDomain)
		if err != nil || bundle == nil {
			http.Error(w, fmt.Sprintf("bundle unavailable: %v", err), http.StatusServiceUnavailable)
			return
		}
		b, err := marshalJWKS(bundle)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		e.mu.Lock()
		e.cached = b
		e.at = time.Now()
		body = b
		e.mu.Unlock()
	}

	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "max-age=10, must-revalidate")
	_, _ = w.Write(body)
}

// marshalJWKS converts a SPIFFE JWT bundle into a JWKS document. Each JWT
// authority is serialised via the go-spiffe marshaler which produces RFC 7517
// JWK JSON; we concatenate them into a {"keys": [...]} envelope.
func marshalJWKS(bundle *jwtbundle.Bundle) ([]byte, error) {
	raw, err := bundle.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal bundle: %w", err)
	}
	// bundle.Marshal already returns a JWKS {"keys":[...]} document, but
	// without the `use` claims we need. Re-decode and enrich.
	var parsed struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("re-decode bundle: %w", err)
	}
	for _, k := range parsed.Keys {
		if _, ok := k["use"]; !ok {
			k["use"] = "sig"
		}
		if _, ok := k["alg"]; !ok {
			// SPIRE JWT-SVIDs are signed with ES256 by default.
			k["alg"] = "ES256"
		}
	}
	return json.Marshal(parsed)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
