// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/readiness"
)

// The kubelet cannot probe the TLS ports of ext-authz. The health listener and
// the metrics listener both demand a client certificate, and the image has no
// shell for an exec probe. EXT_AUTHZ_PROBE_ADDR names a separate plaintext
// listener for the kubelet, as the daemon has one. It serves GET /healthz and
// GET /readyz and nothing else. The two handlers are the handlers of the mTLS
// health listener, so the readiness condition is the same one. The listener
// reports status only. It holds no metrics, no pprof and no version.

// probeMux serves the two probe paths of agg with the method GET. Every other
// path and every other method gets 404.
func probeMux(agg *readiness.Aggregator) http.Handler {
	live, ready := agg.LivenessHandler(), agg.ReadyHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/healthz":
			live.ServeHTTP(w, r)
		case "/readyz":
			ready.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// startProbeListener starts the plaintext probe listener on addr. An empty addr
// starts nothing and returns a nil channel, which never receives. A serve error
// arrives on the returned channel. The listener stops when ctx ends.
func startProbeListener(
	ctx context.Context, log *slog.Logger, addr string, agg *readiness.Aggregator,
) (<-chan error, error) {
	if addr == "" {
		return nil, nil
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("probe listener %s: %w", addr, err)
	}
	srv := &http.Server{Handler: probeMux(agg), ReadHeaderTimeout: 5 * time.Second}
	errC := make(chan error, 1)
	go func() {
		log.Info("plaintext probe listener starting (healthz and readyz only)", "addr", lis.Addr().String())
		if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errC <- fmt.Errorf("probe listener: %w", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	return errC, nil
}
