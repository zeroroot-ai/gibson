// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command tlsfront serves the mock provider over HTTPS. A ModelProvider takes an
// https base URL, and the mock provider speaks plain HTTP. The two run in one
// pod. This command takes the TLS connection and sends each request to the mock
// provider on the loopback address of the pod.
//
// The exit tests of the AAIF epics use it (exit-test-aaif-alignment.yml).
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", ":8443", "listen address")
	upstream := flag.String("upstream", "http://127.0.0.1:18080", "URL of the mock provider")
	certFile := flag.String("cert", "/tls/tls.crt", "server certificate")
	keyFile := flag.String("key", "/tls/tls.key", "server key")
	flag.Parse()

	target, err := url.Parse(*upstream)
	if err != nil {
		slog.Error("the upstream URL is not valid", "error", err)
		os.Exit(1)
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           httputil.NewSingleHostReverseProxy(target),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	slog.Info("mock provider TLS front listening", "addr", *addr, "upstream", *upstream)
	if err := srv.ListenAndServeTLS(*certFile, *keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("TLS front stopped", "error", err)
		os.Exit(1)
	}
}
