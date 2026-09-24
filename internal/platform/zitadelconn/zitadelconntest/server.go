// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package zitadelconntest is a fake Zitadel that selects its instance the way
// the real one does, for tests of any in-cluster Zitadel client (ADR-0092).
//
// Every request must name the instance in the x-zitadel-instance-host header.
// Without it, or with a ported host, the fake answers 404 "Instance not
// found", as Zitadel v4.18.0 answered on staging on 2026-09-23. A ported host
// is refused here even though real Zitadel accepts it, because real Zitadel
// then stamps the port into the issuer and every later check fails. The fake
// makes that mistake fail at once.
//
// The earlier fake behind the gibson#1560 test answered every request
// whatever the host, so that test stayed green while no staging install could
// create its first admin.
package zitadelconntest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
)

// DefaultDomain is a claimed host that can never resolve (RFC 6761
// reserves .invalid), so a client that dials the public name fails loudly
// instead of reaching something.
const DefaultDomain = "app.zitadel.invalid"

// AccessToken is the token the fake's token endpoint issues.
const AccessToken = "test-admin-token"

// Request is one request the fake received after instance selection.
type Request struct {
	Method   string
	Path     string
	Instance string
	OrgID    string
	Auth     string
}

// Server is the fake. Handler serves every path except the token endpoint,
// and only for requests that selected the instance.
type Server struct {
	*httptest.Server
	Domain string

	mu       sync.Mutex
	requests []Request
	refused  int
}

// New starts a fake for domain. A nil handler answers 404 for every path
// except the token endpoint.
func New(tb testing.TB, domain string, handler http.Handler) *Server {
	tb.Helper()
	if domain == "" {
		domain = DefaultDomain
	}
	s := &Server{Domain: domain}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inst := r.Header.Get(zitadelconn.InstanceHostHeader)
		if inst != s.Domain {
			s.mu.Lock()
			s.refused++
			s.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    5,
				"message": "unable to set instance using origin " + r.Host + ": Instance not found",
			})
			return
		}
		s.mu.Lock()
		s.requests = append(s.requests, Request{
			Method:   r.Method,
			Path:     r.URL.Path,
			Instance: inst,
			OrgID:    r.Header.Get("x-zitadel-orgid"),
			Auth:     r.Header.Get("Authorization"),
		})
		s.mu.Unlock()
		if r.Method == http.MethodPost && r.URL.Path == "/oauth/v2/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": AccessToken, "token_type": "Bearer", "expires_in": 3600,
			})
			return
		}
		if handler == nil {
			http.NotFound(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	tb.Cleanup(s.Close)
	return s
}

// Endpoint returns the zitadelconn.Endpoint a correct client uses.
func (s *Server) Endpoint(tb testing.TB) zitadelconn.Endpoint {
	tb.Helper()
	e, err := zitadelconn.New(s.URL, s.Domain)
	if err != nil {
		tb.Fatalf("zitadelconntest: endpoint: %v", err)
	}
	return e
}

// Requests returns a copy of every request that selected the instance.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Refused counts requests answered 404 because they named no instance or the
// wrong one.
func (s *Server) Refused() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refused
}

// Paths returns the paths of every accepted request, for compact assertions.
func (s *Server) Paths() []string {
	reqs := s.Requests()
	out := make([]string, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, r.Method+" "+r.Path)
	}
	return out
}

// HasPath reports whether any accepted request hit path with method.
func (s *Server) HasPath(method, path string) bool {
	for _, p := range s.Paths() {
		if p == method+" "+path || strings.HasPrefix(p, method+" "+path+"?") {
			return true
		}
	}
	return false
}
