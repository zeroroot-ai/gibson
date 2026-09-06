// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — connector_oauth_callback.go
//
// The OAuth callback for the connector authorize flow (ADR-0014). The vendor
// redirects the operator's browser here after they approve. The route mounts
// on the pre-auth :8085 listener, in the same bucket as /.well-known/gibson-login,
// because the browser holds no gibson credential at this point.
//
// The handler validates state, then hands the code to the ConnectorAuthService,
// which exchanges it daemon-side and stores the grant. The refresh token never
// leaves the daemon.
package daemon

import (
	"context"
	"html"
	"io"
	"log/slog"
	"net/http"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// connectorAuthFinisher is the slice of ConnectorAuthService the callback needs:
// take a state + code and finish the grant. *admin.ConnectorAuthAdminServer
// satisfies it. expectTenant is empty here — the callback trusts the state,
// whose pending record carries the tenant that (authenticated) started the flow.
type connectorAuthFinisher interface {
	FinishAuthorization(ctx context.Context, state, code, expectTenant string) (*tenantv1.GetConnectorAuthStatusResponse, error)
}

// connectorOAuthCallbackHandler completes a started authorization on the
// pre-auth listener. The vendor redirects the browser here with ?code&state;
// the handler validates state, exchanges the code daemon-side, stores the
// grant, and shows a plain "you may close this window" page.
func connectorOAuthCallbackHandler(finisher connectorAuthFinisher, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			// The human declined, or the vendor refused. Nothing is stored.
			writeCallbackPage(w, http.StatusBadRequest, "Authorization was declined at the vendor. You may close this window.")
			return
		}
		code := q.Get("code")
		state := q.Get("state")
		if code == "" || state == "" {
			writeCallbackPage(w, http.StatusBadRequest, "This link is missing its authorization code. Start again from the dashboard.")
			return
		}
		if _, err := finisher.FinishAuthorization(r.Context(), state, code, ""); err != nil {
			// The error carries a vendor code, never credential material, but
			// the browser must not see the daemon's internals; log it and show
			// a plain message.
			if logger != nil {
				logger.Warn("connector oauth callback failed", "error", err)
			}
			writeCallbackPage(w, http.StatusBadRequest, "Authorization could not be completed. Start again from the dashboard.")
			return
		}
		writeCallbackPage(w, http.StatusOK, "Authorized — you may close this window.")
	}
}

// writeCallbackPage renders the minimal HTML the browser lands on. The message
// is escaped though it is always a constant, so this cannot become an injection
// point if the messages ever grow dynamic.
func writeCallbackPage(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = io.WriteString(w,
		"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"+
			"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"+
			"<title>Connector authorization</title></head>"+
			"<body><p>"+html.EscapeString(msg)+"</p></body></html>")
}
