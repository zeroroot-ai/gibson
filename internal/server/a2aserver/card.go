// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package a2aserver

import (
	"encoding/json"
	"errors"
	"net/http"
)

// cardHandler serves the Agent Card of the agent that the route names. The
// path names the agent too, and the two must agree. The gateway sets the route
// header from the path, and ext-authz checked the right to see the agent.
func cardHandler(cards Cards) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c, r, ok := CallFrom(req.Context())
		if !ok {
			http.Error(w, ErrNoCaller.Error(), http.StatusUnauthorized)
			return
		}
		if name := req.PathValue("name"); name != r.Agent {
			http.Error(w, "the path and the route name different agents", http.StatusForbidden)
			return
		}
		card, err := cards.Card(req.Context(), c.Tenant, r.Agent)
		if err != nil {
			if errors.Is(err, ErrNoCard) {
				http.NotFound(w, req)
				return
			}
			http.Error(w, "the card is not available", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(w).Encode(card); err != nil {
			return // the client is gone
		}
	})
}
