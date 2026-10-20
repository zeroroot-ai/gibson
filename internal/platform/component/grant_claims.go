// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"google.golang.org/grpc/metadata"
)

// callerGrantClaim reads one string claim from the capability grant that the
// caller presented. ext-authz verified the grant at the edge, so the payload is
// the daemon's own statement about the caller. A request with no grant, and a
// token that does not parse, has no claim.
func callerGrantClaim(ctx context.Context, name string) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, v := range md.Get("x-capability-grant") {
		token := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(v, "Bearer "), "bearer "))
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			continue
		}
		var payload map[string]any
		if json.Unmarshal(raw, &payload) != nil {
			continue
		}
		if claim, _ := payload[name].(string); claim != "" {
			return claim
		}
	}
	return ""
}
