// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"

	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc"
)

// withActingUser names the person a call acts for. It runs after the
// identity interceptor, so the identity on ctx is the one ext-authz verified
// (or a SPIFFE peer). Only a human session sets the acting user: the
// credential type is oidc-user, and the acting user is the verified subject.
// A service, component or SPIFFE identity sets none. No metadata header is
// read, so a client cannot name an acting user.
//
// The readers of auth.ActingUserFromContext attribute work to this person:
// the destructive-action and ontology reviews, bet settlement, labels, the
// per-user budget, the model gate and its audit, and component registration.
func withActingUser(ctx context.Context) context.Context {
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" || id.CredentialType != auth.CredentialOIDCUser {
		return ctx
	}
	return auth.ContextWithActingUser(ctx, id.Subject)
}

// actingUserUnary sets the acting user of a human caller on a unary call.
func actingUserUnary(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	return handler(withActingUser(ctx), req)
}

// actingUserStream sets the acting user of a human caller on a stream.
func actingUserStream(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return handler(srv, &serverStreamCtxOverride{ServerStream: ss, ctx: withActingUser(ss.Context())})
}
