// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package cgjwt

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// ErrNotDaemonCall marks a token that is not a daemon call grant (its type
// header is another one). It is not a refusal of a bad token: the caller reads
// the token as another kind.
var ErrNotDaemonCall = errors.New("cgjwt: not a daemon call grant")

// DaemonCall is a verified daemon call grant.
type DaemonCall struct {
	Tenant  string
	Purpose string
	// Route is the one path that the grant may call.
	Route string
	// Initiator is the FGA user for whom the daemon calls, or empty.
	Initiator string
	// Subject is the `sub` claim, component:daemon:<purpose>.
	Subject string
}

// IsDaemonCallToken reports whether a token declares the daemon call type. The
// header is not trusted yet: it only routes the token to VerifyDaemonCall, which
// verifies in full.
func IsDaemonCallToken(token string) bool {
	_, typ, err := peekHeader(token)
	return err == nil && typ == modelcall.DaemonCallTokenType
}

// maxDaemonCallSkew is the clock skew that the verifier tolerates.
const maxDaemonCallSkew = 5 * time.Second

// forbiddenDaemonCallClaims are the claims of a task grant. A daemon call grant
// holds none of them, so a task grant with the daemon type header is refused.
var forbiddenDaemonCallClaims = []string{"mission_id", "task_id", "allowed_rpcs", "mrid", "cag"}

// VerifyDaemonCall verifies a daemon call grant: the type header, the signature
// of the daemon key, the issuer and audience, a lifetime of at most 60 seconds,
// the closed purpose with its one route, the tenant, the initiator that the
// chat purpose needs, and the absence of any mission or task claim. It records
// the jti in the replay store, so the grant is accepted one time. With no store,
// or when the store does not answer, it refuses the grant.
func (v *Verifier) VerifyDaemonCall(ctx context.Context, token string) (DaemonCall, error) {
	kid, typ, err := peekHeader(token)
	if err != nil {
		return DaemonCall{}, err
	}
	if typ != modelcall.DaemonCallTokenType {
		return DaemonCall{}, ErrNotDaemonCall
	}
	if kid == "" {
		return DaemonCall{}, fmt.Errorf("%w: missing kid", ErrMalformed)
	}
	if v.replay == nil {
		return DaemonCall{}, fmt.Errorf("%w: no replay store is configured", ErrReplayStateUnavailable)
	}
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(v.expectedIssuer),
		jwt.WithAudience(v.expectedAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(maxDaemonCallSkew),
	)
	parsed, err := parser.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		key, ferr := keyFetcher{v: v}.Fetch(ctx, kid)
		if ferr != nil {
			return nil, fmt.Errorf("%w: kid %s: %w", ErrUnknownKey, kid, ferr)
		}
		return key, nil
	})
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return DaemonCall{}, fmt.Errorf("%w: %w", ErrExpired, err)
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return DaemonCall{}, fmt.Errorf("%w: %w", ErrSignature, err)
		case errors.Is(err, ErrUnknownKey):
			return DaemonCall{}, fmt.Errorf("verify the daemon call grant: %w", err)
		}
		return DaemonCall{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	for _, name := range forbiddenDaemonCallClaims {
		if _, present := claims[name]; present {
			return DaemonCall{}, fmt.Errorf("%w: a daemon call grant holds no %s claim", ErrMalformed, name)
		}
	}
	str := func(name string) string { s, _ := claims[name].(string); return s }
	iat, err := parsed.Claims.GetIssuedAt()
	exp, expErr := parsed.Claims.GetExpirationTime()
	if err != nil || iat == nil || expErr != nil || exp == nil {
		return DaemonCall{}, fmt.Errorf("%w: iat and exp are required", ErrMalformed)
	}
	if exp.Sub(iat.Time) > modelcall.DaemonCallMaxLifetime {
		return DaemonCall{}, fmt.Errorf("%w: the lifetime is over %s", ErrExpired, modelcall.DaemonCallMaxLifetime)
	}
	out := DaemonCall{
		Tenant: str("tenant"), Purpose: str(modelcall.ClaimPurpose), Route: str(modelcall.ClaimRoute),
		Initiator: str(modelcall.InitiatorClaim), Subject: str("sub"),
	}
	wantRoute, ok := modelcall.PurposeRoute(out.Purpose)
	switch {
	case !ok:
		return DaemonCall{}, fmt.Errorf("%w: %q is not a purpose", ErrMalformed, out.Purpose)
	case out.Route != wantRoute:
		return DaemonCall{}, fmt.Errorf("%w: the purpose %s has the route %s", ErrMalformed, out.Purpose, wantRoute)
	case out.Tenant == "":
		return DaemonCall{}, fmt.Errorf("%w: no tenant", ErrMalformed)
	case out.Subject != modelcall.DaemonSubject(out.Purpose):
		return DaemonCall{}, fmt.Errorf("%w: the subject does not match the purpose", ErrMalformed)
	case out.Purpose == modelcall.PurposeChat && !strings.HasPrefix(out.Initiator, "user:"):
		return DaemonCall{}, fmt.Errorf("%w: a chat grant needs the initiator", ErrMalformed)
	}
	jti := str("jti")
	if jti == "" {
		return DaemonCall{}, fmt.Errorf("%w: no jti", ErrMalformed)
	}
	ttl, live := replayTTL(exp.Time, time.Now())
	if !live {
		return DaemonCall{}, fmt.Errorf("%w: expired during verification", ErrExpired)
	}
	first, err := v.replay.Admit(ctx, kid, jti, ttl)
	if err != nil {
		return DaemonCall{}, fmt.Errorf("%w: kid %s: %w", ErrReplayStateUnavailable, kid, err)
	}
	if !first {
		return DaemonCall{}, fmt.Errorf("%w: kid %s jti %s already used", ErrReplayed, kid, jti)
	}
	return out, nil
}
