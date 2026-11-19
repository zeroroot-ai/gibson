// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package cgjwt

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// memReplay is a replay store in memory. It records each admitted pair.
type memReplay struct {
	seen map[string]bool
	err  error
}

func (m *memReplay) Admit(_ context.Context, kid, jti string, _ time.Duration) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	if m.seen == nil {
		m.seen = map[string]bool{}
	}
	key := replayKey(kid, jti)
	if m.seen[key] {
		return false, nil
	}
	m.seen[key] = true
	return true, nil
}

func daemonCallClaims(now time.Time, purpose string) jwt.MapClaims {
	route, _ := modelcall.PurposeRoute(purpose)
	return jwt.MapClaims{
		"iss":                    "https://test.daemon/gibson",
		"aud":                    "test-daemon",
		"sub":                    modelcall.DaemonSubject(purpose),
		"tenant":                 "acme",
		"jti":                    "jti-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(30 * time.Second).Unix(),
		modelcall.ClaimPurpose:   purpose,
		modelcall.ClaimRoute:     route,
		modelcall.InitiatorClaim: "user:alice",
	}
}

func mintDaemonCall(t *testing.T, priv ed25519.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	tok.Header["typ"] = modelcall.DaemonCallTokenType
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func newDaemonCallVerifier(t *testing.T, store ReplayStore) (*Verifier, ed25519.PrivateKey) {
	t.Helper()
	pub, priv := mustGenKey(t)
	ks := startKeyServer(t, "k1", bareKeyDoc(pub, "k1"))
	v, err := NewVerifier(Config{
		KeysBaseURL:      ks.URL + strings.TrimSuffix(testKeysPath, "/"),
		ExpectedIssuer:   "https://test.daemon/gibson",
		ExpectedAudience: "test-daemon",
		TTL:              time.Hour,
		HTTPClient:       ks.Client(),
		ReplayStore:      store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v, priv
}

func TestIsDaemonCallToken(t *testing.T) {
	_, priv := mustGenKey(t)
	daemon := mintDaemonCall(t, priv, "k1", daemonCallClaims(time.Now(), modelcall.PurposeChat))
	task := mintJWT(t, priv, "k1", validClaims(time.Now()))
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{"daemon call type", daemon, true},
		{"task grant type", task, false},
		{"not a JWT", "garbage", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDaemonCallToken(tt.token); got != tt.want {
				t.Fatalf("IsDaemonCallToken = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyDaemonCall_Accepts(t *testing.T) {
	tests := []struct {
		purpose string
		initia  string
	}{
		{modelcall.PurposeChat, "user:alice"},
		{modelcall.PurposeEmbedding, ""},
		{modelcall.PurposeModelList, ""},
		{modelcall.PurposeProviderProbe, ""},
	}
	for _, tt := range tests {
		t.Run(tt.purpose, func(t *testing.T) {
			v, priv := newDaemonCallVerifier(t, &memReplay{})
			claims := daemonCallClaims(time.Now(), tt.purpose)
			if tt.initia == "" {
				delete(claims, modelcall.InitiatorClaim)
			}
			got, err := v.VerifyDaemonCall(context.Background(), mintDaemonCall(t, priv, "k1", claims))
			if err != nil {
				t.Fatalf("VerifyDaemonCall: %v", err)
			}
			wantRoute, _ := modelcall.PurposeRoute(tt.purpose)
			if got.Tenant != "acme" || got.Purpose != tt.purpose || got.Route != wantRoute ||
				got.Initiator != tt.initia || got.Subject != modelcall.DaemonSubject(tt.purpose) {
				t.Fatalf("unexpected grant: %+v", got)
			}
		})
	}
}

func TestVerifyDaemonCall_RefusesSecondUse(t *testing.T) {
	v, priv := newDaemonCallVerifier(t, &memReplay{})
	tok := mintDaemonCall(t, priv, "k1", daemonCallClaims(time.Now(), modelcall.PurposeChat))
	if _, err := v.VerifyDaemonCall(context.Background(), tok); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := v.VerifyDaemonCall(context.Background(), tok); !errors.Is(err, ErrReplayed) {
		t.Fatalf("second use error = %v, want ErrReplayed", err)
	}
}

func TestVerifyDaemonCall_FailsClosedWhenStoreFails(t *testing.T) {
	v, priv := newDaemonCallVerifier(t, &memReplay{err: errors.New("redis down")})
	tok := mintDaemonCall(t, priv, "k1", daemonCallClaims(time.Now(), modelcall.PurposeChat))
	if _, err := v.VerifyDaemonCall(context.Background(), tok); !errors.Is(err, ErrReplayStateUnavailable) {
		t.Fatalf("error = %v, want ErrReplayStateUnavailable", err)
	}
}

func TestVerifyDaemonCall_NoStoreRefuses(t *testing.T) {
	v, priv := newDaemonCallVerifier(t, nil)
	tok := mintDaemonCall(t, priv, "k1", daemonCallClaims(time.Now(), modelcall.PurposeChat))
	if _, err := v.VerifyDaemonCall(context.Background(), tok); !errors.Is(err, ErrReplayStateUnavailable) {
		t.Fatalf("error = %v, want ErrReplayStateUnavailable", err)
	}
}

func TestVerifyDaemonCall_HeaderRefusals(t *testing.T) {
	v, priv := newDaemonCallVerifier(t, &memReplay{})
	ctx := context.Background()
	if _, err := v.VerifyDaemonCall(ctx, "garbage"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("garbage error = %v, want ErrMalformed", err)
	}
	task := mintJWT(t, priv, "k1", validClaims(time.Now()))
	if _, err := v.VerifyDaemonCall(ctx, task); !errors.Is(err, ErrNotDaemonCall) {
		t.Fatalf("task grant error = %v, want ErrNotDaemonCall", err)
	}
	noKid := mintDaemonCall(t, priv, "", daemonCallClaims(time.Now(), modelcall.PurposeChat))
	if _, err := v.VerifyDaemonCall(ctx, noKid); !errors.Is(err, ErrMalformed) {
		t.Fatalf("missing kid error = %v, want ErrMalformed", err)
	}
}

func TestVerifyDaemonCall_SignatureAndKeyRefusals(t *testing.T) {
	v, _ := newDaemonCallVerifier(t, &memReplay{})
	ctx := context.Background()
	_, other := mustGenKey(t)
	bad := mintDaemonCall(t, other, "k1", daemonCallClaims(time.Now(), modelcall.PurposeChat))
	if _, err := v.VerifyDaemonCall(ctx, bad); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key error = %v, want ErrSignature", err)
	}
	unknown := mintDaemonCall(t, other, "k9", daemonCallClaims(time.Now(), modelcall.PurposeChat))
	if _, err := v.VerifyDaemonCall(ctx, unknown); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown kid error = %v, want ErrUnknownKey", err)
	}
}

func TestVerifyDaemonCall_ClaimRefusals(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name   string
		mutate func(c jwt.MapClaims)
		want   error
	}{
		{"expired", func(c jwt.MapClaims) {
			c["iat"] = now.Add(-10 * time.Minute).Unix()
			c["exp"] = now.Add(-9 * time.Minute).Unix()
		}, ErrExpired},
		{"expired during verification", func(c jwt.MapClaims) {
			c["iat"] = now.Add(-30 * time.Second).Unix()
			c["exp"] = now.Add(-2 * time.Second).Unix()
		}, ErrExpired},
		{"lifetime over the maximum", func(c jwt.MapClaims) {
			c["exp"] = now.Add(5 * time.Minute).Unix()
		}, ErrExpired},
		{"no exp", func(c jwt.MapClaims) { delete(c, "exp") }, ErrMalformed},
		{"no iat", func(c jwt.MapClaims) { delete(c, "iat") }, ErrMalformed},
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "https://evil" }, ErrMalformed},
		{"wrong audience", func(c jwt.MapClaims) { c["aud"] = "other" }, ErrMalformed},
		{"task claim mission_id", func(c jwt.MapClaims) { c["mission_id"] = "m" }, ErrMalformed},
		{"task claim allowed_rpcs", func(c jwt.MapClaims) { c["allowed_rpcs"] = []any{"/x"} }, ErrMalformed},
		{"unknown purpose", func(c jwt.MapClaims) { c[modelcall.ClaimPurpose] = "admin" }, ErrMalformed},
		{"wrong route", func(c jwt.MapClaims) { c[modelcall.ClaimRoute] = "/v1/embeddings" }, ErrMalformed},
		{"no tenant", func(c jwt.MapClaims) { delete(c, "tenant") }, ErrMalformed},
		{"wrong subject", func(c jwt.MapClaims) { c["sub"] = "component:daemon:embedding" }, ErrMalformed},
		{"chat without initiator", func(c jwt.MapClaims) { delete(c, modelcall.InitiatorClaim) }, ErrMalformed},
		{"chat with a service initiator", func(c jwt.MapClaims) {
			c[modelcall.InitiatorClaim] = "svc:x"
		}, ErrMalformed},
		{"no jti", func(c jwt.MapClaims) { delete(c, "jti") }, ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, priv := newDaemonCallVerifier(t, &memReplay{})
			claims := daemonCallClaims(now, modelcall.PurposeChat)
			tt.mutate(claims)
			_, err := v.VerifyDaemonCall(context.Background(), mintDaemonCall(t, priv, "k1", claims))
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}
