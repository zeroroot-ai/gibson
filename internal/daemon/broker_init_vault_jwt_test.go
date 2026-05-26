package daemon

// broker_init_vault_jwt_test.go — tests for the SPIRE JWT-SVID mint step
// that the daemon's Vault broker stack performs before each
// sdkvault.RefreshToken / sdkvault.New call.
//
// Spec: ADR-0009 amendment (docs#34); gibson#167 PRD; gibson#168.
//
// The behaviour under test:
//
//   - Configs with Auth.Method != AuthMethodJWT are passed through
//     unchanged.
//   - Configs with Auth.Method == AuthMethodJWT and a non-empty
//     Auth.JWT are passed through unchanged (caller-supplied JWTs win).
//   - Configs with Auth.Method == AuthMethodJWT and an empty Auth.JWT
//     get a freshly-minted JWT stamped onto Auth.JWT via the JWTSource.
//   - When the JWTSource is missing OR the audience is empty, the helper
//     surfaces a clear error (fail-loud).
//   - The end-to-end factory path: given a fake Vault that accepts POST
//     /v1/auth/jwt/login with {role, jwt} and returns a ClientToken, the
//     daemon's broker init successfully wraps the provider — proof that
//     the minted JWT flows all the way through sdkvault.RefreshToken.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/secrets/jwtsource"
	sdkvault "github.com/zeroroot-ai/platform-clients/secrets/vault"
)

// TestStampVaultJWTOnConfig_NoOpForNonJWTMethod verifies that the helper
// is a strict no-op for any auth method other than AuthMethodJWT. The
// helper is called unconditionally from the refresh/factory paths; that
// is only safe when non-JWT configs pass through untouched.
func TestStampVaultJWTOnConfig_NoOpForNonJWTMethod(t *testing.T) {
	t.Parallel()

	captured := &jwtsource.AudienceCapturingJWTSource{
		StaticJWTSource: jwtsource.StaticJWTSource{FixedToken: "should-not-be-used"},
	}
	for _, method := range []sdkvault.AuthMethod{
		sdkvault.AuthMethodToken,
		sdkvault.AuthMethodAppRole,
		sdkvault.AuthMethodAWSIAM,
	} {
		t.Run(string(method), func(t *testing.T) {
			cfg := sdkvault.Config{
				Address: "https://vault.example.invalid:8200",
				Auth: sdkvault.AuthConfig{
					Method: method,
				},
			}
			err := stampVaultJWTOnConfig(context.Background(), &cfg, captured, "vault-aud")
			if err != nil {
				t.Fatalf("stampVaultJWTOnConfig(method=%s) error: %v", method, err)
			}
			if cfg.Auth.JWT != "" {
				t.Errorf("stampVaultJWTOnConfig(method=%s) populated Auth.JWT=%q on a non-JWT config", method, cfg.Auth.JWT)
			}
		})
	}
	if len(captured.RecordedAudiences) != 0 {
		t.Errorf("JWTSource.Token was called for a non-JWT config: %v", captured.RecordedAudiences)
	}
}

// TestStampVaultJWTOnConfig_HappyPath verifies the core seam behaviour:
// AuthMethodJWT + empty Auth.JWT → call source.Token(audience) → stamp
// the result onto cfg.Auth.JWT. This is the path the AuthCache refresh
// closure and the Vault factory fallback both rely on.
func TestStampVaultJWTOnConfig_HappyPath(t *testing.T) {
	t.Parallel()

	captured := &jwtsource.AudienceCapturingJWTSource{
		StaticJWTSource: jwtsource.StaticJWTSource{FixedToken: "test-jwt-token"},
	}
	cfg := sdkvault.Config{
		Address: "https://vault.example.invalid:8200",
		Auth: sdkvault.AuthConfig{
			Method: sdkvault.AuthMethodJWT,
			Role:   "gibson-plugin-acme",
		},
	}
	if err := stampVaultJWTOnConfig(context.Background(), &cfg, captured, "vault-aud"); err != nil {
		t.Fatalf("stampVaultJWTOnConfig: %v", err)
	}
	if cfg.Auth.JWT != "test-jwt-token" {
		t.Errorf("cfg.Auth.JWT = %q, want %q", cfg.Auth.JWT, "test-jwt-token")
	}
	if len(captured.RecordedAudiences) != 1 || captured.RecordedAudiences[0] != "vault-aud" {
		t.Errorf("source called with audiences %v, want [vault-aud]", captured.RecordedAudiences)
	}
}

// TestStampVaultJWTOnConfig_CallerSuppliedJWTWins verifies that when the
// broker config blob ALREADY carries a JWT (caller-supplied / local-dev
// short-circuit), the helper does NOT overwrite it.
//
// This branch is load-bearing for migration scenarios where a per-tenant
// config blob still carries a legacy JWT verbatim — those configs must
// keep working until the operator rewrites them, without forcing a
// JWTSource to be wired.
func TestStampVaultJWTOnConfig_CallerSuppliedJWTWins(t *testing.T) {
	t.Parallel()

	cfg := sdkvault.Config{
		Address: "https://vault.example.invalid:8200",
		Auth: sdkvault.AuthConfig{
			Method: sdkvault.AuthMethodJWT,
			Role:   "gibson-plugin-acme",
			JWT:    "caller-supplied-jwt",
		},
	}
	// Nil source is allowed in this branch — the helper never calls it.
	if err := stampVaultJWTOnConfig(context.Background(), &cfg, nil, ""); err != nil {
		t.Fatalf("stampVaultJWTOnConfig (caller-supplied JWT): %v", err)
	}
	if cfg.Auth.JWT != "caller-supplied-jwt" {
		t.Errorf("cfg.Auth.JWT got overwritten: %q", cfg.Auth.JWT)
	}
}

// TestStampVaultJWTOnConfig_DisabledSourceErrors verifies the
// fail-loud-on-missing-source branch: AuthMethodJWT + no Auth.JWT +
// DisabledJWTSource → error containing ErrJWTSourceDisabled. This is
// the state the daemon is in between gibson#168 and gibson#169 merging,
// and operators reading the error message must be pointed at #169.
func TestStampVaultJWTOnConfig_DisabledSourceErrors(t *testing.T) {
	t.Parallel()

	cfg := sdkvault.Config{
		Address: "https://vault.example.invalid:8200",
		Auth: sdkvault.AuthConfig{
			Method: sdkvault.AuthMethodJWT,
			Role:   "gibson-plugin-acme",
		},
	}
	err := stampVaultJWTOnConfig(context.Background(), &cfg, jwtsource.DisabledJWTSource{}, "vault-aud")
	if err == nil {
		t.Fatal("expected error from DisabledJWTSource, got nil")
	}
	if !strings.Contains(err.Error(), "gibson#169") {
		t.Errorf("error should breadcrumb gibson#169, got: %v", err)
	}
}

// TestStampVaultJWTOnConfig_NilSourceErrors guards against a code path
// forgetting to wire WithVaultJWTSource — the helper must return a
// clean error rather than panic on nil-deref.
func TestStampVaultJWTOnConfig_NilSourceErrors(t *testing.T) {
	t.Parallel()

	cfg := sdkvault.Config{
		Address: "https://vault.example.invalid:8200",
		Auth: sdkvault.AuthConfig{
			Method: sdkvault.AuthMethodJWT,
			Role:   "gibson-plugin-acme",
		},
	}
	err := stampVaultJWTOnConfig(context.Background(), &cfg, nil, "vault-aud")
	if err == nil {
		t.Fatal("expected error for nil source, got nil")
	}
	if !strings.Contains(err.Error(), "JWTSource") {
		t.Errorf("error should name JWTSource, got: %v", err)
	}
}

// TestStampVaultJWTOnConfig_EmptyAudienceErrors guards against the
// "real source wired but operator forgot the audience env var" case.
// Without an audience, SPIRE will mint a JWT with no aud claim that
// Vault rejects with a generic 400. The daemon must surface the
// misconfiguration up front.
func TestStampVaultJWTOnConfig_EmptyAudienceErrors(t *testing.T) {
	t.Parallel()

	cfg := sdkvault.Config{
		Address: "https://vault.example.invalid:8200",
		Auth: sdkvault.AuthConfig{
			Method: sdkvault.AuthMethodJWT,
			Role:   "gibson-plugin-acme",
		},
	}
	src := &jwtsource.StaticJWTSource{FixedToken: "ignored"}
	err := stampVaultJWTOnConfig(context.Background(), &cfg, src, "")
	if err == nil {
		t.Fatal("expected error for empty audience, got nil")
	}
	if !strings.Contains(err.Error(), "GIBSON_DAEMON_VAULT_JWT_AUDIENCE") {
		t.Errorf("error should name the env var, got: %v", err)
	}
}

// TestStampVaultJWTOnConfig_SourceReturningEmptyTokenErrors covers the
// "source malfunction" branch: a JWTSource that returns ("", nil) must
// be treated as an error rather than allowed to propagate as a silent
// empty JWT (which Vault would reject as a generic 400).
func TestStampVaultJWTOnConfig_SourceReturningEmptyTokenErrors(t *testing.T) {
	t.Parallel()

	cfg := sdkvault.Config{
		Address: "https://vault.example.invalid:8200",
		Auth: sdkvault.AuthConfig{
			Method: sdkvault.AuthMethodJWT,
			Role:   "gibson-plugin-acme",
		},
	}
	// emptyTokenSource returns ("", nil) — a malformed but non-error
	// response. The helper must refuse to stamp that onto cfg.
	src := emptyTokenSource{}
	err := stampVaultJWTOnConfig(context.Background(), &cfg, src, "vault-aud")
	if err == nil {
		t.Fatal("expected error from empty-token source, got nil")
	}
}

// emptyTokenSource returns ("", nil) — used to test the helper's
// defensive empty-token branch. (jwtsource.StaticJWTSource turns an
// empty FixedToken into an error rather than ("", nil), so we need a
// separate test double here.)
type emptyTokenSource struct{}

func (emptyTokenSource) Token(_ context.Context, _ string) (string, error) {
	return "", nil
}

// TestVaultBrokerInit_JWTLoginEndToEnd is the integration test demanded
// by the gibson#168 spec: given a JWTSource that returns "test-jwt-token"
// and a Vault config with Method=jwt + Role=gibson-plugin-acme + JWT="",
// the daemon's broker init must (a) call source.Token, (b) POST
// {role, jwt} to /v1/auth/jwt/login on the fake Vault, and (c) receive
// the fake's ClientToken back.
//
// This exercises the stamp helper + sdkvault.RefreshToken together. The
// proof of correctness is that the fake Vault sees exactly the right
// JWT on the login request.
func TestVaultBrokerInit_JWTLoginEndToEnd(t *testing.T) {
	t.Parallel()

	var capturedLoginRole string
	var capturedLoginJWT string

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/jwt/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if v, ok := body["role"].(string); ok {
			capturedLoginRole = v
		}
		if v, ok := body["jwt"].(string); ok {
			capturedLoginJWT = v
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"auth": {
				"client_token": "vault-issued-token",
				"accessor": "test-accessor",
				"policies": ["default"],
				"token_policies": ["default"],
				"lease_duration": 3600,
				"renewable": true
			}
		}`)
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"data": {
				"accessor": "test-accessor",
				"creation_time": 1700000000,
				"display_name": "jwt",
				"id": "vault-issued-token",
				"path": "auth/jwt/login",
				"policies": ["default"],
				"renewable": true,
				"ttl": 3600,
				"type": "service"
			}
		}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := sdkvault.Config{
		Address: srv.URL,
		Auth: sdkvault.AuthConfig{
			Method: sdkvault.AuthMethodJWT,
			Role:   "gibson-plugin-acme",
		},
	}

	src := &jwtsource.StaticJWTSource{FixedToken: "test-jwt-token"}

	// Step 1: stamp the JWT onto the config (the helper).
	if err := stampVaultJWTOnConfig(context.Background(), &cfg, src, "vault-aud"); err != nil {
		t.Fatalf("stampVaultJWTOnConfig: %v", err)
	}
	if cfg.Auth.JWT != "test-jwt-token" {
		t.Fatalf("after stamp: Auth.JWT = %q, want %q", cfg.Auth.JWT, "test-jwt-token")
	}

	// Step 2: run RefreshToken — this is what the daemon's broker
	// stack does at the end of the refresh closure. The fake Vault
	// records the role + jwt sent on the wire.
	tok, ttl, err := sdkvault.RefreshToken(context.Background(), cfg)
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if tok != "vault-issued-token" {
		t.Errorf("RefreshToken token = %q, want %q", tok, "vault-issued-token")
	}
	if ttl == 0 {
		t.Errorf("RefreshToken ttl = 0, expected non-zero (vault returned lease_duration=3600)")
	}

	// Step 3: assert the fake Vault received the right role + jwt.
	if capturedLoginRole != "gibson-plugin-acme" {
		t.Errorf("vault saw role = %q, want %q", capturedLoginRole, "gibson-plugin-acme")
	}
	if capturedLoginJWT != "test-jwt-token" {
		t.Errorf("vault saw jwt = %q, want %q", capturedLoginJWT, "test-jwt-token")
	}
}

// TestVaultBrokerInit_JWTLoginUsesAudienceFromDaemon — same end-to-end
// flow as above, but proves the audience flow: the audience passed into
// stampVaultJWTOnConfig is the one given to the JWTSource. This is the
// load-bearing claim of WithVaultJWTAudience.
func TestVaultBrokerInit_JWTLoginUsesAudienceFromDaemon(t *testing.T) {
	t.Parallel()

	src := &jwtsource.AudienceCapturingJWTSource{
		StaticJWTSource: jwtsource.StaticJWTSource{FixedToken: "tok"},
	}

	cfg := sdkvault.Config{
		Address: "https://vault.example.invalid:8200",
		Auth: sdkvault.AuthConfig{
			Method: sdkvault.AuthMethodJWT,
			Role:   "gibson-plugin-acme",
		},
	}
	if err := stampVaultJWTOnConfig(context.Background(), &cfg, src, "platform-vault"); err != nil {
		t.Fatalf("stampVaultJWTOnConfig: %v", err)
	}
	if len(src.RecordedAudiences) != 1 || src.RecordedAudiences[0] != "platform-vault" {
		t.Errorf("source called with audiences %v, want [platform-vault]", src.RecordedAudiences)
	}
}

// TestVaultBrokerInit_JWTLoginPropagatesSourceError — when the JWTSource
// returns an error, the stamp helper must wrap that error rather than
// silently fall through to a no-JWT RefreshToken (which would surface a
// confusing "jwt is required" error from the SDK).
func TestVaultBrokerInit_JWTLoginPropagatesSourceError(t *testing.T) {
	t.Parallel()

	cfg := sdkvault.Config{
		Address: "https://vault.example.invalid:8200",
		Auth: sdkvault.AuthConfig{
			Method: sdkvault.AuthMethodJWT,
			Role:   "gibson-plugin-acme",
		},
	}
	src := boomSource{err: fmt.Errorf("workload-api unreachable")}
	err := stampVaultJWTOnConfig(context.Background(), &cfg, src, "vault-aud")
	if err == nil {
		t.Fatal("expected error to propagate, got nil")
	}
	if !strings.Contains(err.Error(), "workload-api unreachable") {
		t.Errorf("source error should propagate, got: %v", err)
	}
	if cfg.Auth.JWT != "" {
		t.Errorf("cfg.Auth.JWT got stamped on error: %q", cfg.Auth.JWT)
	}
}

// boomSource returns the configured error. Used to exercise the error
// propagation branch of the stamp helper.
type boomSource struct {
	err error
}

func (b boomSource) Token(_ context.Context, _ string) (string, error) {
	return "", b.err
}
