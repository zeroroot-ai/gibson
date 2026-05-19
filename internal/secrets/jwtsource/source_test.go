package jwtsource

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestStaticJWTSource_ReturnsConfiguredToken — happy-path: the configured
// fixed token is returned verbatim, regardless of audience.
func TestStaticJWTSource_ReturnsConfiguredToken(t *testing.T) {
	t.Parallel()
	s := &StaticJWTSource{FixedToken: "test-jwt-token-abc"}

	for _, aud := range []string{"vault-aud", "another-aud", ""} {
		got, err := s.Token(context.Background(), aud)
		if err != nil {
			t.Fatalf("Token(%q) returned error: %v", aud, err)
		}
		if got != "test-jwt-token-abc" {
			t.Errorf("Token(%q) = %q, want %q", aud, got, "test-jwt-token-abc")
		}
	}
}

// TestStaticJWTSource_EmptyFixedTokenIsError — fail-loud: an empty configured
// token must surface as an error rather than silently returning "". A silent
// "" would later confuse Vault into rejecting the login with "jwt is required",
// hiding the misconfiguration upstream.
func TestStaticJWTSource_EmptyFixedTokenIsError(t *testing.T) {
	t.Parallel()
	s := &StaticJWTSource{}
	_, err := s.Token(context.Background(), "vault-aud")
	if err == nil {
		t.Fatal("expected error from empty StaticJWTSource, got nil")
	}
}

// TestStaticJWTSource_NilReceiverIsError — defensive: a typed-nil pointer
// must produce a clear error rather than panic.
func TestStaticJWTSource_NilReceiverIsError(t *testing.T) {
	t.Parallel()
	var s *StaticJWTSource
	_, err := s.Token(context.Background(), "vault-aud")
	if err == nil {
		t.Fatal("expected error from nil StaticJWTSource, got nil")
	}
}

// TestDisabledJWTSource_ReturnsSentinelError — the default daemon source
// before gibson#169 wires SPIRE. Every call returns ErrJWTSourceDisabled
// so that the AuthCache refresh closure can surface a clear diagnostic.
func TestDisabledJWTSource_ReturnsSentinelError(t *testing.T) {
	t.Parallel()
	var s DisabledJWTSource
	_, err := s.Token(context.Background(), "vault-aud")
	if err == nil {
		t.Fatal("expected error from DisabledJWTSource, got nil")
	}
	if !errors.Is(err, ErrJWTSourceDisabled) {
		t.Errorf("expected error to wrap ErrJWTSourceDisabled, got %v", err)
	}
}

// TestDisabledJWTSource_ErrorMentionsGibson169 — operator-visible breadcrumb:
// the error must name the issue (gibson#169) that will replace it. This is
// load-bearing: an SRE who sees this error in logs needs to know exactly
// which PR will fix it.
func TestDisabledJWTSource_ErrorMentionsGibson169(t *testing.T) {
	t.Parallel()
	if !strings.Contains(ErrJWTSourceDisabled.Error(), "gibson#169") {
		t.Errorf("ErrJWTSourceDisabled message must name issue #169: got %q", ErrJWTSourceDisabled.Error())
	}
}

// TestAudienceCapturingJWTSource_RecordsAudienceList verifies the test
// helper captures the audience passed by the caller — this is what the
// daemon-side broker_init test uses to assert the right audience is
// propagated end-to-end.
func TestAudienceCapturingJWTSource_RecordsAudienceList(t *testing.T) {
	t.Parallel()
	s := &AudienceCapturingJWTSource{
		StaticJWTSource: StaticJWTSource{FixedToken: "tok"},
	}
	_, _ = s.Token(context.Background(), "aud-1")
	_, _ = s.Token(context.Background(), "aud-2")

	if got, want := len(s.RecordedAudiences), 2; got != want {
		t.Fatalf("RecordedAudiences len = %d, want %d", got, want)
	}
	if s.RecordedAudiences[0] != "aud-1" || s.RecordedAudiences[1] != "aud-2" {
		t.Errorf("RecordedAudiences = %v, want [aud-1 aud-2]", s.RecordedAudiences)
	}
}

// Compile-time interface assertions — these guarantee that StaticJWTSource,
// AudienceCapturingJWTSource, and DisabledJWTSource all satisfy JWTSource
// without needing a runtime test. If anyone changes the JWTSource method
// signature, this file fails to compile.
var (
	_ JWTSource = (*StaticJWTSource)(nil)
	_ JWTSource = (*AudienceCapturingJWTSource)(nil)
	_ JWTSource = DisabledJWTSource{}
)
