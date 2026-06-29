package seam_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/gibson/pkg/seam"
)

// discardLogger returns a slog.Logger that drops all output, keeping test
// output clean.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// TestResolve_KnobAbsent_ReturnsFail_Safe proves that when the config knob env
// var is unset, Resolve returns the fail-safe implementation.
func TestResolve_KnobAbsent_ReturnsFail_Safe(t *testing.T) {
	t.Setenv("TEST_SEAM_KNOB_ABSENT", "")

	s := seam.New(seam.Spec[string]{
		Name:       "test-absent",
		ConfigKnob: "TEST_SEAM_KNOB_ABSENT",
		FailSafe:   func() (string, error) { return "fail-safe", nil },
		Remote:     func(_ string) (string, error) { return "remote", nil },
	})

	res, err := s.Resolve(context.Background(), discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Impl != "fail-safe" {
		t.Fatalf("expected fail-safe impl, got %q", res.Impl)
	}
	if res.Wired {
		t.Fatal("Wired must be false when knob is absent")
	}
	if res.Endpoint != "" {
		t.Fatalf("Endpoint must be empty when fail-safe, got %q", res.Endpoint)
	}
}

// TestResolve_KnobSet_ReturnsRemote proves that when the config knob is set
// and Remote succeeds, Resolve returns the remote implementation.
func TestResolve_KnobSet_ReturnsRemote(t *testing.T) {
	t.Setenv("TEST_SEAM_KNOB_SET", "svc.internal:9090")

	s := seam.New(seam.Spec[string]{
		Name:       "test-remote",
		ConfigKnob: "TEST_SEAM_KNOB_SET",
		FailSafe:   func() (string, error) { return "fail-safe", nil },
		Remote:     func(ep string) (string, error) { return "remote:" + ep, nil },
	})

	res, err := s.Resolve(context.Background(), discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Impl != "remote:svc.internal:9090" {
		t.Fatalf("expected remote impl, got %q", res.Impl)
	}
	if !res.Wired {
		t.Fatal("Wired must be true when remote succeeded")
	}
	if res.Endpoint != "svc.internal:9090" {
		t.Fatalf("unexpected endpoint %q", res.Endpoint)
	}
}

// TestResolve_RemoteFailure_FallsBackToFailSafe proves the fail-open contract:
// when the config knob is set but Remote returns an error, Resolve falls back
// to FailSafe and returns the fail-safe implementation without propagating the
// error.
func TestResolve_RemoteFailure_FallsBackToFailSafe(t *testing.T) {
	t.Setenv("TEST_SEAM_KNOB_REMOTE_ERR", "unreachable:59999")

	s := seam.New(seam.Spec[string]{
		Name:       "test-remote-err",
		ConfigKnob: "TEST_SEAM_KNOB_REMOTE_ERR",
		FailSafe:   func() (string, error) { return "fail-safe", nil },
		Remote:     func(_ string) (string, error) { return "", errors.New("dial failed") },
	})

	res, err := s.Resolve(context.Background(), discardLogger())
	if err != nil {
		t.Fatalf("unexpected error from Resolve: %v", err)
	}
	if res.Impl != "fail-safe" {
		t.Fatalf("expected fail-safe after remote failure, got %q", res.Impl)
	}
	if res.Wired {
		t.Fatal("Wired must be false after remote failure")
	}
}

// TestResolve_FailSafeError_PropagatesError proves that a FailSafe constructor
// failure is a hard error (the seam cannot produce any implementation).
func TestResolve_FailSafeError_PropagatesError(t *testing.T) {
	t.Setenv("TEST_SEAM_KNOB_FS_ERR", "")

	s := seam.New(seam.Spec[string]{
		Name:       "test-failsafe-err",
		ConfigKnob: "TEST_SEAM_KNOB_FS_ERR",
		FailSafe:   func() (string, error) { return "", errors.New("fail-safe broken") },
		Remote:     func(_ string) (string, error) { return "remote", nil },
	})

	_, err := s.Resolve(context.Background(), discardLogger())
	if err == nil {
		t.Fatal("expected error from FailSafe construction failure, got nil")
	}
}

// TestResolve_KnobWhitespace_TreatedAsAbsent verifies that an env var
// containing only whitespace is treated as absent (fail-safe path).
func TestResolve_KnobWhitespace_TreatedAsAbsent(t *testing.T) {
	t.Setenv("TEST_SEAM_KNOB_WS", "   ")

	s := seam.New(seam.Spec[string]{
		Name:       "test-whitespace",
		ConfigKnob: "TEST_SEAM_KNOB_WS",
		FailSafe:   func() (string, error) { return "fail-safe", nil },
		Remote:     func(_ string) (string, error) { return "remote", nil },
	})

	res, err := s.Resolve(context.Background(), discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Impl != "fail-safe" {
		t.Fatalf("expected fail-safe for whitespace knob, got %q", res.Impl)
	}
	if res.Wired {
		t.Fatal("Wired must be false for whitespace knob")
	}
}
