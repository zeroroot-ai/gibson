package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadImpersonationKey reads the impersonation signing key (current or
// previous) from the volume-mounted Secret file at
// /etc/gibson/impersonation/<name>, falling back to os.Getenv(<name>)
// when the file is absent or empty. Tracked at deploy#315.
//
// The tests below exercise the source-priority + trim behaviour using
// a temporary directory injected via a test-only override of
// impersonationKeyDir. The override is reverted by t.Cleanup.

func TestLoadImpersonationKey_PrefersFileOverEnv(t *testing.T) {
	dir := t.TempDir()
	withMountDir(t, dir)

	if err := os.WriteFile(filepath.Join(dir, "GIBSON_IMPERSONATION_KEY"), []byte("file-value"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	t.Setenv("GIBSON_IMPERSONATION_KEY", "env-value")

	got := loadImpersonationKey("GIBSON_IMPERSONATION_KEY")
	if string(got) != "file-value" {
		t.Errorf("file should win when both sources are present; got %q", string(got))
	}
}

func TestLoadImpersonationKey_FallsBackToEnvWhenFileAbsent(t *testing.T) {
	dir := t.TempDir()
	withMountDir(t, dir)

	t.Setenv("GIBSON_IMPERSONATION_KEY", "env-value")
	got := loadImpersonationKey("GIBSON_IMPERSONATION_KEY")
	if string(got) != "env-value" {
		t.Errorf("env should be used when file is absent; got %q", string(got))
	}
}

func TestLoadImpersonationKey_FallsBackToEnvWhenFileEmpty(t *testing.T) {
	dir := t.TempDir()
	withMountDir(t, dir)

	if err := os.WriteFile(filepath.Join(dir, "GIBSON_IMPERSONATION_KEY"), []byte(""), 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	t.Setenv("GIBSON_IMPERSONATION_KEY", "env-fallback")

	got := loadImpersonationKey("GIBSON_IMPERSONATION_KEY")
	if string(got) != "env-fallback" {
		t.Errorf("empty file should fall back to env; got %q", string(got))
	}
}

func TestLoadImpersonationKey_ReturnsNilWhenBothAbsent(t *testing.T) {
	dir := t.TempDir()
	withMountDir(t, dir)

	t.Setenv("GIBSON_IMPERSONATION_KEY", "")
	got := loadImpersonationKey("GIBSON_IMPERSONATION_KEY")
	if got != nil {
		t.Errorf("nil expected when neither source has a value; got %q", string(got))
	}
}

func TestLoadImpersonationKey_TrimsTrailingNewlines(t *testing.T) {
	dir := t.TempDir()
	withMountDir(t, dir)

	if err := os.WriteFile(filepath.Join(dir, "GIBSON_IMPERSONATION_KEY"), []byte("file-value\n\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	got := loadImpersonationKey("GIBSON_IMPERSONATION_KEY")
	if string(got) != "file-value" {
		t.Errorf("trailing newlines should be trimmed; got %q", string(got))
	}
}

func TestLoadImpersonationKey_NULByteSurvivesFileRead(t *testing.T) {
	dir := t.TempDir()
	withMountDir(t, dir)

	// The whole point of the volume-mount migration (deploy#315): file
	// reads are length-based and NUL-transparent. A NUL byte in the
	// middle of the key must come through intact rather than truncating
	// the key (which is what env-var-via-secretKeyRef does silently).
	raw := []byte("abc\x00def")
	if err := os.WriteFile(filepath.Join(dir, "GIBSON_IMPERSONATION_KEY"), raw, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	got := loadImpersonationKey("GIBSON_IMPERSONATION_KEY")
	if !strings.HasPrefix(string(got), "abc") || len(got) != len(raw) {
		t.Errorf("NUL byte must not truncate file-sourced key; got %q (len=%d) want len=%d", string(got), len(got), len(raw))
	}
}

// withMountDir swaps impersonationKeyDir for the test's temp dir and
// restores the original via t.Cleanup. The package-level constant
// reference is unaffected outside the test goroutine because
// loadImpersonationKey reads the var by name each invocation.
func withMountDir(t *testing.T, dir string) {
	t.Helper()
	orig := impersonationKeyDirOverride
	impersonationKeyDirOverride = dir
	t.Cleanup(func() { impersonationKeyDirOverride = orig })
}
