package providers

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/types"
)

func writeKEK(t *testing.T, dir string, bytes []byte) string {
	t.Helper()
	path := filepath.Join(dir, "master-kek")
	if err := os.WriteFile(path, bytes, 0o400); err != nil {
		t.Fatalf("write KEK: %v", err)
	}
	return path
}

// TestFileProvider_ColdLoad covers the happy path: a chart-mounted file
// containing exactly 32 bytes is read and cached.
func TestFileProvider_ColdLoad(t *testing.T) {
	dir := t.TempDir()
	kek := bytes.Repeat([]byte{0xab}, 32)
	path := writeKEK(t, dir, kek)

	p, err := NewFileProvider(&crypto.FileKeyConfig{Path: path})
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}
	defer p.Close()

	got, err := p.GetEncryptionKey(context.Background())
	if err != nil {
		t.Fatalf("GetEncryptionKey: %v", err)
	}
	if !bytes.Equal(got, kek) {
		t.Fatalf("KEK mismatch: got %x, want %x", got, kek)
	}
}

// TestFileProvider_MissingFile covers the dev path where the chart
// hasn't projected the Secret yet. Returns a clear error.
func TestFileProvider_MissingFile(t *testing.T) {
	p, err := NewFileProvider(&crypto.FileKeyConfig{
		Path: filepath.Join(t.TempDir(), "does-not-exist"),
	})
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}
	defer p.Close()

	_, err = p.GetEncryptionKey(context.Background())
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// TestFileProvider_WrongSize covers a misconfigured chart: the projected
// Secret value isn't exactly 32 bytes. Provider must fail loud rather
// than silently truncate or pad.
func TestFileProvider_WrongSize(t *testing.T) {
	for _, sz := range []int{0, 16, 31, 33, 64} {
		dir := t.TempDir()
		path := writeKEK(t, dir, bytes.Repeat([]byte{0xcd}, sz))

		p, err := NewFileProvider(&crypto.FileKeyConfig{Path: path})
		if err != nil {
			t.Fatalf("size=%d: NewFileProvider: %v", sz, err)
		}
		if _, err := p.GetEncryptionKey(context.Background()); err == nil {
			t.Errorf("size=%d: expected error, got nil", sz)
		}
		_ = p.Close()
	}
}

// TestFileProvider_CachesOnFirstRead — once cached, subsequent reads
// return the same buffer pointer / value without re-reading disk.
func TestFileProvider_CachesOnFirstRead(t *testing.T) {
	dir := t.TempDir()
	kek := bytes.Repeat([]byte{0x42}, 32)
	path := writeKEK(t, dir, kek)

	p, err := NewFileProvider(&crypto.FileKeyConfig{Path: path})
	if err != nil {
		t.Fatalf("NewFileProvider: %v", err)
	}
	defer p.Close()

	a, _ := p.GetEncryptionKey(context.Background())

	// Mutate the file on disk; cached read must still return the
	// original value (kubelet's symlink-swap during Secret rotation
	// would similarly NOT invalidate the cache without a restart —
	// matches the kubernetes provider's previous sync.Once semantics).
	// chmod first because writeKEK created the file mode 0o400.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod KEK: %v", err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xff}, 32), 0o600); err != nil {
		t.Fatalf("rewrite KEK: %v", err)
	}

	b, _ := p.GetEncryptionKey(context.Background())
	if !bytes.Equal(a, b) {
		t.Fatalf("cached read changed after disk mutation: a=%x b=%x", a, b)
	}
	if !bytes.Equal(a, kek) {
		t.Fatalf("cached read should be the ORIGINAL value, got %x", a)
	}
}

// TestFileProvider_Health reflects the GetEncryptionKey path. Healthy
// when the file is readable + correctly-sized; unhealthy otherwise.
func TestFileProvider_Health(t *testing.T) {
	dir := t.TempDir()
	path := writeKEK(t, dir, bytes.Repeat([]byte{0xab}, 32))

	p, _ := NewFileProvider(&crypto.FileKeyConfig{Path: path})
	defer p.Close()

	h := p.Health(context.Background())
	if h.State != types.HealthStateHealthy {
		t.Fatalf("expected healthy, got %v: %s", h.State, h.Message)
	}

	// Now with a missing file.
	p2, _ := NewFileProvider(&crypto.FileKeyConfig{Path: filepath.Join(t.TempDir(), "missing")})
	defer p2.Close()
	h2 := p2.Health(context.Background())
	if h2.State == types.HealthStateHealthy {
		t.Fatalf("expected unhealthy for missing file, got %v", h2.State)
	}
}

// TestFileProvider_NilConfig is a defensive guard.
func TestFileProvider_NilConfig(t *testing.T) {
	if _, err := NewFileProvider(nil); err == nil {
		t.Fatal("expected error for nil cfg")
	}
	if _, err := NewFileProvider(&crypto.FileKeyConfig{}); err == nil {
		t.Fatal("expected error for empty Path")
	}
}

// TestFileProvider_Name returns "file".
func TestFileProvider_Name(t *testing.T) {
	dir := t.TempDir()
	path := writeKEK(t, dir, bytes.Repeat([]byte{0xab}, 32))
	p, _ := NewFileProvider(&crypto.FileKeyConfig{Path: path})
	defer p.Close()
	if got := p.Name(); got != "file" {
		t.Fatalf("Name: got %q, want %q", got, "file")
	}
}

// TestFileProvider_CloseZeroesKey verifies that Close zeroes the cached
// key buffer — defense-in-depth against post-Close memory disclosure.
func TestFileProvider_CloseZeroesKey(t *testing.T) {
	dir := t.TempDir()
	kek := bytes.Repeat([]byte{0xa5}, 32)
	path := writeKEK(t, dir, kek)

	p, _ := NewFileProvider(&crypto.FileKeyConfig{Path: path})

	got, _ := p.GetEncryptionKey(context.Background())
	if !bytes.Equal(got, kek) {
		t.Fatalf("setup: cold load wrong: %x", got)
	}

	_ = p.Close()

	// The underlying buffer that `got` references is the same buffer
	// the provider cached. Close zeros that buffer in place.
	for _, b := range got {
		if b != 0 {
			t.Fatalf("Close did not zero the key buffer: %x", got)
		}
	}
}
