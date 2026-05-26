package providers

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/crypto"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// FileProvider retrieves the master encryption key from a chart-mounted
// file on disk. The chart projects the underlying Secret as a volume
// (kubelet's native Secret-as-volume projection); the daemon reads the
// file. No K8s API client construction — see ADR-0023.
//
// The kubelet's Secret projection writes the file with mode 0400 by
// default (readable only by the pod's UID). The daemon caches the key
// on first read and zeroes it on Close.
//
// Spec: ADR-0023 (gibson daemon does not consume the Kubernetes API).
// Replaces the kubernetes provider's CoreV1().Secrets().Get() path with
// a file-mount equivalent.
type FileProvider struct {
	config *crypto.FileKeyConfig

	// Cached key (loaded once, immutable during pod lifetime).
	key     []byte
	keyOnce sync.Once
	keyErr  error
}

// NewFileProvider creates a file-mount KeyProvider. The chart mounts a
// Secret as a volume at cfg.Path; the daemon reads from disk.
func NewFileProvider(cfg *crypto.FileKeyConfig) (*FileProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("crypto: NewFileProvider: cfg is required")
	}
	if cfg.Path == "" {
		return nil, fmt.Errorf("crypto: NewFileProvider: cfg.Path is required")
	}
	return &FileProvider{config: cfg}, nil
}

// GetEncryptionKey reads the master encryption key from disk on first
// call and caches it. Subsequent calls return the cached key.
//
// The expected key size is 32 bytes (AES-256). Anything else is an
// error: a chart projecting an oversized or undersized Secret value
// must be fixed at the source, not at the daemon's expense.
func (p *FileProvider) GetEncryptionKey(_ context.Context) ([]byte, error) {
	p.keyOnce.Do(func() {
		raw, err := os.ReadFile(p.config.Path)
		if err != nil {
			p.keyErr = fmt.Errorf("crypto: read master KEK from %s: %w", p.config.Path, err)
			return
		}
		if len(raw) != expectedKeySize {
			p.keyErr = fmt.Errorf("crypto: invalid key size at %s: expected %d bytes, got %d (the chart must mount a Secret whose value is exactly 32 raw bytes — base64 or hex encoding will not work)", p.config.Path, expectedKeySize, len(raw))
			return
		}
		// Copy so we own the buffer and can zero it on Close.
		p.key = make([]byte, expectedKeySize)
		copy(p.key, raw)
	})

	if p.keyErr != nil {
		return nil, p.keyErr
	}
	return p.key, nil
}

// Name returns the provider identifier.
func (p *FileProvider) Name() string { return "file" }

// Health verifies the key is readable. Cheap: the keyOnce.Do has
// already run, so this is a cached-value check.
func (p *FileProvider) Health(ctx context.Context) types.HealthStatus {
	_, err := p.GetEncryptionKey(ctx)
	if err != nil {
		return types.HealthStatus{
			State:   types.HealthStateUnhealthy,
			Message: fmt.Sprintf("file key provider: %v", err),
		}
	}
	return types.HealthStatus{
		State:   types.HealthStateHealthy,
		Message: fmt.Sprintf("master KEK loaded from %s", p.config.Path),
	}
}

// Close zeroes the cached key. Idempotent.
func (p *FileProvider) Close() error {
	for i := range p.key {
		p.key[i] = 0
	}
	return nil
}
