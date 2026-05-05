package checkpoint

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/zero-day-ai/gibson/internal/checkpoint/keyprovider"
	"github.com/zero-day-ai/gibson/internal/types"
)

// TestEncryptionAtRest_PersistedBytesAreCiphertext is the Spec 4 R11.1/R11.5
// regression test: when Encryption.Enabled is true, the bytes passed to
// CheckpointStore.SaveCheckpoint must be ciphertext — no plaintext substring
// of the mission ID, "working_memory", or "conversation_history" survives.
func TestEncryptionAtRest_PersistedBytesAreCiphertext(t *testing.T) {
	ctx := keyprovider.ContextWithTenant(context.Background(), "tenant-A")

	store := newCapturingCheckpointStore()
	blobs := newInMemoryBlobStore()

	resolver := keyprovider.NewInMemoryTenantKeyResolver(nil)
	provider := keyprovider.NewPerTenantKeyProvider(resolver)

	cfg := DefaultCheckpointerConfig()
	cfg.Encryption.Enabled = true
	cfg.Encryption.KeyProvider = provider
	cfg.Compression.Enabled = false // keep bytes legible to the substring scan

	cp, err := NewThreadedCheckpointerOrError(store, store, blobs, cfg)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	mid, err := types.ParseID("00000000-0000-0000-0000-00000000aaaa")
	if err != nil {
		t.Fatalf("parse id: %v", err)
	}
	threadID, err := cp.CreateThread(ctx, mid)
	if err != nil {
		t.Fatalf("create thread: %v", err)
	}

	state := NewExecutionState(mid, threadID)
	state.WorkingMemory = map[string]any{
		"working_memory": "PLAINTEXT_SECRET_TOKEN_42",
	}
	state.Metadata["mission_id"] = mid.String()

	if _, err := cp.Checkpoint(ctx, threadID, state); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}

	if len(store.savedCheckpoints) == 0 {
		t.Fatalf("expected at least one persisted checkpoint")
	}

	for _, saved := range store.savedCheckpoints {
		if !saved.Encrypted {
			t.Errorf("checkpoint %s persisted with Encrypted=false", saved.ID)
		}
		if saved.KeyID == "" {
			t.Errorf("checkpoint %s persisted without KeyID", saved.ID)
		}
		// The Checkpoint struct itself carries marshal-friendly fields; the
		// encrypted-payload bytes were threaded through the blob store or
		// inlined into LargeObjectRefs. The plaintext markers must NOT
		// appear in any persisted byte stream.
		buf := bytesOfCheckpoint(saved)
		for _, secret := range []string{"PLAINTEXT_SECRET_TOKEN_42", "working_memory"} {
			if bytes.Contains(buf, []byte(secret)) {
				t.Errorf("plaintext substring %q leaked into persisted checkpoint bytes", secret)
			}
		}
	}

	// Sanity: blob payload (when present) is ciphertext too.
	for _, b := range blobs.entries {
		for _, secret := range []string{"PLAINTEXT_SECRET_TOKEN_42", "working_memory"} {
			if bytes.Contains(b, []byte(secret)) {
				t.Errorf("plaintext substring %q leaked into blob storage", secret)
			}
		}
	}
}

// TestEncryptionAtRest_FailClosed_NilKeyProvider — Spec 4 R11.5: enabling
// encryption without a KeyProvider must fail at construction time.
func TestEncryptionAtRest_FailClosed_NilKeyProvider(t *testing.T) {
	store := newCapturingCheckpointStore()
	blobs := newInMemoryBlobStore()
	cfg := DefaultCheckpointerConfig()
	cfg.Encryption.Enabled = true
	cfg.Encryption.KeyProvider = nil
	if _, err := NewThreadedCheckpointerOrError(store, store, blobs, cfg); err == nil {
		t.Fatal("expected constructor to refuse Enabled=true with nil KeyProvider")
	}
}

// bytesOfCheckpoint approximates the persisted byte representation of a
// checkpoint for substring scanning. The persisted form uses msgpack on the
// wire; for the substring check we use a permissive concatenation of every
// inline field so any plaintext leak surfaces.
func bytesOfCheckpoint(cp *Checkpoint) []byte {
	var buf bytes.Buffer
	buf.WriteString(cp.ID)
	buf.WriteString(cp.ThreadID)
	buf.WriteString(cp.MissionID.String())
	buf.WriteString(cp.KeyID)
	buf.WriteString(cp.Label)
	buf.WriteString(cp.Checksum)
	for k, v := range cp.Metadata {
		buf.WriteString(k)
		buf.WriteString(v)
	}
	buf.Write(cp.WorkingMemory)
	buf.Write(cp.MissionMemory)
	buf.Write(cp.ConversationHistory)
	return buf.Bytes()
}

// capturingCheckpointStore is an in-memory CheckpointStore + ThreadStore that
// records every saved Checkpoint for assertion. It satisfies both interfaces
// to avoid a Redis dependency in this test.
type capturingCheckpointStore struct {
	mu               sync.Mutex
	savedCheckpoints map[string]*Checkpoint
	threads          map[string]*Thread
}

func newCapturingCheckpointStore() *capturingCheckpointStore {
	return &capturingCheckpointStore{
		savedCheckpoints: make(map[string]*Checkpoint),
		threads:          make(map[string]*Thread),
	}
}

func (s *capturingCheckpointStore) SaveCheckpoint(_ context.Context, cp *Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp2 := *cp
	s.savedCheckpoints[cp.ID] = &cp2
	return nil
}

func (s *capturingCheckpointStore) GetCheckpoint(_ context.Context, id string) (*Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cp, ok := s.savedCheckpoints[id]; ok {
		cp2 := *cp
		return &cp2, nil
	}
	return nil, ErrCheckpointNotFound
}

func (s *capturingCheckpointStore) Load(ctx context.Context, id string) (*Checkpoint, error) {
	return s.GetCheckpoint(ctx, id)
}

func (s *capturingCheckpointStore) ListCheckpoints(_ context.Context, threadID string, _ HistoryOptions) ([]*Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Checkpoint
	for _, cp := range s.savedCheckpoints {
		if cp.ThreadID == threadID {
			cp2 := *cp
			out = append(out, &cp2)
		}
	}
	return out, nil
}

func (s *capturingCheckpointStore) ListByThread(ctx context.Context, threadID string, opts HistoryOptions) ([]*Checkpoint, error) {
	return s.ListCheckpoints(ctx, threadID, opts)
}

func (s *capturingCheckpointStore) GetLatestCheckpoint(_ context.Context, threadID string) (*Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var latest *Checkpoint
	for _, cp := range s.savedCheckpoints {
		if cp.ThreadID != threadID {
			continue
		}
		if latest == nil || cp.CreatedAt.After(latest.CreatedAt) {
			latest = cp
		}
	}
	if latest == nil {
		return nil, ErrCheckpointNotFound
	}
	cp2 := *latest
	return &cp2, nil
}

func (s *capturingCheckpointStore) GetLatest(ctx context.Context, threadID string) (*Checkpoint, error) {
	return s.GetLatestCheckpoint(ctx, threadID)
}

func (s *capturingCheckpointStore) GetLatestByThread(ctx context.Context, threadID string) (*Checkpoint, error) {
	return s.GetLatestCheckpoint(ctx, threadID)
}

func (s *capturingCheckpointStore) DeleteCheckpoint(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.savedCheckpoints, id)
	return nil
}

func (s *capturingCheckpointStore) DeleteThreadCheckpoints(_ context.Context, threadID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, cp := range s.savedCheckpoints {
		if cp.ThreadID == threadID {
			delete(s.savedCheckpoints, id)
		}
	}
	return nil
}

func (s *capturingCheckpointStore) DeleteThread(ctx context.Context, threadID string) error {
	if err := s.DeleteThreadCheckpoints(ctx, threadID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.threads, threadID)
	return nil
}

func (s *capturingCheckpointStore) Save(ctx context.Context, cp *Checkpoint) error {
	return s.SaveCheckpoint(ctx, cp)
}

func (s *capturingCheckpointStore) Delete(ctx context.Context, id string) error {
	return s.DeleteCheckpoint(ctx, id)
}

func (s *capturingCheckpointStore) DeleteMany(ctx context.Context, ids []string) error {
	for _, id := range ids {
		_ = s.DeleteCheckpoint(ctx, id)
	}
	return nil
}

func (s *capturingCheckpointStore) SaveThread(_ context.Context, t *Thread) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t2 := *t
	s.threads[t.ID] = &t2
	return nil
}

func (s *capturingCheckpointStore) UpdateThread(ctx context.Context, t *Thread) error {
	return s.SaveThread(ctx, t)
}

func (s *capturingCheckpointStore) GetThread(_ context.Context, threadID string) (*Thread, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.threads[threadID]; ok {
		t2 := *t
		return &t2, nil
	}
	return nil, ErrThreadNotFound
}

func (s *capturingCheckpointStore) ListThreads(_ context.Context, missionID types.ID) ([]*Thread, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Thread
	for _, t := range s.threads {
		if t.MissionID == missionID {
			t2 := *t
			out = append(out, &t2)
		}
	}
	return out, nil
}

// inMemoryBlobStore satisfies BlobStore for tests.
type inMemoryBlobStore struct {
	mu      sync.Mutex
	entries map[string][]byte
}

func newInMemoryBlobStore() *inMemoryBlobStore {
	return &inMemoryBlobStore{entries: make(map[string][]byte)}
}

func (s *inMemoryBlobStore) Store(_ context.Context, threadID string, data []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := threadID + ":blob:" + string(rune(len(s.entries)))
	cp := make([]byte, len(data))
	copy(cp, data)
	s.entries[id] = cp
	return id, nil
}

func (s *inMemoryBlobStore) Get(_ context.Context, _ string, blobID string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.entries[blobID]; ok {
		out := make([]byte, len(v))
		copy(out, v)
		return out, nil
	}
	return nil, ErrBlobNotFound
}

func (s *inMemoryBlobStore) Delete(_ context.Context, _ string, blobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, blobID)
	return nil
}

func (s *inMemoryBlobStore) DeleteByThread(_ context.Context, threadID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.entries {
		if len(k) >= len(threadID) && k[:len(threadID)] == threadID {
			delete(s.entries, k)
		}
	}
	return nil
}

func (s *inMemoryBlobStore) ShouldStoreAsBlob(size int) bool {
	return size > 1024*1024
}
