package checkpoint

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/checkpoint/keyprovider"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// --- helpers ----------------------------------------------------------------

// newTestKeyProvider returns a mockKeyProvider pre-loaded with a fresh
// 32-byte random key, suitable for use with SerializeOptions.KeyProvider.
func newTestKeyProvider() keyprovider.KeyProvider {
	return newMockKeyProvider(generateTestKey(), "checkpoint-test-key")
}

// createLargeRepetitiveState builds a state with a large, highly compressible
// working memory so we can assert that the output is meaningfully smaller.
func createLargeRepetitiveState() *ExecutionState {
	state := NewExecutionState(types.NewID(), "thread-compress-test")
	for i := 0; i < 500; i++ {
		state.WorkingMemory["key_"+string(rune('a'+i%26))+"_"+string(rune(i))] =
			strings.Repeat("the quick brown fox jumps over the lazy dog ", 50)
	}
	return state
}

// --- Roundtrip tests --------------------------------------------------------

// TestSerializer_CompressOnly verifies that compression alone produces a
// payload that round-trips correctly.
func TestSerializer_CompressOnly(t *testing.T) {
	t.Parallel()

	s := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()

	serOpts := SerializeOptions{
		Format:   FormatMessagePack,
		Compress: true,
	}

	data, err := s.Serialize(ctx, state, serOpts)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Header byte must indicate compressed-only.
	assert.Equal(t, byte(headerCompressed), data[0])

	deserOpts := DeserializeOptions{
		Format: FormatMessagePack,
	}

	restored, err := s.Deserialize(ctx, data, deserOpts)
	require.NoError(t, err)
	require.NotNil(t, restored)

	assert.Equal(t, state.MissionID, restored.MissionID)
	assert.Equal(t, state.ThreadID, restored.ThreadID)
	assert.Equal(t, len(state.NodeStates), len(restored.NodeStates))
	assert.Equal(t, len(state.WorkingMemory), len(restored.WorkingMemory))
}

// TestSerializer_EncryptOnly verifies that encryption alone produces a
// payload that round-trips correctly and differs from plaintext.
func TestSerializer_EncryptOnly(t *testing.T) {
	t.Parallel()

	s := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()
	kp := newTestKeyProvider()

	serOpts := SerializeOptions{
		Format:      FormatMessagePack,
		Encrypt:     true,
		KeyProvider: kp,
	}

	data, err := s.Serialize(ctx, state, serOpts)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Header byte must indicate encrypted-only.
	assert.Equal(t, byte(headerEncrypted), data[0])

	// Serialize the same state without encryption to verify the encrypted
	// payload differs from the plaintext payload.
	plainOpts := SerializeOptions{Format: FormatMessagePack}
	plainData, err := s.Serialize(ctx, state, plainOpts)
	require.NoError(t, err)
	assert.NotEqual(t, plainData, data, "encrypted output must differ from plaintext")

	deserOpts := DeserializeOptions{
		Format:      FormatMessagePack,
		KeyProvider: kp,
	}

	restored, err := s.Deserialize(ctx, data, deserOpts)
	require.NoError(t, err)
	require.NotNil(t, restored)

	assert.Equal(t, state.MissionID, restored.MissionID)
	assert.Equal(t, state.ThreadID, restored.ThreadID)
}

// TestSerializer_CompressAndEncrypt verifies the combined compress+encrypt path.
func TestSerializer_CompressAndEncrypt(t *testing.T) {
	t.Parallel()

	s := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()
	kp := newTestKeyProvider()

	serOpts := SerializeOptions{
		Format:      FormatMessagePack,
		Compress:    true,
		Encrypt:     true,
		KeyProvider: kp,
	}

	data, err := s.Serialize(ctx, state, serOpts)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Header byte must indicate compressed+encrypted.
	assert.Equal(t, byte(headerCompressedEncrypt), data[0])

	deserOpts := DeserializeOptions{
		Format:      FormatMessagePack,
		KeyProvider: kp,
	}

	restored, err := s.Deserialize(ctx, data, deserOpts)
	require.NoError(t, err)
	require.NotNil(t, restored)

	assert.Equal(t, state.MissionID, restored.MissionID)
	assert.Equal(t, state.ThreadID, restored.ThreadID)
	assert.Equal(t, len(state.NodeStates), len(restored.NodeStates))
	assert.Equal(t, len(state.WorkingMemory), len(restored.WorkingMemory))
}

// TestSerializer_CompressAndEncryptJSON verifies compress+encrypt also works
// with the JSON format.
func TestSerializer_CompressAndEncryptJSON(t *testing.T) {
	t.Parallel()

	s := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()
	kp := newTestKeyProvider()

	serOpts := SerializeOptions{
		Format:      FormatJSON,
		Compress:    true,
		Encrypt:     true,
		KeyProvider: kp,
	}

	data, err := s.Serialize(ctx, state, serOpts)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	deserOpts := DeserializeOptions{
		Format:      FormatJSON,
		KeyProvider: kp,
	}

	restored, err := s.Deserialize(ctx, data, deserOpts)
	require.NoError(t, err)
	assert.Equal(t, state.MissionID, restored.MissionID)
}

// --- Backward-compatibility tests -------------------------------------------

// TestSerializer_BackwardCompatRaw verifies that a legacy payload (no header
// byte, raw msgpack) still deserializes without error.
func TestSerializer_BackwardCompatRaw(t *testing.T) {
	t.Parallel()

	s := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()

	// Produce a raw msgpack payload without a header byte by serializing
	// in the old no-op way (Compress:false, Encrypt:false produces headerRaw=0x00,
	// but real legacy data had no header). We hand-craft it via msgpack directly.
	import_msgpack_marshal := func() []byte {
		// Use the new serializer with no flags — that writes headerRaw (0x00).
		// We need truly headerless data: manually marshal with msgpack.
		// Since headerRaw == 0x00 IS a valid header, we need a byte range
		// that msgpack actually uses for its first byte to simulate legacy data.
		// msgpack fixmap starts at 0x80–0x8f, fixarray at 0x90–0x9f, etc.
		// So a real legacy checkpoint (pure msgpack, no header) would start at 0x8x.
		//
		// Workaround: serialize normally, strip the first byte (the 0x00 header),
		// and feed the remaining bytes directly.  That raw msgpack slice should
		// then be recognised as "no header" because its first byte is >= 0x04.
		opts := SerializeOptions{Format: FormatMessagePack}
		full, err := s.Serialize(ctx, state, opts)
		if err != nil {
			panic(err)
		}
		// full[0] == 0x00 (headerRaw). Strip it to get the raw msgpack.
		return full[1:]
	}

	legacyData := import_msgpack_marshal()

	// The legacy data's first byte is a msgpack byte, not a known header,
	// so Deserialize should treat it as raw (no compress, no encrypt).
	deserOpts := DeserializeOptions{
		Format: FormatMessagePack,
		// Deliberately leave Compressed:false, Encrypted:false as in legacy callers.
	}

	restored, err := s.Deserialize(ctx, legacyData, deserOpts)
	require.NoError(t, err)
	require.NotNil(t, restored)
	assert.Equal(t, state.MissionID, restored.MissionID)
}

// TestSerializer_BackwardCompatJSON verifies that a legacy JSON payload (no
// header byte) still deserializes without error.
func TestSerializer_BackwardCompatJSON(t *testing.T) {
	t.Parallel()

	s := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()

	// Build a raw JSON payload (no header) by hand.
	opts := SerializeOptions{Format: FormatJSON}
	full, err := s.Serialize(ctx, state, opts)
	require.NoError(t, err)
	// full[0] == 0x00 (headerRaw). Strip it to get the raw JSON.
	legacyData := full[1:]

	// JSON starts with '{' (0x7B), which is not a known header byte.
	deserOpts := DeserializeOptions{Format: FormatJSON}

	restored, err := s.Deserialize(ctx, legacyData, deserOpts)
	require.NoError(t, err)
	assert.Equal(t, state.MissionID, restored.MissionID)
}

// --- Header detection tests -------------------------------------------------

// TestSerializer_HeaderRaw verifies that a no-op serialize writes headerRaw.
func TestSerializer_HeaderRaw(t *testing.T) {
	t.Parallel()

	s := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()

	data, err := s.Serialize(ctx, state, SerializeOptions{Format: FormatMessagePack})
	require.NoError(t, err)
	assert.Equal(t, byte(headerRaw), data[0])
}

// TestSerializer_FormatHeaders exercises all four header values.
func TestSerializer_FormatHeaders(t *testing.T) {
	t.Parallel()

	kp := newTestKeyProvider()

	tests := []struct {
		name           string
		opts           SerializeOptions
		expectedHeader formatHeader
	}{
		{
			name:           "raw",
			opts:           SerializeOptions{Format: FormatMessagePack},
			expectedHeader: headerRaw,
		},
		{
			name:           "compressed",
			opts:           SerializeOptions{Format: FormatMessagePack, Compress: true},
			expectedHeader: headerCompressed,
		},
		{
			name:           "encrypted",
			opts:           SerializeOptions{Format: FormatMessagePack, Encrypt: true, KeyProvider: kp},
			expectedHeader: headerEncrypted,
		},
		{
			name:           "compressed+encrypted",
			opts:           SerializeOptions{Format: FormatMessagePack, Compress: true, Encrypt: true, KeyProvider: kp},
			expectedHeader: headerCompressedEncrypt,
		},
	}

	s := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := s.Serialize(ctx, state, tt.opts)
			require.NoError(t, err)
			require.NotEmpty(t, data)
			assert.Equal(t, byte(tt.expectedHeader), data[0], "unexpected format header")
		})
	}
}

// --- Compression effectiveness test -----------------------------------------

// TestSerializer_CompressionReducesSize verifies that compressing a highly
// repetitive state produces an output smaller than the raw encoding.
func TestSerializer_CompressionReducesSize(t *testing.T) {
	t.Parallel()

	s := NewStateSerializer()
	ctx := context.Background()
	state := createLargeRepetitiveState()

	rawOpts := SerializeOptions{Format: FormatMessagePack}
	rawData, err := s.Serialize(ctx, state, rawOpts)
	require.NoError(t, err)

	compOpts := SerializeOptions{Format: FormatMessagePack, Compress: true}
	compData, err := s.Serialize(ctx, state, compOpts)
	require.NoError(t, err)

	// The compressed payload (including the 1-byte header) must be smaller.
	assert.Less(t, len(compData), len(rawData),
		"compressed payload (%d bytes) should be smaller than raw (%d bytes)",
		len(compData), len(rawData))
}

// --- Encryption verification ----------------------------------------------------------------

// TestSerializer_EncryptedDiffersFromPlaintext asserts that encrypting the same
// state twice produces different ciphertexts (due to random nonces).
func TestSerializer_EncryptedDiffersFromPlaintext(t *testing.T) {
	t.Parallel()

	s := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()
	kp := newTestKeyProvider()

	encOpts := SerializeOptions{
		Format:      FormatMessagePack,
		Encrypt:     true,
		KeyProvider: kp,
	}

	data1, err := s.Serialize(ctx, state, encOpts)
	require.NoError(t, err)

	data2, err := s.Serialize(ctx, state, encOpts)
	require.NoError(t, err)

	// Two encryptions of the same data must yield different ciphertexts.
	assert.NotEqual(t, data1, data2,
		"two encryptions of the same state must produce different ciphertexts (random nonces)")
}

// TestSerializer_WrongKeyFails asserts that decrypting with a different key
// returns an error.
func TestSerializer_WrongKeyFails(t *testing.T) {
	t.Parallel()

	s := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()

	encKey := newTestKeyProvider()
	decKey := newTestKeyProvider() // Different key

	serOpts := SerializeOptions{
		Format:      FormatMessagePack,
		Encrypt:     true,
		KeyProvider: encKey,
	}

	data, err := s.Serialize(ctx, state, serOpts)
	require.NoError(t, err)

	deserOpts := DeserializeOptions{
		Format:      FormatMessagePack,
		KeyProvider: decKey,
	}

	_, err = s.Deserialize(ctx, data, deserOpts)
	require.Error(t, err, "decryption with wrong key must fail")
	assert.Contains(t, err.Error(), "decryption failed")
}

// --- Error paths ------------------------------------------------------------

// TestSerializer_EncryptNoKeyProvider verifies that requesting encryption
// without a key provider returns an error.
func TestSerializer_EncryptNoKeyProvider(t *testing.T) {
	t.Parallel()

	s := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()

	_, err := s.Serialize(ctx, state, SerializeOptions{
		Format:  FormatMessagePack,
		Encrypt: true,
		// KeyProvider deliberately omitted
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no key provider")
}

// TestSerializer_DecryptNoKeyProvider verifies that attempting to decrypt a
// payload without a key provider returns an error.
func TestSerializer_DecryptNoKeyProvider(t *testing.T) {
	t.Parallel()

	s := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()
	kp := newTestKeyProvider()

	data, err := s.Serialize(ctx, state, SerializeOptions{
		Format:      FormatMessagePack,
		Encrypt:     true,
		KeyProvider: kp,
	})
	require.NoError(t, err)

	_, err = s.Deserialize(ctx, data, DeserializeOptions{
		Format: FormatMessagePack,
		// KeyProvider deliberately omitted
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no key provider")
}

// TestSerializer_CompressEncryptLargeState exercises the full pipeline on a
// state that is large enough to benefit from compression.
func TestSerializer_CompressEncryptLargeState(t *testing.T) {
	t.Parallel()

	s := NewStateSerializer()
	ctx := context.Background()
	state := createLargeRepetitiveState()
	kp := newTestKeyProvider()

	serOpts := SerializeOptions{
		Format:      FormatMessagePack,
		Compress:    true,
		Encrypt:     true,
		KeyProvider: kp,
	}

	data, err := s.Serialize(ctx, state, serOpts)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	deserOpts := DeserializeOptions{
		Format:      FormatMessagePack,
		KeyProvider: kp,
	}

	restored, err := s.Deserialize(ctx, data, deserOpts)
	require.NoError(t, err)
	require.NotNil(t, restored)

	assert.Equal(t, state.MissionID, restored.MissionID)
	assert.Equal(t, len(state.WorkingMemory), len(restored.WorkingMemory))
}

// --- Benchmark: compression+encryption pipeline -----------------------------

func BenchmarkSerializer_CompressOnly(b *testing.B) {
	s := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()
	opts := SerializeOptions{Format: FormatMessagePack, Compress: true}
	dOpts := DeserializeOptions{Format: FormatMessagePack}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		data, err := s.Serialize(ctx, state, opts)
		if err != nil {
			b.Fatal(err)
		}
		_, err = s.Deserialize(ctx, data, dOpts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSerializer_CompressAndEncrypt(b *testing.B) {
	s := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()
	kp := newTestKeyProvider()
	opts := SerializeOptions{
		Format: FormatMessagePack, Compress: true, Encrypt: true, KeyProvider: kp,
	}
	dOpts := DeserializeOptions{Format: FormatMessagePack, KeyProvider: kp}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		data, err := s.Serialize(ctx, state, opts)
		if err != nil {
			b.Fatal(err)
		}
		_, err = s.Deserialize(ctx, data, dOpts)
		if err != nil {
			b.Fatal(err)
		}
	}
}
