package checkpoint

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/vmihailenco/msgpack/v5"
	"github.com/zeroroot-ai/gibson/internal/checkpoint/keyprovider"
)

// SerializationFormat defines the format used for serialization.
type SerializationFormat string

const (
	// FormatMessagePack uses MessagePack binary serialization for compact, efficient encoding.
	FormatMessagePack SerializationFormat = "msgpack"
	// FormatJSON uses JSON serialization for human-readable, debugging-friendly encoding.
	FormatJSON SerializationFormat = "json"
)

// formatHeader is a single byte prepended to serialized payloads to indicate
// which post-processing was applied. Legacy checkpoints (written before this
// feature was added) carry no header byte; they are detected during
// Deserialize by checking whether the first byte is a known header value.
//
// Header byte layout:
//
//	0x00 – raw (no compression, no encryption)
//	0x01 – zstd compressed only
//	0x02 – AES-256-GCM encrypted only
//	0x03 – zstd compressed then AES-256-GCM encrypted
type formatHeader byte

const (
	headerRaw               formatHeader = 0x00
	headerCompressed        formatHeader = 0x01
	headerEncrypted         formatHeader = 0x02
	headerCompressedEncrypt formatHeader = 0x03
)

// isKnownHeader returns true when b is one of the four defined header values.
// Any byte outside this range is treated as the start of a legacy (header-less)
// payload.
func isKnownHeader(b byte) bool {
	return b == byte(headerRaw) ||
		b == byte(headerCompressed) ||
		b == byte(headerEncrypted) ||
		b == byte(headerCompressedEncrypt)
}

// SerializeOptions contains options for serialization.
type SerializeOptions struct {
	// Format specifies the serialization format to use
	Format SerializationFormat

	// Encrypt indicates whether to encrypt the serialized data
	Encrypt bool

	// Compress indicates whether to compress the serialized data
	Compress bool

	// KeyProvider provides encryption keys when Encrypt is true
	KeyProvider keyprovider.KeyProvider
}

// DeserializeOptions contains options for deserialization.
type DeserializeOptions struct {
	// Format specifies the serialization format expected
	Format SerializationFormat

	// Encrypted indicates whether the data is encrypted
	Encrypted bool

	// Compressed indicates whether the data is compressed
	Compressed bool

	// KeyProvider provides decryption keys when Encrypted is true
	KeyProvider keyprovider.KeyProvider
}

// StateSerializer defines the interface for serializing and deserializing execution state.
type StateSerializer interface {
	// Serialize converts an ExecutionState to bytes using the specified options.
	Serialize(ctx context.Context, state *ExecutionState, opts SerializeOptions) ([]byte, error)

	// Deserialize converts bytes back to an ExecutionState using the specified options.
	Deserialize(ctx context.Context, data []byte, opts DeserializeOptions) (*ExecutionState, error)

	// ValidateChecksum verifies the integrity of serialized data.
	ValidateChecksum(data []byte, checksum string) error
}

// DefaultStateSerializer is the default implementation of StateSerializer.
type DefaultStateSerializer struct {
	// No fields needed for stateless serialization
}

// NewStateSerializer creates a new DefaultStateSerializer instance.
func NewStateSerializer() *DefaultStateSerializer {
	return &DefaultStateSerializer{}
}

// Serialize converts an ExecutionState to bytes using the specified options.
//
// Processing order:
//  1. Encode to msgpack or JSON
//  2. Compress with zstd (if opts.Compress)
//  3. Encrypt with AES-256-GCM (if opts.Encrypt)
//  4. Prepend a single format-header byte
func (s *DefaultStateSerializer) Serialize(ctx context.Context, state *ExecutionState, opts SerializeOptions) ([]byte, error) {
	if state == nil {
		return nil, fmt.Errorf("state cannot be nil")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Step 1: encode
	var data []byte
	var err error

	switch opts.Format {
	case FormatMessagePack, "": // Default to MessagePack
		data, err = msgpack.Marshal(state)
		if err != nil {
			return nil, fmt.Errorf("msgpack serialization failed: %w", err)
		}

	case FormatJSON:
		data, err = json.Marshal(state)
		if err != nil {
			return nil, fmt.Errorf("json serialization failed: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported serialization format: %s", opts.Format)
	}

	// Step 2: compress
	if opts.Compress {
		data, err = compressZstd(data)
		if err != nil {
			return nil, fmt.Errorf("compression failed: %w", err)
		}
	}

	// Step 3: encrypt
	if opts.Encrypt {
		if opts.KeyProvider == nil {
			return nil, fmt.Errorf("encryption requested but no key provider specified")
		}

		key, err := opts.KeyProvider.GetKey(ctx)
		if err != nil {
			return nil, fmt.Errorf("retrieve encryption key: %w", err)
		}

		data, err = encryptAESGCM(data, key)
		if err != nil {
			return nil, fmt.Errorf("encryption failed: %w", err)
		}
	}

	// Step 4: prepend format header
	hdr := chooseHeader(opts.Compress, opts.Encrypt)
	out := make([]byte, 1+len(data))
	out[0] = byte(hdr)
	copy(out[1:], data)

	return out, nil
}

// Deserialize converts bytes back to an ExecutionState using the specified options.
//
// It automatically detects whether the payload carries a format header.
// Legacy payloads (written before header support was added) are handled
// transparently: if the first byte is not a known header value, the entire
// byte slice is treated as a raw encoded payload and processed according to
// opts.Compressed / opts.Encrypted.
func (s *DefaultStateSerializer) Deserialize(ctx context.Context, data []byte, opts DeserializeOptions) (*ExecutionState, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Determine whether this payload has a format header.
	var payload []byte
	var compressed, encrypted bool

	if isKnownHeader(data[0]) {
		// New format: read instructions from header, ignore opts flags.
		hdr := formatHeader(data[0])
		payload = data[1:]
		compressed = hdr == headerCompressed || hdr == headerCompressedEncrypt
		encrypted = hdr == headerEncrypted || hdr == headerCompressedEncrypt
	} else {
		// Legacy format: no header, use caller-supplied opts.
		payload = data
		compressed = opts.Compressed
		encrypted = opts.Encrypted
	}

	var err error

	// Decrypt first (reverse of serialize order).
	if encrypted {
		if opts.KeyProvider == nil {
			return nil, fmt.Errorf("data is encrypted but no key provider specified")
		}

		key, err := opts.KeyProvider.GetKey(ctx)
		if err != nil {
			return nil, fmt.Errorf("retrieve decryption key: %w", err)
		}

		payload, err = decryptAESGCM(payload, key)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}
	}

	// Decompress.
	if compressed {
		payload, err = decompressZstd(payload)
		if err != nil {
			return nil, fmt.Errorf("decompression failed: %w", err)
		}
	}

	// Decode.
	var state ExecutionState

	switch opts.Format {
	case FormatMessagePack, "": // Default to MessagePack
		if err = msgpack.Unmarshal(payload, &state); err != nil {
			return nil, fmt.Errorf("msgpack deserialization failed: %w", err)
		}

	case FormatJSON:
		if err = json.Unmarshal(payload, &state); err != nil {
			return nil, fmt.Errorf("json deserialization failed: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported deserialization format: %s", opts.Format)
	}

	// Validate required fields.
	if state.MissionID == "" {
		return nil, fmt.Errorf("deserialized state has empty mission_id")
	}

	return &state, nil
}

// ValidateChecksum verifies the integrity of serialized data by comparing checksums.
// It uses SHA256 hashing to ensure data has not been corrupted or tampered with.
func (s *DefaultStateSerializer) ValidateChecksum(data []byte, checksum string) error {
	if len(data) == 0 {
		return fmt.Errorf("data cannot be empty")
	}

	if checksum == "" {
		return fmt.Errorf("checksum cannot be empty")
	}

	// Generate checksum of the provided data
	computed := GenerateChecksum(data)

	// Compare checksums
	if computed != checksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", checksum, computed)
	}

	return nil
}

// GenerateChecksum generates a SHA256 checksum of the provided data.
// It returns the checksum as a lowercase hexadecimal string.
func GenerateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// chooseHeader maps the (compress, encrypt) flag pair to a formatHeader value.
func chooseHeader(compress, encrypt bool) formatHeader {
	switch {
	case compress && encrypt:
		return headerCompressedEncrypt
	case compress:
		return headerCompressed
	case encrypt:
		return headerEncrypted
	default:
		return headerRaw
	}
}

// serializerCompressor is a package-level ZstdCompressor used by the serializer
// for all compress/decompress operations. It uses SpeedDefault for a balanced
// speed/ratio trade-off and is safe for concurrent use via its internal pool.
var serializerCompressor = NewZstdCompressor(CompressionConfig{
	Enabled:   true,
	Threshold: 0, // Serializer decides when to compress; always honor the request.
	Level:     DefaultCompressionConfig().Level,
})

// compressZstd compresses src using the shared pooled ZstdCompressor.
func compressZstd(src []byte) ([]byte, error) {
	out, err := serializerCompressor.Compress(src)
	if err != nil {
		return nil, fmt.Errorf("zstd compress: %w", err)
	}
	return out, nil
}

// decompressZstd decompresses src using the shared pooled ZstdCompressor.
func decompressZstd(src []byte) ([]byte, error) {
	out, err := serializerCompressor.Decompress(src)
	if err != nil {
		return nil, fmt.Errorf("zstd decompress: %w", err)
	}
	return out, nil
}

// encryptAESGCM encrypts plaintext with AES-256-GCM using the provided key.
//
// The key must be exactly 32 bytes (AES-256). The returned blob has the layout:
//
//	[ nonce (12 bytes) | ciphertext+tag ]
//
// The nonce is generated fresh from crypto/rand for every call, so encrypting
// the same plaintext twice always produces different ciphertexts.
func encryptAESGCM(plaintext, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes for AES-256, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends the ciphertext+tag to nonce, producing: nonce || ciphertext+tag
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decryptAESGCM decrypts a blob produced by encryptAESGCM.
//
// The key must be the same 32-byte key used for encryption. GCM authentication
// is verified automatically; an error is returned if the data has been tampered
// with or the wrong key is used.
func decryptAESGCM(blob, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("decryption key must be 32 bytes for AES-256, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(blob) < nonceSize {
		return nil, fmt.Errorf("encrypted payload too short: %d bytes (minimum %d)", len(blob), nonceSize)
	}

	nonce, ciphertext := blob[:nonceSize], blob[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM authentication/decryption failed: %w", err)
	}

	return plaintext, nil
}
