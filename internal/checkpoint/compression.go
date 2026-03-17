// Package checkpoint provides checkpointing utilities for the Gibson AI agent platform.
package checkpoint

import (
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Compressor defines the interface for compression and decompression operations.
// Implementations should be thread-safe for concurrent use.
type Compressor interface {
	// Compress compresses the input data and returns the compressed bytes.
	// Returns an error if compression fails.
	Compress(data []byte) ([]byte, error)

	// Decompress decompresses the input data and returns the original bytes.
	// Returns an error if decompression fails or data is corrupted.
	Decompress(data []byte) ([]byte, error)

	// ShouldCompress determines whether data of the given size should be compressed
	// based on the configured threshold.
	ShouldCompress(size int) bool
}

// CompressionConfig defines configuration options for compression.
type CompressionConfig struct {
	// Enabled determines whether compression is active.
	Enabled bool

	// Threshold specifies the minimum size in bytes for compression to be applied.
	// Data smaller than this threshold will not be compressed.
	Threshold int64

	// Level specifies the zstd compression level.
	// Valid values: zstd.SpeedFastest (1) to zstd.SpeedBestCompression (22)
	// Use zstd.SpeedDefault (3) for balanced performance.
	Level zstd.EncoderLevel
}

// DefaultCompressionConfig returns the default compression configuration.
// - Enabled: true
// - Threshold: 10MB (10485760 bytes)
// - Level: zstd.SpeedDefault (balanced performance and compression ratio)
func DefaultCompressionConfig() CompressionConfig {
	return CompressionConfig{
		Enabled:   true,
		Threshold: 10485760, // 10MB
		Level:     zstd.SpeedDefault,
	}
}

// ZstdCompressor implements the Compressor interface using zstd compression.
// It uses encoder and decoder pools for efficient concurrent operation.
type ZstdCompressor struct {
	config CompressionConfig

	// Pool of encoders for thread-safe concurrent compression
	encoderPool sync.Pool

	// Pool of decoders for thread-safe concurrent decompression
	decoderPool sync.Pool
}

// NewZstdCompressor creates a new ZstdCompressor with the specified configuration.
// The compressor is thread-safe and uses encoder/decoder pools for efficiency.
func NewZstdCompressor(config CompressionConfig) *ZstdCompressor {
	compressor := &ZstdCompressor{
		config: config,
	}

	// Initialize encoder pool with factory function
	compressor.encoderPool = sync.Pool{
		New: func() interface{} {
			enc, err := zstd.NewWriter(nil,
				zstd.WithEncoderLevel(config.Level),
				zstd.WithEncoderConcurrency(1), // Pool handles concurrency
			)
			if err != nil {
				// This should rarely happen with valid configuration
				panic(fmt.Sprintf("failed to create zstd encoder: %v", err))
			}
			return enc
		},
	}

	// Initialize decoder pool with factory function
	compressor.decoderPool = sync.Pool{
		New: func() interface{} {
			dec, err := zstd.NewReader(nil,
				zstd.WithDecoderConcurrency(1), // Pool handles concurrency
			)
			if err != nil {
				// This should rarely happen
				panic(fmt.Sprintf("failed to create zstd decoder: %v", err))
			}
			return dec
		},
	}

	return compressor
}

// Compress compresses the input data using zstd compression.
// The method is thread-safe and uses a pooled encoder for efficiency.
// Returns the compressed data or an error if compression fails.
func (z *ZstdCompressor) Compress(data []byte) ([]byte, error) {
	if !z.config.Enabled {
		return data, nil
	}

	if len(data) == 0 {
		return data, nil
	}

	// Get encoder from pool
	enc := z.encoderPool.Get().(*zstd.Encoder)
	defer z.encoderPool.Put(enc)

	// Reset encoder for new data
	enc.Reset(nil)

	// Compress data
	compressed := enc.EncodeAll(data, make([]byte, 0, len(data)/2))

	return compressed, nil
}

// Decompress decompresses the input data using zstd decompression.
// The method is thread-safe and uses a pooled decoder for efficiency.
// Returns the original uncompressed data or an error if decompression fails.
func (z *ZstdCompressor) Decompress(data []byte) ([]byte, error) {
	if !z.config.Enabled {
		return data, nil
	}

	if len(data) == 0 {
		return data, nil
	}

	// Get decoder from pool
	dec := z.decoderPool.Get().(*zstd.Decoder)
	defer z.decoderPool.Put(dec)

	// Decompress data
	decompressed, err := dec.DecodeAll(data, nil)
	if err != nil {
		return nil, fmt.Errorf("zstd decompression failed: %w", err)
	}

	return decompressed, nil
}

// ShouldCompress determines whether data of the given size should be compressed
// based on the configured threshold. Returns true if compression is enabled and
// the size exceeds the threshold.
func (z *ZstdCompressor) ShouldCompress(size int) bool {
	return z.config.Enabled && int64(size) > z.config.Threshold
}
