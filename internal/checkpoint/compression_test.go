package checkpoint

import (
	"bytes"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultCompressionConfig(t *testing.T) {
	config := DefaultCompressionConfig()

	assert.True(t, config.Enabled, "compression should be enabled by default")
	assert.Equal(t, int64(10485760), config.Threshold, "threshold should be 10MB")
	assert.Equal(t, zstd.SpeedDefault, config.Level, "compression level should be default")
}

func TestNewZstdCompressor(t *testing.T) {
	t.Run("creates compressor with default config", func(t *testing.T) {
		config := DefaultCompressionConfig()
		compressor := NewZstdCompressor(config)

		require.NotNil(t, compressor)
		assert.Equal(t, config.Enabled, compressor.config.Enabled)
		assert.Equal(t, config.Threshold, compressor.config.Threshold)
		assert.Equal(t, config.Level, compressor.config.Level)
	})

	t.Run("creates compressor with custom config", func(t *testing.T) {
		config := CompressionConfig{
			Enabled:   true,
			Threshold: 1024,
			Level:     zstd.SpeedFastest,
		}
		compressor := NewZstdCompressor(config)

		require.NotNil(t, compressor)
		assert.Equal(t, int64(1024), compressor.config.Threshold)
		assert.Equal(t, zstd.SpeedFastest, compressor.config.Level)
	})
}

func TestZstdCompressor_ShouldCompress(t *testing.T) {
	tests := []struct {
		name      string
		config    CompressionConfig
		size      int
		expected  bool
	}{
		{
			name: "enabled and exceeds threshold",
			config: CompressionConfig{
				Enabled:   true,
				Threshold: 1024,
			},
			size:     2048,
			expected: true,
		},
		{
			name: "enabled but below threshold",
			config: CompressionConfig{
				Enabled:   true,
				Threshold: 1024,
			},
			size:     512,
			expected: false,
		},
		{
			name: "enabled and exactly at threshold",
			config: CompressionConfig{
				Enabled:   true,
				Threshold: 1024,
			},
			size:     1024,
			expected: false,
		},
		{
			name: "disabled",
			config: CompressionConfig{
				Enabled:   false,
				Threshold: 1024,
			},
			size:     2048,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressor := NewZstdCompressor(tt.config)
			result := compressor.ShouldCompress(tt.size)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestZstdCompressor_CompressDecompress(t *testing.T) {
	t.Run("round trip with small data", func(t *testing.T) {
		config := DefaultCompressionConfig()
		compressor := NewZstdCompressor(config)

		original := []byte("Hello, World! This is a test message.")

		compressed, err := compressor.Compress(original)
		require.NoError(t, err)
		require.NotNil(t, compressed)

		decompressed, err := compressor.Decompress(compressed)
		require.NoError(t, err)
		assert.Equal(t, original, decompressed)
	})

	t.Run("round trip with large data", func(t *testing.T) {
		config := DefaultCompressionConfig()
		compressor := NewZstdCompressor(config)

		// Create 1MB of data with patterns (compresses well)
		original := bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog. "), 20000)

		compressed, err := compressor.Compress(original)
		require.NoError(t, err)
		require.NotNil(t, compressed)

		// Compressed should be smaller
		assert.Less(t, len(compressed), len(original), "compressed data should be smaller")

		decompressed, err := compressor.Decompress(compressed)
		require.NoError(t, err)
		assert.Equal(t, original, decompressed)
	})

	t.Run("round trip with random data", func(t *testing.T) {
		config := DefaultCompressionConfig()
		compressor := NewZstdCompressor(config)

		// Create 100KB of random data (won't compress well)
		original := make([]byte, 100*1024)
		_, err := rand.Read(original)
		require.NoError(t, err)

		compressed, err := compressor.Compress(original)
		require.NoError(t, err)
		require.NotNil(t, compressed)

		decompressed, err := compressor.Decompress(compressed)
		require.NoError(t, err)
		assert.Equal(t, original, decompressed)
	})

	t.Run("empty data", func(t *testing.T) {
		config := DefaultCompressionConfig()
		compressor := NewZstdCompressor(config)

		original := []byte{}

		compressed, err := compressor.Compress(original)
		require.NoError(t, err)
		assert.Equal(t, original, compressed)

		decompressed, err := compressor.Decompress(compressed)
		require.NoError(t, err)
		assert.Equal(t, original, decompressed)
	})

	t.Run("compression disabled", func(t *testing.T) {
		config := CompressionConfig{
			Enabled:   false,
			Threshold: 1024,
			Level:     zstd.SpeedDefault,
		}
		compressor := NewZstdCompressor(config)

		original := []byte("This data should not be compressed")

		compressed, err := compressor.Compress(original)
		require.NoError(t, err)
		assert.Equal(t, original, compressed, "data should not be compressed when disabled")

		decompressed, err := compressor.Decompress(compressed)
		require.NoError(t, err)
		assert.Equal(t, original, decompressed)
	})
}

func TestZstdCompressor_CompressionLevels(t *testing.T) {
	// Test data with good compression potential
	testData := bytes.Repeat([]byte("compression test data "), 1000)

	tests := []struct {
		name  string
		level zstd.EncoderLevel
	}{
		{"fastest", zstd.SpeedFastest},
		{"default", zstd.SpeedDefault},
		{"better compression", zstd.SpeedBetterCompression},
		{"best compression", zstd.SpeedBestCompression},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := CompressionConfig{
				Enabled:   true,
				Threshold: 100,
				Level:     tt.level,
			}
			compressor := NewZstdCompressor(config)

			compressed, err := compressor.Compress(testData)
			require.NoError(t, err)
			require.NotNil(t, compressed)

			decompressed, err := compressor.Decompress(compressed)
			require.NoError(t, err)
			assert.Equal(t, testData, decompressed)

			// Verify compression occurred
			assert.Less(t, len(compressed), len(testData))
		})
	}
}

func TestZstdCompressor_InvalidData(t *testing.T) {
	config := DefaultCompressionConfig()
	compressor := NewZstdCompressor(config)

	t.Run("decompress invalid data", func(t *testing.T) {
		invalidData := []byte("this is not compressed data")
		_, err := compressor.Decompress(invalidData)
		assert.Error(t, err, "should fail to decompress invalid data")
		assert.Contains(t, err.Error(), "zstd decompression failed")
	})

	t.Run("decompress corrupted data", func(t *testing.T) {
		original := []byte("test data for corruption")
		compressed, err := compressor.Compress(original)
		require.NoError(t, err)

		// Corrupt the compressed data
		if len(compressed) > 10 {
			corrupted := make([]byte, len(compressed))
			copy(corrupted, compressed)
			corrupted[len(corrupted)/2] ^= 0xFF // Flip bits in middle

			_, err = compressor.Decompress(corrupted)
			assert.Error(t, err, "should fail to decompress corrupted data")
		}
	})
}

func TestZstdCompressor_Concurrent(t *testing.T) {
	config := DefaultCompressionConfig()
	compressor := NewZstdCompressor(config)

	// Test concurrent compression/decompression
	const numGoroutines = 50
	const dataSize = 10000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer wg.Done()

			// Create unique test data for this goroutine
			original := bytes.Repeat([]byte("concurrent test data "), dataSize/20)
			original = append(original, byte(index))

			// Compress
			compressed, err := compressor.Compress(original)
			if err != nil {
				errors <- err
				return
			}

			// Decompress
			decompressed, err := compressor.Decompress(compressed)
			if err != nil {
				errors <- err
				return
			}

			// Verify
			if !bytes.Equal(original, decompressed) {
				errors <- assert.AnError
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Errorf("concurrent operation failed: %v", err)
	}
}

func TestZstdCompressor_Interface(t *testing.T) {
	// Verify ZstdCompressor implements Compressor interface
	var _ Compressor = (*ZstdCompressor)(nil)
}

// Benchmark tests
func BenchmarkZstdCompressor_Compress(b *testing.B) {
	config := DefaultCompressionConfig()
	compressor := NewZstdCompressor(config)

	// Test with 1MB of repetitive data
	data := bytes.Repeat([]byte("benchmark test data for compression performance "), 20000)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		_, err := compressor.Compress(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkZstdCompressor_Decompress(b *testing.B) {
	config := DefaultCompressionConfig()
	compressor := NewZstdCompressor(config)

	// Prepare compressed data
	data := bytes.Repeat([]byte("benchmark test data for decompression performance "), 20000)
	compressed, err := compressor.Compress(data)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		_, err := compressor.Decompress(compressed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkZstdCompressor_CompressParallel(b *testing.B) {
	config := DefaultCompressionConfig()
	compressor := NewZstdCompressor(config)

	// Test with 100KB of data
	data := bytes.Repeat([]byte("parallel benchmark test data "), 3000)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := compressor.Compress(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkZstdCompressor_DecompressParallel(b *testing.B) {
	config := DefaultCompressionConfig()
	compressor := NewZstdCompressor(config)

	// Prepare compressed data
	data := bytes.Repeat([]byte("parallel benchmark test data "), 3000)
	compressed, err := compressor.Compress(data)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := compressor.Decompress(compressed)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
