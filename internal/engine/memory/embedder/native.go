package embedder

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/buckhx/gobert/tokenize"
	"github.com/buckhx/gobert/tokenize/vocab"
	"github.com/gomlx/go-huggingface/hub"
	"github.com/gomlx/gomlx/backends"
	"github.com/gomlx/gomlx/pkg/core/dtypes"
	. "github.com/gomlx/gomlx/pkg/core/graph"
	"github.com/gomlx/gomlx/pkg/core/tensors"
	mlcontext "github.com/gomlx/gomlx/pkg/ml/context"
	"github.com/gomlx/onnx-gomlx/onnx"
	gotypes "github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Singleton for the native embedder - GoMLX backend should only be initialized once per process
var (
	nativeEmbedderInstance *NativeEmbedder
	nativeEmbedderOnce     sync.Once
	nativeEmbedderErr      error
)

// NativeEmbedder uses GoMLX with all-MiniLM-L6-v2 for local embedding generation.
// This embedder runs entirely offline (after initial model download) without requiring external API calls.
//
// Model details:
//   - Architecture: all-MiniLM-L6-v2 (sentence-transformers/all-MiniLM-L6-v2)
//   - Dimensions: 384
//   - Output: float64 vectors
//   - Backend: XLA/PJRT via GoMLX
//   - Tokenizer: BERT WordPiece via gobert library
//
// Thread-safety: All methods are safe for concurrent use.
// Singleton: GoMLX backend should only be initialized once per process.
//
// Implementation details:
//   - Uses gobert (github.com/buckhx/gobert) for BERT tokenization
//   - Applies mean pooling on last_hidden_state output
//   - Handles int32->int64 conversion for ONNX model compatibility
type NativeEmbedder struct {
	model   *onnx.Model
	ctx     *mlcontext.Context
	backend backends.Backend
	// tokenizer is a pointer because tokenize.FeatureFactory contains a
	// sync.Mutex — copying the value by storing it directly would copy the
	// lock (go vet: copylocks).
	tokenizer *tokenize.FeatureFactory
	mu        sync.RWMutex
}

// CreateNativeEmbedder creates or returns the singleton native embedder using GoMLX with all-MiniLM-L6-v2.
// Returns an error if the model or tokenizer cannot be loaded.
//
// IMPORTANT: GoMLX backend should only be initialized once per process. This function
// returns a shared singleton instance. All callers receive the same embedder.
//
// Requirements:
//   - Model and tokenizer are downloaded from HuggingFace on first use
//   - Files are cached in HuggingFace's default cache location (~/.cache/huggingface/)
//   - No external dependencies required after initial download
//
// Example:
//
//	emb, err := CreateNativeEmbedder()
//	if err != nil {
//	    return nil, fmt.Errorf("embedder required: %w", err)
//	}
func CreateNativeEmbedder(logger *slog.Logger) (*NativeEmbedder, error) {
	if logger == nil {
		logger = slog.Default()
	}
	nativeEmbedderOnce.Do(func() {
		logger.Info("embedder.startup.begin")

		// Initialize GoMLX backend (XLA/PJRT)
		backend, err := backends.New()
		if err != nil {
			nativeEmbedderErr = gotypes.WrapError(ErrCodeEmbedderUnavailable,
				"failed to initialize GoMLX backend", err)
			return
		}
		logger.Info("embedder.gomlx.initialized")

		// Try to find cached model files first to avoid network calls
		// This is critical for Kubernetes deployments where network access may be limited
		logger.Info("embedder.cache.lookup")
		modelPath, vocabPath, err := findCachedModelFiles()
		if err != nil {
			logger.Info("embedder.cache.miss", "cause", err)
			// Fall back to HuggingFace Hub download with timeout
			modelPath, vocabPath, err = downloadModelFilesWithTimeout(10 * time.Second)
			if err != nil {
				nativeEmbedderErr = gotypes.WrapError(ErrCodeEmbedderUnavailable,
					"failed to load model files (check network or pre-cache model)", err)
				return
			}
			logger.Info("embedder.download.complete")
		} else {
			logger.Info("embedder.cache.hit", "model", modelPath, "vocab", vocabPath)
		}

		// Load ONNX model via onnx-gomlx
		model, err := onnx.ReadFile(modelPath)
		if err != nil {
			nativeEmbedderErr = gotypes.WrapError(ErrCodeEmbedderUnavailable,
				fmt.Sprintf("failed to load ONNX model from %s", modelPath), err)
			return
		}

		// Create GoMLX context for model execution
		ctx := mlcontext.New()
		if err := model.VariablesToContext(ctx); err != nil {
			nativeEmbedderErr = gotypes.WrapError(ErrCodeEmbedderUnavailable,
				"failed to extract model variables to context", err)
			return
		}

		// Load BERT vocabulary
		vocabDict, err := vocab.FromFile(vocabPath)
		if err != nil {
			nativeEmbedderErr = gotypes.WrapError(ErrCodeEmbedderUnavailable,
				fmt.Sprintf("failed to load vocabulary from %s", vocabPath), err)
			return
		}

		// Create BERT tokenizer with vocabulary
		// The model uses lowercase and max sequence length of 512
		bertTokenizer := tokenize.NewTokenizer(vocabDict,
			tokenize.WithLower(true),
			tokenize.WithUnknownToken("[UNK]"))

		// Create feature factory for converting text to model inputs
		// The model uses a max sequence length of 256 tokens
		featureFactory := tokenize.FeatureFactory{
			Tokenizer: bertTokenizer,
			SeqLen:    256,
		}

		nativeEmbedderInstance = &NativeEmbedder{
			model:     model,
			ctx:       ctx,
			backend:   backend,
			tokenizer: &featureFactory,
		}
		logger.Info("embedder.startup.complete")
	})

	if nativeEmbedderErr != nil {
		return nil, nativeEmbedderErr
	}

	return nativeEmbedderInstance, nil
}

// Embed generates an embedding vector for a single text.
// The text is tokenized, encoded, and passed through the transformer model.
//
// Returns an error if the embedding generation fails or context is canceled.
func (e *NativeEmbedder) Embed(ctx context.Context, text string) ([]float64, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Check if context is already canceled
	if err := ctx.Err(); err != nil {
		return nil, gotypes.WrapError(ErrCodeEmbeddingFailed, "context canceled", err)
	}

	// Tokenize text and create model input features
	feature := e.tokenizer.Feature(text)
	if len(feature.TokenIDs) == 0 {
		return nil, gotypes.NewError(ErrCodeEmbeddingFailed,
			"tokenization failed: no tokens produced")
	}

	// Extract input tensors from feature
	// BERT models expect: input_ids, attention_mask, token_type_ids
	// The tokenizer produces int32, but ONNX model expects int64
	inputIDsInt32 := feature.TokenIDs    // Shape: [seq_len]
	attentionMaskInt32 := feature.Mask   // Shape: [seq_len]
	tokenTypeIDsInt32 := feature.TypeIDs // Shape: [seq_len]

	// Convert int32 to int64 for ONNX model
	inputIDs := make([]int64, len(inputIDsInt32))
	attentionMask := make([]int64, len(attentionMaskInt32))
	tokenTypeIDs := make([]int64, len(tokenTypeIDsInt32))
	for i := range inputIDsInt32 {
		inputIDs[i] = int64(inputIDsInt32[i])
		attentionMask[i] = int64(attentionMaskInt32[i])
		tokenTypeIDs[i] = int64(tokenTypeIDsInt32[i])
	}

	// Create batch dimension (batch_size=1)
	batchInputIDs := [][]int64{inputIDs}
	batchAttentionMask := [][]int64{attentionMask}
	batchTokenTypeIDs := [][]int64{tokenTypeIDs}

	// Execute ONNX model via GoMLX graph
	// The model returns last_hidden_state with shape [batch_size, seq_len, hidden_size]
	result, err := mlcontext.ExecOnce(e.backend, e.ctx, func(ctx *mlcontext.Context, inputs []*Node) *Node {
		g := inputs[0].Graph()

		// Convert input slices to GoMLX tensors
		// inputs[0] = input_ids, inputs[1] = attention_mask, inputs[2] = token_type_ids
		inputIDsTensor := inputs[0]
		attentionMaskTensor := inputs[1]
		tokenTypeIDsTensor := inputs[2]

		// Call the ONNX model graph
		// The model has named inputs: input_ids, attention_mask, token_type_ids
		// Request only the last_hidden_state output
		outputs := e.model.CallGraph(ctx, g, map[string]*Node{
			"input_ids":      inputIDsTensor,
			"attention_mask": attentionMaskTensor,
			"token_type_ids": tokenTypeIDsTensor,
		}, "last_hidden_state")

		// Extract last_hidden_state from outputs
		// outputs is a slice, and we requested only "last_hidden_state"
		lastHiddenState := outputs[0]

		// Apply mean pooling on the sequence dimension
		// Shape: [batch_size, seq_len, hidden_size] -> [batch_size, hidden_size]
		// We need to mask padding tokens before pooling
		attentionMaskExpanded := ExpandDims(attentionMaskTensor, -1) // Shape: [batch_size, seq_len, 1]
		attentionMaskExpanded = ConvertType(attentionMaskExpanded, lastHiddenState.DType())

		// Mask hidden states (set padding tokens to 0)
		maskedHiddenState := Mul(lastHiddenState, attentionMaskExpanded)

		// Sum across sequence dimension
		sumHiddenState := ReduceSum(maskedHiddenState, 1) // Shape: [batch_size, hidden_size]

		// Count non-padding tokens for averaging
		sumMask := ReduceSum(attentionMaskExpanded, 1)  // Shape: [batch_size, hidden_size]
		sumMask = Add(sumMask, Const(g, float32(1e-9))) // Avoid division by zero

		// Mean pooling: divide by number of non-padding tokens
		meanPooled := Div(sumHiddenState, sumMask)

		return meanPooled
	}, batchInputIDs, batchAttentionMask, batchTokenTypeIDs)

	if err != nil {
		return nil, gotypes.WrapError(ErrCodeEmbeddingFailed,
			"GoMLX graph execution failed", err)
	}

	// Convert result tensor to []float64
	// Result shape: [1, 384] for batch_size=1
	embedding := tensorToFloat64Slice(result)
	if len(embedding) != 384 {
		return nil, gotypes.NewError(ErrCodeEmbeddingFailed,
			fmt.Sprintf("unexpected embedding dimension: got %d, want 384", len(embedding)))
	}

	return embedding, nil
}

// tensorToFloat64Slice converts a GoMLX tensor to a []float64 slice.
// Assumes the tensor is 2D with shape [1, dimensions] and extracts the first row.
func tensorToFloat64Slice(tensor *tensors.Tensor) []float64 {
	// Get tensor shape
	shape := tensor.Shape()
	if shape.Rank() != 2 || shape.Dimensions[0] != 1 {
		panic(fmt.Sprintf("expected shape [1, N], got %v", shape))
	}

	dims := shape.Dimensions[1]
	result := make([]float64, dims)

	// Get flat tensor data based on dtype
	switch tensor.DType() {
	case dtypes.Float32:
		// Copy data from tensor using CopyFlatData
		data, err := tensors.CopyFlatData[float32](tensor)
		if err != nil {
			panic(fmt.Sprintf("failed to copy tensor data: %v", err))
		}
		for i := 0; i < dims; i++ {
			result[i] = float64(data[i])
		}
	case dtypes.Float64:
		// Copy data from tensor using CopyFlatData
		data, err := tensors.CopyFlatData[float64](tensor)
		if err != nil {
			panic(fmt.Sprintf("failed to copy tensor data: %v", err))
		}
		copy(result, data)
	default:
		panic(fmt.Sprintf("unsupported tensor dtype: %v", tensor.DType()))
	}

	return result
}

// EmbedBatch generates embeddings for multiple texts efficiently.
// Texts are processed one at a time for now (true batching can be added later).
//
// Returns an error if any embedding fails. Partial results are not returned.
func (e *NativeEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Check if context is already canceled
	if err := ctx.Err(); err != nil {
		return nil, gotypes.WrapError(ErrCodeEmbeddingBatchFailed, "context canceled", err)
	}

	if len(texts) == 0 {
		return [][]float64{}, nil
	}

	// Process each text sequentially
	results := make([][]float64, len(texts))
	for i, text := range texts {
		// Check context between iterations
		if err := ctx.Err(); err != nil {
			return nil, gotypes.WrapError(ErrCodeEmbeddingBatchFailed,
				fmt.Sprintf("context canceled after %d/%d embeddings", i, len(texts)), err)
		}

		// Temporarily unlock for individual embedding
		e.mu.RUnlock()
		embedding, err := e.Embed(ctx, text)
		e.mu.RLock()

		if err != nil {
			return nil, gotypes.WrapError(ErrCodeEmbeddingBatchFailed,
				fmt.Sprintf("failed to generate embedding %d/%d", i+1, len(texts)), err)
		}

		results[i] = embedding
	}

	return results, nil
}

// Dimensions returns the dimensionality of embedding vectors.
// all-MiniLM-L6-v2 produces 384-dimensional embeddings.
func (e *NativeEmbedder) Dimensions() int {
	return 384
}

// Model returns the name of the embedding model.
func (e *NativeEmbedder) Model() string {
	return "all-MiniLM-L6-v2"
}

// Health checks if the embedder is operational.
// Tests the model by generating a test embedding.
func (e *NativeEmbedder) Health(ctx context.Context) gotypes.HealthStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Try to generate a test embedding
	testText := "health check"

	// Create a new context for the health check to avoid blocking
	healthCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Temporarily unlock for embedding
	e.mu.RUnlock()
	_, err := e.Embed(healthCtx, testText)
	e.mu.RLock()

	if err != nil {
		return gotypes.NewHealthStatus(gotypes.HealthStateDegraded,
			fmt.Sprintf("native embedder failed health check: %v", err))
	}

	return gotypes.NewHealthStatus(gotypes.HealthStateHealthy,
		"native embedder operational (all-MiniLM-L6-v2 via GoMLX)")
}

// findCachedModelFiles looks for pre-cached model files in the HuggingFace cache directory.
// This allows the embedder to work offline in Kubernetes environments where the model
// is pre-downloaded into the container image.
//
// Returns the paths to the ONNX model and vocabulary files, or an error if not found.
func findCachedModelFiles() (modelPath, vocabPath string, err error) {
	// Try XDG_CACHE_HOME first, then fall back to ~/.cache
	cacheDir := os.Getenv("XDG_CACHE_HOME")
	if cacheDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		cacheDir = filepath.Join(homeDir, ".cache")
	}

	// HuggingFace hub cache structure
	hubDir := filepath.Join(cacheDir, "huggingface", "hub")
	modelDir := filepath.Join(hubDir, "models--sentence-transformers--all-MiniLM-L6-v2")

	// Check if the model directory exists
	if _, err := os.Stat(modelDir); os.IsNotExist(err) {
		return "", "", fmt.Errorf("model cache directory not found: %s", modelDir)
	}

	// Look for snapshot directory - try refs/main to find the current snapshot
	refsMainPath := filepath.Join(modelDir, "refs", "main")
	snapshotRef, err := os.ReadFile(refsMainPath)
	if err != nil {
		// Fall back to looking in snapshots/main directly
		snapshotDir := filepath.Join(modelDir, "snapshots", "main")
		if _, err := os.Stat(snapshotDir); err == nil {
			modelPath = filepath.Join(snapshotDir, "model.onnx")
			vocabPath = filepath.Join(snapshotDir, "vocab.txt")
			if _, err := os.Stat(modelPath); err == nil {
				if _, err := os.Stat(vocabPath); err == nil {
					return modelPath, vocabPath, nil
				}
			}
			// Try onnx subdirectory
			modelPath = filepath.Join(snapshotDir, "onnx", "model.onnx")
			if _, err := os.Stat(modelPath); err == nil {
				if _, err := os.Stat(vocabPath); err == nil {
					return modelPath, vocabPath, nil
				}
			}
		}
		return "", "", fmt.Errorf("cannot read refs/main: %w", err)
	}

	// Use the snapshot hash from refs
	snapshotHash := string(snapshotRef)
	snapshotDir := filepath.Join(modelDir, "snapshots", snapshotHash)

	// Look for model.onnx in the snapshot or in onnx subdirectory
	modelPath = filepath.Join(snapshotDir, "onnx", "model.onnx")
	if _, err := os.Stat(modelPath); os.IsNotExist(err) {
		modelPath = filepath.Join(snapshotDir, "model.onnx")
		if _, err := os.Stat(modelPath); os.IsNotExist(err) {
			// Check blobs directory (hub stores files by hash)
			return "", "", fmt.Errorf("model.onnx not found in snapshot: %s", snapshotDir)
		}
	}

	// Look for vocab.txt
	vocabPath = filepath.Join(snapshotDir, "vocab.txt")
	if _, err := os.Stat(vocabPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("vocab.txt not found in snapshot: %s", snapshotDir)
	}

	return modelPath, vocabPath, nil
}

// downloadModelFilesWithTimeout downloads model files from HuggingFace Hub with a timeout.
// This prevents the daemon from hanging indefinitely if network is unavailable.
func downloadModelFilesWithTimeout(timeout time.Duration) (modelPath, vocabPath string, err error) {
	done := make(chan struct{})
	var downloadErr error

	go func() {
		defer close(done)
		modelRepo := hub.New("sentence-transformers/all-MiniLM-L6-v2")

		modelPath, downloadErr = modelRepo.DownloadFile("onnx/model.onnx")
		if downloadErr != nil {
			return
		}

		vocabPath, downloadErr = modelRepo.DownloadFile("vocab.txt")
	}()

	select {
	case <-done:
		if downloadErr != nil {
			return "", "", fmt.Errorf("download failed: %w", downloadErr)
		}
		return modelPath, vocabPath, nil
	case <-time.After(timeout):
		return "", "", fmt.Errorf("download timed out after %v", timeout)
	}
}
