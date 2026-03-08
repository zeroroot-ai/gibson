# TODO

This document tracks planned features, improvements, and completed work for Gibson.

## Completed Items

### 2026-03-05 - Vector Store Cleanup and Implementation
Complete overhaul of vector store backends:
- SQLite backend removed
- Qdrant backend implemented with full support
- Milvus backend implemented with full support
- Comprehensive integration tests added for both backends
- Improved configuration and backend selection logic

### 2026-03-05 - OpenAI Embedder Removal
Removed OpenAI embedder implementation from the codebase. The native embedder (all-minilm-l6-v2) is now the recommended and only supported embedder backend. OpenAI embedder code, tests, and dependencies have been removed.

## Future Features

### Embedder Backends
- Investigate additional local/native embedding models for improved performance
- Consider support for other embedding providers if needed

### GraphRAG Enhancements
- Performance optimizations for large-scale graph operations
- Enhanced querying capabilities
- Improved vector search algorithms

## Known Issues

None currently tracked.

## Ideas for Consideration

- Evaluate newer embedding models as they become available
- Consider caching strategies for embeddings
