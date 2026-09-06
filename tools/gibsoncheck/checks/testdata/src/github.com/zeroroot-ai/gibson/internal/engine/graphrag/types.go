// Package graphrag is a synthetic mirror of internal/engine/graphrag for
// gibsoncheck's cypheridentifier analyzer tests. Its import path must be
// EXACTLY github.com/zeroroot-ai/gibson/internal/engine/graphrag — the
// analyzer matches its scoped package by exact path (see cypher_identifier.go)
// — even though analysistest loads it from testdata/src, isolated from the
// real module tree.
package graphrag

// cypherFrag mirrors local_provider.go's type: a value proven safe to splice
// into Cypher query text.
type cypherFrag string
