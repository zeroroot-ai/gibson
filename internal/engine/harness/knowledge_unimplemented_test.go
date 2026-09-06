// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// TEST-ONLY. It lives in a _test.go file deliberately: nothing in the daemon
// embeds it, so as production code every method is unreachable and the deadcode
// gate is right to say so. Keeping it here gives the stubs their defaults
// without putting eight dead methods in the binary.
//
// UnimplementedKnowledgeReader supplies KnowledgeReader defaults that report
// ErrKnowledgeUnavailable. Embed it in a harness that does not serve knowledge
// reads — decorators under test, fakes, partial implementations.
//
// Every method reports UNAVAILABLE rather than returning an empty slice. A type
// embedding this is saying "I cannot answer", not "there is nothing to find",
// and a caller must be able to tell those apart: an agent that reads them as
// equivalent reports a clean prior record for work nobody looked up.
//
// This is also the absorber the SDK's BaseHarness is for its interface — the
// thing whose absence meant adding eight methods touched every mock in the tree.
type UnimplementedKnowledgeReader struct{}

// GetFindings reports ErrKnowledgeUnavailable: this harness serves no knowledge reads.
func (UnimplementedKnowledgeReader) GetFindings(context.Context, FindingFilter) ([]agent.Finding, error) {
	return nil, ErrKnowledgeUnavailable
}

// GetMissionRunHistory reports ErrKnowledgeUnavailable: this harness serves no knowledge reads.
func (UnimplementedKnowledgeReader) GetMissionRunHistory(context.Context) ([]MissionRunSummarySDK, error) {
	return nil, ErrKnowledgeUnavailable
}

// GetRunFindings reports ErrKnowledgeUnavailable: this harness serves no knowledge reads.
func (UnimplementedKnowledgeReader) GetRunFindings(context.Context, harnesspb.RunScope, FindingFilter) ([]agent.Finding, error) {
	return nil, ErrKnowledgeUnavailable
}

// QueryNodes reports ErrKnowledgeUnavailable: this harness serves no knowledge reads.
func (UnimplementedKnowledgeReader) QueryNodes(context.Context, *graphragpb.GraphQuery) ([]*graphragpb.QueryResult, error) {
	return nil, ErrKnowledgeUnavailable
}

// FindSimilarAttacks reports ErrKnowledgeUnavailable: this harness serves no knowledge reads.
func (UnimplementedKnowledgeReader) FindSimilarAttacks(context.Context, string, int) ([]*graphragpb.AttackPattern, error) {
	return nil, ErrKnowledgeUnavailable
}

// GetAttackChains reports ErrKnowledgeUnavailable: this harness serves no knowledge reads.
func (UnimplementedKnowledgeReader) GetAttackChains(context.Context, string, int) ([]*graphragpb.AttackChain, error) {
	return nil, ErrKnowledgeUnavailable
}

// FindSimilarFindings reports ErrKnowledgeUnavailable: this harness serves no knowledge reads.
func (UnimplementedKnowledgeReader) FindSimilarFindings(context.Context, string, int) ([]*graphragpb.FindingNode, error) {
	return nil, ErrKnowledgeUnavailable
}

// GetRelatedFindings reports ErrKnowledgeUnavailable: this harness serves no knowledge reads.
func (UnimplementedKnowledgeReader) GetRelatedFindings(context.Context, string) ([]*graphragpb.FindingNode, error) {
	return nil, ErrKnowledgeUnavailable
}

func (UnimplementedKnowledgeReader) ApplicationFindings(context.Context, string, []string, int) ([]byte, error) {
	return nil, ErrKnowledgeUnavailable
}
