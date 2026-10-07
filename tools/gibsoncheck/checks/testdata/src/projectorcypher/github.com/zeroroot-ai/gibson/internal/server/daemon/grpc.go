// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// readNode is outside the projector files, so this analyzer does not check
// it. GraphWriteAnalyzer and the read-path analyzers own other files.
func readNode(ctx context.Context, tx neo4j.ManagedTransaction, label string) {
	_, _ = tx.Run(ctx, fmt.Sprintf("MATCH (n:%s) RETURN n", label), nil)
}
