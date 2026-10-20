// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	"github.com/zeroroot-ai/sdk/auth"
)

// The list RPCs of WorldService page with a keyset cursor (ADR-0028, rule 3).
// Each list has a unique sort key. The token holds the key of the last item
// that the client has, and the next page is the items with a larger key. An
// item that arrives between two pages never moves another item, and no page
// holds an item twice. The token is signed for the tenant, the RPC and the
// filters of the request.

// worldPagedRPCs are the RPCs that page. Each one has a signing key of its own,
// so a token of one RPC never opens another.
var worldPagedRPCs = []string{
	"GetTimeline", "ListFindings", "ListHosts", "ListLabels",
	"ListLlmCalls", "ListMissions", "ListOpenBets", "ListReviewQueue",
}

// worldSigners derives the signer of each paged RPC from the page token keys.
func worldSigners(keys *pagetoken.Keys) (map[string]*pagetoken.Signer, error) {
	out := make(map[string]*pagetoken.Signer, len(worldPagedRPCs))
	for _, rpc := range worldPagedRPCs {
		signer, err := keys.Signer("world-" + rpc)
		if err != nil {
			return nil, fmt.Errorf("world page signer %s: %w", rpc, err)
		}
		out[rpc] = signer
	}
	return out, nil
}

// keySep joins the parts of a composite sort key. No part holds a NUL byte,
// so the joined keys sort like the parts do.
const keySep = "\x00"

// pageOf checks the token of a request. A token that the daemon did not sign
// for this tenant, RPC and filter set gives InvalidArgument.
func (s *worldServer) pageOf(
	ctx context.Context,
	rpc string,
	size int32,
	token string,
	filters ...string,
) (pagetoken.Request, error) {
	t, ok := auth.TenantFromContext(ctx)
	if !ok {
		return pagetoken.Request{}, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	signer, ok := s.signers[rpc]
	if !ok {
		return pagetoken.Request{}, status.Errorf(codes.Internal, "no page token signer for %s", rpc)
	}
	pr, err := pagetoken.NewRequest(signer, append([]string{t.String(), rpc}, filters...), size, token)
	if err != nil {
		return pagetoken.Request{}, status.Error(codes.InvalidArgument, err.Error())
	}
	return pr, nil
}

// seqWindow returns the range [start, end) of the events of one page, and
// the token of the page after it. The cursor is the seq of the last event that
// the client has. Event seq numbers only grow, so an event that arrives
// between two pages has a seq after the cursor.
func (s *worldServer) seqWindow(p pagetoken.Request, total int) (start, end int, next string, err error) {
	if after, hasAfter := p.After(); hasAfter {
		last, parseErr := strconv.Atoi(after)
		if parseErr != nil || last < 0 {
			return 0, 0, "", status.Error(codes.InvalidArgument, pagetoken.ErrBadToken.Error())
		}
		if last >= total {
			return total, total, "", nil
		}
		start = last + 1
	}
	end = min(start+p.Limit(), total)
	next = p.Token(strconv.Itoa(end-1), end < total)
	return start, end, next, nil
}

// worldKey joins the parts of a composite sort key.
func worldKey(parts ...string) string { return strings.Join(parts, keySep) }
