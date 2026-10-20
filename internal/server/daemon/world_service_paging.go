// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"sort"
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

// worldPageKeyInfo is the HKDF info of the page token key of WorldService.
const worldPageKeyInfo = "gibson-world-page-token-v1"

// keySep joins the parts of a composite sort key. No part holds a NUL byte,
// so the joined keys sort like the parts do.
const keySep = "\x00"

// WorldServerOption changes how NewWorldServer builds the server.
type WorldServerOption func(*worldServer)

// WithWorldPageSigner sets the signer of the page tokens. The daemon passes a
// signer that derives from the master KEK, so a token from one replica works
// on another. Without it, the server signs with a key that only it knows.
func WithWorldPageSigner(signer *pagetoken.Signer) WorldServerOption {
	return func(s *worldServer) { s.signer = signer }
}

// worldPage is the position of one request in its list.
type worldPage struct {
	scope    []string
	after    string
	hasAfter bool
	limit    int
}

// pageOf checks the token of a request. A token that the daemon did not sign
// for this tenant, RPC and filter set gives InvalidArgument.
func (s *worldServer) pageOf(
	ctx context.Context,
	rpc string,
	size int32,
	token string,
	filters ...string,
) (worldPage, error) {
	t, ok := auth.TenantFromContext(ctx)
	if !ok {
		return worldPage{}, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	scope := append([]string{t.String(), rpc}, filters...)
	after, hasAfter, err := s.signer.After(scope, token)
	if err != nil {
		return worldPage{}, status.Error(codes.InvalidArgument, err.Error())
	}
	return worldPage{scope: scope, after: after, hasAfter: hasAfter, limit: pagetoken.Size(size)}, nil
}

// nextToken signs the key of the last item of a page. It returns "" when the
// page is the last one.
func (s *worldServer) nextToken(p worldPage, last string, more bool) string {
	if !more {
		return ""
	}
	return s.signer.Token(p.scope, last)
}

// worldKeyedPage sorts items by key and returns the page after the cursor of p
// and the token of the page after that.
func worldKeyedPage[T any](s *worldServer, p worldPage, items []T, key func(T) string) (page []T, next string) {
	sorted := append([]T(nil), items...)
	sort.SliceStable(sorted, func(i, j int) bool { return key(sorted[i]) < key(sorted[j]) })
	page, last, more := pagetoken.KeysetPage(sorted, key, p.after, p.hasAfter, p.limit)
	return page, s.nextToken(p, last, more)
}

// seqWindow returns the range [start, end) of the events of one page, and
// the token of the page after it. The cursor is the seq of the last event that
// the client has. Event seq numbers only grow, so an event that arrives
// between two pages has a seq after the cursor.
func (s *worldServer) seqWindow(p worldPage, total int) (start, end int, next string, err error) {
	if p.hasAfter {
		last, parseErr := strconv.ParseUint(p.after, 10, 63)
		if parseErr != nil {
			return 0, 0, "", status.Error(codes.InvalidArgument, pagetoken.ErrBadToken.Error())
		}
		if last >= uint64(total) {
			return total, total, "", nil
		}
		start = int(last) + 1
	}
	end = min(start+p.limit, total)
	if end < total {
		next = s.signer.Token(p.scope, strconv.Itoa(end-1))
	}
	return start, end, next, nil
}

// worldKey joins the parts of a composite sort key.
func worldKey(parts ...string) string { return strings.Join(parts, keySep) }
