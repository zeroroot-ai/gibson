// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pagetoken

import (
	"errors"
	"sort"
)

// ErrNoSigner reports a list that has no signer: the daemon built no page keys.
var ErrNoSigner = errors.New("pagetoken: no signer for the list")

// Request is the place of one list request in its list. NewRequest checks the
// token of the request. Page and Token build the page and the next token from
// it. Every paged RPC of the daemon uses it, so the token rules are in one
// place.
type Request struct {
	signer   *Signer
	scope    []string
	after    string
	hasAfter bool
	limit    int
}

// NewRequest checks the token of a request for the scope. The scope holds the
// tenant, the list and each filter that changes the list or its order, so a
// token of another tenant or another query gives ErrBadToken. size is the
// page_size of the request.
func NewRequest(signer *Signer, scope []string, size int32, token string) (Request, error) {
	if signer == nil {
		return Request{}, ErrNoSigner
	}
	after, hasAfter, err := signer.After(scope, token)
	if err != nil {
		return Request{}, err
	}
	return Request{signer: signer, scope: scope, after: after, hasAfter: hasAfter, limit: Size(size)}, nil
}

// After returns the position that the token holds, and false for the first
// page.
func (r Request) After() (position string, hasAfter bool) { return r.after, r.hasAfter }

// Limit returns the size of the page.
func (r Request) Limit() int { return r.limit }

// Token signs the position of the last item of a page. It returns an empty
// token when more is false, so the last page has no token.
func (r Request) Token(last string, more bool) string {
	if !more {
		return ""
	}
	return r.signer.Token(r.scope, last)
}

// Page sorts items by key, ascending, and returns the page after the cursor of
// the request and the token of the next page. The key of an item must be
// unique in the list and must not change.
func Page[T any](r Request, items []T, key func(T) string) (page []T, next string) {
	sorted := append([]T(nil), items...)
	sort.SliceStable(sorted, func(i, j int) bool { return key(sorted[i]) < key(sorted[j]) })
	page, last, more := KeysetPage(sorted, key, r.after, r.hasAfter, r.limit)
	return page, r.Token(last, more)
}
