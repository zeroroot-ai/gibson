// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pagetoken

import (
	"context"
	"errors"
	"fmt"
)

// DefaultMaxPages is the page bound of Collect when the caller gives none.
const DefaultMaxPages = 100

// ErrTooManyPages reports a list with more pages than the bound of Collect.
var ErrTooManyPages = errors.New("pagetoken: the list has more pages than the bound")

// ErrTokenLoop reports a server that returns the token that it just got.
var ErrTokenLoop = errors.New("pagetoken: the server returned the same page token twice")

// Collect reads a whole list from its pages. fetch calls the RPC with a
// token, an empty token for the first page, and returns the items and the
// next token. Collect stops when the next token is empty. It reads at most
// maxPages pages (DefaultMaxPages when maxPages is 0 or less), and it returns
// ErrTooManyPages when the list has more. An operator uses it for a list that
// a person never reads by hand.
func Collect[T any](
	ctx context.Context,
	maxPages int,
	fetch func(ctx context.Context, token string) (items []T, next string, err error),
) ([]T, error) {
	if maxPages <= 0 {
		maxPages = DefaultMaxPages
	}
	var all []T
	token := ""
	for range maxPages {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("pagetoken: %w", err)
		}
		items, next, err := fetch(ctx, token)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if next == "" {
			return all, nil
		}
		if next == token {
			return nil, ErrTokenLoop
		}
		token = next
	}
	return nil, fmt.Errorf("%w (%d pages)", ErrTooManyPages, maxPages)
}
