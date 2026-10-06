// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package pagetoken turns the page_size and page_token of a list request into
// an offset window, and builds the next_page_token of the response
// (ADR-0028, rule 3). The token is opaque to the client. Inside, it holds the
// offset of the next page.
package pagetoken

import (
	"encoding/base64"
	"errors"
	"math"
	"strconv"
	"strings"
)

// DefaultSize is the page size for a request whose page_size is 0.
const DefaultSize = 100

// MaxSize is the largest page. The sdk allows page_size up to 1000.
const MaxSize = 1000

// ErrBadToken reports a page_token that this package did not write.
var ErrBadToken = errors.New("page_token is not valid")

const prefix = "o:"

// Window returns the offset and the limit of one page. pageSize 0 means
// DefaultSize, and a size above MaxSize is MaxSize. An empty token is the
// first page.
func Window(pageSize int32, token string) (offset, limit int, err error) {
	limit = int(pageSize)
	switch {
	case limit <= 0:
		limit = DefaultSize
	case limit > MaxSize:
		limit = MaxSize
	}
	if token == "" {
		return 0, limit, nil
	}
	raw, decErr := base64.RawURLEncoding.DecodeString(token)
	if decErr != nil || !strings.HasPrefix(string(raw), prefix) {
		return 0, 0, ErrBadToken
	}
	offset, convErr := strconv.Atoi(strings.TrimPrefix(string(raw), prefix))
	if convErr != nil || offset <= 0 {
		return 0, 0, ErrBadToken
	}
	return offset, limit, nil
}

// Next returns the token of the page after the window [offset, offset+limit).
// returned is the number of items on this page, and total is the number of
// items in the whole list, or -1 when the caller does not know it. With no
// total, a full page has a next token, so the last page can be empty. An
// empty token means that this page is the last one.
func Next(offset, limit, returned, total int) string {
	end := offset + returned
	if returned < limit || (total >= 0 && end >= total) {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(prefix + strconv.Itoa(end)))
}

// Int32 returns n for a total field of a list response. A value outside the
// int32 range is clamped, never wrapped.
func Int32(n int) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	if n < 0 {
		return 0
	}
	return int32(n)
}

// Uint32 returns n for a uint32 limit or offset. A value outside the range is
// clamped, never wrapped.
func Uint32(n int) uint32 {
	if n < 0 {
		return 0
	}
	if n > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n)
}

// Int returns n for a total that a store counts as uint64. A value above
// MaxInt32 is clamped: no list holds that many items.
func Int(n uint64) int {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return int(n)
}
