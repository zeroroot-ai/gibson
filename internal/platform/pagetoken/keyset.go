// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pagetoken

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// A keyset token holds the sort key of the last item that the client has. The
// next page is the items with a larger key, so an item that arrives between
// two pages never moves another item to a new page. The token is signed with
// a key that every daemon replica derives from the master KEK. The signature
// covers the scope of the request, so a token from another tenant or from
// another query is refused.

// signerKeyLen is the length of the signing key.
const signerKeyLen = 32

// keysetPrefix starts the cursor inside a token. An empty sort key is valid.
const keysetPrefix = "k:"

// Signer signs and checks keyset tokens.
type Signer struct {
	key []byte
}

// keyInfo is the HKDF info of the key of one list. Each list has a key of its
// own, so a token of one list never opens another list.
func keyInfo(list string) string {
	return "gibson/v1/" + list + "-page-token"
}

// deriveKey derives the key of one list from the master KEK.
func deriveKey(masterKEK []byte, list string) ([]byte, error) {
	if len(masterKEK) < signerKeyLen {
		return nil, fmt.Errorf("page token key: master KEK is too short (%d bytes, minimum %d)", len(masterKEK), signerKeyLen)
	}
	key := make([]byte, signerKeyLen)
	if _, err := io.ReadFull(hkdf.New(sha256.New, masterKEK, nil, []byte(keyInfo(list))), key); err != nil {
		return nil, fmt.Errorf("page token key: %w", err)
	}
	return key, nil
}

// NewSigner derives the signer of one list from the master KEK. The HKDF info
// is "gibson/v1/<list>-page-token".
func NewSigner(masterKEK []byte, list string) (*Signer, error) {
	key, err := deriveKey(masterKEK, list)
	if err != nil {
		return nil, err
	}
	return &Signer{key: key}, nil
}

// Keys derives the signer of each list of a service from one master KEK.
type Keys struct {
	masterKEK []byte
}

// NewKeys checks the master KEK and returns the key source of a service.
func NewKeys(masterKEK []byte) (*Keys, error) {
	if _, err := deriveKey(masterKEK, "check"); err != nil {
		return nil, err
	}
	return &Keys{masterKEK: append([]byte(nil), masterKEK...)}, nil
}

// Signer returns the signer of one list. NewKeys checked the KEK, so the
// derivation cannot fail.
func (k *Keys) Signer(list string) *Signer {
	s, err := NewSigner(k.masterKEK, list)
	if err != nil {
		panic("pagetoken: " + err.Error())
	}
	return s
}

// mac signs the scope and the payload. Each field has a length prefix, so two
// scopes cannot give one byte string.
func (s *Signer) mac(scope []string, payload []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	for _, f := range scope {
		_, _ = fmt.Fprintf(m, "%d:%s|", len(f), f)
	}
	_, _ = m.Write(payload)
	return m.Sum(nil)
}

// Token signs the sort key of the last item of a page for the scope. The scope
// holds the tenant, the RPC name and each filter of the request.
func (s *Signer) Token(scope []string, lastKey string) string {
	payload := []byte(keysetPrefix + lastKey)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(s.mac(scope, payload))
}

// After checks the token for the scope and returns the sort key that it
// holds. An empty token is the first page: it returns hasAfter false. A token
// that this signer did not sign for the scope gives ErrBadToken.
func (s *Signer) After(scope []string, token string) (key string, hasAfter bool, err error) {
	if token == "" {
		return "", false, nil
	}
	pStr, sStr, ok := strings.Cut(token, ".")
	if !ok {
		return "", false, ErrBadToken
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(pStr)
	if err != nil {
		return "", false, ErrBadToken
	}
	sig, err := enc.DecodeString(sStr)
	if err != nil || !hmac.Equal(sig, s.mac(scope, payload)) {
		return "", false, ErrBadToken
	}
	rest, found := strings.CutPrefix(string(payload), keysetPrefix)
	if !found {
		return "", false, ErrBadToken
	}
	return rest, true, nil
}

// Size returns the size of one page. Zero means DefaultSize, and a size above
// MaxSize is MaxSize.
func Size(pageSize int32) int {
	switch {
	case pageSize <= 0:
		return DefaultSize
	case int(pageSize) > MaxSize:
		return MaxSize
	default:
		return int(pageSize)
	}
}

// pageOptions holds the order of a list.
type pageOptions struct {
	desc bool
	cmp  func(a, b string) int
}

// PageOption changes how KeysetPage reads the order of a list.
type PageOption func(*pageOptions)

// Descending says that the items are sorted from the largest key to the
// smallest. The page holds the items whose key is smaller than the cursor.
func Descending() PageOption {
	return func(o *pageOptions) { o.desc = true }
}

// WithCompare sets how two positions compare. The default is the byte order of
// the strings. A list with a composite position, for example a timestamp and
// an id, gives its own comparison. The position is any string that the list
// can read back. It need not be an item key that a client can see.
func WithCompare(cmp func(a, b string) int) PageOption {
	return func(o *pageOptions) { o.cmp = cmp }
}

// KeysetPage returns one page of items. items must be sorted by position in
// ascending order, or in descending order with Descending, with one position
// for each item. The page holds the items that come after the cursor, when
// hasAfter is true. last is the position of the final item of the page, and
// more is true when an item follows it. A caller signs last into the next token
// only when more is true, so the last page never has a token and never ends
// with an empty page.
func KeysetPage[T any](
	items []T,
	position func(T) string,
	after string,
	hasAfter bool,
	limit int,
	opts ...PageOption,
) (page []T, last string, more bool) {
	o := pageOptions{cmp: strings.Compare}
	for _, opt := range opts {
		opt(&o)
	}
	start := 0
	if hasAfter {
		start = sort.Search(len(items), func(i int) bool {
			c := o.cmp(position(items[i]), after)
			if o.desc {
				return c < 0
			}
			return c > 0
		})
	}
	end := min(start+limit, len(items))
	page = items[start:end]
	if len(page) == 0 {
		return page, "", false
	}
	return page, position(page[len(page)-1]), end < len(items)
}

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
