// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pagetoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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

// Keys derives the signer of each list of a service from one master KEK. It
// holds the HKDF pseudo-random key (the extract step), never the KEK itself.
type Keys struct {
	prk []byte
}

// NewKeys checks the master KEK and runs the HKDF extract step on it.
func NewKeys(masterKEK []byte) (*Keys, error) {
	if len(masterKEK) < signerKeyLen {
		return nil, fmt.Errorf("page token key: master KEK is too short (%d bytes, minimum %d)", len(masterKEK), signerKeyLen)
	}
	return &Keys{prk: hkdf.Extract(sha256.New, masterKEK, nil)}, nil
}

// Signer returns the signer of one list. The HKDF info is
// "gibson/v1/<list>-page-token".
func (k *Keys) Signer(list string) (*Signer, error) {
	key := make([]byte, signerKeyLen)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, k.prk, []byte(keyInfo(list))), key); err != nil {
		return nil, fmt.Errorf("page token key of %q: %w", list, err)
	}
	return &Signer{key: key}, nil
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

// KeysetPage returns one page of items. items must be sorted by key in
// ascending order with one key for each item. The page holds the items whose
// key is larger than after, when hasAfter is true. last is the key of the
// final item of the page, and more is true when an item follows it. A caller
// signs last into the next token only when more is true, so the last page
// never has a token and never ends with an empty page.
func KeysetPage[T any](
	items []T,
	key func(T) string,
	after string,
	hasAfter bool,
	limit int,
) (page []T, last string, more bool) {
	start := 0
	if hasAfter {
		start = sort.Search(len(items), func(i int) bool { return key(items[i]) > after })
	}
	end := min(start+limit, len(items))
	page = items[start:end]
	if len(page) == 0 {
		return page, "", false
	}
	return page, key(page[len(page)-1]), end < len(items)
}
