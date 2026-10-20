// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
)

// The four list RPCs of DaemonOperatorService page with a signed keyset cursor
// (ADR-0028 rule 3, gibson#1261). The signature covers the RPC, so a token of
// one list is refused by another.

// The name of each list. It selects the signing key of the list, and a token
// binds to it.
const (
	pageScopePendingTenantProvisioning = "operator-pending-tenant-provisioning"
	pageScopePendingTenantOps          = "operator-pending-tenant-ops"
	pageScopeDesiredCatalogPlugins     = "operator-desired-catalog-plugins"
	pageScopeDesiredConnectors         = "operator-desired-connectors"
)

// errNoPageTokenKey reports a daemon that has no page token key.
var errNoPageTokenKey = errors.New("page token key is not configured")

// WithPageTokenKEK derives the page token key of each operator list from the
// master KEK. Every daemon replica holds the same KEK, so a token from one
// replica works on another. Without it, the operator lists answer Unavailable.
func (s *DaemonServer) WithPageTokenKEK(masterKEK []byte) (*DaemonServer, error) {
	keys, err := pagetoken.NewKeys(masterKEK)
	if err != nil {
		return nil, fmt.Errorf("operator page token key: %w", err)
	}
	s.pageKeys = keys
	return s, nil
}

// pageScope is the scope that a token of one list binds to. The operator lists
// read the platform queues, so the request holds no tenant. Their only filter
// is fixed (the rows still pending), so the scope is the platform and the list.
func pageScope(list string) []string {
	return []string{"platform", list}
}

// pageStart returns the sort key that a page token holds, as fields, or nil for
// the first page. A token that this daemon did not sign for this list is
// InvalidArgument.
func (s *DaemonServer) pageStart(list, token string, fields int) ([]string, error) {
	if s.pageKeys == nil {
		return nil, status.Error(codes.Unavailable, errNoPageTokenKey.Error())
	}
	key, has, err := s.pageKeys.Signer(list).After(pageScope(list), token)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if !has {
		return nil, nil
	}
	parts, ok := splitKey(key, fields)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, pagetoken.ErrBadToken.Error())
	}
	return parts, nil
}

// pageToken signs the sort key of the last item of a page.
func (s *DaemonServer) pageToken(list string, fields ...string) string {
	return s.pageKeys.Signer(list).Token(pageScope(list), joinKey(fields...))
}

// joinKey writes the fields of a sort key as one string. Each field has a
// length prefix, so the fields can hold any text.
func joinKey(fields ...string) string {
	var b strings.Builder
	for _, f := range fields {
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
	}
	return b.String()
}

// splitKey reads n fields from a sort key that joinKey wrote.
func splitKey(key string, n int) ([]string, bool) {
	out := make([]string, 0, n)
	for len(out) < n {
		colon := strings.IndexByte(key, ':')
		if colon < 0 {
			return nil, false
		}
		size, err := strconv.Atoi(key[:colon])
		if err != nil || size < 0 || colon+1+size > len(key) {
			return nil, false
		}
		out = append(out, key[colon+1:colon+1+size])
		key = key[colon+1+size:]
	}
	return out, key == ""
}

// timeKey writes a timestamp into a sort key. Postgres keeps microseconds, so
// the key keeps them and no more.
func timeKey(t time.Time) string {
	return strconv.FormatInt(t.UnixMicro(), 10)
}

// parseTimeKey reads a timestamp from a sort key. The signature already covers
// the key, so a value that does not parse is a token that is not valid.
func parseTimeKey(v string) (time.Time, error) {
	us, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Time{}, status.Error(codes.InvalidArgument, pagetoken.ErrBadToken.Error())
	}
	return time.UnixMicro(us).UTC(), nil
}
