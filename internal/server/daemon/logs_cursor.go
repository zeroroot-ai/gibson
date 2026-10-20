// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/zeroroot-ai/gibson/internal/platform/observability/lokilogs"
	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
)

// The page token of the log queries is a keyset cursor (ADR-0028 rule 3).
//
// An offset cannot page Loki. Loki returns at most lokilogs.MaxLimit lines
// for a query, so offset+limit stops there, and a line that arrives between
// two pages shifts every offset. The cursor holds the end of the time range
// of the next page (exclusive) and the start of the range. A page always ends
// on a whole nanosecond: Loki picks which of the lines that share a nanosecond
// fill a limit, so a page that ended inside such a group would lose lines and
// repeat others. The next page asks for the lines older than the end of the
// last group, so no line is skipped and none repeats.
//
// The token is signed. The signature covers the tenant, the query filters and
// the cursor, with a key that the daemon derives from its master KEK. A token
// that another tenant or another query holds, or that anyone edited, is
// refused.

// logsCursorInfo is the HKDF info of the page token key.
const logsCursorInfo = "gibson/v1/logs-page-token"

// logsCursorKeyLen is the length of the page token key.
const logsCursorKeyLen = 32

// errBadLogsCursor reports a page token that this daemon did not sign for this
// query.
var errBadLogsCursor = errors.New("page_token is not valid for this query")

// errTooManyTies reports more lines at one nanosecond than one query returns.
var errTooManyTies = errors.New("too many log lines share one timestamp to page past them")

// deriveLogsCursorKey derives the page token key from the master KEK.
func deriveLogsCursorKey(masterKEK []byte) ([]byte, error) {
	if len(masterKEK) < logsCursorKeyLen {
		return nil, fmt.Errorf("logs page token key: master KEK is too short (%d bytes, minimum %d)", len(masterKEK), logsCursorKeyLen)
	}
	key := make([]byte, logsCursorKeyLen)
	if _, err := io.ReadFull(hkdf.New(sha256.New, masterKEK, nil, []byte(logsCursorInfo)), key); err != nil {
		return nil, fmt.Errorf("logs page token key: %w", err)
	}
	return key, nil
}

// logsCursor is the position of the next page.
type logsCursor struct {
	endNanos   int64 // end of the next page's range, exclusive
	startNanos int64 // start of the range, fixed on the first page
}

// logsQueryScope names the query that a token belongs to. Two requests with
// the same scope page the same list.
type logsQueryScope struct {
	tenant    string
	kind      string // "mission" or "daemon"
	missionID string
	level     string
	start     int64 // the start of the request, before any default
	end       int64 // the end of the request, before any default
}

func (sc logsQueryScope) mac(key, payload []byte) []byte {
	m := hmac.New(sha256.New, key)
	// Length-prefix each field so two scopes cannot produce one byte string.
	for _, f := range []string{sc.tenant, sc.kind, sc.missionID, sc.level,
		strconv.FormatInt(sc.start, 10), strconv.FormatInt(sc.end, 10)} {
		_, _ = fmt.Fprintf(m, "%d:%s|", len(f), f)
	}
	_, _ = m.Write(payload)
	return m.Sum(nil)
}

// encode signs the cursor for the scope.
func (c logsCursor) encode(key []byte, sc logsQueryScope) string {
	payload := make([]byte, logsCursorPayloadLen)
	binary.BigEndian.PutUint64(payload[0:8], uint64(c.endNanos))    //nolint:gosec // a Unix nanosecond is positive
	binary.BigEndian.PutUint64(payload[8:16], uint64(c.startNanos)) //nolint:gosec // a Unix nanosecond is positive
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(sc.mac(key, payload))
}

// logsCursorPayloadLen is the length of the signed part of a token.
const logsCursorPayloadLen = 16

// decodeLogsCursor checks the signature of a token and returns its cursor.
func decodeLogsCursor(key []byte, sc logsQueryScope, token string) (logsCursor, error) {
	pStr, sStr, ok := strings.Cut(token, ".")
	if !ok {
		return logsCursor{}, errBadLogsCursor
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(pStr)
	if err != nil || len(payload) != logsCursorPayloadLen {
		return logsCursor{}, errBadLogsCursor
	}
	sig, err := enc.DecodeString(sStr)
	if err != nil || !hmac.Equal(sig, sc.mac(key, payload)) {
		return logsCursor{}, errBadLogsCursor
	}
	return logsCursor{
		endNanos:   int64(binary.BigEndian.Uint64(payload[0:8])),  //nolint:gosec // written by encode
		startNanos: int64(binary.BigEndian.Uint64(payload[8:16])), //nolint:gosec // written by encode
	}, nil
}

// logsPageSize returns the size of one page: 0 means the default, and a size
// above lokilogs.MaxLimit is MaxLimit.
func logsPageSize(requested int32) int {
	switch {
	case requested <= 0:
		return pagetoken.DefaultSize
	case int(requested) > lokilogs.MaxLimit:
		return lokilogs.MaxLimit
	default:
		return int(requested)
	}
}

// logsWindow is the Loki time range of one page.
type logsWindow struct {
	start, end time.Time // end is exclusive; zero means now
}

// planLogsWindow returns the time range of a page. cur is nil on the first
// page. reqStart and reqEnd are the range of the request.
func planLogsWindow(cur *logsCursor, reqStart, reqEnd, now time.Time) logsWindow {
	if cur != nil {
		return logsWindow{start: time.Unix(0, cur.startNanos).UTC(), end: time.Unix(0, cur.endNanos).UTC()}
	}
	start := reqStart
	if start.IsZero() {
		end := reqEnd
		if end.IsZero() {
			end = now
		}
		start = end.Add(-lokilogs.DefaultWindow)
	}
	return logsWindow{start: start, end: reqEnd}
}

// logsFetch runs one Loki query for a window and a limit.
type logsFetch func(w logsWindow, limit int) ([]lokilogs.Entry, error)

// fetchLogsPage returns one page of whole nanosecond groups, newest first,
// and the end of the next page's range. more is false when no older line
// is left.
//
// It asks Loki for pageSize+1 lines (at most lokilogs.MaxLimit). When Loki returns fewer, the result is
// complete. Otherwise the last group may be cut, so it is dropped, and the next
// page starts with it. When the result holds one group only, the query asks for
// more lines, up to lokilogs.MaxLimit.
func fetchLogsPage(fetch logsFetch, w logsWindow, pageSize int) (page []lokilogs.Entry, nextEnd int64, more bool, err error) {
	for limit := min(pageSize+1, lokilogs.MaxLimit); ; limit = min(limit*2, lokilogs.MaxLimit) {
		entries, ferr := fetch(w, limit)
		if ferr != nil {
			return nil, 0, false, ferr
		}
		truncated := len(entries) >= limit
		groups := groupLogsByNanos(entries)
		if truncated {
			groups = groups[:len(groups)-1] // the last group may be cut
			if len(groups) == 0 {
				if limit >= lokilogs.MaxLimit {
					return nil, 0, false, errTooManyTies
				}
				continue
			}
		}
		taken := 0
		for taken < len(groups) && (taken == 0 || len(page)+len(groups[taken]) <= pageSize) {
			page = append(page, groups[taken]...)
			taken++
		}
		more = truncated || taken < len(groups)
		if more {
			nextEnd = page[len(page)-1].UnixNanos
		}
		return page, nextEnd, more, nil
	}
}

// groupLogsByNanos splits newest-first entries into runs of one nanosecond.
func groupLogsByNanos(entries []lokilogs.Entry) [][]lokilogs.Entry {
	var groups [][]lokilogs.Entry
	for _, e := range entries {
		if n := len(groups); n > 0 && groups[n-1][0].UnixNanos == e.UnixNanos {
			groups[n-1] = append(groups[n-1], e)
			continue
		}
		groups = append(groups, []lokilogs.Entry{e})
	}
	return groups
}
