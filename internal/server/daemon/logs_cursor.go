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
// two pages shifts every offset. The cursor holds the nanosecond of the last
// line that the client has, the number of lines it already has at that
// nanosecond, and the start of the time range. The next page asks Loki for the
// lines up to and including that nanosecond, drops the lines the client has,
// and keeps the next page_size. Each page costs one page of lines.
//
// The token is signed. The signature covers the tenant, the query filters and
// the cursor, with a key that the daemon derives from its master KEK. A token
// that another tenant or another query holds, or that anyone edited, is
// refused.

// logsCursorInfo is the HKDF info of the page token key.
const logsCursorInfo = "gibson-logs-page-token-v1"

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

// logsCursor is the position after the last line that the client has.
type logsCursor struct {
	lastNanos  int64 // nanosecond of the last line returned
	skip       int   // lines the client already has at lastNanos
	startNanos int64 // start of the time range, fixed on the first page
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

func (sc logsQueryScope) mac(key []byte, payload []byte) []byte {
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
	payload := make([]byte, 20)
	binary.BigEndian.PutUint64(payload[0:8], uint64(c.lastNanos))
	binary.BigEndian.PutUint32(payload[8:12], uint32(c.skip)) //nolint:gosec // skip is bounded by lokilogs.MaxLimit
	binary.BigEndian.PutUint64(payload[12:20], uint64(c.startNanos))
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(sc.mac(key, payload))
}

// decodeLogsCursor checks the signature of a token and returns its cursor.
func decodeLogsCursor(key []byte, sc logsQueryScope, token string) (logsCursor, error) {
	pStr, sStr, ok := strings.Cut(token, ".")
	if !ok {
		return logsCursor{}, errBadLogsCursor
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(pStr)
	if err != nil || len(payload) != 20 {
		return logsCursor{}, errBadLogsCursor
	}
	sig, err := enc.DecodeString(sStr)
	if err != nil || !hmac.Equal(sig, sc.mac(key, payload)) {
		return logsCursor{}, errBadLogsCursor
	}
	skip := binary.BigEndian.Uint32(payload[8:12])
	if skip > lokilogs.MaxLimit {
		return logsCursor{}, errBadLogsCursor
	}
	return logsCursor{
		lastNanos:  int64(binary.BigEndian.Uint64(payload[0:8])), //nolint:gosec // written by encode
		skip:       int(skip),
		startNanos: int64(binary.BigEndian.Uint64(payload[12:20])), //nolint:gosec // written by encode
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

// logsWindow is the Loki time range and limit of one page.
type logsWindow struct {
	start, end time.Time
	limit      int
}

// planLogsPage returns the Loki query of one page. cur is nil on the first
// page. reqStart and reqEnd are the range of the request.
func planLogsPage(cur *logsCursor, reqStart, reqEnd time.Time, pageSize int, now time.Time) (logsWindow, error) {
	if cur == nil {
		end := reqEnd
		if end.IsZero() {
			end = now
		}
		start := reqStart
		if start.IsZero() {
			start = end.Add(-lokilogs.DefaultWindow)
		}
		return logsWindow{start: start, end: reqEnd, limit: pageSize}, nil
	}
	limit := pageSize + cur.skip
	if limit > lokilogs.MaxLimit {
		return logsWindow{}, errTooManyTies
	}
	// Loki treats end as exclusive. One nanosecond more includes the lines at
	// the cursor nanosecond that the client does not have yet.
	return logsWindow{
		start: time.Unix(0, cur.startNanos).UTC(),
		end:   time.Unix(0, cur.lastNanos+1).UTC(),
		limit: limit,
	}, nil
}

// cutLogsPage drops the lines the client already has and keeps one page. It
// returns the page and the cursor after it, or a nil cursor when this page is
// the last one.
func cutLogsPage(entries []lokilogs.Entry, prev *logsCursor, startNanos int64, pageSize int) ([]lokilogs.Entry, *logsCursor) {
	if prev != nil {
		entries = entries[min(prev.skip, len(entries)):]
	}
	page := entries[:min(pageSize, len(entries))]
	if len(page) < pageSize {
		return page, nil
	}
	last := page[len(page)-1].UnixNanos
	skip := 0
	for _, e := range page {
		if e.UnixNanos == last {
			skip++
		}
	}
	if prev != nil && prev.lastNanos == last {
		skip += prev.skip
	}
	return page, &logsCursor{lastNanos: last, skip: skip, startNanos: startNanos}
}
