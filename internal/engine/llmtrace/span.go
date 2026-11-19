// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package llmtrace turns one span of the agentgateway trace into the Timeline
// events of a model call (gibson#1390, ADR-0172 and ADR-0173).
//
// The gateway is the one source of a model call record. A span of a call holds:
//
//   - the request body and the response body, in the attributes
//     gibson.request_body and gibson.response_body (a CEL field of the trace
//     policy). The body of a stream is the raw text of the stream;
//   - the model, the provider, the token counts and the cost, in the attributes
//     gen_ai.* and agw.ai.usage.cost.*;
//   - the trusted values of ext-authz, in the attributes gibson.tenant,
//     gibson.subject, gibson.mission and gibson.task. They are CEL fields of the
//     trace policy that read the request headers after ext-authz set them.
//
// The package is pure. It does no I/O. The receiver that gets the spans from the
// collector, and the routing by tenant, are not part of it.
package llmtrace

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"encoding/json"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// The attribute names of a gateway span.
const (
	AttrRequestBody  = "gibson.request_body"
	AttrResponseBody = "gibson.response_body"
	AttrTenant       = "gibson.tenant"
	AttrSubject      = "gibson.subject"
	AttrMission      = "gibson.mission"
	AttrTask         = "gibson.task"

	attrProvider     = "gen_ai.provider.name"
	attrRequestModel = "gen_ai.request.model"
	attrRespModel    = "gen_ai.response.model"
	attrInputUsage   = "gen_ai.usage.input_tokens"
	attrOutputUsage  = "gen_ai.usage.output_tokens"
	attrCacheRead    = "gen_ai.usage.cache_read.input_tokens"
	attrCacheWrite   = "gen_ai.usage.cache_creation.input_tokens"
	attrCostTotal    = "agw.ai.usage.cost.total"
	attrURLPath      = "url.path"
	attrTraceID      = "trace.id"
	attrSpanID       = "span.id"
)

// ErrNotAModelCall means that the span is not a model call: it has no request
// body, or the path is not a model call route.
var ErrNotAModelCall = errors.New("llmtrace: the span is not a model call")

// Span is the attributes of one span. A value is a string, an integer, a float
// or a bool, as OTLP carries it.
type Span struct {
	Attributes map[string]any
	// StartUnixNano and EndUnixNano are the times of the span. A model call
	// does not use them. A delegation to an outside agent does.
	StartUnixNano, EndUnixNano int64
}

// Cost is the cost of a call in US dollars. Known is false when the gateway
// has no price for the model. Total is then empty. An unknown cost is never
// zero.
type Cost struct {
	Known bool
	Total string
}

// Observation is one model call, read from a span.
type Observation struct {
	// CallID is stable for the span. A second read of the same span gives the
	// same ID, so the fold of the event is idempotent.
	CallID   string
	Tenant   string
	Subject  string
	Mission  string
	Task     string
	Provider string
	Model    string
	Format   Format
	Streamed bool

	InputTokens      int64
	OutputTokens     int64
	CacheReadTokens  int64
	CacheWriteTokens int64
	Cost             Cost

	// HTTPStatus is the status that the gateway answered. It is 0 when the span
	// has none. A status of 400 or more is a failed call: Items holds the
	// request items only, and Failure holds the error text of the reply.
	HTTPStatus int
	Failure    string

	// Items is the transcript as Open Responses items: the input items, then
	// the output items.
	Items []json.RawMessage
	// RequestItems is the number of leading items that are the request. A failed
	// call has request items only.
	RequestItems int
}

// maxFailureBytes bounds the error text of a failed call. A provider error is
// short, and the event is not the place for a page of HTML.
const maxFailureBytes = 4096

// Failed reports whether the gateway answered the call with an error status.
func (o Observation) Failed() bool { return o.HTTPStatus >= 400 }

// FromSpan reads a model call from a span. A call with an error status is a
// record too. The gateway answers it with a plain text body, for example
// "route not found", so the body is not decoded. The call holds the request
// items, the status and the text of the reply, and it holds no tokens.
func FromSpan(sp Span) (Observation, error) {
	a := sp.Attributes
	path := attrString(a, attrURLPath)
	var format Format
	switch path {
	case "/v1/responses":
		format = FormatOpenResponses
	case "/v1/messages":
		format = FormatAnthropicMessages
	default:
		return Observation{}, fmt.Errorf("%w: path %q", ErrNotAModelCall, path)
	}
	reqBody := attrString(a, AttrRequestBody)
	if reqBody == "" {
		return Observation{}, fmt.Errorf("%w: no %s", ErrNotAModelCall, AttrRequestBody)
	}
	respBody := attrString(a, AttrResponseBody)

	o := Observation{
		CallID:           "gw-" + attrString(a, attrTraceID) + "-" + attrString(a, attrSpanID),
		Tenant:           attrString(a, AttrTenant),
		Subject:          attrString(a, AttrSubject),
		Mission:          attrString(a, AttrMission),
		Task:             attrString(a, AttrTask),
		Provider:         attrString(a, attrProvider),
		Model:            firstNonEmpty(attrString(a, attrRespModel), attrString(a, attrRequestModel)),
		Format:           format,
		InputTokens:      attrInt(a, attrInputUsage),
		OutputTokens:     attrInt(a, attrOutputUsage),
		CacheReadTokens:  attrInt(a, attrCacheRead),
		CacheWriteTokens: attrInt(a, attrCacheWrite),
		HTTPStatus:       int(attrInt(a, attrHTTPCode)),
	}
	if total := attrString(a, attrCostTotal); total != "" {
		if _, err := strconv.ParseFloat(total, 64); err == nil {
			o.Cost = Cost{Known: true, Total: total}
		}
	}

	in, err := requestItems(format, reqBody)
	if err != nil {
		return Observation{}, err
	}
	o.Items = in
	o.RequestItems = len(in)

	if o.Failed() {
		o.Failure = truncateText(respBody, maxFailureBytes)
		o.InputTokens, o.OutputTokens, o.CacheReadTokens, o.CacheWriteTokens = 0, 0, 0, 0
		o.Cost = Cost{}
		return o, nil
	}
	if respBody != "" {
		reply := respBody
		if IsStreamBody(respBody) {
			o.Streamed = true
			folded, ferr := FoldStream(format, respBody)
			if ferr != nil {
				return Observation{}, ferr
			}
			reply = string(folded)
		}
		out, rerr := responseItems(format, reply)
		if rerr != nil {
			return Observation{}, rerr
		}
		o.Items = append(o.Items, out...)
	}
	return o, nil
}

// Events returns the Timeline events of the call. The call event is always
// there. The token event is there only when the call belongs to a mission,
// because the budget of a mission is the only reader of it. recordedAt is the
// time that the daemon read the span.
func (o Observation) Events(recordedAt time.Time) []brain.Event {
	cost := ""
	if o.Cost.Known {
		cost = o.Cost.Total
	}
	events := []brain.Event{brain.LlmCallObserved{
		CallID:             o.CallID,
		MissionID:          o.Mission,
		Model:              o.Model,
		PromptTokens:       int(o.InputTokens),
		CompletionTokens:   int(o.OutputTokens),
		RecordedAtUnixNano: recordedAt.UnixNano(),
		Items:              o.Items,
		Provider:           o.Provider,
		CacheReadTokens:    int(o.CacheReadTokens),
		CacheWriteTokens:   int(o.CacheWriteTokens),
		Cost:               cost,
		ErrorText:          o.Failure,
		RequestItems:       o.RequestItems,
		HTTPStatus:         o.HTTPStatus,
	}}
	// A failed call used no tokens, so it adds no usage to the mission.
	if o.Mission != "" && !o.Failed() {
		events = append(events, brain.TokenUsed{MissionID: o.Mission, Tokens: o.InputTokens + o.OutputTokens, CallID: o.CallID})
	}
	return events
}

// truncateText cuts s to at most n bytes, on a rune boundary.
func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

func attrString(a map[string]any, k string) string {
	s, _ := a[k].(string)
	return s
}

func attrInt(a map[string]any, k string) int64 {
	switch v := a[k].(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return n
	}
	return 0
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
