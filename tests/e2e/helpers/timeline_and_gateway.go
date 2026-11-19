// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package helpers: timeline_and_gateway.go gives the exit tests of the AAIF epics
// three readers and one client.
//
//   - ReadTimeline reads the Timeline of a mission through WorldService.
//   - ParseLlmCallObserved reads the fields of an llm_call.observed event.
//   - ReadFinding reads a finding with its evidence through TenantService.
//   - GatewayAccess calls the model gateway as the agent of a work item does.
package helpers

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

// TimelineEvent is one event of the Timeline. Summary is the text that the
// daemon prints for the event, with each field name.
type TimelineEvent struct {
	Seq     uint64
	Kind    string
	Summary string
}

// ReadTimeline reads each event of the Timeline of one mission, page by page.
func ReadTimeline(ctx context.Context, world worldpb.WorldServiceClient, missionID string) ([]TimelineEvent, error) {
	var out []TimelineEvent
	token := ""
	for {
		resp, err := world.GetTimeline(ctx, &worldpb.GetTimelineRequest{
			MissionId: missionID, PageSize: 500, PageToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("GetTimeline(mission %s): %w", missionID, err)
		}
		for _, ev := range resp.GetEvents() {
			out = append(out, TimelineEvent{Seq: ev.GetSeq(), Kind: ev.GetKind(), Summary: ev.GetSummary()})
		}
		token = resp.GetNextPageToken()
		if token == "" {
			return out, nil
		}
	}
}

// OfKind returns the events of one kind, in Timeline order.
func OfKind(events []TimelineEvent, kind string) []TimelineEvent {
	var out []TimelineEvent
	for _, ev := range events {
		if ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

// ObservedLlmCall holds the fields of an llm_call.observed event that the exit
// test of the AAIF alignment reads.
type ObservedLlmCall struct {
	CallID           string
	Model            string
	Provider         string
	PromptTokens     int
	CompletionTokens int
	// Cost is the cost in US dollars as a decimal string. It is empty when the
	// gateway has no price for the model.
	Cost string
	// HTTPStatus is the status that the gateway answered. It is 0 when the event
	// has none. A status of 400 or more is a failed call, which has no tokens.
	HTTPStatus int
	// Items is the text of each Open Responses item of the call: the input
	// items, then the output items.
	Items []string
}

var (
	reCallID   = regexp.MustCompile(`CallID:([^\s}]+)`)
	reModel    = regexp.MustCompile(`Model:([^\s}]*)`)
	reProvider = regexp.MustCompile(`Provider:([^\s}]*)`)
	rePrompt   = regexp.MustCompile(`PromptTokens:(\d+)`)
	reComplete = regexp.MustCompile(`CompletionTokens:(\d+)`)
	reStatus   = regexp.MustCompile(`HTTPStatus:(\d+)`)
	reCost     = regexp.MustCompile(`Cost:([^\s}]*)`)
)

// Failed reports whether the gateway answered the call with an error status.
func (c ObservedLlmCall) Failed() bool { return c.HTTPStatus >= 400 }

// ParseLlmCallObserved reads an llm_call.observed event from the summary that
// GetTimeline returns. The summary is the %+v text of the event, in which each
// raw JSON item prints as its own text. The parser reads each item back
// back into its own text. It returns an error when the summary has no call id.
func ParseLlmCallObserved(summary string) (ObservedLlmCall, error) {
	var call ObservedLlmCall
	m := reCallID.FindStringSubmatch(summary)
	if m == nil {
		return call, fmt.Errorf("the summary has no CallID: %s", summary)
	}
	call.CallID = m[1]
	if m = reModel.FindStringSubmatch(summary); m != nil {
		call.Model = m[1]
	}
	if m = reProvider.FindStringSubmatch(summary); m != nil {
		call.Provider = m[1]
	}
	if m = rePrompt.FindStringSubmatch(summary); m != nil {
		call.PromptTokens, _ = strconv.Atoi(m[1])
	}
	if m = reComplete.FindStringSubmatch(summary); m != nil {
		call.CompletionTokens, _ = strconv.Atoi(m[1])
	}
	if m = reStatus.FindStringSubmatch(summary); m != nil {
		call.HTTPStatus, _ = strconv.Atoi(m[1])
	}
	if m = reCost.FindStringSubmatch(summary); m != nil {
		call.Cost = m[1]
	}
	items, err := parseRawItems(summary, "Items:[")
	if err != nil {
		return call, err
	}
	call.Items = items
	return call, nil
}

// parseRawItems reads the list that follows marker. The daemon prints each raw
// JSON item of the event as its own text, with one space between items, so the
// parser reads one JSON value after another until the closing bracket.
func parseRawItems(s, marker string) ([]string, error) {
	idx := strings.Index(s, marker)
	if idx < 0 {
		return nil, nil
	}
	rest := s[idx+len(marker):]
	var items []string
	for {
		rest = strings.TrimLeft(rest, " ")
		if rest == "" {
			return nil, errors.New("the item list of the summary does not end")
		}
		if rest[0] == ']' {
			return items, nil
		}
		dec := json.NewDecoder(strings.NewReader(rest))
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("read an item of the summary: %w", err)
		}
		items = append(items, string(raw))
		rest = rest[dec.InputOffset():]
	}
}

// ReadFinding reads one finding with all of its evidence, as the dashboard does.
func ReadFinding(
	ctx context.Context, t *testing.T, tenant tenantv1.TenantServiceClient, id string,
) *tenantv1.FindingDetail {
	t.Helper()
	resp, err := tenant.GetFinding(ctx, &tenantv1.GetFindingRequest{FindingId: id})
	require.NoError(t, err, "GetFinding(%s)", id)
	require.NotNil(t, resp.GetFinding(), "GetFinding(%s) returned no finding", id)
	return resp.GetFinding()
}

// GatewayAccess calls the model gateway with what a work item of an agent holds:
// the route that ResolveModel returned and the task grant of the item.
type GatewayAccess struct {
	// URL is the public base URL of the model gateway (the Edge route).
	URL string
	// RouteHeaders are the headers that the route matches on.
	RouteHeaders map[string]string
	// Grant is the task grant of the work item.
	Grant string
	// Tenant, Provider and Model name the target of the calls.
	Tenant, Provider, Model string
	// Mission and Task scope the grant.
	Mission, Task string

	http *http.Client
}

// RespondWhenRouted sends an Open Responses call and sends it again while the
// gateway has no route for the provider or the call is retryable. The tenant
// operator renders the route of a new provider after the save, so the first
// calls can get a 404. A refusal or any other failure returns at once. The
// call returns the last error when the timeout passes.
func RespondWhenRouted(
	ctx context.Context, c *modelclient.Client, caller modelclient.Caller, target modelclient.Target,
	req modelclient.Request, timeout time.Duration,
) (*modelclient.Response, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		resp, err := c.Respond(ctx, caller, target, req)
		if err == nil {
			return resp, nil
		}
		var api *modelclient.APIError
		if !errors.As(err, &api) || !api.Retryable() {
			return nil, fmt.Errorf("the model call failed and a retry does not help: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for the route of the provider: %w", ctx.Err())
		case <-deadline.C:
			return nil, fmt.Errorf("no route after %s: %w", timeout, err)
		case <-time.After(time.Second):
		}
	}
}

// ResolveGateway asks the daemon for the model of the primary slot of a work
// item and builds a GatewayAccess from the reply.
func ResolveGateway(
	ctx context.Context, comp componentpb.ComponentServiceClient, tenant string, work ComponentWork,
) (*GatewayAccess, error) {
	res, err := comp.ResolveModel(ctx, &componentpb.ResolveModelRequest{WorkId: work.WorkID, Slot: "primary"})
	if err != nil {
		return nil, fmt.Errorf("resolve the primary slot of work %s: %w", work.WorkID, err)
	}
	client, err := HTTPClientWithCA(res.GetGatewayCaPem())
	if err != nil {
		return nil, err
	}
	return &GatewayAccess{
		URL: res.GetGatewayUrl(), RouteHeaders: res.GetRouteHeaders(), Grant: work.TaskGrant,
		Tenant: tenant, Provider: res.GetProvider(), Model: res.GetModel(),
		Mission: work.MissionID, Task: work.WorkID, http: client,
	}, nil
}

type grantToken string

func (g grantToken) Grant(context.Context, modelclient.Caller) (string, error) { return string(g), nil }

// Client returns a model client that sends the task grant of the work item.
func (g *GatewayAccess) Client() (*modelclient.Client, error) {
	c, err := modelclient.New(modelclient.Config{BaseURL: g.URL, Grants: grantToken(g.Grant), HTTPClient: g.http})
	if err != nil {
		return nil, fmt.Errorf("build the model client: %w", err)
	}
	return c, nil
}

// Caller returns the caller of the work item for the model client.
func (g *GatewayAccess) Caller() modelclient.Caller {
	return modelclient.Caller{Tenant: g.Tenant, Mission: g.Mission, Task: g.Task, Purpose: "e2e-exit-test"}
}

// Target returns the target of the primary slot.
func (g *GatewayAccess) Target() modelclient.Target {
	return modelclient.Target{Tenant: g.Tenant, Provider: g.Provider, Model: g.Model}
}

// RawCall sends one request to the gateway with the headers of the route and the
// grant of the work item. A key of overrides replaces the header of that name. An
// empty value removes the header. It returns the status and the start of the body.
func (g *GatewayAccess) RawCall(
	ctx context.Context, method, path string, body []byte, overrides map[string]string,
) (int, string, error) {
	headers := map[string]string{"content-type": "application/json", "x-capability-grant": g.Grant}
	for k, v := range g.RouteHeaders {
		headers[strings.ToLower(k)] = v
	}
	for k, v := range overrides {
		headers[strings.ToLower(k)] = v
	}
	var rdr io.Reader
	if body != nil {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(g.URL, "/")+path, rdr)
	if err != nil {
		return 0, "", fmt.Errorf("build the request: %w", err)
	}
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("send to the gateway: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return resp.StatusCode, string(b), nil
}

// StreamResponse sends one streamed Open Responses call with the headers of the
// route and the grant of the work item. It reads the server-sent events to the
// end. It returns the text of the deltas and whether response.completed came.
// The daemon has no streamed call, so the stream reader lives in the test.
func (g *GatewayAccess) StreamResponse(ctx context.Context, r modelclient.Request) (string, bool, error) {
	r.Model, r.Stream = g.Model, true
	body, err := json.Marshal(r)
	if err != nil {
		return "", false, fmt.Errorf("encode the request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(g.URL, "/")+"/v1/responses", strings.NewReader(string(body)))
	if err != nil {
		return "", false, fmt.Errorf("build the request: %w", err)
	}
	for k, v := range g.RouteHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("x-capability-grant", g.Grant)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	resp, err := g.http.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("send to the gateway: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", false, fmt.Errorf("the gateway answered %d: %s", resp.StatusCode, b)
	}
	var text strings.Builder
	completed := false
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		data, ok := strings.CutPrefix(sc.Text(), "data:")
		data = strings.TrimSpace(data)
		if !ok || data == "" || data == "[DONE]" {
			continue
		}
		var ev struct {
			Type  string `json:"type"`
			Delta string `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &ev); err != nil {
			return "", false, fmt.Errorf("decode a stream event: %w", err)
		}
		switch ev.Type {
		case "response.output_text.delta":
			text.WriteString(ev.Delta)
		case "response.completed":
			completed = true
		case "response.failed", "error":
			return "", false, fmt.Errorf("the stream failed: %s", data)
		}
	}
	if err := sc.Err(); err != nil {
		return "", false, fmt.Errorf("read the stream: %w", err)
	}
	return text.String(), completed, nil
}

// IsRefusal reports whether a status is a refusal by policy.
func IsRefusal(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

// HTTPClientWithCA returns an HTTP client that trusts exactly the PEM bundle. An
// empty bundle means the system roots.
func HTTPClientWithCA(caPEM string) (*http.Client, error) {
	client := &http.Client{Timeout: time.Minute}
	if caPEM == "" {
		return client, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errors.New("the CA bundle of the gateway holds no certificate")
	}
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return client, nil
}
