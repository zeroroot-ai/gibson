// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package llmtrace

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// loadA2ASpan reads testdata/a2a_send_message.json. The file is a real span: the
// fixture test TestA2AThroughGateway made it with agentgateway v1.7.0, an A2A
// agent and a trace policy that adds the trusted headers and the route header.
func loadA2ASpan(t *testing.T) Span {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "a2a_send_message.json"))
	if err != nil {
		t.Fatalf("read span: %v", err)
	}
	var f struct {
		Attributes map[string]any `json:"attributes"`
		Start      int64          `json:"start_unix_nano"`
		End        int64          `json:"end_unix_nano"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse span: %v", err)
	}
	return Span{Attributes: f.Attributes, StartUnixNano: f.Start, EndUnixNano: f.End}
}

func TestOutsideCallFromSpan_RealA2ASpan(t *testing.T) {
	c, err := OutsideCallFromSpan(loadA2ASpan(t))
	if err != nil {
		t.Fatalf("OutsideCallFromSpan: %v", err)
	}
	if c.Tenant != "tenant-a" || c.Subject != "user:u1" || c.Mission != "m-1" || c.Task != "task-1" ||
		c.Target != "partner-scout" || c.Method != "SendMessage" || c.HTTPStatus != 200 || c.Outcome != "ok" {
		t.Errorf("call = %+v", c)
	}
	if c.CallID != "gw-9ed131e11583fe197585b3e80f9277f4-c9b4eb6fad52868a" {
		t.Errorf("CallID = %q", c.CallID)
	}
	if c.EndUnixNano <= c.StartUnixNano {
		t.Errorf("times = %d, %d", c.StartUnixNano, c.EndUnixNano)
	}
	ev, ok := c.Event(time.Unix(5, 0)).(brain.OutsideAgentCalled)
	if !ok || ev.Target != "partner-scout" || ev.MissionID != "m-1" || ev.Status != "ok" ||
		ev.StartUnixNano != c.StartUnixNano || ev.EndUnixNano != c.EndUnixNano {
		t.Errorf("event = %+v", ev)
	}
}

// An A2A span is not a model call, and a model span is not an A2A call.
func TestOutsideCallFromSpan_TheTwoKindsOfSpanStayApart(t *testing.T) {
	if _, err := FromSpan(loadA2ASpan(t)); !errors.Is(err, ErrNotAModelCall) {
		t.Errorf("FromSpan(a2a) error = %v, want ErrNotAModelCall", err)
	}
	if _, err := OutsideCallFromSpan(loadSpan(t, "responses_plain")); !errors.Is(err, ErrNotAnA2ACall) {
		t.Errorf("OutsideCallFromSpan(model) error = %v, want ErrNotAnA2ACall", err)
	}
}

func TestOutsideCallFromSpan_Refusals(t *testing.T) {
	good := func() Span {
		sp := loadA2ASpan(t)
		return sp
	}
	cases := map[string]func(sp *Span){
		"no target":   func(sp *Span) { delete(sp.Attributes, AttrRouteAgent) },
		"no span id":  func(sp *Span) { delete(sp.Attributes, "span.id"); delete(sp.Attributes, "trace.id") },
		"no start":    func(sp *Span) { sp.StartUnixNano = 0 },
		"end < start": func(sp *Span) { sp.EndUnixNano = sp.StartUnixNano - 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			sp := good()
			mutate(&sp)
			if _, err := OutsideCallFromSpan(sp); err == nil || errors.Is(err, ErrNotAnA2ACall) {
				t.Errorf("error = %v, want a defect error", err)
			}
		})
	}
}

func TestOutsideCallFromSpan_AnErrorStatusIsAnError(t *testing.T) {
	sp := loadA2ASpan(t)
	sp.Attributes["http.response.status_code"] = float64(502)
	c, err := OutsideCallFromSpan(sp)
	if err != nil || c.Outcome != "error" {
		t.Errorf("call = %+v, %v; want outcome error", c, err)
	}
	sp = loadA2ASpan(t)
	sp.Attributes["a2a.response.outcome"] = "error"
	c, err = OutsideCallFromSpan(sp)
	if err != nil || c.Outcome != "error" {
		t.Errorf("call = %+v, %v; want outcome error", c, err)
	}
}
