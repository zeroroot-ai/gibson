// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package modelclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// Stream events that the client gives to the caller.
const (
	EventTextDelta = "response.output_text.delta"
	EventCompleted = "response.completed"
)

// Event is one event of a stream. Delta is set for EventTextDelta. Response is
// set for EventCompleted. Another event has only its Type.
type Event struct {
	Type     string
	Delta    string
	Response *Response
}

// Stream reads the server-sent events of a streamed call. Use it in a loop:
//
//	for s.Next() { ev := s.Event() }
//	if err := s.Err(); err != nil { ... }
type Stream struct {
	body io.Closer
	sc   *bufio.Scanner
	ev   Event
	err  error
	done bool
}

// Stream sends one Open Responses call with stream set, and returns the stream.
// The caller must close it.
func (c *Client) Stream(ctx context.Context, caller Caller, target Target, req Request) (*Stream, error) {
	if err := target.validate(true); err != nil {
		return nil, err
	}
	req.Model = target.Model
	req.Stream = true
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("modelclient: encode the request: %w", err)
	}
	resp, err := c.send(ctx, caller, target, http.MethodPost, modelcall.RouteResponses, body, "text/event-stream")
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), maxResponseBytes)
	return &Stream{body: resp.Body, sc: sc}, nil
}

// Next reads the next event. It returns false at the end of the stream and on
// an error. Err tells which.
func (s *Stream) Next() bool {
	if s.done {
		return false
	}
	for {
		data, ok := s.readFrame()
		if !ok {
			s.done = true
			return false
		}
		if string(data) == "[DONE]" {
			s.done = true
			return false
		}
		var head struct {
			Type     string          `json:"type"`
			Delta    string          `json:"delta"`
			Response json.RawMessage `json:"response"`
			Code     string          `json:"code"`
			Message  string          `json:"message"`
		}
		if err := json.Unmarshal(data, &head); err != nil {
			s.err = fmt.Errorf("modelclient: decode a stream event: %w", err)
			s.done = true
			return false
		}
		switch head.Type {
		case EventTextDelta:
			s.ev = Event{Type: head.Type, Delta: head.Delta}
			return true
		case EventCompleted, "response.incomplete":
			var r Response
			if err := json.Unmarshal(head.Response, &r); err != nil {
				s.err = fmt.Errorf("modelclient: decode the final response: %w", err)
				s.done = true
				return false
			}
			s.ev = Event{Type: head.Type, Response: &r}
			return true
		case "response.failed":
			var r Response
			_ = json.Unmarshal(head.Response, &r)
			f := &ResponseFailure{Code: "failed", Message: "the response failed"}
			if r.Error != nil {
				f = &ResponseFailure{Code: r.Error.Code, Message: r.Error.Message}
			}
			s.err = f
			s.done = true
			return false
		case "error":
			s.err = &ResponseFailure{Code: head.Code, Message: head.Message}
			s.done = true
			return false
		default:
			s.ev = Event{Type: head.Type}
			return true
		}
	}
}

// readFrame returns the data of the next server-sent event. A frame ends at an
// empty line. Lines that start with a colon, "event:", "id:" and "retry:" are
// not data.
func (s *Stream) readFrame() ([]byte, bool) {
	var data []byte
	for s.sc.Scan() {
		line := s.sc.Bytes()
		if len(line) == 0 {
			if len(data) > 0 {
				return data, true
			}
			continue
		}
		if rest, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			rest = bytes.TrimPrefix(rest, []byte(" "))
			if len(data) > 0 {
				data = append(data, '\n')
			}
			data = append(data, rest...)
		}
	}
	if err := s.sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		s.err = fmt.Errorf("modelclient: read the stream: %w", err)
		return nil, false
	}
	if len(data) > 0 {
		return data, true
	}
	return nil, false
}

// Event returns the event that Next read.
func (s *Stream) Event() Event { return s.ev }

// Err returns the error that ended the stream, or nil at a clean end.
func (s *Stream) Err() error { return s.err }

// Close releases the connection.
func (s *Stream) Close() error {
	if err := s.body.Close(); err != nil {
		return fmt.Errorf("modelclient: close the stream: %w", err)
	}
	return nil
}
