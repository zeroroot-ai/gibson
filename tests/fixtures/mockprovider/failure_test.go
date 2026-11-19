// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestServeHTTP_BodyReadFailureIsABadRequestAndIsNotRecorded(t *testing.T) {
	p := &Provider{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", failingBody{})

	p.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "read body: read failed")
	assert.Empty(t, p.Requests())
}

func TestReset_DeletesTheRecordedRequests(t *testing.T) {
	p := &Provider{}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/models", http.NoBody))
	require.Len(t, p.Requests(), 1)

	p.Reset()

	assert.Empty(t, p.Requests())
}

func TestRequests_ReturnsACopy(t *testing.T) {
	p := &Provider{}
	p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/models", http.NoBody))

	got := p.Requests()
	got[0].Path = "changed"

	assert.Equal(t, "/v1/models", p.Requests()[0].Path)
}

func TestWriteJSON_ReplyThatDoesNotMarshalIsAServerError(t *testing.T) {
	rec := httptest.NewRecorder()

	writeJSON(rec, http.StatusOK, map[string]any{"bad": make(chan int)})

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "marshal reply")
}

func TestSSEEvent_DropsAnEventThatDoesNotMarshal(t *testing.T) {
	rec := httptest.NewRecorder()
	sse := newSSE(rec)

	sse.event("bad", map[string]any{"x": make(chan int)})
	sse.event("good", map[string]any{"x": 1})

	assert.Equal(t, "event: good\ndata: {\"type\":\"good\",\"x\":1}\n\n", rec.Body.String())
}
