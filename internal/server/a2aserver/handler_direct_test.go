// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package a2aserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

func callContext() context.Context {
	return WithCall(context.Background(), Caller{Tenant: "acme", Subject: "s", Mission: "m1", Task: "w1"},
		Route{Agent: "scout"})
}

func TestHandler_RefusesACallWithNoCallerInTheContext(t *testing.T) {
	h := &handler{runs: &fakeRuns{}}
	ctx := context.Background()
	msg := &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hi"))}
	if _, err := h.SendMessage(ctx, msg); !errors.Is(err, a2a.ErrUnauthenticated) {
		t.Errorf("SendMessage error = %v", err)
	}
	if _, err := h.GetTask(ctx, &a2a.GetTaskRequest{ID: "t"}); !errors.Is(err, a2a.ErrUnauthenticated) {
		t.Errorf("GetTask error = %v", err)
	}
	if _, err := h.CancelTask(ctx, &a2a.CancelTaskRequest{ID: "t"}); !errors.Is(err, a2a.ErrUnauthenticated) {
		t.Errorf("CancelTask error = %v", err)
	}
}

func TestHandler_RefusesARequestThatNamesNothing(t *testing.T) {
	h := &handler{runs: &fakeRuns{}}
	ctx := callContext()
	if _, err := h.SendMessage(ctx, nil); !errors.Is(err, a2a.ErrInvalidParams) {
		t.Errorf("nil request error = %v", err)
	}
	if _, err := h.SendMessage(ctx, &a2a.SendMessageRequest{}); !errors.Is(err, a2a.ErrInvalidParams) {
		t.Errorf("no message error = %v", err)
	}
	if _, err := h.GetTask(ctx, nil); !errors.Is(err, a2a.ErrInvalidParams) {
		t.Errorf("GetTask nil error = %v", err)
	}
	if _, err := h.GetTask(ctx, &a2a.GetTaskRequest{}); !errors.Is(err, a2a.ErrInvalidParams) {
		t.Errorf("GetTask no id error = %v", err)
	}
	if _, err := h.CancelTask(ctx, nil); !errors.Is(err, a2a.ErrInvalidParams) {
		t.Errorf("CancelTask nil error = %v", err)
	}
	if _, err := h.CancelTask(ctx, &a2a.CancelTaskRequest{}); !errors.Is(err, a2a.ErrInvalidParams) {
		t.Errorf("CancelTask no id error = %v", err)
	}
}

func TestHandler_MapsRunErrorsOnGetAndCancel(t *testing.T) {
	h := &handler{runs: &fakeRuns{err: ErrNotFound}}
	ctx := callContext()
	if _, err := h.GetTask(ctx, &a2a.GetTaskRequest{ID: "t"}); !errors.Is(err, a2a.ErrTaskNotFound) {
		t.Errorf("GetTask error = %v", err)
	}
	h = &handler{runs: &fakeRuns{err: ErrNotCancelable}}
	if _, err := h.CancelTask(ctx, &a2a.CancelTaskRequest{ID: "t"}); !errors.Is(err, a2a.ErrTaskNotCancelable) {
		t.Errorf("CancelTask error = %v", err)
	}
	h = &handler{runs: &fakeRuns{err: errors.New("database is down")}}
	_, err := h.SendMessage(ctx, &a2a.SendMessageRequest{
		Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hi")),
	})
	if !errors.Is(err, a2a.ErrInternalError) {
		t.Errorf("SendMessage error = %v", err)
	}
}

func TestHandler_UnsupportedMethodsSayWhy(t *testing.T) {
	h := &handler{runs: &fakeRuns{}}
	ctx := callContext()
	if _, err := h.ListTasks(ctx, &a2a.ListTasksRequest{}); !errors.Is(err, a2a.ErrUnsupportedOperation) {
		t.Errorf("ListTasks error = %v", err)
	}
	for name, seq := range map[string]func() error{
		"SubscribeToTask": func() error {
			for _, err := range h.SubscribeToTask(ctx, &a2a.SubscribeToTaskRequest{}) {
				return err
			}
			return nil
		},
		"SendStreamingMessage": func() error {
			for _, err := range h.SendStreamingMessage(ctx, &a2a.SendMessageRequest{}) {
				return err
			}
			return nil
		},
	} {
		if err := seq(); !errors.Is(err, a2a.ErrUnsupportedOperation) {
			t.Errorf("%s error = %v", name, err)
		}
	}
	errPush := a2a.ErrPushNotificationNotSupported
	errNoExt := a2a.ErrExtendedCardNotConfigured
	if _, err := h.GetTaskPushConfig(ctx, &a2a.GetTaskPushConfigRequest{}); !errors.Is(err, errPush) {
		t.Errorf("GetTaskPushConfig error = %v", err)
	}
	if _, err := h.ListTaskPushConfigs(ctx, &a2a.ListTaskPushConfigRequest{}); !errors.Is(err, errPush) {
		t.Errorf("ListTaskPushConfigs error = %v", err)
	}
	if _, err := h.CreateTaskPushConfig(ctx, &a2a.PushConfig{}); !errors.Is(err, errPush) {
		t.Errorf("CreateTaskPushConfig error = %v", err)
	}
	if err := h.DeleteTaskPushConfig(ctx, &a2a.DeleteTaskPushConfigRequest{}); !errors.Is(err, errPush) {
		t.Errorf("DeleteTaskPushConfig error = %v", err)
	}
	if _, err := h.GetExtendedAgentCard(ctx, &a2a.GetExtendedAgentCardRequest{}); !errors.Is(err, errNoExt) {
		t.Errorf("GetExtendedAgentCard error = %v", err)
	}
}

func TestMapError_KeepsInvalidParamsAndRefusals(t *testing.T) {
	invalid := fmt.Errorf("%w: bad", a2a.ErrInvalidParams)
	if got := MapError(invalid); !errors.Is(got, a2a.ErrInvalidParams) {
		t.Errorf("invalid params mapped to %v", got)
	}
	got := MapError(fmt.Errorf("%w: depth", ErrRefused))
	if !errors.Is(got, a2a.ErrUnauthorized) {
		t.Errorf("a refusal mapped to %v", got)
	}
}

func TestTextOf_SkipsNilAndEmptyParts(t *testing.T) {
	if got := TextOf(nil); got != "" {
		t.Errorf("TextOf(nil) = %q", got)
	}
	m := &a2a.Message{Parts: a2a.ContentParts{nil, a2a.NewTextPart(""), a2a.NewTextPart("a"), a2a.NewTextPart("b")}}
	if got := TextOf(m); got != "a\nb" {
		t.Errorf("TextOf = %q", got)
	}
}

// brokenWriter fails each write, as a client that has gone away.
type brokenWriter struct{ *httptest.ResponseRecorder }

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("client gone") }

func TestCard_StopsQuietlyWhenTheClientIsGone(t *testing.T) {
	h := NewHandler(&fakeRuns{}, fakeCards{})
	req := cardRequest("/agents/scout/.well-known/agent-card.json", nil)
	rec := brokenWriter{httptest.NewRecorder()}
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestCardHandler_RefusesARequestWithNoCallerInTheContext(t *testing.T) {
	rec := httptest.NewRecorder()
	cardHandler(fakeCards{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
