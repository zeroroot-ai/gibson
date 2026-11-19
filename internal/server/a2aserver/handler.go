// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package a2aserver

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

// StartRequest is one message to an agent.
type StartRequest struct {
	Caller Caller
	Route  Route
	// Message is the A2A message of the caller.
	Message *a2a.Message
}

// Runs creates, reads and cancels the agent runs that A2A calls start. Each
// method acts only on a run of the same tenant and the same mission as the
// caller. A run of another tenant or another mission is not found.
type Runs interface {
	// Start creates agent work for the target agent in the mission of the
	// caller, and returns its Task at once. It does not wait for the result.
	Start(ctx context.Context, req StartRequest) (*a2a.Task, error)
	// Task returns the Task of a run.
	Task(ctx context.Context, caller Caller, id a2a.TaskID) (*a2a.Task, error)
	// Cancel cancels a run and returns its Task.
	Cancel(ctx context.Context, caller Caller, id a2a.TaskID) (*a2a.Task, error)
}

// handler is the a2asrv.RequestHandler of the daemon. It serves SendMessage,
// GetTask and CancelTask. Every other method is not supported.
type handler struct {
	UnsupportedMethods
	runs Runs
}

var _ a2asrv.RequestHandler = (*handler)(nil)

func (h *handler) callOf(ctx context.Context) (Caller, Route, error) {
	c, r, ok := CallFrom(ctx)
	if !ok {
		return Caller{}, Route{}, a2a.ErrUnauthenticated
	}
	return c, r, nil
}

// SendMessage starts agent work for the target agent.
func (h *handler) SendMessage(ctx context.Context, req *a2a.SendMessageRequest) (a2a.SendMessageResult, error) {
	c, r, err := h.callOf(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil || req.Message == nil {
		return nil, fmt.Errorf("%w: the request holds no message", a2a.ErrInvalidParams)
	}
	if strings.TrimSpace(TextOf(req.Message)) == "" {
		return nil, fmt.Errorf("%w: the message holds no text", a2a.ErrInvalidParams)
	}
	task, err := h.runs.Start(ctx, StartRequest{Caller: c, Route: r, Message: req.Message})
	if err != nil {
		return nil, MapError(err)
	}
	return task, nil
}

// GetTask returns the Task of a run of the caller.
func (h *handler) GetTask(ctx context.Context, req *a2a.GetTaskRequest) (*a2a.Task, error) {
	c, _, err := h.callOf(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil || req.ID == "" {
		return nil, fmt.Errorf("%w: the request names no task", a2a.ErrInvalidParams)
	}
	t, err := h.runs.Task(ctx, c, req.ID)
	if err != nil {
		return nil, MapError(err)
	}
	return t, nil
}

// CancelTask cancels a run of the caller.
func (h *handler) CancelTask(ctx context.Context, req *a2a.CancelTaskRequest) (*a2a.Task, error) {
	c, _, err := h.callOf(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil || req.ID == "" {
		return nil, fmt.Errorf("%w: the request names no task", a2a.ErrInvalidParams)
	}
	t, err := h.runs.Cancel(ctx, c, req.ID)
	if err != nil {
		return nil, MapError(err)
	}
	return t, nil
}

// UnsupportedMethods answers each A2A method that the daemon does not serve:
// listing, streaming, push notifications and the extended card. A handler embeds
// it and implements the methods that it serves.
type UnsupportedMethods struct{}

func (UnsupportedMethods) ListTasks(context.Context, *a2a.ListTasksRequest) (*a2a.ListTasksResponse, error) {
	return nil, a2a.ErrUnsupportedOperation
}

func (UnsupportedMethods) SubscribeToTask(context.Context, *a2a.SubscribeToTaskRequest) iter.Seq2[a2a.Event, error] {
	return unsupportedStream()
}

func (UnsupportedMethods) SendStreamingMessage(context.Context, *a2a.SendMessageRequest) iter.Seq2[a2a.Event, error] {
	return unsupportedStream()
}

func unsupportedStream() iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) { yield(nil, a2a.ErrUnsupportedOperation) }
}

func (UnsupportedMethods) GetTaskPushConfig(context.Context, *a2a.GetTaskPushConfigRequest) (*a2a.PushConfig, error) {
	return nil, a2a.ErrPushNotificationNotSupported
}

func (UnsupportedMethods) ListTaskPushConfigs(context.Context, *a2a.ListTaskPushConfigRequest) (*a2a.ListTaskPushConfigResponse, error) {
	return nil, a2a.ErrPushNotificationNotSupported
}

func (UnsupportedMethods) CreateTaskPushConfig(context.Context, *a2a.PushConfig) (*a2a.PushConfig, error) {
	return nil, a2a.ErrPushNotificationNotSupported
}

func (UnsupportedMethods) DeleteTaskPushConfig(context.Context, *a2a.DeleteTaskPushConfigRequest) error {
	return a2a.ErrPushNotificationNotSupported
}

func (UnsupportedMethods) GetExtendedAgentCard(context.Context, *a2a.GetExtendedAgentCardRequest) (*a2a.AgentCard, error) {
	return nil, a2a.ErrExtendedCardNotConfigured
}

// Errors that a Runs implementation returns. MapError turns them into the A2A
// errors that the JSON-RPC layer reports.
var (
	// ErrNotFound reports a task that does not exist for the caller.
	ErrNotFound = errors.New("a2a: no such task")
	// ErrRefused reports a request that policy refuses: the depth limit, or a
	// delegation that the caller may not make.
	ErrRefused = errors.New("a2a: the request is refused")
	// ErrNotCancelable reports a task in a final state.
	ErrNotCancelable = errors.New("a2a: the task is in a final state")
)

// MapError maps an error of Runs to an A2A error. An error that is not known
// becomes an internal error. Its text does not reach the caller.
func MapError(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return a2a.ErrTaskNotFound
	case errors.Is(err, ErrNotCancelable):
		return a2a.ErrTaskNotCancelable
	case errors.Is(err, ErrRefused):
		return fmt.Errorf("%w: %w", a2a.ErrUnauthorized, err)
	case errors.Is(err, ErrResultTooLarge):
		// The caller needs the reason. The error holds the sizes and nothing of the
		// findings.
		return fmt.Errorf("%w: %w", a2a.ErrInvalidAgentResponse, err)
	case errors.Is(err, a2a.ErrInvalidParams):
		return err
	default:
		return a2a.ErrInternalError
	}
}

// TextOf joins the text parts of a message.
func TextOf(m *a2a.Message) string {
	if m == nil {
		return ""
	}
	var parts []string
	for _, p := range m.Parts {
		if p == nil {
			continue
		}
		if t := p.Text(); t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, "\n")
}

// Cards returns the Agent Card of an agent for a tenant.
type Cards interface {
	Card(ctx context.Context, tenant, agent string) (*a2a.AgentCard, error)
}

// ErrNoCard reports an agent with no card for the tenant.
var ErrNoCard = errors.New("a2a: no card for the agent")

// NewHandler returns the HTTP handler of the A2A listener. The JSON-RPC
// endpoint is at "/". The Agent Card of an agent is at
// "/agents/<name>/.well-known/agent-card.json".
func NewHandler(runs Runs, cards Cards) http.Handler {
	rpc := a2asrv.NewJSONRPCHandler(&handler{runs: runs})
	mux := http.NewServeMux()
	mux.Handle("POST /{$}", callMiddleware(rpc, true))
	mux.Handle("GET /agents/{name}/.well-known/agent-card.json", callMiddleware(cardHandler(cards), false))
	return mux
}

// callMiddleware reads the caller from the headers and refuses a request that
// has none.
func callMiddleware(next http.Handler, requireMission bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c, r, err := FromHeaders(req.Header, requireMission)
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, ErrNoRoute) || errors.Is(err, ErrNoMission) {
				status = http.StatusForbidden
			}
			http.Error(w, err.Error(), status)
			return
		}
		next.ServeHTTP(w, req.WithContext(WithCall(req.Context(), c, r)))
	})
}
