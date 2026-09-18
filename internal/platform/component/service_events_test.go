// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/componentevents"
	"github.com/zeroroot-ai/sdk/auth"
)

// eventStream is a fake grpc.ServerStreamingServer[ComponentEvent].
type eventStream struct {
	grpc.ServerStream
	ctx  context.Context
	sent chan *componentpb.ComponentEvent
}

func (s *eventStream) Context() context.Context { return s.ctx }
func (s *eventStream) Send(ev *componentpb.ComponentEvent) error {
	s.sent <- ev
	return nil
}

func newEventsServer(t *testing.T) (*ComponentServiceServer, *componentevents.Hub, *redis.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	hub := componentevents.NewHub(rdb, nil, 50*time.Millisecond, 4)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	hub.Start(ctx)
	t.Cleanup(hub.Stop)
	return newParityServer().WithEventHub(hub), hub, rdb
}

// TestWatchComponentEvents_DeliversRevocationToTheCaller is the gibson#154
// fixture: a revocation published for the caller's principal reaches the
// stream as a secret_access_revoked event, and a heartbeat arrives while
// nothing else happens.
func TestWatchComponentEvents_DeliversRevocationToTheCaller(t *testing.T) {
	svc, _, rdb := newEventsServer(t)
	ctx, cancel := context.WithCancel(credCallerCtx(t, "plugin_principal:plugin-github-1", "acme"))
	defer cancel()
	st := &eventStream{ctx: ctx, sent: make(chan *componentpb.ComponentEvent, 8)}
	done := make(chan error, 1)
	go func() { done <- svc.WatchComponentEvents(&componentpb.WatchComponentEventsRequest{}, st) }()
	time.Sleep(60 * time.Millisecond)

	when := time.Date(2026, 9, 18, 21, 0, 0, 0, time.UTC)
	if err := componentevents.NewPublisher(rdb).Publish(context.Background(), "acme", "plugin_principal:plugin-github-1",
		componentevents.Event{Type: componentevents.TypeSecretAccessRevoked, SecretName: "github_token", Reason: "revoked", OccurredAt: when}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// A revocation for another principal must not arrive.
	_ = componentevents.NewPublisher(rdb).Publish(context.Background(), "acme", "plugin_principal:other",
		componentevents.Event{Type: componentevents.TypeSecretAccessRevoked, SecretName: "leak"})

	var gotRevoked, gotHeartbeat bool
	deadline := time.After(3 * time.Second)
	for !gotRevoked || !gotHeartbeat {
		select {
		case ev := <-st.sent:
			switch ev.GetType() {
			case componentevents.TypeSecretAccessRevoked:
				if ev.GetSecretName() != "github_token" || ev.GetReason() != "revoked" || !ev.GetOccurredAt().AsTime().Equal(when) {
					t.Fatalf("event = %+v", ev)
				}
				if ev.GetSecretName() == "leak" {
					t.Fatal("another principal's revocation leaked")
				}
				gotRevoked = true
			case componentevents.TypeHeartbeat:
				gotHeartbeat = true
			default:
				t.Fatalf("unexpected event %+v", ev)
			}
		case <-deadline:
			t.Fatalf("revoked=%v heartbeat=%v", gotRevoked, gotHeartbeat)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("stream ended with %v", err)
	}
}

func TestWatchComponentEvents_RefusesWithoutHubTenantOrIdentity(t *testing.T) {
	t.Parallel()
	none := newParityServer()
	st := &eventStream{ctx: credCallerCtx(t, "plugin_principal:p", "acme"), sent: make(chan *componentpb.ComponentEvent, 1)}
	if err := none.WatchComponentEvents(nil, st); status.Code(err) != codes.Unavailable {
		t.Fatalf("no hub: %v", err)
	}
	svc, _, _ := newEventsServer(t)
	if err := svc.WatchComponentEvents(nil, &eventStream{ctx: context.Background(), sent: make(chan *componentpb.ComponentEvent, 1)}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no tenant: %v", err)
	}
	tid, err := auth.NewTenantID("acme")
	if err != nil {
		t.Fatal(err)
	}
	tenantOnly := auth.ContextWithTenant(context.Background(), tid)
	if err := svc.WatchComponentEvents(nil, &eventStream{ctx: tenantOnly, sent: make(chan *componentpb.ComponentEvent, 1)}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no identity: %v", err)
	}
}

type failingEventStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *failingEventStream) Context() context.Context { return s.ctx }
var errClientGone = errors.New("client gone")

func (s *failingEventStream) Send(*componentpb.ComponentEvent) error {
	return errClientGone
}

// TestWatchComponentEvents_SendFailureEndsTheStream: a Send error on an
// event or on a heartbeat returns to gRPC instead of looping.
func TestWatchComponentEvents_SendFailureEndsTheStream(t *testing.T) {
	svc, _, rdb := newEventsServer(t)
	ctx := credCallerCtx(t, "plugin_principal:p", "acme")
	done := make(chan error, 1)
	go func() {
		done <- svc.WatchComponentEvents(nil, &failingEventStream{ctx: ctx}) //nolint:contextcheck // the context travels in the stream
	}()
	select {
	case err := <-done: // the 50ms heartbeat fails first
		if err == nil || !errors.Is(err, errClientGone) {
			t.Fatalf("heartbeat send failure: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not end on heartbeat send failure")
	}
	// The same on an event: a hub with a long heartbeat, a publish, a failing Send.
	svc2 := newParityServer().WithEventHub(componentevents.NewHub(rdb, nil, time.Hour, 4))
	svc2.eventHub.Start(context.Background())
	defer svc2.eventHub.Stop()
	go func() { done <- svc2.WatchComponentEvents(nil, &failingEventStream{ctx: ctx}) }() //nolint:contextcheck // the context travels in the stream
	time.Sleep(60 * time.Millisecond)
	_ = componentevents.NewPublisher(rdb).Publish(context.Background(), "acme", "plugin_principal:p", componentevents.Event{Type: componentevents.TypeSecretRotated})
	select {
	case err := <-done:
		if err == nil || !errors.Is(err, errClientGone) {
			t.Fatalf("event send failure: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not end on event send failure")
	}
}
