package daemon

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Spec: deploy#207 (epic one-code-path M11, dashboard error class
// mapping + correlation IDs). The daemon must emit a `correlation_id`
// per-RPC, forward an upstream `x-correlation-id` metadata header
// verbatim, and echo the ID back to the caller in the response
// metadata so the dashboard's response header matches.

func TestGenerateCorrelationID_FormatMatchesDashboard(t *testing.T) {
	// req-<26 Crockford-base32 chars> — same shape the dashboard
	// emits, so a single grep over both logs returns related lines.
	re := regexp.MustCompile(`^req-[0-9A-HJKMNP-TV-Z]{26}$`)
	for i := 0; i < 16; i++ {
		got := generateCorrelationID()
		if !re.MatchString(got) {
			t.Fatalf("generateCorrelationID()=%q does not match %s", got, re)
		}
	}
}

func TestGenerateCorrelationID_Unique(t *testing.T) {
	seen := make(map[string]struct{}, 64)
	for i := 0; i < 64; i++ {
		id := generateCorrelationID()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate correlation id %q at iteration %d", id, i)
		}
		seen[id] = struct{}{}
	}
}

// recordingServerTransportStream lets us capture SetHeader calls from
// the unary interceptor under test. The interceptor calls
// grpc.SetHeader(ctx, ...), which looks up a ServerTransportStream on
// the context — without one, SetHeader is a no-op and we can't
// assert the echo. The signature follows
// grpc.ServerTransportStream in google.golang.org/grpc.
type recordingServerTransportStream struct {
	method  string
	headers metadata.MD
}

func (s *recordingServerTransportStream) Method() string { return s.method }
func (s *recordingServerTransportStream) SetHeader(md metadata.MD) error {
	if s.headers == nil {
		s.headers = metadata.MD{}
	}
	for k, v := range md {
		s.headers[k] = append(s.headers[k], v...)
	}
	return nil
}
func (s *recordingServerTransportStream) SendHeader(md metadata.MD) error {
	return s.SetHeader(md)
}
func (s *recordingServerTransportStream) SetTrailer(metadata.MD) error { return nil }

func TestCorrelationIDInterceptor_ForwardsUpstreamID(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	unary, _ := correlationIDInterceptors(logger)

	incoming := metadata.Pairs(CorrelationIDMetadataKey, "req-UPSTREAM01234567890ABCDEFG")
	ctx := metadata.NewIncomingContext(context.Background(), incoming)
	rts := &recordingServerTransportStream{method: "/test/Method"}
	ctx = grpc.NewContextWithServerTransportStream(ctx, rts)

	var seenInHandler string
	_, err := unary(
		ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/test/Method"},
		func(handlerCtx context.Context, _ any) (any, error) {
			seenInHandler = CorrelationIDFromContext(handlerCtx)
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("interceptor returned err: %v", err)
	}

	want := "req-UPSTREAM01234567890ABCDEFG"
	if seenInHandler != want {
		t.Errorf("handler ctx got %q, want %q", seenInHandler, want)
	}
	if got := rts.headers.Get(CorrelationIDMetadataKey); len(got) != 1 || got[0] != want {
		t.Errorf("response header got %v, want [%s]", got, want)
	}
}

func TestCorrelationIDInterceptor_MintsFreshIDWhenAbsent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	unary, _ := correlationIDInterceptors(logger)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{})
	rts := &recordingServerTransportStream{method: "/test/Method"}
	ctx = grpc.NewContextWithServerTransportStream(ctx, rts)

	var seenInHandler string
	_, err := unary(
		ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/test/Method"},
		func(handlerCtx context.Context, _ any) (any, error) {
			seenInHandler = CorrelationIDFromContext(handlerCtx)
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("interceptor returned err: %v", err)
	}

	if !strings.HasPrefix(seenInHandler, "req-") {
		t.Errorf("handler ctx got %q; want req-<...>", seenInHandler)
	}
	echoed := rts.headers.Get(CorrelationIDMetadataKey)
	if len(echoed) != 1 || echoed[0] != seenInHandler {
		t.Errorf("response header got %v, want [%s]", echoed, seenInHandler)
	}
}

func TestCorrelationIDInterceptor_LogsCorrelationID(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	unary, _ := correlationIDInterceptors(logger)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{})
	rts := &recordingServerTransportStream{method: "/test/Method"}
	ctx = grpc.NewContextWithServerTransportStream(ctx, rts)

	_, _ = unary(
		ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/test/Method"},
		func(context.Context, any) (any, error) { return nil, nil },
	)

	if !strings.Contains(buf.String(), `"correlation_id":"req-`) {
		t.Errorf("expected log line to carry correlation_id, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), `"grpc_method":"/test/Method"`) {
		t.Errorf("expected log line to carry grpc_method, got: %s", buf.String())
	}
}

func TestCorrelationIDFromContext_DefaultsEmpty(t *testing.T) {
	if got := CorrelationIDFromContext(context.Background()); got != "" {
		t.Errorf("expected empty correlation id on bare context, got %q", got)
	}
}
