package api

import (
	"log/slog"
	"os"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var testSlogLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

// blankServer returns a DaemonServer with no external dependencies wired.
// Only suitable for input-validation and nil-store branch tests.
//
// reembedTrigger is defaulted to the no-op (mirroring NewDaemonServer) so the
// field is never nil at request time — the provider-config handlers call
// s.reembedTrigger.Trigger unconditionally ([[0003]]: no request-path nil-guard).
func blankServer() *DaemonServer {
	return &DaemonServer{
		logger:         testSlogLogger,
		reembedTrigger: noopReembedTrigger{},
	}
}

func grpcCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	s, _ := status.FromError(err)
	return s.Code()
}
