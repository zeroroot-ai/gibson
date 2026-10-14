// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"log/slog"
	"os"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
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
		// A unit test must never reach a real provider. The save path asks the
		// provider for a model list, so the default factory is a stub whose
		// list is empty. A test that needs a real provider against a fake sets
		// its own factory.
		providerFactory: func(llm.ProviderConfig) (llm.LLMProvider, error) { return &stubMockProvider{}, nil },
	}
}

func grpcCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	s, _ := status.FromError(err)
	return s.Code()
}
