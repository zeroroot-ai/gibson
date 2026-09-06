// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package sandboxed — session-scoped sandboxes (gibson#1183).
//
// The per-call path in executor.go launches a microVM, runs one command, and
// destroys it. That is correct for a tool invocation and wrong for an
// interactive coding session: an agent that runs `git clone` and then `go
// build` expects the second command to see the first one's output.
//
// A SESSION sandbox is launched once per (tenant, session_id), keeps a durable
// /workspace volume across commands, and is torn down explicitly. Commands run
// inside it via setec's SandboxService.Exec (setec#239) rather than by
// launching anything new.
//
// This file holds the transport-agnostic half: the client surface an adapter
// must satisfy and the registry that owns the mapping. It has ZERO setec
// imports, exactly like the rest of this package — internal/server/daemon's
// setec adapter is the single point of contact.
package sandboxed

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// ExecExitStatus discriminates how a command ended.
//
// It exists because an exit code cannot be synthesised: a caller handed a bare
// stream close, or a zero-valued int32, cannot tell a clean success from a
// microVM that vanished mid-build. setec's SessionExecExit.Status makes the
// same distinction for the same reason, and this type carries it through
// rather than flattening it.
type ExecExitStatus string

const (
	// ExecExited — the command ran to completion and Code is its real exit code.
	ExecExited ExecExitStatus = "exited"
	// ExecFailed — the command did not complete. Code is meaningless; Message says why.
	ExecFailed ExecExitStatus = "failed"
	// ExecUnknown — the outcome could not be determined. Never treat as success.
	ExecUnknown ExecExitStatus = "unknown"
)

// ExecExit is the terminal event of an exec. Exactly one is produced per
// established stream, and it is always last.
type ExecExit struct {
	Status  ExecExitStatus
	Code    int32
	Message string
}

// ExecEvent is one message from a running command. Exactly one field is set.
type ExecEvent struct {
	Stdout []byte
	Stderr []byte
	Exit   *ExecExit
}

// ExecStream is one in-flight command inside a session sandbox.
//
// Ownership: the caller must Close() it. Recv returns io.EOF-shaped
// termination only AFTER an Exit event; a stream that ends without one is an
// error, because "the connection dropped" and "the command succeeded" must
// never look alike.
type ExecStream interface {
	// Send writes a chunk to the command's stdin.
	Send(stdin []byte) error
	// CloseSend half-closes stdin. A command that reads to EOF hangs forever
	// without it.
	CloseSend() error
	// Recv returns the next event, or an error (including a wrapped io.EOF
	// when the peer closed cleanly).
	Recv() (ExecEvent, error)
	// Close releases the stream. Safe to call more than once.
	Close() error
}

// SessionLaunchRequest is a launch that produces a SESSION sandbox rather than
// an ephemeral one. It is deliberately narrower than LaunchRequest: a session
// has no Command (nothing runs until the first Exec) and no per-call Timeout
// semantics — Idle bounds the session, not one command.
type SessionLaunchRequest struct {
	Image        string
	Env          map[string]string
	VCPU         int32
	Memory       string
	Tenant       string
	SandboxClass string

	// WorkspaceSize is the durable /workspace PVC size ("10Gi"). Empty defers
	// to the operator default.
	WorkspaceSize string

	// Idle is the session lifetime setec enforces. A session that outlives it
	// is destroyed with its workspace, so this is the backstop against a
	// forgotten session pinning a PVC and a metal node indefinitely.
	Idle time.Duration
}

// SessionClient is the transport surface a session sandbox needs, on top of
// the per-call SandboxClient.
type SessionClient interface {
	SandboxClient

	// LaunchSession creates a session-mode sandbox with a durable workspace.
	LaunchSession(ctx context.Context, req SessionLaunchRequest) (LaunchResponse, error)

	// Exec runs argv inside an existing session sandbox. argv is executed
	// directly — no shell is interposed, so no quoting, globbing or
	// redirection happens on the way. A caller that wants a shell asks for
	// one: argv = ["sh", "-c", "..."].
	Exec(ctx context.Context, sandboxID string, argv []string) (ExecStream, error)
}

// ErrSessionUnavailable is returned when session execution is not wired on
// this daemon (no setec, or the sandbox subsystem is disabled).
var ErrSessionUnavailable = errors.New("session sandboxes are not available on this daemon")

// SessionSpec is the launch shape the registry uses for a cache miss. The
// daemon supplies it once at construction; a session's image and class are
// deployment policy, not something a component chooses per call.
type SessionSpec struct {
	Image         string
	VCPU          int32
	Memory        string
	SandboxClass  string
	WorkspaceSize string
	Idle          time.Duration
}

// SessionRegistry maps (tenant, session_id) to a live session sandbox,
// launching one on first use.
//
// # WHY THE LOCK IS PER-KEY AND NOT GLOBAL
//
// A launch takes tens of seconds (metal scale-from-zero, image pull, microVM
// boot). Holding one mutex across it would serialise every tenant's first
// command behind whichever session happened to be first. Each key gets its own
// entry with its own once-semantics instead, so concurrent Resolve calls for
// the SAME session share one launch and calls for DIFFERENT sessions do not
// wait on each other.
type SessionRegistry struct {
	client SessionClient
	spec   SessionSpec

	mu      sync.Mutex
	entries map[string]*sessionEntry
}

type sessionEntry struct {
	ready     chan struct{} // closed once sandboxID/err are final
	sandboxID string
	err       error
}

// NewSessionRegistry builds a registry over client. A nil client yields a
// registry whose Resolve always returns ErrSessionUnavailable, so the daemon
// can wire it unconditionally and let the failure surface per-call with a
// clear message rather than at startup.
func NewSessionRegistry(client SessionClient, spec SessionSpec) *SessionRegistry {
	return &SessionRegistry{
		client:  client,
		spec:    spec,
		entries: make(map[string]*sessionEntry),
	}
}

// sessionKey namespaces a session by tenant. The tenant half is server-derived
// from the caller identity, never from the request, so one tenant cannot name
// another's session by guessing its id.
//
// LENGTH-PREFIXED, not separator-joined. Any single-separator scheme is
// forgeable when a half can contain the separator: with `tenant + "\x00" + id`,
// tenant "a" / id "\x00x" and tenant "a\x00" / id "x" both encode to
// "a\x00\x00x" — the same map key, so one caller's session resolves to
// another's sandbox. session_id is agent-chosen and arbitrary, so that is
// attacker-controlled input. Encoding the tenant's byte length first makes the
// split unambiguous for every possible pair.
func sessionKey(tenant, sessionID string) string {
	return strconv.Itoa(len(tenant)) + ":" + tenant + sessionID
}

// Resolve returns the sandbox id backing (tenant, sessionID), launching a
// session sandbox on first use. Concurrent callers for the same key share one
// launch.
func (r *SessionRegistry) Resolve(ctx context.Context, tenant, sessionID string) (string, error) {
	if r == nil || r.client == nil {
		return "", ErrSessionUnavailable
	}
	if tenant == "" {
		return "", errors.New("session resolve: empty tenant")
	}
	if sessionID == "" {
		return "", errors.New("session resolve: empty session id")
	}

	key := sessionKey(tenant, sessionID)

	r.mu.Lock()
	e, found := r.entries[key]
	if !found {
		e = &sessionEntry{ready: make(chan struct{})}
		r.entries[key] = e
	}
	r.mu.Unlock()

	if found {
		// Someone else is launching (or already did). Wait, but stay
		// cancellable — a caller that gave up must not be pinned to another
		// caller's slow launch.
		select {
		case <-e.ready:
		case <-ctx.Done():
			return "", fmt.Errorf("waiting for session sandbox launch: %w", ctx.Err())
		}
		if e.err != nil {
			return "", e.err
		}
		return e.sandboxID, nil
	}

	// We own the launch for this key.
	resp, err := r.client.LaunchSession(ctx, SessionLaunchRequest{
		Image:         r.spec.Image,
		VCPU:          r.spec.VCPU,
		Memory:        r.spec.Memory,
		Tenant:        tenant,
		SandboxClass:  r.spec.SandboxClass,
		WorkspaceSize: r.spec.WorkspaceSize,
		Idle:          r.spec.Idle,
	})
	if err != nil {
		e.err = fmt.Errorf("launch session sandbox: %w", err)
		close(e.ready)
		// A failed launch must not poison the key forever — the next command
		// should get a fresh attempt rather than a cached error.
		r.forget(key, e)
		return "", e.err
	}

	e.sandboxID = resp.SandboxID
	close(e.ready)
	return e.sandboxID, nil
}

// Exec resolves the session and runs argv in it.
func (r *SessionRegistry) Exec(ctx context.Context, tenant, sessionID string, argv []string) (ExecStream, error) {
	if len(argv) == 0 {
		return nil, errors.New("session exec: argv is required")
	}
	sandboxID, err := r.Resolve(ctx, tenant, sessionID)
	if err != nil {
		return nil, err
	}
	stream, err := r.client.Exec(ctx, sandboxID, argv)
	if err != nil {
		return nil, fmt.Errorf("exec in session sandbox %s: %w", sandboxID, err)
	}
	return stream, nil
}

// Release tears down the session sandbox and its workspace, and forgets the
// mapping. Absent is success — releasing an unknown session is not an error,
// so a component can call it unconditionally on shutdown.
func (r *SessionRegistry) Release(ctx context.Context, tenant, sessionID string) error {
	if r == nil || r.client == nil {
		return ErrSessionUnavailable
	}
	key := sessionKey(tenant, sessionID)

	r.mu.Lock()
	e, ok := r.entries[key]
	if ok {
		delete(r.entries, key)
	}
	r.mu.Unlock()
	if !ok {
		return nil
	}

	// Wait for an in-flight launch before killing: killing an id that does not
	// exist yet would leak the sandbox the launch is about to produce.
	select {
	case <-e.ready:
	case <-ctx.Done():
		return fmt.Errorf("waiting for session sandbox launch before release: %w", ctx.Err())
	}
	// A session whose launch FAILED has no sandbox to kill, and the entry is
	// already removed above, so there is nothing left to do and nothing to
	// report. Returning e.err here would make Release fail for a session that
	// never existed — which is the opposite of the absent-is-success contract
	// a component relies on when it calls Release unconditionally on shutdown.
	if e.err != nil || e.sandboxID == "" {
		return nil //nolint:nilerr // a failed launch left no sandbox; absent is success
	}
	if err := r.client.Kill(ctx, e.sandboxID); err != nil {
		return fmt.Errorf("kill session sandbox %s: %w", e.sandboxID, err)
	}
	return nil
}

// forget drops the entry if it is still the one we created. The identity check
// matters: a concurrent Release may already have replaced it, and deleting
// blindly would drop a live session's mapping and leak its sandbox.
func (r *SessionRegistry) forget(key string, want *sessionEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if got, ok := r.entries[key]; ok && got == want {
		delete(r.entries, key)
	}
}
