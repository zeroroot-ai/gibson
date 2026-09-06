// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/bank"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/liveagents"
	bankpb "github.com/zeroroot-ai/sdk/api/gen/gibson/bank/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// The sign-in relay (ADR-0019 decision 4, gibson#1715).
//
// A subscription member signs in inside its sandbox. The daemon relays two
// strings out (the authorization URL and the paste prompt, which the driver
// prints on the stream the console already follows) and two words in (start,
// and the code the person pasted, which ride the member's inbox as control
// inputs). It stores nothing from the flow. No URL, no code and no token
// reach Postgres or a log line: the URL and the code exist in memory for as
// long as the relay takes, and the credential never leaves the sandbox.
//
// Only the bank's owner may drive it, because the sign-in is theirs.

// SignInFeed is the member's live stream the relay reads. The live-agents
// registry satisfies it.
type SignInFeed interface {
	Subscribe(tenant, runID string, sinceSeq uint64) (backlog []liveagents.Event, events <-chan liveagents.Event, cancel func(), err error)
}

// The line types the driver prints for the relay. Keyed by type like every
// other console line.
const (
	signInLineURL     = "sign_in"
	signInLineInvalid = "sign_in_invalid"
	signInLineDone    = "sign_in_done"
	signInLineFailed  = "sign_in_failed"
)

// signInLine is what the driver prints. Only the fields the relay forwards.
type signInLine struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	CodePrompt string `json:"code_prompt"`
	Message    string `json:"message"`
	Error      string `json:"error"`
}

// signInMember checks the caller owns the bank and the member is its, and
// returns the member. Anything the caller may not drive is not found.
func (s *bankServer) signInMember(ctx context.Context, bankID, memberID string) (signInCaller, *bank.Member, error) {
	tenant, err := s.tenant(ctx)
	if err != nil {
		return signInCaller{}, nil, err
	}
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		return signInCaller{}, nil, status.Error(codes.PermissionDenied, "no caller identity in context")
	}
	if bankID == "" || memberID == "" {
		return signInCaller{}, nil, status.Error(codes.InvalidArgument, "bank_id and member_id are required")
	}
	if err := s.authorize(ctx, "owner", bankID); err != nil {
		return signInCaller{}, nil, err
	}
	m, err := s.store.GetMember(ctx, tenant, memberID)
	if err != nil || m.BankID != bankID {
		return signInCaller{}, nil, status.Errorf(codes.NotFound, "no member %s on bank %s", memberID, bankID)
	}
	return signInCaller{tenant: tenant, subject: id.Subject}, m, nil
}

// signInCaller is who is driving the relay: the tenant and the owner.
type signInCaller struct {
	tenant  string
	subject string
}

// StartSignIn tells the member to start the flow.
func (s *bankServer) StartSignIn(ctx context.Context, req *bankpb.StartSignInRequest) (*bankpb.StartSignInResponse, error) {
	caller, m, err := s.signInMember(ctx, req.GetBankId(), req.GetMemberId())
	if err != nil {
		return nil, err
	}
	s.control.StartSignIn(caller.tenant, m.ID, caller.subject)
	s.logger.InfoContext(ctx, "sign-in started", "bank_id", m.BankID, "member_id", m.ID)
	return &bankpb.StartSignInResponse{Member: memberToProto(m)}, nil
}

// SubmitSignInCode hands the pasted code to the member. The code is queued in
// memory for the member's inbox and nowhere else.
func (s *bankServer) SubmitSignInCode(ctx context.Context, req *bankpb.SubmitSignInCodeRequest) (*bankpb.SubmitSignInCodeResponse, error) {
	caller, m, err := s.signInMember(ctx, req.GetBankId(), req.GetMemberId())
	if err != nil {
		return nil, err
	}
	code := strings.TrimSpace(req.GetCode())
	if code == "" {
		return nil, status.Error(codes.InvalidArgument, "code is required")
	}
	s.control.SubmitSignInCode(caller.tenant, m.ID, code, caller.subject)
	s.logger.InfoContext(ctx, "sign-in code submitted", "bank_id", m.BankID, "member_id", m.ID)
	return &bankpb.SubmitSignInCodeResponse{Member: memberToProto(m)}, nil
}

// StreamSignIn relays the flow's lines from the member's live stream until it
// reports done or failed. Nothing is stored on the way through.
func (s *bankServer) StreamSignIn(req *bankpb.StreamSignInRequest, stream bankpb.BankService_StreamSignInServer) error {
	ctx := stream.Context()
	caller, m, err := s.signInMember(ctx, req.GetBankId(), req.GetMemberId())
	if err != nil {
		return err
	}
	if m.AgentRunID == "" {
		return status.Errorf(codes.FailedPrecondition, "member %s has no live run to relay from", m.ID)
	}
	backlog, events, cancel, err := s.feed.Subscribe(caller.tenant, m.AgentRunID, 0)
	if err != nil {
		if errors.Is(err, liveagents.ErrInstanceNotFound) {
			return status.Errorf(codes.FailedPrecondition, "member %s is not running", m.ID)
		}
		return status.Errorf(codes.Internal, "follow the member: %v", err)
	}
	defer cancel()

	for _, ev := range signInReplay(backlog) {
		if done, serr := relaySignInLine(stream, ev.Data); serr != nil || done {
			return serr
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			if done, serr := relaySignInLine(stream, ev.Data); serr != nil || done {
				return serr
			}
		}
	}
}

// signInReplay picks the part of the backlog that is this flow's. An earlier
// finished flow is not replayed. A flow that finished last is replayed whole,
// end included, so a console that opens late sees it ended.
func signInReplay(backlog []liveagents.Event) []liveagents.Event {
	last, previous := -1, -1
	for i, ev := range backlog {
		if line, ok := parseSignInLine(ev.Data); ok && (line.Type == signInLineDone || line.Type == signInLineFailed) {
			previous, last = last, i
		}
	}
	switch {
	case last == -1:
		return backlog
	case last == len(backlog)-1:
		return backlog[previous+1:]
	default:
		return backlog[last+1:]
	}
}

// relaySignInLine forwards one line when it is the flow's, and reports
// whether the flow ended.
func relaySignInLine(stream bankpb.BankService_StreamSignInServer, data []byte) (bool, error) {
	line, ok := parseSignInLine(data)
	if !ok {
		return false, nil
	}
	var resp *bankpb.StreamSignInResponse
	switch line.Type {
	case signInLineURL:
		resp = &bankpb.StreamSignInResponse{Url: line.URL, CodePrompt: line.CodePrompt}
	case signInLineInvalid:
		resp = &bankpb.StreamSignInResponse{Error: line.Message}
	case signInLineDone:
		resp = &bankpb.StreamSignInResponse{Done: true}
	case signInLineFailed:
		resp = &bankpb.StreamSignInResponse{Done: true, Error: line.Error}
	default:
		return false, nil
	}
	if err := stream.Send(resp); err != nil {
		return false, fmt.Errorf("relay a sign-in line: %w", err)
	}
	return resp.GetDone(), nil
}

// parseSignInLine reads one stream line. Anything that is not a sign-in line
// is not the relay's to read.
func parseSignInLine(data []byte) (signInLine, bool) {
	var line signInLine
	if err := json.Unmarshal(data, &line); err != nil || !strings.HasPrefix(line.Type, "sign_in") {
		return signInLine{}, false
	}
	return line, true
}
