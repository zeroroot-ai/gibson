// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"strconv"
	"sync"
	"time"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The sign-in relay's control channel (ADR-0019 decision 4, gibson#1715).
//
// A subscription member signs in inside its sandbox: the driver runs
// `claude auth login`, relays the authorization URL and the paste prompt on
// its stdout (which the console already follows), and needs two things from
// the daemon: the word to start, and the code the person pasted. Both travel
// on the member's inbox as control inputs, so the driver reads them where it
// reads everything else.
//
// Neither is ever stored. A control input lives in memory until the member's
// SubscribeInput stream takes it, and a code that is not taken within
// ControlInputTTL is dropped: the platform never holds a credential, and a
// code that sat in a table would be one (decision 4). There is no turn
// grant on a control input either. It carries no authority; it is a word.

// SignInJobID is the job id a control input carries. It names no job: the
// driver recognizes it and routes the input to the sign-in flow.
const SignInJobID = "sign-in"

// The two control messages.
const (
	// SignInStart, as a TURN, tells the driver to start the flow.
	SignInStart = "start"
)

// ControlInputTTL is how long an untaken control input waits. A code is
// good for minutes on the vendor's side, and a member that is not reading
// its inbox is not signing in.
const ControlInputTTL = 5 * time.Minute

// controlInput is one queued word for a member.
type controlInput struct {
	input  *jobpb.Input
	queued time.Time
}

// MemberControl is the in-memory queue of control inputs, per tenant and
// member. The daemon holds one and shares it between the bank service, which
// enqueues, and the callback service, which delivers.
type MemberControl struct {
	mu     sync.Mutex
	queues map[string][]controlInput
	now    func() time.Time
	seq    int64
}

// NewMemberControl builds an empty queue.
func NewMemberControl() *MemberControl {
	return &MemberControl{queues: map[string][]controlInput{}, now: time.Now}
}

func controlKey(tenantID, memberID string) string { return tenantID + "/" + memberID }

// StartSignIn queues the start word for a member, from the person who asked.
func (c *MemberControl) StartSignIn(tenantID, memberID, senderID string) {
	c.enqueue(tenantID, memberID, jobpb.InputKind_INPUT_KIND_TURN, SignInStart, senderID)
}

// SubmitSignInCode queues the code the person pasted. It is held in memory
// only, and only until the member takes it or the TTL ends.
func (c *MemberControl) SubmitSignInCode(tenantID, memberID, code, senderID string) {
	c.enqueue(tenantID, memberID, jobpb.InputKind_INPUT_KIND_ANSWER, code, senderID)
}

func (c *MemberControl) enqueue(tenantID, memberID string, kind jobpb.InputKind, message, senderID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	key := controlKey(tenantID, memberID)
	c.queues[key] = append(c.queues[key], controlInput{
		queued: c.now(),
		input: &jobpb.Input{
			Id: "control-" + strconv.FormatInt(c.seq, 10), JobId: SignInJobID, Kind: kind, Message: message,
			Sender: &commonpb.Principal{Kind: commonpb.Principal_KIND_USER, Id: senderID},
			SentAt: timestamppb.New(c.now()),
		},
	})
}

// Drain takes every live control input for a member, oldest first, and
// forgets them. An input older than the TTL is dropped unseen.
func (c *MemberControl) Drain(tenantID, memberID string) []*jobpb.Input {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := controlKey(tenantID, memberID)
	queued := c.queues[key]
	delete(c.queues, key)
	out := make([]*jobpb.Input, 0, len(queued))
	cutoff := c.now().Add(-ControlInputTTL)
	for _, ci := range queued {
		if ci.queued.Before(cutoff) {
			continue
		}
		out = append(out, ci.input)
	}
	return out
}

// Pending reports how many control inputs wait for a member. A console uses
// it to say "the member has not taken the code yet".
func (c *MemberControl) Pending(tenantID, memberID string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.queues[controlKey(tenantID, memberID)])
}
