// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package grpcvalidate

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

func badConfig() *missionv1.AgentNodeConfig {
	return &missionv1.AgentNodeConfig{AgentName: "test", MaxTokensPerCall: proto.Int32(-1)}
}

func okConfig() *missionv1.AgentNodeConfig {
	return &missionv1.AgentNodeConfig{AgentName: "test", MaxTokensPerCall: proto.Int32(1)}
}

func fieldErrorOf(t *testing.T, err error) []*commonpb.FieldError {
	t.Helper()
	for _, d := range status.Convert(err).Details() {
		if ed, ok := d.(*commonpb.ErrorDetail); ok {
			return ed.GetFieldErrors()
		}
	}
	t.Fatalf("status %v has no ErrorDetail", err)
	return nil
}

func TestUnaryInterceptor(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	intercept := UnaryInterceptor(v)
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Method"}
	reached := 0
	handler := func(context.Context, any) (any, error) { reached++; return "ok", nil }

	if _, err := intercept(context.Background(), okConfig(), info, handler); err != nil || reached != 1 {
		t.Fatalf("valid request: err = %v, reached = %d; want nil and 1", err, reached)
	}
	if _, err := intercept(context.Background(), "not a proto message", info, handler); err != nil || reached != 2 {
		t.Fatalf("non-proto request: err = %v, reached = %d; want a pass-through", err, reached)
	}
	_, err = intercept(context.Background(), badConfig(), info, handler)
	if status.Code(err) != codes.InvalidArgument || reached != 2 {
		t.Fatalf("invalid request: code = %v, reached = %d; want InvalidArgument and 2", status.Code(err), reached)
	}
	if fe := fieldErrorOf(t, err); len(fe) != 1 || fe[0].GetField() != "max_tokens_per_call" {
		t.Fatalf("field errors = %v, want max_tokens_per_call", fe)
	}
}

// recvStream receives one message.
type recvStream struct {
	grpc.ServerStream
	msg proto.Message
	err error
}

func (s *recvStream) RecvMsg(m any) error {
	if s.err != nil {
		return s.err
	}
	proto.Merge(m.(proto.Message), s.msg)
	return nil
}

func TestStreamInterceptor(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	intercept := StreamInterceptor(v)
	info := &grpc.StreamServerInfo{FullMethod: "/test.Stream"}
	recv := func(inner *recvStream) error {
		return intercept(nil, inner, info, func(_ any, ss grpc.ServerStream) error {
			return ss.RecvMsg(&missionv1.AgentNodeConfig{})
		})
	}

	if err := recv(&recvStream{msg: okConfig()}); err != nil {
		t.Fatalf("valid message: %v", err)
	}
	if err := recv(&recvStream{msg: badConfig()}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid message: code = %v, want InvalidArgument", status.Code(err))
	}
	boom := errors.New("transport closed")
	if err := recv(&recvStream{err: boom}); !errors.Is(err, boom) {
		t.Fatalf("receive error = %v, want the transport error unchanged", err)
	}
}

func TestAttachDetail(t *testing.T) {
	err := errors.New("boom")
	if got := AttachDetail(err, status.New(codes.OK, ""), &commonpb.ErrorDetail{}); !errors.Is(got, err) {
		t.Fatalf("a status that cannot take a detail: got %v, want the error unchanged", got)
	}
	st := status.New(codes.NotFound, "gone")
	got := AttachDetail(st.Err(), st, &commonpb.ErrorDetail{Reason: "NOT_FOUND"})
	if status.Code(got) != codes.NotFound || len(status.Convert(got).Details()) != 1 {
		t.Fatalf("got %v, want NotFound with one detail", got)
	}
}
