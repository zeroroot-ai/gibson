// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package protorules

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// minStartRequests is the floor of the idempotency guard. The daemon-local
// protos had five RPCs with a start verb when the guard shipped. A run that
// finds fewer read the wrong tree.
const minStartRequests = 5

// TestEachStartRequestHasAnIdempotencyKey is the guard of gibson#694: each
// daemon-local request that creates something or starts work carries the key
// that the idempotency interceptor reads.
func TestEachStartRequestHasAnIdempotencyKey(t *testing.T) {
	found := 0
	for _, fd := range loadedFiles(t) {
		services := fd.Services()
		for i := range services.Len() {
			methods := services.Get(i).Methods()
			for j := range methods.Len() {
				if startVerb.MatchString(string(methods.Get(j).Name())) {
					found++
				}
			}
		}
		for _, line := range MissingIdempotencyKeys(fd) {
			t.Errorf("%s. Add `string %s = <next number> [(buf.validate.field).string = { max_len: 128 }];` (ADR-0028, rule 2).",
				line, IdempotencyKeyField)
		}
	}
	if found < minStartRequests {
		t.Fatalf("found %d RPCs with a start verb, want at least %d: the guard read the wrong tree", found, minStartRequests)
	}
}

// idempotencyFixture builds a proto file with one RPC CreateWidget, and one
// message StartJobRequest that no RPC uses. withKey gives both requests the
// field idempotency_key. The file also holds RunnerStatusRequest and its RPC
// RunnerStatus, which the verb rule must not match.
func idempotencyFixture(t *testing.T, withKey bool) protoreflect.FileDescriptor {
	t.Helper()
	str := func(name string, num int32) *descriptorpb.FieldDescriptorProto {
		return &descriptorpb.FieldDescriptorProto{
			Name: proto.String(name), Number: proto.Int32(num), JsonName: proto.String(name),
			Type:  descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
		}
	}
	fields := func() []*descriptorpb.FieldDescriptorProto {
		out := []*descriptorpb.FieldDescriptorProto{str("name", 1)}
		if withKey {
			out = append(out, str(IdempotencyKeyField, 2))
		}
		return out
	}
	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("fixture/v1/idempotency.proto"),
		Package: proto.String("fixture.idem.v1"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("CreateWidgetRequest"), Field: fields()},
			{Name: proto.String("StartJobRequest"), Field: fields()},
			{Name: proto.String("RunnerStatusRequest"), Field: []*descriptorpb.FieldDescriptorProto{str("id", 1)}},
			{Name: proto.String("Empty")},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("WidgetService"),
			Method: []*descriptorpb.MethodDescriptorProto{
				{
					Name:       proto.String("CreateWidget"),
					InputType:  proto.String(".fixture.idem.v1.CreateWidgetRequest"),
					OutputType: proto.String(".fixture.idem.v1.Empty"),
				},
				{
					Name:       proto.String("RunnerStatus"),
					InputType:  proto.String(".fixture.idem.v1.RunnerStatusRequest"),
					OutputType: proto.String(".fixture.idem.v1.Empty"),
				},
			},
		}},
	}
	fd, err := protodesc.NewFile(file, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("build the fixture file: %v", err)
	}
	return fd
}

// TestIdempotencyGuardFixture is the failing fixture of the guard.
func TestIdempotencyGuardFixture(t *testing.T) {
	t.Run("a start request with no key is refused, by RPC and by name", func(t *testing.T) {
		got := MissingIdempotencyKeys(idempotencyFixture(t, false))
		want := []string{
			"fixture/v1/idempotency.proto: fixture.idem.v1.CreateWidgetRequest (the request of fixture.idem.v1.WidgetService.CreateWidget) has no string field idempotency_key",
			"fixture/v1/idempotency.proto: fixture.idem.v1.StartJobRequest (a request message with a start verb) has no string field idempotency_key",
		}
		if len(got) != len(want) {
			t.Fatalf("got %d lines, want %d: %q", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("line %d:\n got %q\nwant %q", i, got[i], want[i])
			}
		}
	})

	t.Run("the same requests with the key pass, and RunnerStatus is not a start verb", func(t *testing.T) {
		if got := MissingIdempotencyKeys(idempotencyFixture(t, true)); len(got) != 0 {
			t.Fatalf("requests with the key were refused: %q", got)
		}
	})
}
