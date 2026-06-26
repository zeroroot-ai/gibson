package harness

// merge_tool_response_test.go covers mergeToolResponse (gibson#963): the
// descriptor-identity bridge that keeps DefaultAgentHarness.CallToolProto from
// panicking when a tool adapter returns a structurally-identical message built
// from a distinct descriptor instance (e.g. a dynamicpb.Message rebuilt from a
// re-parsed FileDescriptorSet).

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// fooFileProto is a minimal proto3 file with one message Foo{string name=1;
// int32 count=2;}. Building two independent descriptor instances from it yields
// name-equal but identity-different MessageDescriptors — exactly the case
// proto.Merge rejects.
func fooFileProto() *descriptorpb.FileDescriptorProto {
	return &descriptorpb.FileDescriptorProto{
		Name:    proto.String("merge_tool_response_test.proto"),
		Package: proto.String("mergetest"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Foo"),
			Field: []*descriptorpb.FieldDescriptorProto{
				{
					Name:   proto.String("name"),
					Number: proto.Int32(1),
					Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
				},
				{
					Name:   proto.String("count"),
					Number: proto.Int32(2),
					Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					Type:   descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(),
				},
			},
		}},
	}
}

// newFooMessage parses fooFileProto into a fresh descriptor instance and returns
// an empty dynamicpb.Message for mergetest.Foo. Two calls return messages whose
// descriptors are name-equal but not identical.
func newFooMessage(t *testing.T) *dynamicpb.Message {
	t.Helper()
	fd, err := protodesc.NewFile(fooFileProto(), nil)
	if err != nil {
		t.Fatalf("protodesc.NewFile: %v", err)
	}
	md := fd.Messages().Get(0)
	return dynamicpb.NewMessage(md)
}

func setFoo(t *testing.T, m *dynamicpb.Message, name string, count int32) {
	t.Helper()
	fields := m.Descriptor().Fields()
	m.Set(fields.ByName("name"), protoreflect.ValueOfString(name))
	m.Set(fields.ByName("count"), protoreflect.ValueOfInt32(count))
}

func getFoo(t *testing.T, m *dynamicpb.Message) (string, int32) {
	t.Helper()
	fields := m.Descriptor().Fields()
	return m.Get(fields.ByName("name")).String(), int32(m.Get(fields.ByName("count")).Int())
}

// TestMergeToolResponse_DistinctDescriptors is the regression guard: two
// messages of the same type built from distinct descriptor instances must merge
// without panicking, and the destination must end up with the source's fields.
func TestMergeToolResponse_DistinctDescriptors(t *testing.T) {
	src := newFooMessage(t)
	setFoo(t, src, "hello", 7)
	dst := newFooMessage(t)

	// Precondition: the descriptors really are distinct, so a bare proto.Merge
	// would panic. Proving this keeps the test honest about what it guards.
	if src.Descriptor() == dst.Descriptor() {
		t.Fatal("expected distinct descriptor instances; test no longer reproduces the bug")
	}
	if !panicsOnMerge(dst, src) {
		t.Fatal("expected proto.Merge to panic on distinct descriptors; bridge would be unnecessary")
	}

	// mergeToolResponse must bridge them.
	if err := mergeToolResponse(dst, src); err != nil {
		t.Fatalf("mergeToolResponse: %v", err)
	}
	name, count := getFoo(t, dst)
	if name != "hello" || count != 7 {
		t.Fatalf("dst not populated: name=%q count=%d", name, count)
	}
}

// TestMergeToolResponse_SameDescriptor exercises the fast path: identical
// descriptors go straight through proto.Merge.
func TestMergeToolResponse_SameDescriptor(t *testing.T) {
	src := wrapperspb.String("hi")
	dst := &wrapperspb.StringValue{}
	if src.ProtoReflect().Descriptor() != dst.ProtoReflect().Descriptor() {
		t.Fatal("concrete types should share a descriptor instance")
	}
	if err := mergeToolResponse(dst, src); err != nil {
		t.Fatalf("mergeToolResponse: %v", err)
	}
	if dst.GetValue() != "hi" {
		t.Fatalf("dst value = %q, want hi", dst.GetValue())
	}
}

// panicsOnMerge reports whether proto.Merge(dst, src) panics.
func panicsOnMerge(dst, src proto.Message) (panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	proto.Merge(dst, src)
	return false
}
