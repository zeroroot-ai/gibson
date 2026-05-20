package daemon

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// newIdemRequest builds a dynamicpb-backed proto.Message whose
// descriptor declares:
//
//	message IdemRequest {
//	  string idempotency_key = 1;
//	  string payload         = 2;
//	}
//
// Used by the interceptor test suite to drive the protoreflect-based
// extractor without depending on a daemon proto under regen.
func newIdemRequest(key, payload string) proto.Message {
	msg := dynamicpb.NewMessage(idemRequestDescriptor())
	r := msg.ProtoReflect()
	r.Set(idemRequestKeyField, protoreflect.ValueOfString(key))
	r.Set(idemRequestPayloadField, protoreflect.ValueOfString(payload))
	return msg
}

// newWrongKindRequest builds a proto.Message whose `idempotency_key`
// field is declared as int32, NOT string. The extractor must reject
// it as an unsupported shape.
func newWrongKindRequest() proto.Message {
	return dynamicpb.NewMessage(wrongKindRequestDescriptor())
}

var (
	idemRequestKeyField     protoreflect.FieldDescriptor
	idemRequestPayloadField protoreflect.FieldDescriptor

	idemRequestDescriptorOnce     protoreflect.MessageDescriptor
	wrongKindRequestDescriptorVal protoreflect.MessageDescriptor
)

func idemRequestDescriptor() protoreflect.MessageDescriptor {
	if idemRequestDescriptorOnce != nil {
		return idemRequestDescriptorOnce
	}
	buildFixtureDescriptors()
	return idemRequestDescriptorOnce
}

func wrongKindRequestDescriptor() protoreflect.MessageDescriptor {
	if wrongKindRequestDescriptorVal != nil {
		return wrongKindRequestDescriptorVal
	}
	buildFixtureDescriptors()
	return wrongKindRequestDescriptorVal
}

// buildFixtureDescriptors compiles a one-off FileDescriptor containing
// two message types used by the interceptor test suite. The file
// path / package is fully-qualified to avoid clashing with any other
// fixture descriptor that might appear in the same test binary.
func buildFixtureDescriptors() {
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("daemon_idem_test_fixture.proto"),
		Package: proto.String("gibson.daemon.idemfixture"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("IdemRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:   proto.String("idempotency_key"),
						Number: proto.Int32(1),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
					{
						Name:   proto.String("payload"),
						Number: proto.Int32(2),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
				},
			},
			{
				Name: proto.String("WrongKindRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:   proto.String("idempotency_key"),
						Number: proto.Int32(1),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
				},
			},
		},
	}
	fileDesc, err := protodesc.NewFile(fdp, nil)
	if err != nil {
		panic("buildFixtureDescriptors: " + err.Error())
	}
	idemRequestDescriptorOnce = fileDesc.Messages().ByName("IdemRequest")
	wrongKindRequestDescriptorVal = fileDesc.Messages().ByName("WrongKindRequest")
	idemRequestKeyField = idemRequestDescriptorOnce.Fields().ByName("idempotency_key")
	idemRequestPayloadField = idemRequestDescriptorOnce.Fields().ByName("payload")
}
