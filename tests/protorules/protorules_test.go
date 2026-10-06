// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package protorules

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	// Each daemon-local proto package registers its descriptors on import.
	// TestEachTrackedProtoIsLoaded fails when a tracked proto file is not in
	// the registry, so this list cannot go stale with no signal.
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/agentconsole/v1"
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/connection/v1"
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/destructiveauthz/v1"
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/discovery/v1"
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/logs/v1"
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/session/v1"
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
)

// protoRoot is the directory of the daemon-local protos, from the repo root.
const protoRoot = "internal/server/daemon/api"

// The floors. A run that loads fewer files, services or RPCs than these read
// the wrong tree and must not pass.
const (
	minFiles    = 20
	minServices = 20
	minMethods  = 100
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory; cannot locate the repo root")
		}
		dir = parent
	}
}

// trackedProtoPaths returns the import path of each proto file under
// protoRoot, for example gibson/tenant/v1/secrets.proto.
func trackedProtoPaths(t *testing.T) []string {
	t.Helper()
	root := filepath.Join(repoRoot(t), protoRoot)
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}
		if d.IsDir() || !strings.HasSuffix(path, ".proto") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return fmt.Errorf("relativize %s against %s: %w", path, root, relErr)
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// loadedFiles returns the descriptor of each tracked proto file. It fails the
// test when a tracked file is not in the registry.
func loadedFiles(t *testing.T) []protoreflect.FileDescriptor {
	t.Helper()
	var files []protoreflect.FileDescriptor
	for _, path := range trackedProtoPaths(t) {
		fd, err := protoregistry.GlobalFiles.FindFileByPath(path)
		if err != nil {
			t.Errorf("%s is a tracked proto file, and the registry does not hold it: %v. "+
				"Add a blank import of its Go package to protorules_test.go.", path, err)
			continue
		}
		files = append(files, fd)
	}
	return files
}

func fieldRuleExtension(t *testing.T) protoreflect.ExtensionType {
	t.Helper()
	xt, err := protoregistry.GlobalTypes.FindExtensionByName(FieldRuleExtension)
	if err != nil {
		t.Fatalf("the extension %s is not registered: %v", FieldRuleExtension, err)
	}
	return xt
}

// TestEachTrackedProtoIsLoaded holds the floor: the test read the real tree.
func TestEachTrackedProtoIsLoaded(t *testing.T) {
	files := loadedFiles(t)
	services, methods := 0, 0
	for _, fd := range files {
		services += fd.Services().Len()
		for i := range fd.Services().Len() {
			methods += fd.Services().Get(i).Methods().Len()
		}
	}
	if len(files) < minFiles || services < minServices || methods < minMethods {
		t.Fatalf("read %d proto files, %d services and %d RPCs; want at least %d, %d and %d. "+
			"The test read the wrong tree.", len(files), services, methods, minFiles, minServices, minMethods)
	}
}

// TestEachRequestFieldHasARule is the guard of gibson#696.
func TestEachRequestFieldHasARule(t *testing.T) {
	xt := fieldRuleExtension(t)
	hasRule := func(f protoreflect.FieldDescriptor) bool { return HasFieldRule(f, xt) }
	for _, fd := range loadedFiles(t) {
		for _, line := range MissingRules(fd, hasRule) {
			t.Errorf("%s. Add a rule, for example [(buf.validate.field).string = { max_len: 1024 }] "+
				"or [(buf.validate.field).enum = { defined_only: true }] (ADR-0028).", line)
		}
	}
}

// fixtureFile builds a proto file with one service, one RPC and one request
// message. The request has a string field and an enum field. withRules sets a
// rule on each of the two fields.
func fixtureFile(t *testing.T, xt protoreflect.ExtensionType, withRules bool) protoreflect.FileDescriptor {
	t.Helper()
	fieldOpts := func() *descriptorpb.FieldOptions {
		if !withRules {
			return nil
		}
		opts := &descriptorpb.FieldOptions{}
		proto.SetExtension(opts, xt, xt.InterfaceOf(xt.New()))
		return opts
	}
	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("fixture/v1/widget.proto"),
		Package: proto.String("fixture.v1"),
		Syntax:  proto.String("proto3"),
		EnumType: []*descriptorpb.EnumDescriptorProto{{
			Name:  proto.String("Color"),
			Value: []*descriptorpb.EnumValueDescriptorProto{{Name: proto.String("COLOR_UNSPECIFIED"), Number: proto.Int32(0)}},
		}},
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("CreateWidgetRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name: proto.String("name"), Number: proto.Int32(1), JsonName: proto.String("name"),
						Type:    descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:   descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						Options: fieldOpts(),
					},
					{
						Name: proto.String("color"), Number: proto.Int32(2), JsonName: proto.String("color"),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_ENUM.Enum(),
						TypeName: proto.String(".fixture.v1.Color"),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						Options:  fieldOpts(),
					},
					{
						// A repeated field and a number are not in the rule.
						Name: proto.String("tags"), Number: proto.Int32(3), JsonName: proto.String("tags"),
						Type:  descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label: descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
					},
					{
						Name: proto.String("count"), Number: proto.Int32(4), JsonName: proto.String("count"),
						Type:  descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(),
						Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
				},
			},
			{
				// A message that is not the request of an RPC is not in the rule.
				Name: proto.String("CreateWidgetResponse"),
				Field: []*descriptorpb.FieldDescriptorProto{{
					Name: proto.String("id"), Number: proto.Int32(1), JsonName: proto.String("id"),
					Type:  descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
					Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				}},
			},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("WidgetService"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:       proto.String("CreateWidget"),
				InputType:  proto.String(".fixture.v1.CreateWidgetRequest"),
				OutputType: proto.String(".fixture.v1.CreateWidgetResponse"),
			}},
		}},
	}
	fd, err := protodesc.NewFile(file, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("build the fixture file: %v", err)
	}
	return fd
}

// TestGuardFixture is the failing fixture of the guard. A request with no rule
// is refused for its reason, and the same request with rules passes.
func TestGuardFixture(t *testing.T) {
	xt := fieldRuleExtension(t)
	hasRule := func(f protoreflect.FieldDescriptor) bool { return HasFieldRule(f, xt) }

	t.Run("a string field and an enum field with no rule are refused", func(t *testing.T) {
		got := MissingRules(fixtureFile(t, xt, false), hasRule)
		const request = "fixture.v1.CreateWidgetRequest (the request of fixture.v1.WidgetService.CreateWidget)"
		want := []string{
			"fixture/v1/widget.proto: field color of " + request + " has no buf.validate rule",
			"fixture/v1/widget.proto: field name of " + request + " has no buf.validate rule",
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

	t.Run("the same request with rules passes", func(t *testing.T) {
		if got := MissingRules(fixtureFile(t, xt, true), hasRule); len(got) != 0 {
			t.Fatalf("a request with rules was refused: %q", got)
		}
	})
}

// invalidRequest returns a request of the message that breaks one stated rule,
// and the name of the field. It returns nil when no field of the message has a
// string rule with a bound that a test can break.
func invalidRequest(t *testing.T, msg protoreflect.MessageDescriptor, xt protoreflect.ExtensionType) (req proto.Message, fieldName string) {
	t.Helper()
	fields := msg.Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		if field.Kind() != protoreflect.StringKind || field.IsList() || field.IsMap() || !HasFieldRule(field, xt) {
			continue
		}
		rules := proto.GetExtension(field.Options(), xt).(proto.Message).ProtoReflect()
		strRules := rules.Descriptor().Fields().ByName("string")
		if strRules == nil || !rules.Has(strRules) {
			continue
		}
		str := rules.Get(strRules).Message()
		maxLen := str.Descriptor().Fields().ByName("max_len")
		if maxLen == nil || !str.Has(maxLen) {
			continue
		}
		bound := str.Get(maxLen).Uint()
		if bound >= math.MaxInt32 {
			continue
		}
		msgReq := dynamicpb.NewMessage(msg)
		msgReq.Set(field, protoreflect.ValueOfString(strings.Repeat("a", int(bound)+1)))
		return msgReq, string(field.Name())
	}
	return nil, ""
}

// TestOneInvalidRequestForEachService sends one request that breaks a stated
// rule to the validator of each service. The daemon runs the same validator in
// its interceptor before the handler (internal/server/daemon/grpc_validate.go).
func TestOneInvalidRequestForEachService(t *testing.T) {
	xt := fieldRuleExtension(t)
	validator, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}

	checked := 0
	for _, fd := range loadedFiles(t) {
		services := fd.Services()
		for i := range services.Len() {
			svc := services.Get(i)
			var req proto.Message
			var fieldName string
			var method protoreflect.MethodDescriptor
			hasCheckedField := false
			for j := range svc.Methods().Len() {
				method = svc.Methods().Get(j)
				in := method.Input().Fields()
				for k := range in.Len() {
					hasCheckedField = hasCheckedField || needsRule(in.Get(k))
				}
				if req, fieldName = invalidRequest(t, method.Input(), xt); req != nil {
					break
				}
			}
			if req == nil {
				if hasCheckedField {
					t.Errorf("%s: no request of the service has a string rule with a max_len bound, "+
						"so no invalid request exists for it", svc.FullName())
				}
				// A service whose requests have no string and no enum field
				// has nothing to refuse.
				continue
			}
			if err := validator.Validate(req); err == nil {
				t.Errorf("%s: the validator accepted a %s with a field %s that is longer than its bound",
					method.FullName(), method.Input().FullName(), fieldName)
			}
			checked++
		}
	}
	if checked < minServices-5 {
		t.Fatalf("only %d services got an invalid request; the test read the wrong tree", checked)
	}
}
