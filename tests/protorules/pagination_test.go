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

// minListRPCs is the floor of the pagination guard. A run that finds fewer
// list RPCs read the wrong tree.
const minListRPCs = 20

// TestEachListRequestPagesWithAToken is the guard of gibson#995: each list
// request of the module uses page_size and page_token (ADR-0028, rule 3).
func TestEachListRequestPagesWithAToken(t *testing.T) {
	found := 0
	for _, fd := range loadedFiles(t) {
		services := fd.Services()
		for i := range services.Len() {
			methods := services.Get(i).Methods()
			for j := range methods.Len() {
				if listVerb.MatchString(string(methods.Get(j).Name())) {
					found++
				}
			}
		}
		for _, line := range PaginationViolations(fd) {
			t.Errorf("%s. Use `int32 page_size` and `string page_token` in the request and "+
				"`string next_page_token` in the response, and reserve the old field (ADR-0028, rule 3).", line)
		}
	}
	if found < minListRPCs {
		t.Fatalf("found %d list RPCs, want at least %d: the guard read the wrong tree", found, minListRPCs)
	}
}

// paginationFixture builds a proto file with three RPCs: ListWidgets (limit
// and offset), AdminListJobs (page_token, but no page_size and no
// next_page_token), and ListenEvents (limit, which the verb rule must not
// match). good gives ListWidgets and AdminListJobs the right shape.
func paginationFixture(t *testing.T, good bool) protoreflect.FileDescriptor {
	t.Helper()
	field := func(name string, num int32, typ descriptorpb.FieldDescriptorProto_Type) *descriptorpb.FieldDescriptorProto {
		return &descriptorpb.FieldDescriptorProto{
			Name: proto.String(name), Number: proto.Int32(num), JsonName: proto.String(name),
			Type: typ.Enum(), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
		}
	}
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING
	i32 := descriptorpb.FieldDescriptorProto_TYPE_INT32
	tokenRequest := []*descriptorpb.FieldDescriptorProto{field("page_size", 1, i32), field("page_token", 2, str)}
	tokenResponse := []*descriptorpb.FieldDescriptorProto{field("next_page_token", 1, str)}

	widgets := []*descriptorpb.FieldDescriptorProto{field("limit", 1, i32), field("offset", 2, i32)}
	jobs := []*descriptorpb.FieldDescriptorProto{field("page_token", 1, str)}
	var jobsResponse []*descriptorpb.FieldDescriptorProto
	if good {
		widgets, jobs, jobsResponse = tokenRequest, tokenRequest, tokenResponse
	}
	method := func(name, in, out string) *descriptorpb.MethodDescriptorProto {
		return &descriptorpb.MethodDescriptorProto{
			Name: proto.String(name), InputType: proto.String(".fixture.page.v1." + in), OutputType: proto.String(".fixture.page.v1." + out),
		}
	}
	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("fixture/v1/pagination.proto"),
		Package: proto.String("fixture.page.v1"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("ListWidgetsRequest"), Field: widgets},
			{Name: proto.String("ListWidgetsResponse"), Field: tokenResponse},
			{Name: proto.String("AdminListJobsRequest"), Field: jobs},
			{Name: proto.String("AdminListJobsResponse"), Field: jobsResponse},
			{Name: proto.String("ListenEventsRequest"), Field: []*descriptorpb.FieldDescriptorProto{field("limit", 1, i32)}},
			{Name: proto.String("Empty")},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("WidgetService"),
			Method: []*descriptorpb.MethodDescriptorProto{
				method("ListWidgets", "ListWidgetsRequest", "ListWidgetsResponse"),
				method("AdminListJobs", "AdminListJobsRequest", "AdminListJobsResponse"),
				method("ListenEvents", "ListenEventsRequest", "Empty"),
			},
		}},
	}
	fd, err := protodesc.NewFile(file, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("build the fixture file: %v", err)
	}
	return fd
}

// TestPaginationGuardFixture is the failing fixture of the guard.
func TestPaginationGuardFixture(t *testing.T) {
	t.Run("the old shapes are refused", func(t *testing.T) {
		got := PaginationViolations(paginationFixture(t, false))
		want := []string{
			"fixture/v1/pagination.proto: fixture.page.v1.AdminListJobsRequest (the request of fixture.page.v1.WidgetService.AdminListJobs) has page_token and no page_size",
			"fixture/v1/pagination.proto: fixture.page.v1.AdminListJobsResponse (the response of fixture.page.v1.WidgetService.AdminListJobs) has no next_page_token",
			"fixture/v1/pagination.proto: fixture.page.v1.ListWidgetsRequest (the request of fixture.page.v1.WidgetService.ListWidgets) has a field limit",
			"fixture/v1/pagination.proto: fixture.page.v1.ListWidgetsRequest (the request of fixture.page.v1.WidgetService.ListWidgets) has a field offset",
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
	t.Run("the token shape passes, and ListenEvents is not a list verb", func(t *testing.T) {
		if got := PaginationViolations(paginationFixture(t, true)); len(got) != 0 {
			t.Fatalf("the token shape was refused: %q", got)
		}
	})
}
