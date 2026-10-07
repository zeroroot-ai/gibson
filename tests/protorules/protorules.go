// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package protorules checks that each request message of a daemon-local
// service states its field rules (ADR-0028, rule 1, gibson#696), and that each
// request that creates something or starts work has an idempotency_key
// (ADR-0028, rule 2, gibson#694).
//
// The daemon runs protovalidate on each request before the handler runs. The
// interceptor can check only a rule that a proto states. A string field with
// no rule has no bound, and an enum field with no rule accepts a number that
// the enum does not define.
//
// The rule that this package holds: in the request message of each RPC, each
// string field and each enum field has a buf.validate rule. A repeated field
// and a map field are not checked.
package protorules

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// FieldRuleExtension is the full name of the protovalidate field option.
const FieldRuleExtension = "buf.validate.field"

// MissingRules returns one line for each string or enum field of a request
// message of the file that has no buf.validate rule. hasRule reports whether a
// field carries the option. The lines are sorted.
func MissingRules(file protoreflect.FileDescriptor, hasRule func(protoreflect.FieldDescriptor) bool) []string {
	var out []string
	seen := map[protoreflect.FullName]bool{}
	services := file.Services()
	for i := range services.Len() {
		methods := services.Get(i).Methods()
		for j := range methods.Len() {
			method := methods.Get(j)
			input := method.Input()
			if seen[input.FullName()] {
				continue
			}
			seen[input.FullName()] = true
			fields := input.Fields()
			for k := range fields.Len() {
				field := fields.Get(k)
				if !needsRule(field) || hasRule(field) {
					continue
				}
				out = append(out, fmt.Sprintf(
					"%s: field %s of %s (the request of %s) has no buf.validate rule",
					file.Path(), field.Name(), input.FullName(), method.FullName()))
			}
		}
	}
	sort.Strings(out)
	return out
}

// needsRule reports whether the rule of this package covers the field: a
// string field or an enum field that is not repeated and not a map.
func needsRule(field protoreflect.FieldDescriptor) bool {
	if field.IsList() || field.IsMap() {
		return false
	}
	return field.Kind() == protoreflect.StringKind || field.Kind() == protoreflect.EnumKind
}

// HasFieldRule reports whether the field carries the extension xt in its
// options.
func HasFieldRule(field protoreflect.FieldDescriptor, xt protoreflect.ExtensionType) bool {
	opts := field.Options()
	if opts == nil {
		return false
	}
	return proto.HasExtension(opts, xt)
}

// IdempotencyKeyField is the name of the request field that the idempotency
// interceptor of the daemon reads (ADR-0028, rule 2, gibson#694).
const IdempotencyKeyField = "idempotency_key"

// startVerb matches an RPC name or a request message name that creates
// something or starts work. The verb is a full word: RunnerStatus is not a
// match.
var startVerb = regexp.MustCompile(`^(Create|Run|Start|Submit)([A-Z0-9]|$)`)

// MissingIdempotencyKeys returns one line for each request of the file that
// creates something or starts work and has no string field idempotency_key.
// Two kinds of request are checked: the request message of each RPC whose
// name starts with Create, Run, Start or Submit, and each message whose name
// is one of these verbs, a name, and Request. The lines are sorted.
//
// No allowlist exists. A request that must not have the field needs a
// different verb.
func MissingIdempotencyKeys(file protoreflect.FileDescriptor) []string {
	var out []string
	seen := map[protoreflect.FullName]bool{}
	check := func(msg protoreflect.MessageDescriptor, why string) {
		if seen[msg.FullName()] {
			return
		}
		seen[msg.FullName()] = true
		if hasIdempotencyKey(msg) {
			return
		}
		out = append(out, fmt.Sprintf("%s: %s (%s) has no string field %s",
			file.Path(), msg.FullName(), why, IdempotencyKeyField))
	}
	services := file.Services()
	for i := range services.Len() {
		methods := services.Get(i).Methods()
		for j := range methods.Len() {
			method := methods.Get(j)
			if startVerb.MatchString(string(method.Name())) {
				check(method.Input(), "the request of "+string(method.FullName()))
			}
		}
	}
	messages := file.Messages()
	for i := range messages.Len() {
		msg := messages.Get(i)
		name := string(msg.Name())
		if startVerb.MatchString(name) && strings.HasSuffix(name, "Request") {
			check(msg, "a request message with a start verb")
		}
	}
	sort.Strings(out)
	return out
}

// hasIdempotencyKey reports whether the message has a singular string field
// idempotency_key.
func hasIdempotencyKey(msg protoreflect.MessageDescriptor) bool {
	field := msg.Fields().ByName(IdempotencyKeyField)
	return field != nil && field.Kind() == protoreflect.StringKind && !field.IsList() && !field.IsMap()
}

// listVerb matches the name of an RPC that lists: List, or a prefix such as
// Admin, then List as a full word. ListenX is not a match.
var listVerb = regexp.MustCompile(`(^|[a-z0-9])List([A-Z0-9]|$)`)

// forbiddenPageFields are the request fields of the old pagination shapes.
// Rule 3 of ADR-0028 allows one shape: page_size and page_token.
var forbiddenPageFields = []protoreflect.Name{"limit", "offset", "cursor"}

// PaginationViolations returns one line for each list RPC of the file that
// breaks rule 3 of ADR-0028 (gibson#995). A list request must not have a
// field limit, offset or cursor. A list request with page_token must have
// page_size, and its response must have next_page_token. The lines are
// sorted. No allowlist exists.
func PaginationViolations(file protoreflect.FileDescriptor) []string {
	var out []string
	services := file.Services()
	for i := range services.Len() {
		methods := services.Get(i).Methods()
		for j := range methods.Len() {
			method := methods.Get(j)
			if !listVerb.MatchString(string(method.Name())) {
				continue
			}
			req, resp := method.Input(), method.Output()
			for _, name := range forbiddenPageFields {
				if req.Fields().ByName(name) != nil {
					out = append(out, fmt.Sprintf("%s: %s (the request of %s) has a field %s",
						file.Path(), req.FullName(), method.FullName(), name))
				}
			}
			if req.Fields().ByName("page_token") == nil {
				continue
			}
			if req.Fields().ByName("page_size") == nil {
				out = append(out, fmt.Sprintf("%s: %s (the request of %s) has page_token and no page_size",
					file.Path(), req.FullName(), method.FullName()))
			}
			if resp.Fields().ByName("next_page_token") == nil {
				out = append(out, fmt.Sprintf("%s: %s (the response of %s) has no next_page_token",
					file.Path(), resp.FullName(), method.FullName()))
			}
		}
	}
	sort.Strings(out)
	return out
}

// ImportPath returns the import path of a proto file of the module. repoRel
// is the path of the file from the repo root, with forward slashes. The
// import path is the path from the proto root that holds the file. ok is
// false when no root holds the file.
func ImportPath(roots []string, repoRel string) (importPath string, ok bool) {
	for _, root := range roots {
		prefix := strings.TrimSuffix(root, "/") + "/"
		if strings.HasPrefix(repoRel, prefix) {
			return strings.TrimPrefix(repoRel, prefix), true
		}
	}
	return "", false
}
