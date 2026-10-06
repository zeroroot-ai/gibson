// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package protorules checks that each request message of a daemon-local
// service states its field rules (ADR-0028, rule 1, gibson#696).
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
	"sort"

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
