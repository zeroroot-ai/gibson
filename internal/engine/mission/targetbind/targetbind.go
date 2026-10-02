// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package targetbind resolves a mission definition's {{target.*}} placeholders
// against the target the run names.
//
// A catalog mission says `input: {host: "{{target.domain}}"}` and its comment
// says the host is "bound from the mission's target at submit — never from a
// parameter, so a caller cannot point a scan at a host the tenant has not
// registered". That sentence described a mechanism that did not exist: nothing
// substituted anything, so the dispatched tool received the eleven characters
// "{{target.domain}}" as its hostname and the scan ran against nothing. The
// catalog test asserted only that the placeholder was present (gibson#495).
//
// Binding happens server-side, from the target record the daemon has already
// resolved and whose tenant ownership it has already checked. The definition
// never gets to name a host, which is what makes the comment's promise true.
package targetbind

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Prefix is the namespace every binding this package resolves lives under. A
// placeholder outside it is left alone, so another binding namespace can be
// added later without this package claiming its names.
const Prefix = "target."

// Open and Close delimit a placeholder.
const (
	Open  = "{{"
	Close = "}}"
)

// Bindings returns the resolved value of every {{target.*}} name, for one
// target. The map is the whole vocabulary: a name absent from it is unknown,
// and a name present with an empty value is known but unset on this target.
//
// Both cases refuse at bind time. An unknown name is a typo in the definition;
// an empty one is a target that cannot answer what the mission asks of it. A
// tool that received either would run against the literal text or against
// nothing, and report a clean result for a scan that never happened.
func Bindings(t *types.Target) map[string]string {
	raw := targetURL(t)
	host, domain := hostAndDomain(raw)
	return map[string]string{
		"target.id":     t.ID.String(),
		"target.name":   t.Name,
		"target.type":   t.Type,
		"target.url":    raw,
		"target.host":   host,   // host[:port], what a dialer takes
		"target.domain": domain, // host alone, what a certificate or a scanner takes
	}
}

// targetURL is the target's endpoint, from whichever field carries it.
// types.Target keeps URL and Connection["url"] in step for new records, and
// older records set only one, so both are read (mission_manager.runTargetRef
// reads them the same way).
func targetURL(t *types.Target) string {
	if t.URL != "" {
		return t.URL
	}
	if u, ok := t.Connection["url"].(string); ok {
		return u
	}
	return ""
}

// hostAndDomain splits an endpoint into host[:port] and host.
//
// A bare "host:port" or "host" is accepted as well as a full URL, because a
// target registered by a cluster endpoint carries no scheme.
func hostAndDomain(raw string) (host, domain string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		host = u.Host
	} else {
		host = raw
	}
	domain = host
	if h, _, err := net.SplitHostPort(host); err == nil {
		domain = h
	}
	return host, domain
}

// Bind returns a copy of def with every {{target.*}} placeholder in every
// string field replaced by its bound value.
//
// Every string field, found by walking the message, not a list of the fields
// that carry a placeholder today. A list would have to be extended with each
// new node config, and the one that got missed would dispatch the placeholder
// verbatim — the defect this package exists to stop, reintroduced quietly.
//
// def is not modified. An error names every placeholder that could not be
// resolved, with the field it sits in, and nothing is bound: a half-bound
// definition is a run that does part of its work against the wrong host.
func Bind(def *missionv1.MissionDefinition, t *types.Target) (*missionv1.MissionDefinition, error) {
	if def == nil {
		return nil, errors.New("targetbind: nil mission definition")
	}
	if t == nil {
		return nil, fmt.Errorf("targetbind: mission %q names no target to bind against", def.GetId())
	}
	bindings := Bindings(t)

	out, ok := proto.Clone(def).(*missionv1.MissionDefinition)
	if !ok {
		return nil, fmt.Errorf("targetbind: clone of mission %q is not a MissionDefinition", def.GetId())
	}

	var problems []string
	walkStrings(out.ProtoReflect(), "", func(path, in string) (string, bool) {
		bound, errs := substitute(in, bindings)
		for _, e := range errs {
			problems = append(problems, fmt.Sprintf("%s: %s", path, e))
		}
		return bound, len(errs) == 0
	})
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("targetbind: mission %q has unresolved bindings against target %q:\n  %s",
			def.GetId(), t.Name, strings.Join(problems, "\n  "))
	}
	return out, nil
}

// substitute replaces every {{target.*}} in s, collecting one message per
// placeholder it cannot resolve. A placeholder in another namespace is left in
// place and is not an error here; Unbound reports what survived.
func substitute(s string, bindings map[string]string) (bound string, errs []string) {
	if !strings.Contains(s, Open) {
		return s, nil
	}
	var b strings.Builder
	rest := s
	for {
		i := strings.Index(rest, Open)
		if i < 0 {
			b.WriteString(rest)
			break
		}
		j := strings.Index(rest[i:], Close)
		if j < 0 { // an unterminated "{{" is text, not a placeholder
			b.WriteString(rest)
			break
		}
		j += i
		name := strings.TrimSpace(rest[i+len(Open) : j])
		b.WriteString(rest[:i])
		switch {
		case !strings.HasPrefix(name, Prefix):
			b.WriteString(rest[i : j+len(Close)]) // not ours
		default:
			value, known := bindings[name]
			switch {
			case !known:
				errs = append(errs, fmt.Sprintf("%s%s%s names no target field (known: %s)",
					Open, name, Close, strings.Join(knownNames(bindings), ", ")))
				b.WriteString(rest[i : j+len(Close)])
			case value == "":
				errs = append(errs, fmt.Sprintf("%s%s%s is empty on this target; register the target with it before running",
					Open, name, Close))
				b.WriteString(rest[i : j+len(Close)])
			default:
				b.WriteString(value)
			}
		}
		rest = rest[j+len(Close):]
	}
	return b.String(), errs
}

func knownNames(bindings map[string]string) []string {
	out := make([]string, 0, len(bindings))
	for k := range bindings {
		out = append(out, Open+k+Close)
	}
	sort.Strings(out)
	return out
}

// Unbound returns every placeholder still present in def, with the field path
// it sits in. The dispatcher calls it as a last check: a placeholder that
// reaches a tool is sent as literal text, and the tool reports a clean run
// against a host that does not exist.
func Unbound(m proto.Message) []string {
	if m == nil {
		return nil
	}
	var found []string
	walkStrings(m.ProtoReflect(), "", func(path, in string) (string, bool) {
		for _, name := range placeholders(in) {
			found = append(found, fmt.Sprintf("%s: %s%s%s", path, Open, name, Close))
		}
		return in, false
	})
	sort.Strings(found)
	return found
}

// placeholders lists the names inside every {{...}} in s.
func placeholders(s string) []string {
	var out []string
	rest := s
	for {
		i := strings.Index(rest, Open)
		if i < 0 {
			return out
		}
		j := strings.Index(rest[i:], Close)
		if j < 0 {
			return out
		}
		j += i
		out = append(out, strings.TrimSpace(rest[i+len(Open):j]))
		rest = rest[j+len(Close):]
	}
}

// walkStrings visits every string in m — scalar fields, repeated entries, and
// map keys and values — and writes back whatever visit returns true for.
//
// Map KEYS are visited too. A node whose input key is built from a placeholder
// is strange, but a key that silently keeps its placeholder while its value
// resolves is stranger, and costs one branch to rule out.
// isForEachTemplate reports whether fd is ForEachNodeConfig.template.
//
// Full-name comparison, so it cannot match a differently-parented field called
// "template" and it breaks loudly if the message is renamed rather than quietly
// binding what it should skip.
func isForEachTemplate(fd protoreflect.FieldDescriptor) bool {
	return fd.FullName() == forEachTemplateField
}

// forEachTemplateField is ForEachNodeConfig.template's fully-qualified name.
const forEachTemplateField protoreflect.FullName = "gibson.mission.v1.ForEachNodeConfig.template"

// BindNode binds one node against one target, for a for_each instance.
//
// Bind() deliberately skips for_each templates, so this is how an instance gets
// its own values: the caller clones the template per item in the source set and
// binds each copy against that item. Returns an error when a placeholder cannot
// be resolved, for the same reason Bind does — a tool handed the literal text
// "{{target.host}}" reports a clean run against a host that does not exist.
func BindNode(n *missionv1.MissionNode, t *types.Target) (*missionv1.MissionNode, error) {
	if n == nil {
		return nil, errors.New("targetbind: nil mission node")
	}
	if t == nil {
		return nil, fmt.Errorf("targetbind: node %q names no target to bind against", n.GetId())
	}
	out, ok := proto.Clone(n).(*missionv1.MissionNode)
	if !ok {
		return nil, fmt.Errorf("targetbind: clone of node %q is not a MissionNode", n.GetId())
	}
	bindings := Bindings(t)
	var problems []string
	// The instance's own body IS bound, including a nested for_each template —
	// which cannot occur, because graph.Project refuses a nested for_each before
	// a run reaches here (gibson#524).
	walkStringsAll(out.ProtoReflect(), "", func(path, in string) (string, bool) {
		bound, errs := substitute(in, bindings)
		for _, e := range errs {
			problems = append(problems, fmt.Sprintf("%s: %s", path, e))
		}
		return bound, len(errs) == 0
	})
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("targetbind: node %q has unresolved bindings against target %q:\n  %s",
			n.GetId(), t.Name, strings.Join(problems, "\n  "))
	}
	return out, nil
}

// walkStringsAll is walkStrings without the for_each-template skip. It exists
// for BindNode, which is binding one instance and must reach every string in it.
func walkStringsAll(m protoreflect.Message, path string, visit func(path, in string) (string, bool)) {
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		at := fd.TextName()
		if path != "" {
			at = path + "." + at
		}
		switch {
		case fd.IsMap():
			walkMap(fd, at, v.Map(), visit)
		case fd.IsList():
			walkList(fd, at, v.List(), visit)
		case fd.Kind() == protoreflect.StringKind:
			if out, ok := visit(at, v.String()); ok {
				m.Set(fd, protoreflect.ValueOfString(out))
			}
		case fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind:
			walkStringsAll(v.Message(), at, visit)
		}
		return true
	})
}

func walkStrings(m protoreflect.Message, path string, visit func(path, in string) (string, bool)) {
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		at := fd.TextName()
		if path != "" {
			at = path + "." + at
		}
		switch {
		case fd.IsMap():
			walkMap(fd, at, v.Map(), visit)
		case fd.IsList():
			walkList(fd, at, v.List(), visit)
		case fd.Kind() == protoreflect.StringKind:
			if out, ok := visit(at, v.String()); ok {
				m.Set(fd, protoreflect.ValueOfString(out))
			}
		case fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind:
			// A for_each template is NOT bound here. Its `{{target.*}}` belong to
			// each instance and are bound per instance against that instance's own
			// target, at projection. Binding them to the mission's primary target
			// here would make every instance of a fan-out scan the first target
			// and report as though it had covered them all — the exact failure the
			// fan-out epic exists to remove (gibson#525).
			//
			// Matched on the descriptor rather than on a field name string: a
			// rename moves this with the proto instead of silently re-enabling the
			// binding.
			if isForEachTemplate(fd) {
				return true
			}
			walkStrings(v.Message(), at, visit)
		}
		return true
	})
}

func walkMap(fd protoreflect.FieldDescriptor, at string, mp protoreflect.Map, visit func(path, in string) (string, bool)) {
	type rekey struct {
		from, to protoreflect.MapKey
		value    protoreflect.Value
	}
	var rekeys []rekey
	mp.Range(func(k protoreflect.MapKey, v protoreflect.Value) bool {
		where := fmt.Sprintf("%s[%v]", at, k.Interface())
		if fd.MapKey().Kind() == protoreflect.StringKind {
			if out, ok := visit(where+" (key)", k.String()); ok && out != k.String() {
				rekeys = append(rekeys, rekey{from: k, to: protoreflect.ValueOfString(out).MapKey(), value: v})
			}
		}
		// Two kinds of the seventeen matter: a placeholder is text, so a number,
		// a bool or an enum has nothing to bind.
		//
		//nolint:exhaustive // staticcheck QF1002/QF1003 require the tagged form
		// for this comparison, and `exhaustive` runs with
		// default-signifies-exhaustive: false, so it demands all seventeen cases
		// of protoreflect.Kind. No switch and no if chain satisfies both. Listing
		// fifteen no-op cases would, and would go stale the next time protobuf
		// adds a kind.
		switch fd.MapValue().Kind() {
		case protoreflect.StringKind:
			if out, ok := visit(where, v.String()); ok {
				mp.Set(k, protoreflect.ValueOfString(out))
			}
		case protoreflect.MessageKind, protoreflect.GroupKind:
			walkStrings(v.Message(), where, visit)
		default:
		}
		return true
	})
	for _, r := range rekeys {
		mp.Clear(r.from)
		mp.Set(r.to, r.value)
	}
}

func walkList(fd protoreflect.FieldDescriptor, at string, list protoreflect.List, visit func(path, in string) (string, bool)) {
	for i := range list.Len() {
		where := fmt.Sprintf("%s[%d]", at, i)
		//nolint:exhaustive // see walkMap: the two linters cannot both be
		// satisfied for a comparison over protoreflect.Kind.
		switch fd.Kind() {
		case protoreflect.StringKind:
			if out, ok := visit(where, list.Get(i).String()); ok {
				list.Set(i, protoreflect.ValueOfString(out))
			}
		case protoreflect.MessageKind, protoreflect.GroupKind:
			walkStrings(list.Get(i).Message(), where, visit)
		default:
		}
	}
}

// UnboundTarget returns every {{target.*}} placeholder still present in m.
//
// The dispatcher calls it as the last check before a node becomes work. A
// placeholder that reaches a tool is sent as literal text, and the tool then
// reports a clean run against a host that does not exist — the quietest way for
// a scan to find nothing. Refusing the node is the loud alternative.
//
// Only the target namespace, because that is the only namespace this package
// resolves. A placeholder someone else owns is not this check's business.
func UnboundTarget(m proto.Message) []string {
	var out []string
	for _, s := range Unbound(m) {
		if i := strings.Index(s, Open); i >= 0 && strings.HasPrefix(s[i+len(Open):], Prefix) {
			out = append(out, s)
		}
	}
	return out
}

// Names is the vocabulary: every {{target.*}} name this package resolves,
// sorted. Derived from Bindings so there is one definition of the vocabulary
// and a new field cannot be added to one and missed in the other.
//
// Validation uses it to refuse a typo at definition registration, where the
// author is still looking at the source, rather than at run submit.
func Names() []string {
	names := make([]string, 0, 8)
	for k := range Bindings(&types.Target{}) {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Known reports whether name is in the vocabulary. name carries no braces.
func Known(name string) bool {
	_, ok := Bindings(&types.Target{})[strings.TrimSpace(name)]
	return ok
}
