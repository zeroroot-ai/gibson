// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package authz — model_subject_types.go
//
// A ListUsers call carries a subject-type filter, and OpenFGA does NOT reject a
// filter type the relation cannot admit: it finds no possible edges for that
// type and answers with a normal, successful, EMPTY user list. Over the wire
// that is indistinguishable from "this relation genuinely has no holders right
// now", which is the answer a security guard reads as "nobody has it, let the
// request through". Two guards in this repo have shipped that way.
//
// The distinguishing information is not in the response — it is in model.fga.
// So model.fga is embedded here and resolved into "can a subject of type T ever
// appear under (objectType, relation)?", and the client refuses to issue a query
// whose answer is structurally guaranteed to be empty. A refusal is an error the
// caller must handle; an empty list is silently believed.
package authz

import (
	"bufio"
	_ "embed"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// modelDSL is the authoritative OpenFGA model, embedded so the subject-type
// rules cannot drift from the model the FGA store is loaded with. model.fga is
// the same file cmd/gen-fga-model-json renders into the Helm chart.
//
//go:embed model.fga
var modelDSL string

// relationDef is one `define <name>: <body>` decomposed into the three term
// shapes that decide which subject types can appear under the relation.
type relationDef struct {
	// direct are the entries of the `[...]` type-restriction list with any
	// `with <condition>` suffix stripped. Each is a bare object type ("user",
	// "tenant"), a wildcard ("user:*"), or a userset ("team#member").
	direct []string
	// refs are relation names on the SAME type — the `owner` in `[user] or owner`.
	refs []string
	// ttus are tuple-to-userset terms `<relation> from <viaRelation>`, held as
	// {relation, viaRelation}.
	ttus [][2]string
}

// fgaModel maps object type → relation name → its definition.
type fgaModel map[string]map[string]relationDef

// gibsonFGAModel is model.fga parsed once. A parse failure is a programming
// error in the embedded model, so it panics at first use rather than degrading
// every guard that depends on it into "allow".
var gibsonFGAModel = sync.OnceValue(func() fgaModel {
	m := parseFGAModel(modelDSL)
	if len(m) == 0 {
		panic("authz: model.fga parsed to zero types — the embedded model or its parser is broken")
	}
	return m
})

// operatorSplit splits a relation body on the set-algebra operators. "but not"
// is listed first so the alternation prefers it over a bare word boundary.
var operatorSplit = regexp.MustCompile(`\s+(?:but\s+not|or|and)\s+`)

// parseFGAModel reads the DSL into type → relation → relationDef.
//
// The parser is deliberately small and covers exactly the OpenFGA 1.1 grammar
// model.fga uses: one `type <name>` header per line at column 0, one
// `define <name>: <body>` per line, `#`-prefixed comment lines. It does not
// need to evaluate the model — only to know which terms a relation is built
// from.
func parseFGAModel(dsl string) fgaModel {
	out := fgaModel{}
	var currentType string
	scanner := bufio.NewScanner(strings.NewReader(dsl))
	for scanner.Scan() {
		line := scanner.Text()
		trim := strings.TrimSpace(line)
		// Comments are only ever whole lines here. A "#" is NOT stripped
		// inline: usersets ("[team#member]") use it as syntax.
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.HasPrefix(line, "type ") {
			currentType = strings.TrimSpace(strings.TrimPrefix(trim, "type"))
			if _, seen := out[currentType]; !seen {
				out[currentType] = map[string]relationDef{}
			}
			continue
		}
		if !strings.HasPrefix(trim, "define ") || currentType == "" {
			continue
		}
		rest := strings.TrimPrefix(trim, "define ")
		name, body, ok := strings.Cut(rest, ":")
		if !ok {
			continue
		}
		out[currentType][strings.TrimSpace(name)] = parseRelationBody(body)
	}
	return out
}

// parseRelationBody decomposes `[user, team#admin] or admin from parent` into
// its direct entries, same-type references, and tuple-to-userset terms.
func parseRelationBody(body string) relationDef {
	var def relationDef

	if open := strings.IndexByte(body, '['); open >= 0 {
		if closeOff := strings.IndexByte(body[open:], ']'); closeOff >= 0 {
			list := body[open+1 : open+closeOff]
			for _, entry := range strings.Split(list, ",") {
				entry = strings.TrimSpace(entry)
				// "[user with token_not_revoked]" — the condition does not
				// change which type the subject is.
				if i := strings.Index(entry, " with "); i >= 0 {
					entry = strings.TrimSpace(entry[:i])
				}
				if entry != "" {
					def.direct = append(def.direct, entry)
				}
			}
			body = body[:open] + " " + body[open+closeOff+1:]
		}
	}

	// Parentheses only group; every operator this model uses is a union or an
	// intersection/difference, and for "which subject types can appear" a union
	// over all operands is the safe over-approximation: it can only make the
	// guard more permissive, never wrongly reject a working caller.
	body = strings.NewReplacer("(", " ", ")", " ").Replace(body)
	for _, term := range operatorSplit.Split(body, -1) {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		if rel, via, isTTU := strings.Cut(term, " from "); isTTU {
			def.ttus = append(def.ttus, [2]string{strings.TrimSpace(rel), strings.TrimSpace(via)})
			continue
		}
		def.refs = append(def.refs, term)
	}
	return def
}

// admitsSubjectType reports whether a subject of type userType can appear in a
// ListUsers answer for (objectType, relation).
//
// It follows the same edges OpenFGA's resolver does: direct type restrictions,
// usersets (a `[team#member]` restriction admits every type team#member admits,
// which is why component.team_write_disabled DOES admit "user"), same-type
// references, and tuple-to-userset terms.
//
// An unknown type or relation is an error, not a false: the caller has named
// something model.fga does not define, and answering "no" would let a drifted
// call site read as a deliberate refusal.
func (m fgaModel) admitsSubjectType(objectType, relation, userType string, seen map[string]bool) (bool, error) {
	key := objectType + "#" + relation
	if seen[key] {
		// Already on this traversal: either a cycle, or a node that already
		// resolved false (a true would have returned before we got back here).
		return false, nil
	}
	seen[key] = true

	def, err := m.lookup(objectType, relation)
	if err != nil {
		return false, err
	}

	for _, entry := range def.direct {
		typ, usersetRel, isUserset := strings.Cut(entry, "#")
		typ = strings.TrimSuffix(typ, ":*")
		if !isUserset {
			if typ == userType {
				return true, nil
			}
			continue
		}
		ok, err := m.admitsSubjectType(typ, usersetRel, userType, seen)
		if err != nil || ok {
			return ok, err
		}
	}
	for _, ref := range def.refs {
		ok, err := m.admitsSubjectType(objectType, ref, userType, seen)
		if err != nil || ok {
			return ok, err
		}
	}
	for _, ttu := range def.ttus {
		viaDef, err := m.lookup(objectType, ttu[1])
		if err != nil {
			return false, err
		}
		for _, entry := range viaDef.direct {
			viaType, _, isUserset := strings.Cut(entry, "#")
			if isUserset {
				continue // a TTU traverses object types, not usersets
			}
			ok, err := m.admitsSubjectType(viaType, ttu[0], userType, seen)
			if err != nil || ok {
				return ok, err
			}
		}
	}
	return false, nil
}

func (m fgaModel) lookup(objectType, relation string) (relationDef, error) {
	rels, ok := m[objectType]
	if !ok {
		return relationDef{}, fmt.Errorf("model.fga defines no type %q", objectType)
	}
	def, ok := rels[relation]
	if !ok {
		return relationDef{}, fmt.Errorf("model.fga type %q has no relation %q", objectType, relation)
	}
	return def, nil
}

// requireSubjectType refuses a ListUsers query whose subject-type filter
// model.fga says can never match.
//
// This is the control that makes a mistyped listing loud. OpenFGA answers such
// a query with an empty list and no error (see the package comment), so without
// this the caller cannot tell "nobody holds this relation" from "this query was
// incapable of returning anything" — and a guard written on the first reading
// passes unconditionally under the second.
func requireSubjectType(objectType, relation, userType string) error {
	admits, err := gibsonFGAModel().admitsSubjectType(objectType, relation, userType, map[string]bool{})
	if err != nil {
		return &FgaError{
			Sentinel: ErrInvalidArgument,
			Message:  fmt.Sprintf("ListUsers(%s, %s) with subject type %q: %v", objectType, relation, userType, err),
		}
	}
	if !admits {
		return &FgaError{
			Sentinel: ErrInvalidArgument,
			Message: fmt.Sprintf(
				"ListUsers(%s, %s) with subject type %q can never match: model.fga does not admit %q under that relation, so OpenFGA would answer with an empty list and no error — refusing rather than reporting \"none\"",
				objectType, relation, userType, userType),
		}
	}
	return nil
}
