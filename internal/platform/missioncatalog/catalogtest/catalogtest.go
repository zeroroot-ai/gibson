// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package catalogtest gives tests one rule for the example value of a catalog
// mission parameter.
//
// A test that renders a mission needs a value for each parameter that renders
// and that it cares about nothing else. Three tests used to hold their own copy
// of the rule that picks it, so a mission that added a typed parameter forced
// three hand edits (gibson#1692). The rule now lives here, and the example value
// lives in the mission's own CUE, in an `@example("...")` attribute on the
// parameter:
//
//	forgeConnector?: "github-fixloop" | "gitlab-fixloop" @example("github-fixloop")
//
// A parameter that the mission declares as a plain `string` needs no attribute.
// Its example is "v-" plus its name. A parameter with any other declaration (an
// enum, a pattern, a number) must carry the attribute, and ExampleParams
// returns an error when it does not.
//
// The package reads the CUE syntax only. It does not import missioncatalog, so
// the tests of missioncatalog itself can import it without a cycle. Only tests
// import it, so no production binary links it.
package catalogtest

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	"cuelang.org/go/cue/ast"
	"cuelang.org/go/cue/parser"
)

// exampleAttr is the name of the attribute that carries an example value.
const exampleAttr = "example"

// ExampleParams returns one example value for each parameter that the mission
// source declares in its top-level `_params`, optional ones included.
//
// It returns an error for a parameter that has a typed declaration and no
// `@example`, because the placeholder for a plain string would not render.
func ExampleParams(source string) (map[string]string, error) {
	file, err := parser.ParseFile("mission.cue", source, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("catalogtest: parse the mission source: %w", err)
	}

	out := map[string]string{}
	var missing []string
	for _, decl := range file.Decls {
		decl, ok := decl.(*ast.Field)
		if !ok || fieldName(decl) != "_params" {
			continue
		}
		body, ok := decl.Value.(*ast.StructLit)
		if !ok {
			return nil, fmt.Errorf("catalogtest: _params is not a struct")
		}
		for _, elt := range body.Elts {
			param, ok := elt.(*ast.Field)
			if !ok {
				continue
			}
			name := fieldName(param)
			if name == "" {
				continue
			}
			value, found, aerr := exampleAttribute(param)
			if aerr != nil {
				return nil, fmt.Errorf("catalogtest: parameter %q: %w", name, aerr)
			}
			switch {
			case found:
				out[name] = value
			case isPlainString(param.Value):
				out[name] = "v-" + name
			default:
				missing = append(missing, name)
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("catalogtest: the typed parameters %s have no @example(\"...\") attribute in the mission source",
			strings.Join(missing, ", "))
	}
	return out, nil
}

// Params is ExampleParams for a test: it stops the test when the source has a
// typed parameter with no example value.
func Params(tb testing.TB, source string) map[string]string {
	tb.Helper()
	out, err := ExampleParams(source)
	if err != nil {
		tb.Fatal(err)
	}
	return out
}

// fieldName returns the name of a field with an identifier or string label, and
// an empty string for any other label.
func fieldName(f *ast.Field) string {
	name, _, err := ast.LabelName(f.Label)
	if err != nil {
		return ""
	}
	return name
}

// exampleAttribute reads the `@example("...")` attribute of a field.
func exampleAttribute(f *ast.Field) (string, bool, error) {
	for _, attr := range f.Attrs {
		name, contents := attr.Split()
		if name != exampleAttr {
			continue
		}
		body := strings.TrimSpace(contents)
		value, err := strconv.Unquote(body)
		if err != nil {
			return "", false, fmt.Errorf("@%s must hold one quoted string, got %s", exampleAttr, body)
		}
		if strings.TrimSpace(value) == "" {
			return "", false, fmt.Errorf("@%s must not be blank", exampleAttr)
		}
		return value, true, nil
	}
	return "", false, nil
}

// isPlainString reports whether the declaration is exactly `string`.
func isPlainString(v ast.Expr) bool {
	id, ok := v.(*ast.Ident)
	return ok && id.Name == "string"
}
