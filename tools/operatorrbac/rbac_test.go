// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package operatorrbac

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

const markerPrefix = "+kubebuilder:rbac:"

// operators are the operators that ship a generated ClusterRole.
var operators = []string{"connector", "platform", "tenant"}

// minMarkers is a floor on the markers each operator must yield. A scan that
// finds none would compare an empty set with an empty file and pass.
const minMarkers = 5

// triple is one permission: a verb on a resource of an API group. namespace is
// empty for a cluster-wide grant, and names is the sorted, comma-joined
// resourceNames, or empty for every object of the resource.
type triple struct{ namespace, group, resource, names, verb string }

func (t triple) String() string {
	g := t.group
	if g == "" {
		g = `""`
	}
	out := fmt.Sprintf("%s on %s/%s", t.verb, g, t.resource)
	if t.names != "" {
		out += " named " + t.names
	}
	if t.namespace != "" {
		out += " in namespace " + t.namespace
	}
	return out
}

// scan reads every non-test Go file under dir. It returns the permissions of
// the markers that controller-gen reads, and the position of each marker that
// it ignores because the marker stands in the doc comment of a type.
func scan(t *testing.T, dir string) (granted map[triple]bool, markers int, ignored []string) {
	t.Helper()
	granted = map[triple]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		typeDocs := map[*ast.CommentGroup]bool{}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			typeDocs[gd.Doc] = true
			for _, spec := range gd.Specs {
				typeDocs[spec.(*ast.TypeSpec).Doc] = true
			}
		}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
				rest, ok := strings.CutPrefix(text, markerPrefix)
				if !ok {
					continue
				}
				pos := fset.Position(c.Pos())
				if typeDocs[cg] {
					ignored = append(ignored, fmt.Sprintf("%s:%d", pos.Filename, pos.Line))
					continue
				}
				ts, err := parseMarker(rest)
				if err != nil {
					return fmt.Errorf("%s:%d: %w", pos.Filename, pos.Line, err)
				}
				markers++
				for _, tr := range ts {
					granted[tr] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan %s: %v", dir, err)
	}
	return granted, markers, ignored
}

// parseMarker expands "groups=a;b,resources=x;y,verbs=get;list" into its
// permissions. It refuses a key it does not know: a marker with a namespace,
// a resource name or a URL means something this comparison does not model,
// and a silent skip would let the guard pass on a role it did not check.
func parseMarker(body string) ([]triple, error) {
	fields := map[string][]string{}
	for _, part := range strings.Split(body, ",") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("rbac marker field %q has no value", part)
		}
		switch key {
		case "groups", "resources", "verbs", "namespace", "resourceNames":
		default:
			return nil, fmt.Errorf("rbac marker key %q is not modelled by this guard; extend parseMarker before using it", key)
		}
		for _, v := range strings.Split(value, ";") {
			v = strings.Trim(v, `"`)
			if key == "groups" && v == "core" {
				// controller-gen writes the core API group as "".
				v = ""
			}
			fields[key] = append(fields[key], v)
		}
	}
	for _, key := range []string{"groups", "resources", "verbs"} {
		if len(fields[key]) == 0 {
			return nil, fmt.Errorf("rbac marker %q has no %s", body, key)
		}
	}
	if len(fields["namespace"]) > 1 {
		return nil, fmt.Errorf("rbac marker %q names more than one namespace", body)
	}
	namespace := ""
	if len(fields["namespace"]) == 1 {
		namespace = fields["namespace"][0]
	}
	names := append([]string(nil), fields["resourceNames"]...)
	sort.Strings(names)
	joined := strings.Join(names, ",")
	var out []triple
	for _, g := range fields["groups"] {
		for _, r := range fields["resources"] {
			for _, v := range fields["verbs"] {
				out = append(out, triple{namespace, g, r, joined, v})
			}
		}
	}
	return out, nil
}

// rolePath is the generated ClusterRole, relative to an operator's root.
const rolePath = "config/rbac/role.yaml"

// roleTriples reads the permissions of the generated roles of the operator at
// root.
func roleTriples(t *testing.T, root string) map[triple]bool {
	t.Helper()
	path := filepath.Join(root, rolePath)
	raw, err := fs.ReadFile(os.DirFS(root), rolePath)
	if err != nil {
		t.Fatalf("read %s: %v (generate it with `make -C %s manifests`)", path, err, root)
	}
	out, err := parseRoles(raw)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return out
}

// parseRoles reads each document of a generated role file: a ClusterRole gives
// cluster-wide permissions, and a Role gives permissions in its namespace.
func parseRoles(raw []byte) (map[triple]bool, error) {
	out := map[triple]bool{}
	docs := 0
	for _, doc := range strings.Split(string(raw), "\n---\n") {
		if strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(doc), "---")) == "" {
			continue
		}
		var role struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Rules []struct {
				APIGroups       []string `json:"apiGroups"`
				Resources       []string `json:"resources"`
				Verbs           []string `json:"verbs"`
				ResourceNames   []string `json:"resourceNames"`
				NonResourceURLs []string `json:"nonResourceURLs"`
			} `json:"rules"`
		}
		if err := yaml.Unmarshal([]byte(doc), &role); err != nil {
			return nil, fmt.Errorf("parse: %w", err)
		}
		namespace := ""
		switch role.Kind {
		case "ClusterRole":
		case "Role":
			namespace = role.Metadata.Namespace
			if namespace == "" {
				return nil, errors.New("a Role names no namespace")
			}
		default:
			return nil, fmt.Errorf("kind = %q, want ClusterRole or Role", role.Kind)
		}
		docs++
		for _, rule := range role.Rules {
			if len(rule.NonResourceURLs) > 0 {
				return nil, errors.New("a rule uses nonResourceURLs, which this guard does not model")
			}
			names := append([]string(nil), rule.ResourceNames...)
			sort.Strings(names)
			joined := strings.Join(names, ",")
			for _, g := range rule.APIGroups {
				for _, r := range rule.Resources {
					for _, v := range rule.Verbs {
						out[triple{namespace, g, r, joined, v}] = true
					}
				}
			}
		}
	}
	if docs == 0 {
		return nil, errors.New("no role in the file")
	}
	return out, nil
}

func diff(a, b map[triple]bool) []string {
	var out []string
	for tr := range a {
		if !b[tr] {
			out = append(out, tr.String())
		}
	}
	sort.Strings(out)
	return out
}

// TestGeneratedRoleMatchesTheMarkers is the guard. For each operator, every
// marker is one that controller-gen reads, and role.yaml grants exactly the
// permissions that the markers state.
func TestGeneratedRoleMatchesTheMarkers(t *testing.T) {
	for _, op := range operators {
		t.Run(op, func(t *testing.T) {
			root := filepath.Join("..", "..", "operators", op)
			granted, markers, ignored := scan(t, root)
			for _, pos := range ignored {
				t.Errorf("%s: this rbac marker is in the doc comment of a type, where controller-gen ignores it. Move it above a function, apart from the function's doc comment", pos)
			}
			if markers < minMarkers {
				t.Fatalf("found %d rbac marker(s) under %s, want at least %d: the scan is not looking at the operator", markers, root, minMarkers)
			}
			role := roleTriples(t, root)
			for _, missing := range diff(granted, role) {
				t.Errorf("role.yaml does not grant %s, which a marker states. Run `make -C operators/%s manifests`", missing, op)
			}
			for _, extra := range diff(role, granted) {
				t.Errorf("role.yaml grants %s, which no marker states. Run `make -C operators/%s manifests`", extra, op)
			}
		})
	}
}

// TestScan_FindsAMarkerInATypeDoc is the failing fixture for the first half
// of the guard: the marker in testdata/typedoc is the shape that left the
// platform operator with no generated role.
func TestScan_FindsAMarkerInATypeDoc(t *testing.T) {
	granted, markers, ignored := scan(t, filepath.Join("testdata", "typedoc"))
	if len(ignored) != 1 || !strings.Contains(ignored[0], "reconciler.go") {
		t.Fatalf("ignored = %v, want the one marker in the type doc of reconciler.go", ignored)
	}
	if markers != 0 || len(granted) != 0 {
		t.Errorf("a marker in a type doc was counted as granted: markers = %d, granted = %v", markers, granted)
	}
}

// TestScan_ReadsAMarkerAboveAFunction is the passing twin: the same marker
// above a function is read, and it expands to the product of its groups,
// resources and verbs. The group "core" is the empty group.
func TestScan_ReadsAMarkerAboveAFunction(t *testing.T) {
	granted, markers, ignored := scan(t, filepath.Join("testdata", "clean"))
	if len(ignored) != 0 || markers != 1 {
		t.Fatalf("markers = %d, ignored = %v; want one marker read and none ignored", markers, ignored)
	}
	// A marker grants every verb on every resource in every group it names.
	for _, group := range []string{"example.io", ""} {
		for _, resource := range []string{"widgets", "secrets"} {
			for _, verb := range []string{"get", "list"} {
				if want := (triple{"", group, resource, "", verb}); !granted[want] {
					t.Errorf("missing %s", want)
				}
			}
		}
	}
	if len(granted) != 8 {
		t.Errorf("granted = %v, want eight permissions", granted)
	}
}

// TestParseMarker_RefusesWhatItDoesNotModel: an unknown key, and a marker
// with no verbs, are errors and never a silent skip.
func TestParseMarker_RefusesWhatItDoesNotModel(t *testing.T) {
	for _, body := range []string{
		"groups=example.io,resources=widgets,verbs=get,url=/healthz",
		"groups=example.io,resources=widgets,verbs=get,namespace=a;b",
		"groups=example.io,resources=widgets",
		"groups=example.io,resources,verbs=get",
	} {
		if got, err := parseMarker(body); err == nil {
			t.Errorf("parseMarker(%q) = %v, want an error", body, got)
		}
	}
}

// A marker with a namespace and resource names grants only that, and the role
// file must say the same. A ClusterRole that grants get on every DaemonSet, where
// the marker names one DaemonSet in one namespace, is a difference (gibson#1580).
func TestRoles_AMarkerWithANamespaceAndNamesIsNotMetByAClusterRole(t *testing.T) {
	marker, err := parseMarker("groups=apps,namespace=kube-system,resources=daemonsets,resourceNames=cilium,verbs=get")
	if err != nil {
		t.Fatal(err)
	}
	granted := map[triple]bool{}
	for _, tr := range marker {
		granted[tr] = true
	}

	namespaced, err := parseRoles([]byte(`kind: ClusterRole
metadata:
  name: manager
rules: []
---
kind: Role
metadata:
  name: manager
  namespace: kube-system
rules:
- apiGroups: [apps]
  resources: [daemonsets]
  resourceNames: [cilium]
  verbs: [get]
`))
	if err != nil {
		t.Fatalf("parseRoles: %v", err)
	}
	if d := diff(granted, namespaced); len(d) != 0 {
		t.Errorf("a Role with the same namespace and names must meet the marker: %v", d)
	}
	if d := diff(namespaced, granted); len(d) != 0 {
		t.Errorf("a Role with the same namespace and names must grant no more: %v", d)
	}

	wide, err := parseRoles([]byte(`kind: ClusterRole
metadata:
  name: manager
rules:
- apiGroups: [apps]
  resources: [daemonsets]
  verbs: [get]
`))
	if err != nil {
		t.Fatalf("parseRoles: %v", err)
	}
	if d := diff(granted, wide); len(d) == 0 {
		t.Error("a ClusterRole on every DaemonSet was accepted for a marker that names one")
	}
	if d := diff(wide, granted); len(d) == 0 {
		t.Error("a ClusterRole on every DaemonSet was not reported as a grant that no marker states")
	}
}
