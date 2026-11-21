// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build test_fixtures

package daemon

// This guard keeps the method policy of the exit-test runner (e2ePeerMethodPolicies)
// in step with the exit tests. It reads the code of the tests and no list of its
// own.
//
// 1. It reads the exit workflows (.github/workflows/exit-test-*.yml). Each call of
//    run-e2e-job.sh names the tests that the job runs, and the identity that it
//    runs them as (the runner, or the member when E2E_RUNNER_COMPONENT=e2e-member).
// 2. It follows the calls by name from each of those tests through the functions
//    of tests/e2e and tests/e2e/helpers.
// 3. It parses those functions with go/ast and collects each call on a generated
//    gRPC client. It maps each call to its full method name with the
//    FullMethodName constants of the generated *_grpc.pb.go files.
// 4. It fails for each collected method that the policy of the identity does not
//    allow.
//
// A call is a call on a client in one of two ways. The receiver is a variable
// that holds the result of a New<Service>Client call, or the call passes a
// literal of the request type <Method>Request of a generated package.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// e2eIdentity is the identity that a job runs its tests as.
type e2eIdentity int

const (
	e2eAsRunner e2eIdentity = iota
	e2eAsMember
)

// e2eJob is one call of run-e2e-job.sh in a workflow.
type e2eJob struct {
	workflow string
	tests    []string
	identity e2eIdentity
}

var (
	runJobRe  = regexp.MustCompile(`run-e2e-job\.sh\s+\S+\s+'?(Test[^'\s]*)'?`)
	stepNameR = regexp.MustCompile(`^\s*- (name|uses):`)
	// A Job manifest that a workflow applies itself passes the test pattern as
	// args: ["-test.run", "TestX", ...].
	manifestRunRe = regexp.MustCompile(`"-test\.run",\s*"(Test[^"]*)"`)
	// A workflow that compiles the suite builds a test binary of tests/e2e.
	buildsSuiteRe = regexp.MustCompile(`go test\b[^\n]*\s-c\b|-o\s+\S*e2e\.test`)
)

// testNamesOf splits a -test.run pattern into the names of its tests.
func testNamesOf(pattern string) []string {
	var tests []string
	for _, alt := range strings.Split(pattern, "|") {
		alt = strings.Trim(alt, "^$()")
		if alt != "" {
			tests = append(tests, alt)
		}
	}
	return tests
}

// e2eJobsOf reads the jobs of one workflow text. A job is one call of
// run-e2e-job.sh, or one Job manifest with a -test.run argument.
func e2eJobsOf(workflow, text string) []e2eJob {
	lines := strings.Split(text, "\n")
	var jobs []e2eJob
	for i, line := range lines {
		if m := runJobRe.FindStringSubmatch(line); m != nil {
			// The command may continue over lines with a backslash, so the
			// identity variable can sit on an earlier line of the same step.
			identity := e2eAsRunner
			for j := i; j >= 0; j-- {
				if strings.Contains(lines[j], "E2E_RUNNER_COMPONENT=e2e-member") {
					identity = e2eAsMember
				}
				if stepNameR.MatchString(lines[j]) {
					break
				}
			}
			jobs = append(jobs, e2eJob{workflow: workflow, tests: testNamesOf(m[1]), identity: identity})
			continue
		}
		if m := manifestRunRe.FindStringSubmatch(line); m != nil {
			// The identity is the service account of the pod of the same
			// manifest. It sits above the args, in the same pod spec.
			identity := e2eAsRunner
			for j := i; j >= 0; j-- {
				line := strings.TrimSpace(lines[j])
				if strings.HasPrefix(line, "serviceAccountName:") {
					if strings.Contains(line, "e2e-member") {
						identity = e2eAsMember
					}
					break
				}
				// The start of the manifest: the pod spec is below it.
				if strings.HasPrefix(line, "kind:") || line == "---" {
					break
				}
			}
			jobs = append(jobs, e2eJob{workflow: workflow, tests: testNamesOf(m[1]), identity: identity})
		}
	}
	return jobs
}

// hasSecretsBinary reports whether a workflow runs another test binary through
// run-e2e-job.sh (E2E_RUNNER_BINARY). The cluster workflow does so for the
// secrets suite, which this guard does not read.
func hasSecretsBinary(text string) bool {
	return strings.Contains(text, "E2E_RUNNER_BINARY")
}

// buildsSuite reports whether a workflow builds the e2e test binary. A comment
// does not count.
func buildsSuite(text string) bool {
	var code []string
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			code = append(code, line)
		}
	}
	return buildsSuiteRe.MatchString(strings.Join(code, "\n"))
}

// generatedMethods maps the import path of a generated package to its methods:
// service, then method, then the full method name.
type generatedMethods map[string]map[string]map[string]string

var fullMethodConstRe = regexp.MustCompile(`^(\w+?)_(\w+)_FullMethodName$`)

// loadGeneratedMethods reads the FullMethodName constants of the *_grpc.pb.go
// files in the directory of each import path.
func loadGeneratedMethods(t *testing.T, repoRoot string, importPaths []string) generatedMethods {
	t.Helper()
	out := generatedMethods{}
	if len(importPaths) == 0 {
		return out
	}
	args := append([]string{"list", "-f", "{{.ImportPath}} {{.Dir}}"}, importPaths...)
	cmd := exec.Command("go", args...)
	cmd.Dir = repoRoot
	raw, err := cmd.Output()
	require.NoError(t, err, "go list of the imports of the e2e files")
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		ip, dir, ok := strings.Cut(line, " ")
		require.True(t, ok, "go list line %q", line)
		files, err := filepath.Glob(filepath.Join(dir, "*_grpc.pb.go"))
		require.NoError(t, err)
		for _, f := range files {
			af, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
			require.NoError(t, err, "parse %s", f)
			ast.Inspect(af, func(n ast.Node) bool {
				vs, ok := n.(*ast.ValueSpec)
				if !ok {
					return true
				}
				for i, name := range vs.Names {
					m := fullMethodConstRe.FindStringSubmatch(name.Name)
					lit, isLit := vs.Values[i].(*ast.BasicLit)
					if m == nil || !isLit {
						continue
					}
					full, uerr := strconv.Unquote(lit.Value)
					require.NoError(t, uerr)
					if out[ip] == nil {
						out[ip] = map[string]map[string]string{}
					}
					if out[ip][m[1]] == nil {
						out[ip][m[1]] = map[string]string{}
					}
					out[ip][m[1]][m[2]] = full
				}
				return true
			})
		}
	}
	return out
}

// e2eImports returns the import path of each import of the files, for the paths
// that can hold generated code (those that contain "/gen/" or "/api/gibson/").
func e2eImports(files map[string]*ast.File) []string {
	seen := map[string]bool{}
	for _, f := range files {
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if strings.Contains(p, "/gen/") || strings.Contains(p, "/api/gibson/") {
				seen[p] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// importAliases maps the name of each import of a file to its path.
func importAliases(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		name := path.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		out[name] = p
	}
	return out
}

var newClientRe = regexp.MustCompile(`^New(\w+)Client$`)

// collectClientCalls returns the full method name of each call on a generated
// client in the files. The key is the method, and the value is where it is
// called from.
func collectClientCalls(files map[string]*ast.File, gen generatedMethods) map[string][]string {
	calls := map[string][]string{}
	// The fields of a struct that hold a client, from every file: a test calls
	// clients.Daemon.X, and the struct is in a helper file.
	type client struct{ pkg, service string }
	fieldVars := map[string][]client{}
	for _, f := range files {
		aliases := importAliases(f)
		ast.Inspect(f, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok {
				return true
			}
			for _, fld := range st.Fields.List {
				ts, ok := fld.Type.(*ast.SelectorExpr)
				if !ok || !strings.HasSuffix(ts.Sel.Name, "Client") {
					continue
				}
				if pkgID, ok := ts.X.(*ast.Ident); ok {
					for _, nm := range fld.Names {
						fieldVars[nm.Name] = append(fieldVars[nm.Name],
							client{pkg: aliases[pkgID.Name], service: strings.TrimSuffix(ts.Sel.Name, "Client")})
					}
				}
			}
			return true
		})
	}
	for name, f := range files {
		aliases := importAliases(f)
		// The variables that hold a client, with their service and package.
		vars := map[string][]client{}
		for k, v := range fieldVars {
			vars[k] = append(vars[k], v...)
		}
		noteClient := func(lhs []ast.Expr, rhs []ast.Expr) {
			for i, l := range lhs {
				id, ok := l.(*ast.Ident)
				if !ok || i >= len(rhs) {
					continue
				}
				call, ok := rhs[i].(*ast.CallExpr)
				if !ok {
					continue
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				pkgID, ok := sel.X.(*ast.Ident)
				if !ok {
					continue
				}
				if m := newClientRe.FindStringSubmatch(sel.Sel.Name); m != nil {
					vars[id.Name] = append(vars[id.Name], client{pkg: aliases[pkgID.Name], service: m[1]})
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.Field:
				// A parameter or a field of a client type: pkg.<Service>Client.
				if ts, ok := s.Type.(*ast.SelectorExpr); ok && strings.HasSuffix(ts.Sel.Name, "Client") {
					if pkgID, ok := ts.X.(*ast.Ident); ok {
						for _, nm := range s.Names {
							vars[nm.Name] = append(vars[nm.Name], client{pkg: aliases[pkgID.Name], service: strings.TrimSuffix(ts.Sel.Name, "Client")})
						}
					}
				}
			case *ast.AssignStmt:
				noteClient(s.Lhs, s.Rhs)
			case *ast.ValueSpec:
				lhs := make([]ast.Expr, len(s.Names))
				for i, nm := range s.Names {
					lhs[i] = nm
				}
				noteClient(lhs, s.Values)
			}
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			method := sel.Sel.Name
			// A receiver that is a variable or a field of a client. The last name
			// of the receiver counts: c.X, p.comp.X and clients.Daemon.X. A name
			// can hold two clients in one file, so each one is tried. A miss falls
			// through to the check of the request literal.
			recv := ""
			switch r := sel.X.(type) {
			case *ast.Ident:
				recv = r.Name
			case *ast.SelectorExpr:
				recv = r.Sel.Name
			}
			found := false
			for _, c := range vars[recv] {
				if full, ok := gen[c.pkg][c.service][method]; ok {
					calls[full] = append(calls[full], name)
					found = true
				}
			}
			if found {
				return true
			}
			// A literal of the request type of the method, as an argument.
			for _, arg := range call.Args {
				if u, ok := arg.(*ast.UnaryExpr); ok {
					arg = u.X
				}
				lit, ok := arg.(*ast.CompositeLit)
				if !ok {
					continue
				}
				ts, ok := lit.Type.(*ast.SelectorExpr)
				if !ok || ts.Sel.Name != method+"Request" {
					continue
				}
				pkgID, ok := ts.X.(*ast.Ident)
				if !ok {
					continue
				}
				for _, byMethod := range gen[aliases[pkgID.Name]] {
					if full, ok := byMethod[method]; ok {
						calls[full] = append(calls[full], name)
					}
				}
			}
			return true
		})
	}
	return calls
}

// e2eMissing returns the methods of calls that the policy does not allow.
func e2eMissing(policy map[string]bool, calls map[string][]string) []string {
	var out []string
	for m, where := range calls {
		if !policy[m] {
			out = append(out, fmt.Sprintf("%s (called in %s)", m, strings.Join(dedupe(where), ", ")))
		}
	}
	sort.Strings(out)
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// gibsonRoot returns the root of the repository.
func gibsonRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Join(wd, "..", "..", "..")
}

func parseFiles(t *testing.T, paths []string) map[string]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	for _, p := range paths {
		f, err := parser.ParseFile(fset, p, nil, 0)
		require.NoError(t, err, "parse %s", p)
		out[p] = f
	}
	return out
}

// The runner and the member may call each method that the tests of their jobs
// call on a generated client. A test that grows a call outside the policy fails
// here, and no longer on the cluster (gibson#1591: #1585 added two calls, a hand
// copy of the list still passed, and the exit test failed on main).
func TestE2EPeerPolicy_AllowsEachCallOfTheExitTests(t *testing.T) {
	root := gibsonRoot(t)
	workflows, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "exit-test-*.yml"))
	require.NoError(t, err)
	require.NotEmpty(t, workflows, "the exit workflows")

	var jobs []e2eJob
	for _, w := range workflows {
		raw, err := os.ReadFile(w)
		require.NoError(t, err)
		found := e2eJobsOf(filepath.Base(w), string(raw))
		// A workflow that builds the suite and starts no job that the guard
		// reads has changed how it starts its tests. It must not drop out.
		if buildsSuite(string(raw)) && !hasSecretsBinary(string(raw)) {
			require.NotEmpty(t, found, "%s builds the e2e test binary and the guard finds no job in it", filepath.Base(w))
		}
		jobs = append(jobs, found...)
	}
	require.NotEmpty(t, jobs, "no exit workflow calls run-e2e-job.sh, so the guard would check nothing")

	// Every function of the package of the tests and of its helpers. The tests
	// reach the RPCs through these, so the guard follows the calls by name.
	files, err := filepath.Glob(filepath.Join(root, "tests", "e2e", "*_test.go"))
	require.NoError(t, err)
	helperFiles, err := filepath.Glob(filepath.Join(root, "tests", "e2e", "helpers", "*.go"))
	require.NoError(t, err)
	for _, h := range helperFiles {
		if !strings.HasSuffix(h, "_test.go") {
			files = append(files, h)
		}
	}
	parsed := parseFiles(t, files)

	policies := e2ePeerMethodPolicies(testTD)
	policyOf := map[e2eIdentity]map[string]bool{
		e2eAsRunner: policies[e2eRunnerSVID(testTD)],
		e2eAsMember: policies[e2eMemberSVID(testTD)],
	}
	entries := map[e2eIdentity][]string{}
	for _, j := range jobs {
		entries[j.identity] = append(entries[j.identity], j.tests...)
	}
	gen := loadGeneratedMethods(t, root, e2eImports(parsed))
	for identity, names := range entries {
		reached := reachableFiles(t, parsed, dedupe(names))
		calls := collectClientCalls(reached, gen)
		require.NotEmpty(t, calls, "the guard found no call on a generated client for identity %d", identity)
		for _, m := range e2eMissing(policyOf[identity], calls) {
			t.Errorf("the policy of identity %d does not allow %s", identity, m)
		}
	}
}

// reachableFiles returns a copy of each file that holds only the functions that
// the named entry functions reach, by name. A name that is no function of the
// files fails the test, so a renamed test cannot slip out of the guard.
func reachableFiles(t *testing.T, files map[string]*ast.File, entries []string) map[string]*ast.File {
	t.Helper()
	byName := map[string][]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				byName[fd.Name.Name] = append(byName[fd.Name.Name], fd)
			}
		}
	}
	reached := map[*ast.FuncDecl]bool{}
	var queue []*ast.FuncDecl
	for _, name := range entries {
		require.NotEmpty(t, byName[name], "the workflows run %s, and no function of tests/e2e defines it", name)
		queue = append(queue, byName[name]...)
	}
	for len(queue) > 0 {
		fd := queue[0]
		queue = queue[1:]
		if reached[fd] {
			continue
		}
		reached[fd] = true
		ast.Inspect(fd, func(n ast.Node) bool {
			var name string
			switch v := n.(type) {
			case *ast.Ident:
				name = v.Name
			case *ast.SelectorExpr:
				name = v.Sel.Name
			}
			for _, next := range byName[name] {
				queue = append(queue, next)
			}
			return true
		})
	}
	out := map[string]*ast.File{}
	for path, f := range files {
		only := *f
		only.Decls = nil
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				if reached[fd] {
					only.Decls = append(only.Decls, d)
				}
				continue
			}
			only.Decls = append(only.Decls, d)
		}
		out[path] = &only
	}
	return out
}

// The guard fails on a file that calls an RPC outside the policy. The fixture is
// the proof that the guard can fail.
func TestE2EPeerPolicy_GuardNamesACallOutsideThePolicy(t *testing.T) {
	root := gibsonRoot(t)
	fixture := filepath.Join(root, "internal", "server", "daemon", "testdata", "e2e_guard", "outside_policy.go.txt")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, fixture, nil, 0)
	require.NoError(t, err)
	parsed := map[string]*ast.File{fixture: f}

	gen := loadGeneratedMethods(t, root, e2eImports(parsed))
	calls := collectClientCalls(parsed, gen)
	missing := e2eMissing(e2ePeerMethodPolicies(testTD)[e2eRunnerSVID(testTD)], calls)

	require.Len(t, missing, 1)
	assert.Contains(t, missing[0], "/gibson.tenant.v1.AdminTenantService/AdminDeleteTenant")
}

// The jobs of a workflow carry the identity of the step that runs them.
func TestE2EJobsOf_ReadsTheIdentityOfTheStep(t *testing.T) {
	text := `      - name: one
        run: |
          gibson/.github/scripts/run-e2e-job.sh job-a 'TestA$|TestB$' 30m
      - name: two
        run: |
          E2E_RUNNER_COMPONENT=e2e-member E2E_RUNNER_ENV_FILE="x" \
            gibson/.github/scripts/run-e2e-job.sh job-b 'TestC$' 10m
`
	jobs := e2eJobsOf("w.yml", text)
	require.Len(t, jobs, 2)
	assert.Equal(t, []string{"TestA", "TestB"}, jobs[0].tests)
	assert.Equal(t, e2eAsRunner, jobs[0].identity)
	assert.Equal(t, []string{"TestC"}, jobs[1].tests)
	assert.Equal(t, e2eAsMember, jobs[1].identity)
}

// A workflow can apply its own Job manifest. The tests are in the -test.run
// argument, and the identity is the service account of the pod.
func TestE2EJobsOf_ReadsAJobManifest(t *testing.T) {
	text := `      - name: run
        run: |
          kubectl apply -f - <<EOF
          kind: Job
          spec:
            template:
              spec:
                serviceAccountName: ${RELEASE}-e2e-runner
                containers:
                  - name: e2e
                    args: ["-test.run", "TestBank", "-test.v", "-test.timeout", "40m"]
          ---
          kind: Job
          spec:
            template:
              spec:
                serviceAccountName: ${RELEASE}-e2e-member
                containers:
                  - name: e2e
                    args: ["-test.run", "TestMember$|TestOther", "-test.v"]
          EOF
`
	jobs := e2eJobsOf("w.yml", text)
	require.Len(t, jobs, 2)
	assert.Equal(t, []string{"TestBank"}, jobs[0].tests)
	assert.Equal(t, e2eAsRunner, jobs[0].identity)
	assert.Equal(t, []string{"TestMember", "TestOther"}, jobs[1].tests)
	assert.Equal(t, e2eAsMember, jobs[1].identity)
}

// A workflow that builds the suite is told apart from one that only names the
// binary in a comment.
func TestBuildsSuite(t *testing.T) {
	assert.True(t, buildsSuite("run: CGO_ENABLED=0 go test -tags=e2e -c \\\n  -o /tmp/ectx/e2e.test ./tests/e2e/\n"))
	assert.False(t, buildsSuite("      # the image holds e2e.test and runs it as a Job\n"))
}

// A receiver that is a field (p.comp), a name that two clients share, and a
// request literal all resolve to a method.
func TestCollectClientCalls_ResolvesFieldsAndCollisions(t *testing.T) {
	src := `package e2e

import (
	"context"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

type probe struct{ comp componentpb.ComponentServiceClient }

func (p *probe) submit(ctx context.Context, req *componentpb.SubmitResultRequest) {
	_, _ = p.comp.SubmitResult(ctx, req)
}

func twice(ctx context.Context) {
	c := tenantv1.NewMembershipServiceClient(nil)
	_, _ = c.ListMembers(ctx, nil)
}

func twiceMore(ctx context.Context) {
	c := componentpb.NewComponentServiceClient(nil)
	_, _ = c.Heartbeat(ctx, nil)
}
`
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	require.NoError(t, err)
	parsed := map[string]*ast.File{"x.go": f}
	gen := loadGeneratedMethods(t, gibsonRoot(t), e2eImports(parsed))

	calls := collectClientCalls(parsed, gen)

	assert.Contains(t, calls, "/gibson.component.v1.ComponentService/SubmitResult")
	assert.Contains(t, calls, "/gibson.tenant.v1.MembershipService/ListMembers")
	assert.Contains(t, calls, "/gibson.component.v1.ComponentService/Heartbeat",
		"the second client with the name c is not lost")
}
