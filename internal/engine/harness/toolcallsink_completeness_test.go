// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package harness — the ToolCallSink completeness guard (gibson#380, epic
// intelligence-phase-2, ADR-0030 §3).
//
// ADR-0030 §3 makes "every tool invocation flows through the flight
// recorder" a hard invariant, not a convention: independent-evidence
// integrity for proof settlement rests on it. This file is the completeness
// guard the ADR requires — it fails CI if any tool-execution path in the
// harness callback surface hands a completed outcome (success or failure)
// back across the trust boundary without first folding it through
// captureToolCall (the ingestToolCall choke point's harness-side call site).
//
// Design. This is real static analysis over the current AST, not a grep on
// fixed line numbers (repo rule: guards are keyed by content, never by line
// number — a guard that needs re-pinning after an unrelated edit is a defect
// in the guard). For each function in the files listed in
// toolCallSinkCompletenessFiles, the scanner:
//
//  1. Finds every "terminal" point — a place that constructs a completed
//     *harnesspb.CallToolProtoResponse, a terminal (Complete/Error)
//     *harnesspb.CallToolProtoStreamResponse, or a return that delegates to
//     one of the local response-building helpers (metaToolErr /
//     marshalMetaResult) — purely from the type/call names involved, so a
//     brand-new terminal return needs no manual tagging to be seen.
//  2. Passes it if a captureToolCall(...) call appears earlier in the same
//     function's source (by token position), OR if its enclosing statement
//     carries a "gibson:no-tool-executed" comment — an explicit, reviewed
//     admission that no tool actually ran on this path (bad input, denied
//     before dispatch, tool not found, etc.), so there is nothing to record.
//  3. Fails otherwise.
//
// This is a positional heuristic (source order within one function), not
// full control-flow dominance: it cannot detect a capture call that exists
// in a sibling, non-dominating branch. That is sufficient for the current,
// mostly linear dispatch functions this guard covers — it catches exactly
// the shape of bug fixed in gibson#380 (a whole path with zero capture calls
// anywhere) — but a future function with independent parallel branches after
// a shared capture call would need tighter, branch-scoped analysis.
//
// The failing fixture proving this guard fires lives in this file too (repo
// rule: every new guard ships with a failing fixture) — see
// TestToolCallSinkCompleteness_CatchesUnrecordedCallToolProtoBypass and its
// siblings below.
package harness

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// toolCallSinkCompletenessFiles lists, by filename (content — never by line
// number), the harness source files where a tool-execution outcome is
// handed back across the trust boundary. Adding a file here is a deliberate,
// reviewed act: a tool-execution path added anywhere else is invisible to
// this guard, so a new dispatch surface (a fifth way to run a tool) must add
// its file here in the same change.
var toolCallSinkCompletenessFiles = []string{
	"callback_service.go", // main callback path: CallToolProto (also covers sandboxed
	// setec dispatch, which routes through the same
	// captureToolCall call site via DefaultAgentHarness.CallToolProto)
	"callback_service_streaming.go", // streaming path: CallToolProtoStream
	"callback_metatool.go",          // metatool path: invoke_tool via callMetaTool/metaInvoke
}

const (
	// toolCallSinkExemptionMarker is the sentinel comment a reviewer places on
	// a terminal return's enclosing statement to declare, explicitly and
	// auditably, that no tool executed on this path.
	toolCallSinkExemptionMarker = "gibson:no-tool-executed"
	// toolCallSinkCaptureFunc is the one recording choke point every
	// tool-execution path must reach before returning a completed outcome.
	toolCallSinkCaptureFunc = "captureToolCall"
)

// toolCallSinkHelperFuncs lists local functions that construct and return a
// *harnesspb.CallToolProtoResponse on behalf of their caller (metaToolErr,
// marshalMetaResult in callback_metatool.go). Their own bodies are not
// scanned as terminal points — a bare error-response constructor has no
// mission/tool context to record — because the completeness requirement is
// enforced at each CALL site instead, via isHelperTerminalReturn.
var toolCallSinkHelperFuncs = map[string]bool{
	"metaToolErr":       true,
	"marshalMetaResult": true,
}

// toolCallSinkViolation is one terminal tool-result point with no preceding
// capture and no exemption comment.
type toolCallSinkViolation struct {
	file     string
	funcName string
	pos      token.Position
	desc     string
}

func (v toolCallSinkViolation) String() string {
	return fmt.Sprintf(
		"%s:%d:%d: func %s %s, with no preceding %s(...) call and no %q exemption comment",
		v.file, v.pos.Line, v.pos.Column, v.funcName, v.desc, toolCallSinkCaptureFunc, toolCallSinkExemptionMarker,
	)
}

// terminalCandidate is one place inside a function that appears to hand a
// completed tool outcome back to the caller.
type terminalCandidate struct {
	pos  token.Pos
	stmt ast.Node // nearest enclosing statement, for exemption-comment lookup
	desc string
}

// scanToolCallSinkCompleteness parses src under filename and returns every
// terminal tool-result point that is neither preceded by a captureToolCall
// call in the same function nor marked with the exemption comment.
func scanToolCallSinkCompleteness(filename string, src []byte) ([]toolCallSinkViolation, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filename, err)
	}

	var violations []toolCallSinkViolation
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		if toolCallSinkHelperFuncs[fd.Name.Name] {
			continue // scrutinized at each call site instead; see doc comment.
		}
		violations = append(violations, scanToolCallSinkFunc(fset, file, filename, fd)...)
	}
	return violations, nil
}

// scanToolCallSinkFunc applies the completeness rule to one function.
func scanToolCallSinkFunc(fset *token.FileSet, file *ast.File, filename string, fd *ast.FuncDecl) []toolCallSinkViolation {
	var (
		capturePositions []token.Pos
		terminals        []terminalCandidate
		stack            []ast.Node
	)

	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if n == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return true
		}
		stack = append(stack, n)

		switch node := n.(type) {
		case *ast.CallExpr:
			if toolCallSinkCalleeName(node) == toolCallSinkCaptureFunc {
				capturePositions = append(capturePositions, node.Pos())
			}
		case *ast.CompositeLit:
			if desc, ok := toolCallSinkTerminalCompositeLit(node); ok {
				terminals = append(terminals, terminalCandidate{
					pos:  node.Pos(),
					stmt: toolCallSinkEnclosingStmt(stack),
					desc: desc,
				})
			}
		case *ast.ReturnStmt:
			if toolCallSinkIsHelperTerminalReturn(node) {
				terminals = append(terminals, terminalCandidate{
					pos:  node.Pos(),
					stmt: node,
					desc: "returns via a tool-result helper (metaToolErr/marshalMetaResult)",
				})
			}
		}
		return true
	})

	if len(terminals) == 0 {
		return nil
	}

	var violations []toolCallSinkViolation
	for _, term := range terminals {
		if toolCallSinkPrecededByCapture(term.pos, capturePositions) {
			continue
		}
		if toolCallSinkExemptedByComment(fset, file, term.stmt) {
			continue
		}
		violations = append(violations, toolCallSinkViolation{
			file:     filename,
			funcName: fd.Name.Name,
			pos:      fset.Position(term.pos),
			desc:     term.desc,
		})
	}
	return violations
}

// toolCallSinkCalleeName returns a call expression's unqualified callee name
// (the part after the last '.', if any), so "s.captureToolCall(...)" and
// "captureToolCall(...)" both match by name alone — content, never position.
func toolCallSinkCalleeName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fn.Sel.Name
	case *ast.Ident:
		return fn.Name
	}
	return ""
}

// toolCallSinkTypeName returns a type expression's unqualified name, e.g.
// "CallToolProtoResponse" for both "CallToolProtoResponse" and
// "harnesspb.CallToolProtoResponse".
func toolCallSinkTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return toolCallSinkTypeName(t.X)
	}
	return ""
}

// toolCallSinkTerminalCompositeLit reports whether a composite literal is a
// terminal tool-result point: any CallToolProtoResponse (the non-streaming
// RPC's response type — every construction of one IS that RPC's outcome), or
// a CallToolProtoStreamResponse specifically wrapping a Complete or Error
// payload (Progress/Partial/Warning are not terminal outcomes).
func toolCallSinkTerminalCompositeLit(cl *ast.CompositeLit) (string, bool) {
	switch toolCallSinkTypeName(cl.Type) {
	case "CallToolProtoResponse":
		return "constructs a CallToolProtoResponse", true
	case "CallToolProtoStreamResponse":
		if kind := toolCallSinkStreamPayloadKind(cl); kind != "" {
			return fmt.Sprintf("constructs a terminal CallToolProtoStreamResponse (%s payload)", kind), true
		}
	}
	return "", false
}

// toolCallSinkStreamPayloadKind returns "Complete" or "Error" when cl's
// Payload field is set to the corresponding oneof variant, else "".
func toolCallSinkStreamPayloadKind(cl *ast.CompositeLit) string {
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "Payload" {
			continue
		}
		un, ok := kv.Value.(*ast.UnaryExpr)
		if !ok || un.Op != token.AND {
			continue
		}
		inner, ok := un.X.(*ast.CompositeLit)
		if !ok {
			continue
		}
		name := toolCallSinkTypeName(inner.Type)
		switch {
		case strings.HasSuffix(name, "_Complete"):
			return "Complete"
		case strings.HasSuffix(name, "_Error"):
			return "Error"
		}
	}
	return ""
}

// toolCallSinkIsHelperTerminalReturn reports whether ret returns (as its
// first result) a direct call to one of toolCallSinkHelperFuncs — the
// callback_metatool.go shape, where the response literal lives inside the
// helper rather than at the call site.
func toolCallSinkIsHelperTerminalReturn(ret *ast.ReturnStmt) bool {
	if len(ret.Results) == 0 {
		return false
	}
	call, ok := ret.Results[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	return toolCallSinkHelperFuncs[toolCallSinkCalleeName(call)]
}

// toolCallSinkEnclosingStmt walks an ancestor stack (innermost last) and
// returns the nearest node that is itself an ast.Stmt — the statement a
// terminal composite literal lives inside, used to look up an adjacent
// exemption comment.
func toolCallSinkEnclosingStmt(stack []ast.Node) ast.Node {
	for i := len(stack) - 1; i >= 0; i-- {
		if _, ok := stack[i].(ast.Stmt); ok {
			return stack[i]
		}
	}
	return nil
}

// toolCallSinkPrecededByCapture reports whether any captureToolCall call in
// the function appears earlier in the source than pos.
func toolCallSinkPrecededByCapture(pos token.Pos, captures []token.Pos) bool {
	for _, c := range captures {
		if c < pos {
			return true
		}
	}
	return false
}

// toolCallSinkExemptedByComment reports whether stmt carries a
// gibson:no-tool-executed comment immediately above it (a standalone comment
// group ending on the line before stmt starts) or on its own first line.
func toolCallSinkExemptedByComment(fset *token.FileSet, file *ast.File, stmt ast.Node) bool {
	if stmt == nil {
		return false
	}
	stmtLine := fset.Position(stmt.Pos()).Line
	for _, cg := range file.Comments {
		if !strings.Contains(cg.Text(), toolCallSinkExemptionMarker) {
			continue
		}
		startLine := fset.Position(cg.Pos()).Line
		endLine := fset.Position(cg.End()).Line
		if endLine == stmtLine-1 || startLine == stmtLine || endLine == stmtLine {
			return true
		}
	}
	return false
}

// TestToolCallSinkCompleteness is the CI-enforced guard itself (gibson#380,
// ADR-0030 §3): it fails if any real tool-execution path in the harness
// callback surface returns a completed outcome without recording it. See the
// package doc comment above for the rule, and
// TestToolCallSinkCompleteness_CatchesUnrecordedCallToolProtoBypass et al.
// below for the failing-fixture proof that this guard actually fires.
func TestToolCallSinkCompleteness(t *testing.T) {
	for _, name := range toolCallSinkCompletenessFiles {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		violations, err := scanToolCallSinkCompleteness(name, src)
		if err != nil {
			t.Fatalf("scan %s: %v", name, err)
		}
		for _, v := range violations {
			t.Error(v.String())
		}
	}
}

// --- Failing-fixture proof (repo rule: every new guard ships with one) ---
//
// Each fixture below is parsed as an isolated, synthetic Go source string —
// never written to disk, never part of the build — so the bypass it proves
// the guard catches never actually ships. Running these tests IS running the
// guard against a deliberately-bypassing path.

const toolCallSinkBypassFixture = `package harness

func bypassingCallToolProto() *harnesspb.CallToolProtoResponse {
	// Deliberately skips the flight recorder and carries no exemption of any
	// kind, proving the guard fires on a bare, unrecorded tool result.
	return &harnesspb.CallToolProtoResponse{OutputJson: []byte("{}")}
}
`

func TestToolCallSinkCompleteness_CatchesUnrecordedCallToolProtoBypass(t *testing.T) {
	violations, err := scanToolCallSinkCompleteness("bypass_fixture.go", []byte(toolCallSinkBypassFixture))
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("guard must catch exactly one violation in the bypass fixture, got %d: %v", len(violations), violations)
	}
	if violations[0].funcName != "bypassingCallToolProto" {
		t.Fatalf("violation named the wrong function: %+v", violations[0])
	}
}

const toolCallSinkBypassStreamingFixture = `package harness

func (s *HarnessCallbackService) bypassingStreamComplete() {
	response := &harnesspb.CallToolProtoStreamResponse{
		Payload: &harnesspb.CallToolProtoStreamResponse_Complete{
			Complete: &harnesspb.ToolCompleteEvent{OutputJson: []byte("{}")},
		},
	}
	_ = stream.Send(response)
}
`

func TestToolCallSinkCompleteness_CatchesUnrecordedStreamingComplete(t *testing.T) {
	violations, err := scanToolCallSinkCompleteness("bypass_stream_fixture.go", []byte(toolCallSinkBypassStreamingFixture))
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("guard must catch exactly one violation in the streaming bypass fixture, got %d: %v", len(violations), violations)
	}
}

const toolCallSinkBypassMetaHelperFixture = `package harness

func (s *HarnessCallbackService) bypassingMetaInvoke() (*harnesspb.CallToolProtoResponse, error) {
	result, err := h.Invoke(ctx, caller, id, args)
	if err != nil {
		return metaToolErr(code, err.Error()), nil
	}
	return marshalMetaResult(s, result)
}
`

func TestToolCallSinkCompleteness_CatchesUnrecordedMetaInvokeHelperReturns(t *testing.T) {
	violations, err := scanToolCallSinkCompleteness("bypass_meta_fixture.go", []byte(toolCallSinkBypassMetaHelperFixture))
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	if len(violations) != 2 {
		t.Fatalf("guard must catch both the failure and success returns, got %d: %v", len(violations), violations)
	}
}

const toolCallSinkCapturedFixture = `package harness

func (s *HarnessCallbackService) properlyRecordedCallToolProto() *harnesspb.CallToolProtoResponse {
	s.captureToolCall(ctx, nil, "tool", "{}", "{}", "")
	return &harnesspb.CallToolProtoResponse{OutputJson: []byte("{}")}
}
`

// TestToolCallSinkCompleteness_AllowsProperlyCapturedReturn proves the guard
// does not false-positive on the pattern every real fix in this PR follows.
func TestToolCallSinkCompleteness_AllowsProperlyCapturedReturn(t *testing.T) {
	violations, err := scanToolCallSinkCompleteness("captured_fixture.go", []byte(toolCallSinkCapturedFixture))
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("a properly captured tool result must not violate the guard: %v", violations)
	}
}

const toolCallSinkExemptedFixture = `package harness

func (s *HarnessCallbackService) preExecutionRejection() *harnesspb.CallToolProtoResponse {
	// gibson:no-tool-executed — rejected before dispatch in this fixture.
	return &harnesspb.CallToolProtoResponse{Error: nil}
}
`

// TestToolCallSinkCompleteness_AllowsExplicitlyExemptedReturn proves the
// documented escape hatch works for a genuine pre-execution rejection.
func TestToolCallSinkCompleteness_AllowsExplicitlyExemptedReturn(t *testing.T) {
	violations, err := scanToolCallSinkCompleteness("exempted_fixture.go", []byte(toolCallSinkExemptedFixture))
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("an explicitly exempted return must not violate the guard: %v", violations)
	}
}
