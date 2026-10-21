// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package llm

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// CustomHeadersKey is the credential field of an Anthropic provider that
// carries extra request headers. The format is the one of the variable
// ANTHROPIC_CUSTOM_HEADERS of Claude Code: one "Name: Value" pair on each line.
// The daemon client and the sandbox variable read this one field.
const CustomHeadersKey = "custom_headers"

// WorkspaceHeader is the one header that the field may carry. An organization
// user key works only with it.
const WorkspaceHeader = "anthropic-workspace-id"

// ErrInvalidCustomHeaders is returned for a value that is not on the allowlist.
// The message never holds the value.
var ErrInvalidCustomHeaders = errors.New("invalid custom_headers")

var workspaceIDPattern = regexp.MustCompile(`^wrkspc_[A-Za-z0-9]{1,64}$`)

// ParseCustomHeaders reads and checks the value of the field. It accepts the
// header anthropic-workspace-id only, once, with a value of the form
// wrkspc_<letters and digits>. Any other name, a repeated name, a line with no
// colon and any other value shape is refused.
func ParseCustomHeaders(raw string) (http.Header, error) {
	h := http.Header{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" {
			return nil, fmt.Errorf("%w: each line must be \"Name: Value\"", ErrInvalidCustomHeaders)
		}
		if !strings.EqualFold(name, WorkspaceHeader) {
			return nil, fmt.Errorf("%w: only the header %s is accepted", ErrInvalidCustomHeaders, WorkspaceHeader)
		}
		if !workspaceIDPattern.MatchString(value) {
			return nil, fmt.Errorf("%w: the value of %s must look like wrkspc_ followed by letters and digits", ErrInvalidCustomHeaders, WorkspaceHeader)
		}
		if h.Get(WorkspaceHeader) != "" {
			return nil, fmt.Errorf("%w: the header %s is given twice", ErrInvalidCustomHeaders, WorkspaceHeader)
		}
		h.Set(WorkspaceHeader, value)
	}
	return h, nil
}

// CanonicalCustomHeaders checks the value and returns it in one fixed form, so
// the stored value, and the sandbox that reads it, hold nothing but the checked
// header. An empty value returns an empty value.
func CanonicalCustomHeaders(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	h, err := ParseCustomHeaders(raw)
	if err != nil {
		return "", err
	}
	if id := h.Get(WorkspaceHeader); id != "" {
		return WorkspaceHeader + ": " + id, nil
	}
	return "", nil
}
