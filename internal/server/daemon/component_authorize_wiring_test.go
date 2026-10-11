// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wiresRunAuthorizer reports whether src calls compSvc.WithRunAuthorizer in
// code, not in a comment. Without that call ComponentService.Authorize refuses
// every request (it fails closed), so a lost wire would stop every pull-mode
// agent from passing an Authorize check and no other test would notice.
func wiresRunAuthorizer(src string) bool {
	for _, line := range strings.Split(src, "\n") {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "//") {
			continue
		}
		if strings.Contains(code, "compSvc.WithRunAuthorizer(") {
			return true
		}
	}
	return false
}

func TestDaemonWiresTheRunAuthorizerIntoComponentService(t *testing.T) {
	b, err := os.ReadFile("grpc.go")
	require.NoError(t, err)
	assert.True(t, wiresRunAuthorizer(string(b)),
		"grpc.go must call compSvc.WithRunAuthorizer, or ComponentService.Authorize refuses every request (D86)")
}

// TestWiresRunAuthorizerFixtures is the failing fixture of the guard above: it
// shows the guard turns red when the call is gone or only named in a comment.
func TestWiresRunAuthorizerFixtures(t *testing.T) {
	assert.True(t, wiresRunAuthorizer("\tcompSvc.WithRunAuthorizer(d.callback.Service())\n"))
	assert.False(t, wiresRunAuthorizer("\tcompSvc.WithWorkContextRegistry(r)\n"))
	assert.False(t, wiresRunAuthorizer("\t// compSvc.WithRunAuthorizer(x) was removed\n"))
}
