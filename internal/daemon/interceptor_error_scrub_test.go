package daemon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zero-day-ai/gibson/internal/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNeedsScrubbing(t *testing.T) {
	tests := []struct {
		name     string
		msg      string
		expected bool
	}{
		{
			name:     "clean message",
			msg:      "mission not found",
			expected: false,
		},
		{
			name:     "tmp file path",
			msg:      "failed to parse /tmp/gibson-mission-12345.yaml: invalid syntax",
			expected: true,
		},
		{
			name:     "home directory leak",
			msg:      "failed to load /home/user/.gibson/config.yaml",
			expected: true,
		},
		{
			name:     "yaml unmarshal with Go type",
			msg:      "cannot unmarshal !!str 'foo' into mission.yamlNodeData",
			expected: true,
		},
		{
			name:     "yaml type error",
			msg:      "yaml.TypeError: line 5: field not found",
			expected: true,
		},
		{
			name:     "go file reference",
			msg:      "error in parser.go:215: unexpected token",
			expected: true,
		},
		{
			name:     "YAML parse error wrapping",
			msg:      "failed to parse YAML: line 3 column 5: found unexpected ':'",
			expected: true,
		},
		{
			name:     "YAML validation error",
			msg:      "YAML validation failed:\n  line 5: cannot unmarshal !!str into int",
			expected: true,
		},
		{
			name:     "YAML syntax error",
			msg:      "YAML syntax error: did not find expected key",
			expected: true,
		},
		{
			name:     "gibson config dir",
			msg:      "failed to read /.gibson/data/vectors",
			expected: true,
		},
		{
			name:     "simple user-facing error",
			msg:      "either workflow_path or workflow_yaml must be provided",
			expected: false,
		},
		{
			name:     "goroutine leak",
			msg:      "goroutine 1 [running]: main.go",
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := needsScrubbing(tc.msg)
			assert.Equal(t, tc.expected, result, "needsScrubbing(%q)", tc.msg)
		})
	}
}

func TestBuildSafeMessage(t *testing.T) {
	tests := []struct {
		name     string
		code     codes.Code
		msg      string
		err      error
		expected string
	}{
		{
			name:     "invalid argument with yaml",
			code:     codes.InvalidArgument,
			msg:      "invalid workflow YAML: yaml.TypeError line 5",
			err:      status.Error(codes.InvalidArgument, "invalid workflow YAML: yaml.TypeError line 5"),
			expected: "invalid workflow definition: check YAML syntax and required fields",
		},
		{
			name:     "invalid argument with component",
			code:     codes.InvalidArgument,
			msg:      "invalid component manifest: failed to unmarshal",
			err:      status.Error(codes.InvalidArgument, "invalid component manifest"),
			expected: "invalid component configuration",
		},
		{
			name:     "internal error generic",
			code:     codes.Internal,
			msg:      "failed to start mission: /tmp/blah.yaml parse error",
			err:      status.Error(codes.Internal, "something"),
			expected: "internal server error",
		},
		{
			name:     "not found",
			code:     codes.NotFound,
			msg:      "resource at /var/data/missions/123 not found",
			err:      status.Error(codes.NotFound, "something"),
			expected: "requested resource not found",
		},
		{
			name:     "gibson error with config code",
			code:     codes.InvalidArgument,
			msg:      "config parse failed: /etc/gibson/config.yaml",
			err:      types.WrapError(types.CONFIG_PARSE_FAILED, "failed to parse configuration", nil),
			expected: "configuration error: failed to parse configuration",
		},
		{
			name:     "unavailable",
			code:     codes.Unavailable,
			msg:      "connection to /var/run/redis.sock refused",
			err:      status.Error(codes.Unavailable, "connection refused"),
			expected: "service temporarily unavailable",
		},
		{
			name:     "deadline exceeded",
			code:     codes.DeadlineExceeded,
			msg:      "context deadline exceeded while connecting to internal service",
			err:      status.Error(codes.DeadlineExceeded, "timeout"),
			expected: "request timed out",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := buildSafeMessage(tc.code, tc.msg, tc.err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestScrubError_PassthroughCleanErrors(t *testing.T) {
	// Clean errors should pass through without modification
	cleanErr := status.Error(codes.InvalidArgument, "either workflow_path or workflow_yaml must be provided")
	result := scrubError(nil, nil, nil, cleanErr, "/test.Method")
	st, _ := status.FromError(result)
	assert.Equal(t, "either workflow_path or workflow_yaml must be provided", st.Message())
}

func TestScrubError_ScrubbsDirtyErrors(t *testing.T) {
	// Dirty errors should be scrubbed
	dirtyErr := status.Error(codes.InvalidArgument, "invalid workflow YAML: yaml: line 5: cannot unmarshal !!str into mission.yamlNodeData")
	result := scrubError(nil, nil, nil, dirtyErr, "/test.Method")
	st, _ := status.FromError(result)
	assert.Equal(t, "invalid workflow definition: check YAML syntax and required fields", st.Message())
	assert.Equal(t, codes.InvalidArgument, st.Code())
}
