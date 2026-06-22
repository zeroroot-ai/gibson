package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateLLMEndpoint_AllowPrivateBypass(t *testing.T) {
	assert.NoError(t, validateLLMEndpoint("http://127.0.0.1:8080", true))
	assert.NoError(t, validateLLMEndpoint("http://169.254.169.254/latest/meta-data", true))
}

func TestValidateLLMEndpoint_RejectsLoopbackAndMetadata(t *testing.T) {
	cases := []struct {
		raw      string
		wantFail bool
	}{
		// These rely on DNS of well-known hostnames → block by name.
		{"http://metadata.google.internal/computeMetadata/v1/", true},

		// IPv4 literals trigger the IP class check.
		{"http://127.0.0.1:8080", true},
		{"http://169.254.169.254/", true},
		{"http://10.0.0.5:8080", true},
		{"http://192.168.1.10:8080", true},
		{"http://172.20.0.1:8080", true},

		// Public IP — must pass.
		{"https://api.anthropic.com/v1/messages", false},
		{"https://8.8.8.8/", false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			err := validateLLMEndpoint(tc.raw, false)
			if tc.wantFail {
				assert.Error(t, err, "expected %q to be blocked", tc.raw)
			} else {
				assert.NoError(t, err, "expected %q to be allowed", tc.raw)
			}
		})
	}
}

func TestValidateLLMEndpoint_InvalidURL(t *testing.T) {
	err := validateLLMEndpoint("::::not a url", false)
	assert.Error(t, err)
}

func TestValidateLLMEndpoint_NoHost(t *testing.T) {
	err := validateLLMEndpoint("/path-only", false)
	assert.Error(t, err)
}
