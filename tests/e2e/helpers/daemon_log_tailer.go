//go:build e2e
// +build e2e

package helpers

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// IdentityDebugLine is a parsed [identity-debug] log line from the daemon.
// The daemon emits these when GIBSON_IDENTITY_TRACE=1 is set on the pod.
// See internal/identity/interceptor.go for the exact format.
type IdentityDebugLine struct {
	// Method is the gRPC full method name, e.g. "/gibson.daemon.admin.v1.DaemonAdminService/UpsertTenantQuota"
	Method string
	// MetadataKeys is the full list of incoming gRPC metadata keys (sorted).
	MetadataKeys []string
	// Headers is the parsed x-gibson-identity-* header values (without redaction).
	// Signature is NOT included here — the log only reports presence (Security NFR).
	Headers map[string]string
	// SignaturePresent is true if [identity-debug] reported the signature header
	// was non-empty.
	SignaturePresent bool
	// HMACError is the error string if IdentityFromHeaders returned an error.
	// Empty string means HMAC verification succeeded.
	HMACError string
	// Raw is the original log line for debugging.
	Raw string
}

// identityHeaders is the list of x-gibson-identity-* headers the daemon
// expects to receive.  Must match the constants in internal/identity/headers.go.
var identityHeaders = []string{
	"x-gibson-identity-subject",
	"x-gibson-identity-issuer",
	"x-gibson-identity-credential-type",
	"x-gibson-identity-tenant",
	"x-gibson-identity-issued-at",
	"x-gibson-identity-signature",
}

// TailIdentityDebug streams log lines from the daemon pod (pod name or label
// selector), filters for [identity-debug] prefixed lines, and parses them
// into IdentityDebugLine values.
//
// The returned channel is closed when ctx is cancelled or the log stream ends.
//
// podName is the exact pod name (e.g. "gibson-0") in namespace "gibson".
// since is the start-of-window time — only lines emitted after this time are
// parsed (we use the --since-time kubectl flag).
//
// IMPORTANT: The daemon pod must have GIBSON_IDENTITY_TRACE=1 in its env for
// the [identity-debug] lines to appear.  The e2e Makefile target sets this
// via a helm value override before running the test.
//
// Requirements: R2.1, R2.2.
// Bug catalog: B16 (x-gibson-identity-* headers stripped → daemon log has no
// header values), B15 (HMAC mismatch → HMACError field non-empty).
func TailIdentityDebug(ctx context.Context, kubeClient kubernetes.Interface,
	podName string, since time.Time) (<-chan IdentityDebugLine, error) {

	// Request logs since the given time.  We use the streaming log API.
	sinceTime := metav1.NewTime(since)
	logOpts := &corev1.PodLogOptions{
		Follow:    true,
		SinceTime: &sinceTime,
	}

	req := kubeClient.CoreV1().Pods("gibson").GetLogs(podName, logOpts)
	stream, err := req.Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("daemon_log_tailer: stream logs from %s: %w", podName, err)
	}

	ch := make(chan IdentityDebugLine, 64)
	go func() {
		defer close(ch)
		defer stream.Close()

		scanner := bufio.NewScanner(stream)
		for scanner.Scan() {
			if ctx.Err() != nil {
				return
			}
			line := scanner.Text()
			parsed, ok := parseIdentityDebugLine(line)
			if !ok {
				continue
			}
			select {
			case ch <- parsed:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, nil
}

// parseIdentityDebugLine parses a single [identity-debug] log line.
// Returns (line, true) on success, ("", false) if the line is not an
// [identity-debug] line.
//
// The daemon emits two formats:
//
// 1. Method line:
//
//	[identity-debug] method=/foo/Bar metadata_keys=[key1,key2,key3]
//
// 2. Header value line:
//
//	[identity-debug]   x-gibson-identity-subject="alice@example.com"
//
// 3. HMAC error line:
//
//	[identity-debug] IdentityFromHeaders err: identity: HMAC signature mismatch
//
// Parsing is intentionally lenient — we don't assert on exact format so the
// test still works if the log format gains additional fields.
func parseIdentityDebugLine(line string) (IdentityDebugLine, bool) {
	const prefix = "[identity-debug]"
	if !strings.Contains(line, prefix) {
		return IdentityDebugLine{}, false
	}

	payload := line[strings.Index(line, prefix)+len(prefix):]
	payload = strings.TrimSpace(payload)

	out := IdentityDebugLine{Raw: line, Headers: make(map[string]string)}

	switch {
	case strings.HasPrefix(payload, "method="):
		// Format: method=<method> metadata_keys=[k1,k2,...]
		parts := strings.Fields(payload)
		for _, p := range parts {
			if strings.HasPrefix(p, "method=") {
				out.Method = strings.TrimPrefix(p, "method=")
			}
			if strings.HasPrefix(p, "metadata_keys=[") {
				keysRaw := strings.TrimPrefix(p, "metadata_keys=[")
				keysRaw = strings.TrimSuffix(keysRaw, "]")
				if keysRaw != "" {
					out.MetadataKeys = strings.Split(keysRaw, ",")
				}
			}
		}
		return out, true

	case strings.HasPrefix(payload, "x-gibson-identity-"):
		// Format:   x-gibson-identity-<name>="<value>"
		eqIdx := strings.Index(payload, "=")
		if eqIdx < 0 {
			return IdentityDebugLine{}, false
		}
		headerName := strings.TrimSpace(payload[:eqIdx])
		headerVal := strings.TrimSpace(payload[eqIdx+1:])
		// Strip surrounding quotes if present.
		headerVal = strings.Trim(headerVal, `"`)

		if headerName == "x-gibson-identity-signature" {
			out.SignaturePresent = strings.Contains(headerVal, "present")
		} else {
			out.Headers[headerName] = headerVal
		}
		return out, true

	case strings.HasPrefix(payload, "IdentityFromHeaders err:"):
		out.HMACError = strings.TrimPrefix(payload, "IdentityFromHeaders err:")
		out.HMACError = strings.TrimSpace(out.HMACError)
		return out, true

	case strings.HasPrefix(payload, "HMAC mismatch:"):
		out.HMACError = "HMAC mismatch"
		return out, true
	}

	return IdentityDebugLine{}, false
}

// AssertHeadersLanded waits for evidence in the daemon log that at least one
// RPC executed during the time window [since, since+deadline] had ALL six
// x-gibson-identity-* headers present AND that HMAC verification succeeded
// (no HMACError line following the method line).
//
// This is the direct regression assertion for B16 (headers stripped by Envoy's
// request_headers_to_remove) and B15 (HMAC secret byte-interpretation mismatch).
//
// If the assertion fails, the error message includes the exact metadata keys
// the daemon received (for B16 diagnosis) and the HMAC error string (for B15).
//
// Requirements: R2.1, R2.2, R2.3.
// Bug catalog: B15 (HMACError non-empty), B16 (missing x-gibson-identity-* keys).
func AssertHeadersLanded(t interface {
	Fatalf(string, ...interface{})
	Logf(string, ...interface{})
},
	ctx context.Context,
	kubeClient kubernetes.Interface,
	podName string,
	since time.Time,
	deadline time.Duration) {

	tailCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	ch, err := TailIdentityDebug(tailCtx, kubeClient, podName, since)
	if err != nil {
		t.Fatalf(
			"AssertHeadersLanded: failed to stream daemon logs from pod %q: %v\n"+
				"Ensure the daemon pod is running and GIBSON_IDENTITY_TRACE=1 is set",
			podName, err,
		)
		return
	}

	// Collect lines into buckets keyed by method name.
	type methodState struct {
		metadataKeys    []string
		presentHeaders  map[string]bool
		signaturePresent bool
		hmacError       string
	}
	methods := map[string]*methodState{}
	var currentMethod string

	for line := range ch {
		if line.Method != "" {
			// New method call started.
			currentMethod = line.Method
			if methods[currentMethod] == nil {
				methods[currentMethod] = &methodState{
					metadataKeys:   line.MetadataKeys,
					presentHeaders: make(map[string]bool),
				}
			} else {
				methods[currentMethod].metadataKeys = line.MetadataKeys
			}
		}
		if currentMethod != "" && methods[currentMethod] != nil {
			for k, v := range line.Headers {
				if v != "" {
					methods[currentMethod].presentHeaders[k] = true
				}
			}
			if line.SignaturePresent {
				methods[currentMethod].signaturePresent = true
			}
			if line.HMACError != "" {
				methods[currentMethod].hmacError = line.HMACError
			}
		}

		// Check if any method now has all 6 headers + no HMAC error.
		for method, state := range methods {
			if state.hmacError != "" {
				continue
			}
			allPresent := true
			for _, hk := range identityHeaders {
				if hk == "x-gibson-identity-signature" {
					if !state.signaturePresent {
						allPresent = false
					}
					continue
				}
				if !state.presentHeaders[hk] {
					allPresent = false
				}
			}
			if allPresent {
				t.Logf("AssertHeadersLanded: PASS — method %q received all 6 x-gibson-identity-* headers with HMAC OK", method)
				return
			}
		}
	}

	// Build a diagnostic dump.
	var sb strings.Builder
	if len(methods) == 0 {
		sb.WriteString("  No [identity-debug] lines received — daemon pod may not have GIBSON_IDENTITY_TRACE=1 set,\n")
		sb.WriteString("  OR the proxy (Envoy) is not forwarding requests to the daemon,\n")
		sb.WriteString("  OR the daemon pod name is wrong.\n")
	}
	for method, state := range methods {
		fmt.Fprintf(&sb, "  method=%s:\n", method)
		fmt.Fprintf(&sb, "    metadata_keys=%v\n", state.metadataKeys)
		fmt.Fprintf(&sb, "    present_identity_headers=%v\n", state.presentHeaders)
		fmt.Fprintf(&sb, "    signature_present=%v\n", state.signaturePresent)
		fmt.Fprintf(&sb, "    hmac_error=%q\n", state.hmacError)
		missing := []string{}
		for _, hk := range identityHeaders {
			if hk == "x-gibson-identity-signature" {
				if !state.signaturePresent {
					missing = append(missing, hk)
				}
			} else if !state.presentHeaders[hk] {
				missing = append(missing, hk)
			}
		}
		if len(missing) > 0 {
			fmt.Fprintf(&sb, "    MISSING headers: %v — B16: check Envoy route request_headers_to_remove does NOT contain x-gibson-identity-*\n", missing)
		}
		if state.hmacError != "" {
			fmt.Fprintf(&sb, "    HMAC error: %q — B15: check ext-authz and daemon agree on HMAC secret byte interpretation\n", state.hmacError)
		}
	}

	t.Fatalf(
		"AssertHeadersLanded: no RPC in the %.0fs window had all 6 x-gibson-identity-* headers land at the daemon with HMAC OK.\n"+
			"Diagnostic dump:\n%s\n"+
			"Bug catalog:\n"+
			"  B16: Envoy route's request_headers_to_remove strips x-gibson-identity-* headers added by ext-authz filter.\n"+
			"  B15: HMAC secret byte-interpretation mismatch between ext-authz (may hex-decode 64-char keys) and daemon.\n"+
			"  B14: Envoy dials daemon on plain h2c but daemon expects mTLS (connection drops before headers arrive).\n",
		deadline.Seconds(), sb.String(),
	)
}
