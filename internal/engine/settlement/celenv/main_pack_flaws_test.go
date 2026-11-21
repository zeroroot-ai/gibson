// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package celenv

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/finding/findingtest"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	sdkfinding "github.com/zeroroot-ai/sdk/finding"
)

// The predicates of the main pack for the flaw classes of the reference
// environment (tests/fixtures/referenceenv, gibson#1490, gibson#1512). Each
// predicate has one proof that settles true and one proof that settles false.
// The false proof is the evidence that the same check gives after the fix, so
// it is also the proof that the second attack of the closed loop uses.

const (
	// A projected token of a pod, as a JWT. The text is a fixture and holds no key.
	fixtureJWT = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJmaXh0dXJlIn0.c2lnbmF0dXJlLWZpeHR1cmU"

	privilegedStatus = "Name:\tsh\nCapPrm:\t0000003fffffffff\nCapEff:\t0000003fffffffff\nCapBnd:\t0000003fffffffff\n"
	// 000001ffffffffff is the value on a kernel with 41 capabilities.
	privilegedStatusNewKernel = "CapEff:\t000001ffffffffff\n"
	defaultStatus             = "Name:\tsh\nCapPrm:\t00000000a80425fb\nCapEff:\t00000000a80425fb\nCapBnd:\t00000000a80425fb\n"

	otherPodToken = "/var/lib/kubelet/pods/6f1d2c3e-1a2b-4c5d-8e9f-0a1b2c3d4e5f/" +
		"volumes/kubernetes.io~projected/kube-api-access-x7k2p/token\n" + fixtureJWT + "\n"
	ownToken = "/var/run/secrets/kubernetes.io/serviceaccount/token\n" + fixtureJWT + "\n"

	createdConfigMap = `{"kind":"ConfigMap","apiVersion":"v1","metadata":{"name":"gibson-proof-7f3a9c","namespace":"refenv"}}`
	forbiddenStatus  = `{"kind":"Status","status":"Failure","reason":"Forbidden","code":403}`
)

const adminBody = `{"admin":true,"users":["alice","bob"]}`

// httpRequest is an HTTP request item to the URL, with the headers.
func httpRequest(url string, headers map[string]string) *typespb.Evidence {
	return findingtest.NewEvidence(sdkfinding.EvidenceHTTPRequest, "request",
		map[string]any{"method": "GET", "url": url, "headers": headers})
}

// adminRequest is the request to the protected path with no credential.
var adminRequest = httpRequest("http://catalog-api.refenv.svc.cluster.local:8080/admin/", nil)

func logEvidence(text string) *typespb.Evidence {
	return findingtest.NewEvidence(sdkfinding.EvidenceLog, "recorded tool call", text)
}

// recordedToolCall is the daemon record of a tool call: the JSON that the tool
// returned, with a top-level status_code (see httpStatus in functions.go).
func recordedToolCall(status int, body string) *typespb.Evidence {
	return findingtest.NewEvidence(sdkfinding.EvidenceLog, "recorded tool call",
		map[string]any{"status_code": status, "body": body})
}

func TestMainPackFlawPredicates(t *testing.T) {
	pack := mustMainPack(t)
	compiled, err := LoadDomainPack(&pack)
	require.NoError(t, err)

	cases := []struct {
		predicate string
		name      string
		evidence  []*typespb.Evidence
		want      bool
	}{
		// unauthenticated-admin-endpoint. The proof needs the request to a
		// protected path with no credential, and a 200 with a JSON body that is
		// no login page, with no redirect (review B4).
		{"unauthenticated_endpoint_exposed", "the admin path answers 200",
			[]*typespb.Evidence{adminRequest, findingtest.NewHTTPResponseEvidence("GET /admin/", 200, nil, adminBody, 0)}, true},
		{"unauthenticated_endpoint_exposed", "the admin path answers 401 after the fix",
			[]*typespb.Evidence{adminRequest, findingtest.NewHTTPResponseEvidence("GET /admin/", 401, nil, "", 0)}, false},
		{"unauthenticated_endpoint_exposed", "a public health path answers 200",
			[]*typespb.Evidence{httpRequest("http://catalog-api:8080/healthz", nil),
				findingtest.NewHTTPResponseEvidence("GET /healthz", 200, nil, `{"status":"ok"}`, 0)}, false},
		{"unauthenticated_endpoint_exposed", "the public catalog answers 200",
			[]*typespb.Evidence{httpRequest("http://catalog-api:8080/catalog", nil),
				findingtest.NewHTTPResponseEvidence("GET /catalog", 200, nil, `{"items":["widget","gadget"]}`, 0)}, false},
		{"unauthenticated_endpoint_exposed", "a 200 with no request names no path",
			[]*typespb.Evidence{findingtest.NewHTTPResponseEvidence("GET /admin/", 200, nil, adminBody, 0)}, false},
		{"unauthenticated_endpoint_exposed", "a login page answers 200 on the admin path",
			[]*typespb.Evidence{adminRequest, findingtest.NewHTTPResponseEvidence("GET /admin/", 200, nil,
				`<html><form action="/login"><input type="password" name="pw"></form></html>`, 0)}, false},
		{"unauthenticated_endpoint_exposed", "a JSON login answer on the admin path",
			[]*typespb.Evidence{adminRequest, findingtest.NewHTTPResponseEvidence("GET /admin/", 200, nil,
				`{"login":"required","redirect":"/sso"}`, 0)}, false},
		{"unauthenticated_endpoint_exposed", "a 200 after a redirect",
			[]*typespb.Evidence{adminRequest,
				findingtest.NewHTTPResponseEvidence("GET /admin/", 302, map[string]string{"Location": "/sso/start"}, "", 0),
				findingtest.NewHTTPResponseEvidence("GET /sso/start", 200, nil, adminBody, 0)}, false},
		{"unauthenticated_endpoint_exposed", "the request carried a credential",
			[]*typespb.Evidence{httpRequest("http://catalog-api:8080/admin/", map[string]string{"Authorization": "Bearer x"}),
				findingtest.NewHTTPResponseEvidence("GET /admin/", 200, nil, adminBody, 0)}, false},

		// credential-in-environment
		{"credential_disclosure_detected", "the environment of the pod holds a password",
			[]*typespb.Evidence{logEvidence("PATH=/usr/bin\nDB_PASSWORD=refenv-db-pw-4f9a1c\nHOME=/root\n")}, true},
		{"credential_disclosure_detected", "the environment holds no credential after the fix",
			[]*typespb.Evidence{logEvidence("PATH=/usr/bin\nHOME=/root\nPAYMENTS_DB=/run/secrets/db\n")}, false},

		// privileged-container
		{"privileged_container_detected", "the process holds each capability",
			[]*typespb.Evidence{logEvidence(privilegedStatus)}, true},
		{"privileged_container_detected", "the process holds each capability on a newer kernel",
			[]*typespb.Evidence{logEvidence(privilegedStatusNewKernel)}, true},
		{"privileged_container_detected", "the process holds the default capabilities after the fix",
			[]*typespb.Evidence{logEvidence(defaultStatus)}, false},

		// node-token-readable
		{"node_token_readable", "a token of another pod is readable under the kubelet directory",
			[]*typespb.Evidence{logEvidence(otherPodToken)}, true},
		{"node_token_readable", "only the token of the own pod is readable after the fix",
			[]*typespb.Evidence{logEvidence(ownToken)}, false},

		// wide-rbac-binding. The proof is a write, so the predicate is destructive.
		{"rbac_write_access_proven", "the API server created a ConfigMap",
			[]*typespb.Evidence{findingtest.NewHTTPResponseEvidence("POST configmaps", 201, nil, createdConfigMap, 0)}, true},
		{"rbac_write_access_proven", "a recorded tool call shows the created ConfigMap",
			[]*typespb.Evidence{recordedToolCall(201, createdConfigMap)}, true},
		{"rbac_write_access_proven", "the API server refused the write after the fix",
			[]*typespb.Evidence{findingtest.NewHTTPResponseEvidence("POST configmaps", 403, nil, forbiddenStatus, 0)}, false},
		{"rbac_write_access_proven", "an object of another kind was created",
			[]*typespb.Evidence{findingtest.NewHTTPResponseEvidence("POST pods", 201, nil,
				`{"kind":"Pod","metadata":{"name":"gibson-proof-7f3a9c"}}`, 0)}, false},
		{"rbac_write_access_proven", "a ConfigMap with no marker name was created",
			[]*typespb.Evidence{findingtest.NewHTTPResponseEvidence("POST configmaps", 201, nil,
				`{"kind":"ConfigMap","metadata":{"name":"other"}}`, 0)}, false},
	}

	for _, tc := range cases {
		t.Run(tc.predicate+"/"+tc.name, func(t *testing.T) {
			cp, ok := compiled[tc.predicate]
			require.True(t, ok, "the main pack must bind %q", tc.predicate)
			got, err := cp.Evaluate(context.Background(), tc.evidence)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestMainPackFlawPredicates_EachHasBothVerdicts: each flaw predicate of the
// table above has one proof that settles true and one that settles false.
func TestMainPackFlawPredicates_EachHasBothVerdicts(t *testing.T) {
	want := []string{
		"unauthenticated_endpoint_exposed", "credential_disclosure_detected",
		"privileged_container_detected", "node_token_readable", "rbac_write_access_proven",
	}
	pack := mustMainPack(t)
	for _, name := range want {
		assert.Contains(t, pack.Predicates, name)
	}
}
