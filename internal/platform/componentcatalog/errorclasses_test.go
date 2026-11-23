// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package componentcatalog

import (
	"strings"
	"testing"
)

const hostedConnector = `id: x
kind: connector
displayName: X
description: x
spec:
  class: git-host
  shape: Hosted
  image: %IMAGE%
  transport: streamable-http
  port: 8080
  auth: none
  %CLAIM%
`

func connectorBody(image, claim string) string {
	return strings.NewReplacer("%IMAGE%", image, "%CLAIM%", claim).Replace(hostedConnector)
}

// A manifest may set errorClasses only for a Hosted image of ghcr.io/zeroroot-ai/connectors-*.
// A vendor image, a look-alike path and a Remote connector cannot claim the protocol, so no
// vendor connector can make the member repeat a partial write.
func TestErrorClasses_OnlyZeroRootConnectorImagesMayClaimIt(t *testing.T) {
	const own = "ghcr.io/zeroroot-ai/connectors-github-fixloop@sha256:" +
		"f248539564c8e15d54af93b9f46b5c1aaf80985afc96716eb66e20ebedf2f912"
	m, err := loadOne(t, connectorBody(own, "errorClasses: true"))
	if err != nil {
		t.Fatalf("a Zero Root connector image must be accepted: %v", err)
	}
	if !m.connector.ErrorClasses {
		t.Fatal("the field must be read")
	}
	if m, err = loadOne(t, connectorBody(own, "")); err != nil || m.connector.ErrorClasses {
		t.Fatalf("the default is false: %v", err)
	}

	const digest = "@sha256:14d500c02066672253f2a6c6e1b5c9f4e3aaa6a8b2568468e85404cbcd54b7de"
	for name, image := range map[string]string{
		"a vendor image":                 "quay.io/crowdstrike/falcon-mcp" + digest,
		"another zeroroot repository":    "ghcr.io/zeroroot-ai/gibson-executor" + digest,
		"a look-alike registry":          "ghcr.io/zeroroot-ai-evil/connectors-x" + digest,
		"a second path segment":          "ghcr.io/zeroroot-ai/connectors-evil.example/x" + digest,
		"a second segment after a slash": "ghcr.io/zeroroot-ai/connectors-a/b" + digest,
		"a tag with no digest":           "ghcr.io/zeroroot-ai/connectors-github-fixloop:0.8.2",
		"a short digest":                 "ghcr.io/zeroroot-ai/connectors-github-fixloop@sha256:f2485395",
		"a digest with upper case":       "ghcr.io/zeroroot-ai/connectors-github-fixloop@sha256:" + strings.Repeat("F", 64),
		"a digest with trailing text":    "ghcr.io/zeroroot-ai/connectors-github-fixloop" + digest + "x",
		"an upper case name":             "ghcr.io/zeroroot-ai/connectors-GitHub" + digest,
		"an empty name":                  "ghcr.io/zeroroot-ai/connectors-" + digest,
	} {
		_, err := loadOne(t, connectorBody(image, "errorClasses: true"))
		if err == nil {
			t.Errorf("%s: the manifest must be refused", name)
			continue
		}
		// An image with no digest fails the pin check of every Hosted connector first. An image
		// with a digest reaches the errorClasses check, and it must fail there.
		if strings.Contains(image, "@sha256:") && !strings.Contains(err.Error(), "errorClasses is only for") {
			t.Errorf("%s: err = %v, want the errorClasses refusal", name, err)
		}
	}

	_, err = loadOne(t, responseConnector+"  errorClasses: true\n")
	if err == nil || !strings.Contains(err.Error(), "errorClasses is only for") {
		t.Errorf("a Remote connector: err = %v, want the errorClasses refusal", err)
	}
}

// The shipped catalog sets errorClasses for the three Zero Root connectors that speak the protocol
// and for no other connector.
func TestErrorClasses_TheShippedCatalogClaimsItForTheZeroRootConnectorsOnly(t *testing.T) {
	want := map[string]bool{"github-fixloop": true, "gitlab-fixloop": true, "prometheus-health": true}
	for _, e := range ListConnectors() {
		if e.ErrorClasses != want[e.ID] {
			t.Errorf("%s: errorClasses = %v, want %v", e.ID, e.ErrorClasses, want[e.ID])
		}
		if e.ErrorClasses && !errorClassImage.MatchString(e.Image) {
			t.Errorf("%s: errorClasses with the image %q", e.ID, e.Image)
		}
		if HonorsErrorClasses(e.ID) != e.ErrorClasses {
			t.Errorf("%s: HonorsErrorClasses disagrees with the entry", e.ID)
		}
	}
	if HonorsErrorClasses("no-such-connector") {
		t.Error("an unknown connector must not be trusted")
	}
}
