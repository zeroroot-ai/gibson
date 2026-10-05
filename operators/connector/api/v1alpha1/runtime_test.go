// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package v1alpha1

import (
	"os"
	"reflect"
	"testing"

	"sigs.k8s.io/yaml"
)

const connectorInstanceCRDPath = "../../config/crd/bases/gibson.zeroroot.ai_connectorinstances.yaml"

// crdRuntimeEnum reads the enum of spec.runtime from the generated CRD.
func crdRuntimeEnum(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(connectorInstanceCRDPath)
	if err != nil {
		t.Fatalf("read the CRD: %v", err)
	}
	var crd struct {
		Spec struct {
			Versions []struct {
				Schema struct {
					OpenAPIV3Schema struct {
						Properties struct {
							Spec struct {
								Properties struct {
									Runtime struct {
										Enum []string `json:"enum"`
									} `json:"runtime"`
								} `json:"properties"`
							} `json:"spec"`
						} `json:"properties"`
					} `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal(raw, &crd); err != nil {
		t.Fatalf("parse the CRD: %v", err)
	}
	if len(crd.Spec.Versions) != 1 {
		t.Fatalf("the CRD has %d versions, want 1", len(crd.Spec.Versions))
	}
	return crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties.Spec.Properties.Runtime.Enum
}

// A connector has one runtime, a pod. The generated CRD must accept no other
// value.
func TestConnectorRuntime_CRDAcceptsPodOnly(t *testing.T) {
	got := crdRuntimeEnum(t)
	want := []string{string(ConnectorRuntimePod)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("spec.runtime enum = %v, want %v", got, want)
	}
}

// A ConnectorInstance that was stored with runtime: pod before the setec value
// left must still load, with no unknown field.
func TestConnectorRuntime_StoredPodObjectLoads(t *testing.T) {
	stored := []byte(`
apiVersion: gibson.zeroroot.ai/v1alpha1
kind: ConnectorInstance
metadata:
  name: slack
  namespace: tenant-acme
spec:
  connector: slack
  shape: Hosted
  image: ghcr.io/example/mcp@sha256:0000000000000000000000000000000000000000000000000000000000000000
  runtime: pod
  auth: none
`)
	var ci ConnectorInstance
	if err := yaml.UnmarshalStrict(stored, &ci); err != nil {
		t.Fatalf("load a stored object with runtime pod: %v", err)
	}
	if ci.Spec.Runtime != ConnectorRuntimePod {
		t.Fatalf("spec.runtime = %q, want %q", ci.Spec.Runtime, ConnectorRuntimePod)
	}
}
