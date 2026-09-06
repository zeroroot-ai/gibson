// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"context"
	"regexp"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	dpclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane/client"
	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
)

// ---------------------------------------------------------------------------
// A Neo4j configuration evaluator.
//
// These tests do not compare the allowlist string to another copy of itself —
// that assertion is true of any string, including "apoc.*", and would pass
// while the database happily loaded apoc.export.cypher.all. Instead they
// reimplement the two rules Neo4j actually applies, and ask the question an
// attacker would ask: "given this configuration, is apoc.load.json callable?"
//
// Rule 1 (dbms.security.procedures.allowlist): a comma-separated list of
// fully-qualified names and wildcard patterns. A procedure is loaded only if
// some entry matches it. Empty list loads nothing; the default "*" loads
// everything.
//
// Rule 2 (NEO4J_-prefixed environment variables): the image entrypoint turns
// a variable into a setting name by stripping NEO4J_, replacing '_' with '.',
// then '..' with '_'. Asserting on the derived SETTING rather than on the
// variable spelling is what makes the "unrestricted is never set" test
// resistant to someone reaching the same setting by another spelling.
// ---------------------------------------------------------------------------

// procedureLoaded reports whether allowlist admits procedure name.
func procedureLoaded(t *testing.T, allowlist, name string) bool {
	t.Helper()
	for _, entry := range strings.Split(allowlist, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		var pattern strings.Builder
		pattern.WriteString("^")
		for i, lit := range strings.Split(entry, "*") {
			if i > 0 {
				pattern.WriteString(".*")
			}
			pattern.WriteString(regexp.QuoteMeta(lit))
		}
		pattern.WriteString("$")
		re, err := regexp.Compile(pattern.String())
		if err != nil {
			t.Fatalf("allowlist entry %q is not a usable pattern: %v", entry, err)
		}
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// settingName converts a NEO4J_-prefixed environment variable name into the
// neo4j.conf / apoc.conf setting it becomes.
func settingName(envVar string) string {
	if !strings.HasPrefix(envVar, "NEO4J_") {
		return ""
	}
	s := strings.TrimPrefix(envVar, "NEO4J_")
	s = strings.ReplaceAll(s, "_", ".")
	return strings.ReplaceAll(s, "..", "_")
}

// neo4jSettings returns every configuration setting the Neo4j container's
// environment produces, keyed by setting name.
func neo4jSettings(t *testing.T, sts *appsv1.StatefulSet) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, c := range append(
		append([]corev1.Container{}, sts.Spec.Template.Spec.InitContainers...),
		sts.Spec.Template.Spec.Containers...,
	) {
		for _, e := range c.Env {
			if name := settingName(e.Name); name != "" {
				out[name] = e.Value
			}
		}
	}
	return out
}

// neo4jContainer returns the Neo4j container from the pod template.
func neo4jContainer(t *testing.T, sts *appsv1.StatefulSet) corev1.Container {
	t.Helper()
	for _, c := range sts.Spec.Template.Spec.Containers {
		if c.Name == "neo4j" {
			return c
		}
	}
	t.Fatal("pod template has no neo4j container")
	return corev1.Container{}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestTenantNeo4jLoadsOnlyTheMergeProcedures is the allowlist's reason for
// existing: the projector needs apoc.merge.*, and every APOC procedure that
// touches the filesystem or the network must be absent from the database
// entirely (ADR-0012).
//
// It fails if the allowlist is widened — `apoc.*`, `apoc.export.*`, an added
// `apoc.load.json`, or the Neo4j default `*` all flip one of the "must not be
// loaded" rows.
func TestTenantNeo4jLoadsOnlyTheMergeProcedures(t *testing.T) {
	t.Parallel()
	sts, _ := buildTestNeo4j(t)
	allowlist, ok := neo4jSettings(t, sts)["dbms.security.procedures.allowlist"]
	if !ok {
		t.Fatal("dbms.security.procedures.allowlist is unset; Neo4j then defaults to * and loads every APOC procedure in the plugins dir")
	}

	cases := []struct {
		procedure string
		want      bool
		why       string
	}{
		{"apoc.merge.node", true, "the projector shapes :Host through it"},
		{"apoc.merge.relationship", true, "relationship types as parameters, same property"},

		{"apoc.export.cypher.all", false, "writes the whole graph to a file"},
		{"apoc.export.json.all", false, "writes the whole graph to a file"},
		{"apoc.export.csv.query", false, "writes attacker-chosen query output to a file"},
		{"apoc.load.json", false, "fetches an attacker-chosen URL from inside the database"},
		{"apoc.load.jsonParams", false, "arbitrary outbound HTTP with headers"},
		{"apoc.load.csv", false, "reads an attacker-chosen file or URL"},
		{"apoc.cypher.runFile", false, "executes Cypher from a file"},
		{"apoc.cypher.doIt", false, "executes a Cypher string, i.e. re-opens the injection surface"},
		{"apoc.util.sleep", false, "not needed; the allowlist is least-privilege, not a denylist"},
		{"apoc.meta.stats", false, "not needed by the write path"},
	}
	for _, tc := range cases {
		t.Run(tc.procedure, func(t *testing.T) {
			got := procedureLoaded(t, allowlist, tc.procedure)
			if got != tc.want {
				t.Errorf("allowlist %q loads %s = %v, want %v (%s)",
					allowlist, tc.procedure, got, tc.want, tc.why)
			}
		})
	}
}

// TestTenantNeo4jNeverSetsProceduresUnrestricted guards the setting ADR-0012
// singles out. Neo4j Community has no in-database RBAC, so `unrestricted`
// applies to every connection holding the bolt credential — the same
// credential the projector uses — and converts a graph-write bug into a
// cluster pivot.
//
// It also fails on NEO4J_PLUGINS, which is the non-obvious way to set
// unrestricted: the image entrypoint reads /startup/neo4j-plugins.json, whose
// apoc entry carries `dbms.security.procedures.unrestricted: apoc.*`, and
// appends it to neo4j.conf. Verified on neo4j:5.26.27-community. Because
// plugin installation runs before NEO4J_-prefixed settings are applied, and
// empty-valued variables are skipped, no environment variable can undo it.
func TestTenantNeo4jNeverSetsProceduresUnrestricted(t *testing.T) {
	t.Parallel()
	sts, _ := buildTestNeo4j(t)

	if v, ok := neo4jSettings(t, sts)["dbms.security.procedures.unrestricted"]; ok {
		t.Errorf("dbms.security.procedures.unrestricted is set to %q; ADR-0012 says it is never set — "+
			"on Community it grants filesystem and network reach to every holder of the bolt credential", v)
	}

	for _, c := range append(
		append([]corev1.Container{}, sts.Spec.Template.Spec.InitContainers...),
		sts.Spec.Template.Spec.Containers...,
	) {
		for _, e := range c.Env {
			if e.Name == "NEO4J_PLUGINS" {
				t.Errorf("container %q sets NEO4J_PLUGINS=%q; the image entrypoint would then append "+
					"dbms.security.procedures.unrestricted=apoc.* to neo4j.conf. Install the jar with the "+
					"%s init container instead", c.Name, e.Value, apocInitContainerName)
			}
		}
	}
}

// TestTenantNeo4jInstallsAPOCCoreFromTheImage asserts the plugin actually
// arrives. An allowlist naming apoc.merge.node on a database with no APOC jar
// is not "secure", it is broken: every Host projection fails.
//
// The jar is copied out of the running image rather than downloaded, which is
// also the only thing that works once CNI policy enforcement is on — the
// tenant Neo4j NetworkPolicy (gibson#1263) permits egress to DNS and nothing
// else.
func TestTenantNeo4jInstallsAPOCCoreFromTheImage(t *testing.T) {
	t.Parallel()
	sts, _ := buildTestNeo4j(t)
	pod := sts.Spec.Template.Spec

	var install *corev1.Container
	for i := range pod.InitContainers {
		if pod.InitContainers[i].Name == apocInitContainerName {
			install = &pod.InitContainers[i]
		}
	}
	if install == nil {
		t.Fatalf("no %q init container: APOC Core never reaches the plugins directory", apocInitContainerName)
	}

	db := neo4jContainer(t, sts)
	if install.Image != db.Image {
		t.Errorf("init container image %q != neo4j image %q; the APOC Core jar ships inside the server "+
			"image and must stay version-locked to it", install.Image, db.Image)
	}

	cmd := strings.Join(append(install.Command, install.Args...), " ")
	if !strings.Contains(cmd, pdataplane.APOCCoreJarGlob) {
		t.Errorf("init container command %q does not read the bundled jar at %q", cmd, pdataplane.APOCCoreJarGlob)
	}
	if !strings.Contains(cmd, pdataplane.Neo4jPluginsDir) {
		t.Errorf("init container command %q does not write into %q", cmd, pdataplane.Neo4jPluginsDir)
	}
	for _, bad := range []string{"curl", "wget", "http://", "https://"} {
		if strings.Contains(cmd, bad) {
			t.Errorf("init container command %q reaches the network (%q); the tenant Neo4j NetworkPolicy "+
				"permits egress to DNS only, so this cannot work once enforcement is on", cmd, bad)
		}
	}

	// The plugins directory must be the SAME volume in both containers, or
	// the install lands somewhere Neo4j never looks.
	mountedVolume := func(c corev1.Container) string {
		for _, m := range c.VolumeMounts {
			if m.MountPath == pdataplane.Neo4jPluginsDir {
				return m.Name
			}
		}
		return ""
	}
	installVol, dbVol := mountedVolume(*install), mountedVolume(db)
	if installVol == "" {
		t.Fatalf("init container does not mount %s", pdataplane.Neo4jPluginsDir)
	}
	if installVol != dbVol {
		t.Fatalf("init container writes the jar to volume %q but neo4j reads %s from %q",
			installVol, pdataplane.Neo4jPluginsDir, dbVol)
	}

	var found *corev1.Volume
	for i := range pod.Volumes {
		if pod.Volumes[i].Name == installVol {
			found = &pod.Volumes[i]
		}
	}
	if found == nil {
		t.Fatalf("pod declares no volume %q", installVol)
	}
	if found.EmptyDir == nil {
		t.Errorf("volume %q is not an emptyDir; the plugin is derived from the image and must be "+
			"reinstalled on every start, or a stale jar outlives an image bump", installVol)
	}
}

// TestTenantNeo4jAPOCReachesAlreadyProvisionedTenants covers the half of the
// change that is easy to skip. Adding APOC to buildResources only helps
// tenants provisioned after the change; a tenant whose StatefulSet already
// exists keeps a Neo4j with no APOC, and every Host projection into it fails
// forever. The provisioner must reconcile the pod template onto it.
func TestTenantNeo4jAPOCReachesAlreadyProvisionedTenants(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, appsv1.AddToScheme, networkingv1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatalf("AddToScheme: %v", err)
		}
	}

	names, err := tenantNames(testTenantID)
	if err != nil {
		t.Fatalf("tenantNames: %v", err)
	}
	stsName := names.Neo4jStatefulSet()

	// A tenant provisioned before this change: plain Neo4j, no init
	// container, no plugins volume, no procedure settings.
	legacy := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: stsName, Namespace: testTenantNS},
		Spec: appsv1.StatefulSetSpec{
			ServiceName: stsName,
			Selector:    &metav1.LabelSelector{MatchLabels: neo4jLabels(testTenantID, testTenantNS)},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: neo4jLabels(testTenantID, testTenantNS)},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "neo4j", Image: neo4jImage}},
				},
			},
		},
	}

	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(legacy).Build()
	n := &Neo4jProvisioner{cfg: Neo4jConfig{
		K8sClient:         dpclient.New(k8s, ""),
		VaultClient:       newRecordingVaultAdmin(),
		PlatformNamespace: testPlatformNS,
	}}
	ctx := context.Background()

	if err := n.applyResources(ctx, testTenantID, testTenantID, "team", testTenantNS, "pw"); err != nil {
		t.Fatalf("applyResources over an existing StatefulSet: %v", err)
	}

	got := &appsv1.StatefulSet{}
	if err := k8s.Get(ctx, types.NamespacedName{Namespace: testTenantNS, Name: stsName}, got); err != nil {
		t.Fatalf("get StatefulSet: %v", err)
	}

	var haveInit bool
	for _, c := range got.Spec.Template.Spec.InitContainers {
		if c.Name == apocInitContainerName {
			haveInit = true
		}
	}
	if !haveInit {
		t.Error("an already-provisioned tenant did not gain the APOC init container; " +
			"its graph stays unwritable because apoc.merge.node is not registered")
	}
	if got := neo4jSettings(t, got)["dbms.security.procedures.allowlist"]; got != pdataplane.Neo4jProcedureAllowlist {
		t.Errorf("allowlist on the reconciled StatefulSet = %q, want %q", got, pdataplane.Neo4jProcedureAllowlist)
	}
}
