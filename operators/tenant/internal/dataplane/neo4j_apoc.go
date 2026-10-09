// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	corev1 "k8s.io/api/core/v1"

	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
)

// APOC Core provisioning for the per-tenant Neo4j pod (ADR-0112, gibson#1257).
//
// The projector writes :Host through apoc.merge.node, so APOC Core is a
// required plugin rather than an optional one — a tenant Neo4j without it
// fails every Host projection. The shared contract (which jar, which
// directory, which allowlist, and why NOT NEO4J_PLUGINS) lives in
// pkg/platform/dataplane/apoc.go, next to the daemon that depends on it.
const (
	// apocPluginsVolumeName is the emptyDir shared between the init
	// container that installs the jar and the Neo4j container that loads
	// it. It is deliberately NOT the data PVC: the plugin is derived from
	// the image and must be reinstalled on every start, so persisting it
	// would let a stale jar outlive an image bump.
	apocPluginsVolumeName = "apoc-plugins"

	// apocInitContainerName installs APOC Core before Neo4j starts.
	apocInitContainerName = "install-apoc-core"
)

// apocPluginVolume returns the emptyDir the plugin jar is installed into.
func apocPluginVolume() corev1.Volume {
	return corev1.Volume{
		Name:         apocPluginsVolumeName,
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
	}
}

// apocPluginMount returns the mount both containers use for the plugins dir.
func apocPluginMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      apocPluginsVolumeName,
		MountPath: pdataplane.Neo4jPluginsDir,
	}
}

// apocInitContainer copies APOC Core out of the Neo4j image's labs directory
// into the plugins volume. No network: the jar is already in the image, which
// matters because the tenant Neo4j NetworkPolicy permits egress to DNS only.
// It runs the SAME image as the Neo4j container (Neo4jConfig.Image), which is
// what keeps the APOC Core jar version locked to the server version.
func apocInitContainer(image string) corev1.Container {
	return corev1.Container{
		Name:            apocInitContainerName,
		Image:           image,
		Command:         []string{"sh", "-c", pdataplane.APOCInstallCommand(pdataplane.Neo4jPluginsDir)},
		VolumeMounts:    []corev1.VolumeMount{apocPluginMount()},
		SecurityContext: neo4jContainerSecurityContext(),
	}
}

// neo4jUID is the numeric id of the neo4j user and group in the official
// image. The pod runs as this id from the start, so the image entrypoint never
// runs as root.
const neo4jUID int64 = 7474

// neo4jPodSecurityContext and neo4jContainerSecurityContext together make the
// tenant Neo4j pod meet the Kubernetes Pod Security Standard "restricted"
// (ADR-0165). The fsGroup makes the data volume and the plugins volume
// writable for the neo4j group.
func neo4jPodSecurityContext() *corev1.PodSecurityContext {
	uid := neo4jUID
	nonRoot := true
	return &corev1.PodSecurityContext{
		RunAsNonRoot:   &nonRoot,
		RunAsUser:      &uid,
		RunAsGroup:     &uid,
		FSGroup:        &uid,
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

func neo4jContainerSecurityContext() *corev1.SecurityContext {
	no := false
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: &no,
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
}

// neo4jSecurityEnv returns the procedure-security settings for the Neo4j
// container. The image entrypoint turns a NEO4J_-prefixed variable into a
// configuration setting by stripping the prefix, replacing '_' with '.' and
// '__' with '_', and routes apoc.*-prefixed settings to apoc.conf.
//
// dbms.security.procedures.unrestricted is absent, and must stay absent. It is
// not "absent because the default is safe" — it is absent because setting it
// on Community, which has no in-database RBAC, grants filesystem and network
// reach to every holder of the bolt credential. The test that asserts this is
// what stops a future "just add apoc.* to unrestricted so backups work" from
// landing quietly.
func neo4jSecurityEnv() []corev1.EnvVar {
	settings := pdataplane.Neo4jSecuritySettings()
	names := pdataplane.Neo4jSettingNames()
	env := make([]corev1.EnvVar, 0, len(names))
	for _, name := range names {
		env = append(env, corev1.EnvVar{
			Name:  pdataplane.Neo4jSettingEnvVar(name),
			Value: settings[name],
		})
	}
	return env
}
