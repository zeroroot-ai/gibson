// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ciliumegress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The egress policy of a workload has the shape of CVE-2024-47825: a CIDR
// deny and a narrow CIDR allow with a port, which Cilium makes from each
// address of a toFQDNs allow. A Cilium agent before the fixed release of its
// minor line can drop the deny. An operator reads the version of the agent
// and refuses to start below the fixed release.
const (
	// EnvDaemonSetNamespace and EnvDaemonSetName name the settings that tell the
	// operator where the Cilium agent runs. The chart sets them when the install
	// does not use the defaults. The Role of the operator follows the namespace.
	EnvDaemonSetNamespace = "CILIUM_DAEMONSET_NAMESPACE"
	EnvDaemonSetName      = "CILIUM_DAEMONSET_NAME"
	// DefaultDaemonSetNamespace and DefaultDaemonSetName are what a Cilium
	// install gives the agent DaemonSet.
	DefaultDaemonSetNamespace = "kube-system"
	DefaultDaemonSetName      = "cilium"
	// agentContainer is the container of the DaemonSet and of each pod that
	// runs the agent.
	agentContainer = "cilium-agent"
	// agentPodLabel selects the pods of the Cilium agent.
	agentPodLabel = "k8s-app"
	// agentPodLabelValue is the value of agentPodLabel on an agent pod.
	agentPodLabelValue = "cilium"
)

// DaemonSetRef names the Cilium agent DaemonSet.
type DaemonSetRef struct{ Namespace, Name string }

// DaemonSetFromEnv reads where the Cilium agent runs. An unset value takes the
// default of a Cilium install.
func DaemonSetFromEnv(getenv func(string) string) DaemonSetRef {
	ref := DaemonSetRef{Namespace: DefaultDaemonSetNamespace, Name: DefaultDaemonSetName}
	if v := strings.TrimSpace(getenv(EnvDaemonSetNamespace)); v != "" {
		ref.Namespace = v
	}
	if v := strings.TrimSpace(getenv(EnvDaemonSetName)); v != "" {
		ref.Name = v
	}
	return ref
}

// ErrCiliumVersion reports a Cilium agent that the operator cannot accept. It
// covers a version below the minimum and a version that the operator cannot
// read, because the operator fails closed.
var ErrCiliumVersion = errors.New("the Cilium version is not accepted")

// fixedPatch is the first release of each minor line that fixes
// CVE-2024-47825. A minor line below 1.14 has no fix. A minor line above
// 1.16 holds the fix.
var fixedPatch = map[int]int{14: 16, 15: 10, 16: 3}

// CheckVersion accepts a Cilium version of 1.14.16, 1.15.10, 1.16.3 or later.
// It takes a tag such as "v1.15.10" or "1.16.3". A pre-release of the minimum
// is below the minimum.
func CheckVersion(version string) error {
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	core, pre, _ := strings.Cut(v, "-")
	core, _, _ = strings.Cut(core, "+")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return fmt.Errorf("%w: %q is not a version of the form 1.15.10", ErrCiliumVersion, version)
	}
	var n [3]int
	for i, p := range parts {
		x, err := strconv.Atoi(p)
		if err != nil || x < 0 {
			return fmt.Errorf("%w: %q is not a version of the form 1.15.10", ErrCiliumVersion, version)
		}
		n[i] = x
	}
	major, minor, patch := n[0], n[1], n[2]
	switch {
	case major > 1, major == 1 && minor > 16:
		return nil
	case major < 1, major == 1 && minor < 14:
		return fmt.Errorf("%w: %s has no fix for CVE-2024-47825, use 1.14.16, 1.15.10, 1.16.3 or later",
			ErrCiliumVersion, version)
	}
	fixed := fixedPatch[minor]
	if patch < fixed || (patch == fixed && pre != "") {
		return fmt.Errorf("%w: %s is below 1.%d.%d, which fixes CVE-2024-47825. A tag with a suffix, such as "+
			"-cee.1 of a distro build or -rc.1, counts as below the release itself, so use a build with no suffix "+
			"or a later patch", ErrCiliumVersion, version, minor, fixed)
	}
	return nil
}

// ImageVersion returns the tag of a container image, for example "v1.15.10"
// from "quay.io/cilium/cilium:v1.15.10@sha256:abc". An image with a digest
// and no tag has no version to read.
func ImageVersion(image string) (string, error) {
	ref, _, _ := strings.Cut(image, "@")
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon < 0 || colon < slash || colon == len(ref)-1 {
		return "", fmt.Errorf("%w: the image %q has no tag", ErrCiliumVersion, image)
	}
	return ref[colon+1:], nil
}

// RequireFixedVersion reads the Cilium agent DaemonSet and the pods that run
// the agent, and refuses a version below the minimum. It checks the image of the
// DaemonSet template and the image of the cilium-agent container of each running
// pod, so a node that still runs an old agent after a rollout is found. It fails
// closed: a DaemonSet that the operator cannot read, a missing agent container
// and a template or pod spec image with no tag all refuse.
func RequireFixedVersion(ctx context.Context, r client.Reader, ref DaemonSetRef) error {
	var ds appsv1.DaemonSet
	key := client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}
	if err := r.Get(ctx, key, &ds); err != nil {
		return fmt.Errorf("%w: read the DaemonSet %s/%s: %w", ErrCiliumVersion, key.Namespace, key.Name, err)
	}
	found := false
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name != agentContainer {
			continue
		}
		found = true
		if err := checkImage(c.Image); err != nil {
			return fmt.Errorf("DaemonSet %s/%s: %w", key.Namespace, key.Name, err)
		}
	}
	if !found {
		return fmt.Errorf("%w: the DaemonSet %s/%s has no container %q",
			ErrCiliumVersion, key.Namespace, key.Name, agentContainer)
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(ref.Namespace),
		client.MatchingLabels{agentPodLabel: agentPodLabelValue}); err != nil {
		return fmt.Errorf("%w: list the agent pods in %s: %w", ErrCiliumVersion, ref.Namespace, err)
	}
	for i := range pods.Items {
		if err := checkPod(&pods.Items[i]); err != nil {
			return err
		}
	}
	return nil
}

// checkPod checks the cilium-agent container of one running agent pod. The pod
// spec keeps the image that the DaemonSet wrote when it made the pod, with its
// tag, so an old pod after a rollout still shows its old version. The status
// image is checked too when it has a tag. On containerd an image pinned by tag
// and digest often shows only the digest in the status, and that is no refusal.
func checkPod(pod *corev1.Pod) error {
	found := false
	for _, c := range pod.Spec.Containers {
		if c.Name != agentContainer {
			continue
		}
		found = true
		if err := checkImage(c.Image); err != nil {
			return fmt.Errorf("agent pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}
	if !found {
		return fmt.Errorf("%w: the agent pod %s/%s has no container %q",
			ErrCiliumVersion, pod.Namespace, pod.Name, agentContainer)
	}
	for _, st := range pod.Status.ContainerStatuses {
		if st.Name != agentContainer {
			continue
		}
		if _, err := ImageVersion(st.Image); err != nil {
			continue
		}
		if err := checkImage(st.Image); err != nil {
			return fmt.Errorf("agent pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}
	return nil
}

// checkImage reads the tag of an image and checks it against the minimum.
func checkImage(image string) error {
	v, err := ImageVersion(image)
	if err != nil {
		return err
	}
	return CheckVersion(v)
}

// ParseClusterCIDRs parses the pod and the service ranges of the cluster, the
// comma list of an environment value. The name is the variable that held it,
// for the error text. The deny rule of each workload names the ranges (review
// B3). The value is required (review R7): a cluster range outside RFC 1918
// and CGNAT would otherwise stay open with no word. A missing value or a bad
// range fails the start, so a typo never drops the deny rule.
func ParseClusterCIDRs(name, raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%s is required: set the pod and the service ranges of the cluster, "+
			"for example 10.244.0.0/16,10.96.0.0/12", name)
	}
	var out []string
	for _, c := range strings.Split(raw, ",") {
		c = strings.TrimSpace(c)
		if _, _, err := net.ParseCIDR(c); err != nil {
			return nil, fmt.Errorf("%s: %q is not a CIDR: %w", name, c, err)
		}
		out = append(out, c)
	}
	return out, nil
}
