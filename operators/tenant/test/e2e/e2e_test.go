// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// deployment is the chart's tenant-operator Deployment and the label of its
// pods (charts helm/gibson-operators/templates/tenant-operator).
const (
	deployment = "gibson-tenant-operator"
	podLabel   = "app.kubernetes.io/name=gibson-tenant-operator"
	// metricsPort is the plain metrics listener the chart sets
	// (--metrics-bind-address=:8080 --metrics-secure=false).
	metricsPort = 8080
	// leaseName is the leader election Lease the chart sets
	// (--leader-election-id=gibson-tenant-operator).
	leaseName = "gibson-tenant-operator"
)

// kubectl runs kubectl with the arguments and returns its stdout. stderr is
// part of the error, so a failure names its cause.
func kubectl(args ...string) (string, error) {
	cmd := exec.Command("kubectl", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return string(out), fmt.Errorf("kubectl %s: %w: %s", strings.Join(args, " "), err, stderr.String())
	}
	return string(out), nil
}

var _ = Describe("The tenant-operator of the checkout on the installed platform", Ordered, func() {
	var namespace, image string

	BeforeAll(func() {
		namespace = os.Getenv("TENANT_OPERATOR_NAMESPACE")
		if namespace == "" {
			namespace = "gibson"
		}
		image = os.Getenv("TENANT_OPERATOR_IMAGE")
		Expect(image).NotTo(BeEmpty(),
			"TENANT_OPERATOR_IMAGE names the checkout build the exit test pointed the chart at")
	})

	AfterEach(func() {
		if !CurrentSpecReport().Failed() {
			return
		}
		for _, args := range [][]string{
			{"-n", namespace, "get", "pods", "-l", podLabel, "-o", "wide"},
			{"-n", namespace, "describe", "deployment", deployment},
			{"-n", namespace, "logs", "deployment/" + deployment, "-c", "manager", "--tail=120"},
		} {
			out, err := kubectl(args...)
			_, _ = fmt.Fprintf(GinkgoWriter, "kubectl %s:\n%s %v\n", strings.Join(args, " "), out, err)
		}
	})

	It("runs the checkout build", func() {
		got, err := kubectl("-n", namespace, "get", "deployment", deployment,
			"-o", `jsonpath={.spec.template.spec.containers[?(@.name=="manager")].image}`)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(image), "the Deployment must run the image of the checkout")

		_, err = kubectl("-n", namespace, "rollout", "status", "deployment/"+deployment, "--timeout=10m")
		Expect(err).NotTo(HaveOccurred(), "the operator of the checkout must roll out and stay up")
	})

	It("has every pod Ready on that image", func() {
		Eventually(func(g Gomega) {
			out, err := kubectl("-n", namespace, "get", "pods", "-l", podLabel, "-o",
				`jsonpath={range .items[*]}{.metadata.name}{" "}{.spec.containers[?(@.name=="manager")].image}{" "}`+
					`{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}`)
			g.Expect(err).NotTo(HaveOccurred())
			lines := strings.Fields(strings.TrimSpace(out))
			g.Expect(lines).NotTo(BeEmpty(), "no tenant-operator pod")
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				f := strings.Fields(line)
				g.Expect(f).To(HaveLen(3), "pod line %q", line)
				g.Expect(f[1]).To(Equal(image), "pod %s runs another image", f[0])
				g.Expect(f[2]).To(Equal("True"), "pod %s is not Ready", f[0])
			}
		}, 5*time.Minute, 5*time.Second).Should(Succeed())
	})

	// The chart runs two replicas with leader election. Only the leader
	// starts the controllers, so only the leader serves the reconcile
	// metrics. The spec reads the leader from the Lease and asks that pod.
	It("serves the controller metrics on the leader", func() {
		Eventually(func(g Gomega) {
			holder, err := kubectl("-n", namespace, "get", "lease", leaseName,
				"-o", "jsonpath={.spec.holderIdentity}")
			g.Expect(err).NotTo(HaveOccurred())
			leader, _, _ := strings.Cut(strings.TrimSpace(holder), "_")
			g.Expect(leader).NotTo(BeEmpty(), "the Lease %s has no holder", leaseName)
			got, err := kubectl("-n", namespace, "get", "pod", leader,
				"-o", `jsonpath={.spec.containers[?(@.name=="manager")].image}`)
			g.Expect(err).NotTo(HaveOccurred(), "the leader %s is not a pod of the Deployment", leader)
			g.Expect(got).To(Equal(image), "the leader %s runs another image", leader)
			out, err := kubectl("get", "--raw",
				fmt.Sprintf("/api/v1/namespaces/%s/pods/%s:%d/proxy/metrics", namespace, leader, metricsPort))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(ContainSubstring("controller_runtime_reconcile_total"),
				"the leader %s runs no controller", leader)
		}, 3*time.Minute, 5*time.Second).Should(Succeed())
	})
})
