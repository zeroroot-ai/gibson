// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga/flows"
)

// The provisioning saga creates the belief trainer CronJob of a tenant
// against a real API server (gibson#616). The API server accepts the owner
// reference to the live Tenant, which is what makes a tenant delete remove
// the CronJob and its NetworkPolicy: the garbage collector of a cluster
// deletes a dependent whose owner is gone. envtest runs no garbage
// collector, so this spec proves the owner reference, not the collection.
var _ = ginkgo.Describe("belief trainer provisioning", func() {
	ginkgo.It("creates the CronJob and its NetworkPolicy, owned by the Tenant", func() {
		tenant := &gibsonv1alpha1.Tenant{
			ObjectMeta: metav1.ObjectMeta{Name: "trainer-envtest"},
			Spec: gibsonv1alpha1.TenantSpec{
				DisplayName: "Trainer envtest",
				Owner:       "owner@example.org",
				Tier:        "team",
			},
		}
		gomega.Expect(k8sClient.Create(ctx, tenant)).To(gomega.Succeed())
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-trainer-envtest"}}
		gomega.Expect(k8sClient.Create(ctx, ns)).To(gomega.Succeed())
		tenant.Status.Namespace = ns.Name

		cfg, err := flows.NewBeliefTrainerConfig("ghcr.io/zeroroot-ai/gibson:test",
			"gibson.gibson.svc:50051", "spiffe://example.org/platform/daemon", "gibson")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		var ran bool
		for _, step := range flows.ProvisionSteps(flows.ProvisionDeps{K8sClient: k8sClient, BeliefTrainer: cfg}) {
			if step.Name() != "EnsureBeliefTrainer" {
				continue
			}
			done, err := step.Provision(ctx, tenant, nil)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(done).To(gomega.BeTrue())
			ran = true
		}
		gomega.Expect(ran).To(gomega.BeTrue(), "ProvisionSteps has no EnsureBeliefTrainer step")

		key := types.NamespacedName{Namespace: ns.Name, Name: flows.BeliefTrainerName}
		var cj batchv1.CronJob
		gomega.Expect(k8sClient.Get(ctx, key, &cj)).To(gomega.Succeed())
		gomega.Expect(cj.Spec.ConcurrencyPolicy).To(gomega.Equal(batchv1.ForbidConcurrent))
		gomega.Expect(cj.OwnerReferences).To(gomega.HaveLen(1))
		gomega.Expect(cj.OwnerReferences[0].UID).To(gomega.Equal(tenant.UID))
		gomega.Expect(cj.OwnerReferences[0].Kind).To(gomega.Equal("Tenant"))

		var np networkingv1.NetworkPolicy
		gomega.Expect(k8sClient.Get(ctx, key, &np)).To(gomega.Succeed())
		gomega.Expect(np.OwnerReferences).To(gomega.HaveLen(1))
		gomega.Expect(np.OwnerReferences[0].UID).To(gomega.Equal(tenant.UID))
	})
})
