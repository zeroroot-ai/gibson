package flows

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

type fakeLimits struct {
	calls []struct {
		tenant, agent string
		max           time.Duration
	}
	err error
}

func (f *fakeLimits) SetAgentEnrollmentLimits(_ context.Context, tenantID, agentName string, maxRuntime time.Duration) error {
	f.calls = append(f.calls, struct {
		tenant, agent string
		max           time.Duration
	}{tenantID, agentName, maxRuntime})
	return f.err
}

// TestReportRuntimeLimitStep_ReportsSpecMaxRuntime proves spec.maxRuntime is
// read (gibson#597): the issuance saga reports it to the daemon keyed by the
// tenant namespace and agent name, revocation clears it, and an unset
// reporter is a loud misconfiguration rather than a silently uncapped run.
func TestReportRuntimeLimitStep_ReportsSpecMaxRuntime(t *testing.T) {
	ae := &gibsonv1alpha1.AgentEnrollment{
		ObjectMeta: metav1.ObjectMeta{Name: "ae-1", Namespace: "tenant-acme"},
		Spec:       gibsonv1alpha1.AgentEnrollmentSpec{AgentName: "breach-checker", MaxRuntime: metav1.Duration{Duration: 15 * time.Minute}},
	}
	rep := &fakeLimits{}
	deps := EnrollmentDeps{Limits: rep}

	done, err := newReportRuntimeLimitStep(deps).Provision(context.Background(), ae, nil)
	if err != nil || !done {
		t.Fatalf("report: done=%v err=%v", done, err)
	}
	done, err = newClearRuntimeLimitStep(deps).Provision(context.Background(), ae, nil)
	if err != nil || !done {
		t.Fatalf("clear: done=%v err=%v", done, err)
	}
	if len(rep.calls) != 2 || rep.calls[0].tenant != "tenant-acme" || rep.calls[0].agent != "breach-checker" ||
		rep.calls[0].max != 15*time.Minute || rep.calls[1].max != 0 {
		t.Fatalf("calls = %+v, want the cap reported then cleared", rep.calls)
	}

	rep.err = errors.New("daemon down")
	if _, err := newReportRuntimeLimitStep(deps).Provision(context.Background(), ae, nil); err == nil {
		t.Fatal("a daemon error must fail the step")
	}
	if _, err := newReportRuntimeLimitStep(EnrollmentDeps{}).Provision(context.Background(), ae, nil); err == nil {
		t.Fatal("an unset reporter must fail the step")
	}
}

// TestClearRuntimeLimitStep_FailuresAreNamed proves the clear step fails on a
// daemon error with the tenant and agent in the message, fails on an unset
// reporter, and both steps refuse an object that is not an AgentEnrollment.
func TestClearRuntimeLimitStep_FailuresAreNamed(t *testing.T) {
	ae := &gibsonv1alpha1.AgentEnrollment{
		ObjectMeta: metav1.ObjectMeta{Name: "ae-1", Namespace: "tenant-acme"},
		Spec:       gibsonv1alpha1.AgentEnrollmentSpec{AgentName: "breach-checker"},
	}
	down := errors.New("daemon down")
	deps := EnrollmentDeps{Limits: &fakeLimits{err: down}}

	_, err := newClearRuntimeLimitStep(deps).Provision(context.Background(), ae, nil)
	if !errors.Is(err, down) || !strings.Contains(err.Error(), "tenant-acme/breach-checker") {
		t.Fatalf("clear with the daemon down = %v, want the cause and tenant-acme/breach-checker", err)
	}
	_, err = newReportRuntimeLimitStep(deps).Provision(context.Background(), ae, nil)
	if !errors.Is(err, down) || !strings.Contains(err.Error(), "tenant-acme/breach-checker") {
		t.Fatalf("report with the daemon down = %v, want the cause and tenant-acme/breach-checker", err)
	}
	if _, err := newClearRuntimeLimitStep(EnrollmentDeps{}).Provision(context.Background(), ae, nil); err == nil {
		t.Fatal("an unset reporter must fail the clear step")
	}
	notAnEnrollment := &gibsonv1alpha1.Tenant{}
	if _, err := newReportRuntimeLimitStep(deps).Provision(context.Background(), notAnEnrollment, nil); err == nil {
		t.Fatal("the report step must refuse an object that is not an AgentEnrollment")
	}
	if _, err := newClearRuntimeLimitStep(deps).Provision(context.Background(), notAnEnrollment, nil); err == nil {
		t.Fatal("the clear step must refuse an object that is not an AgentEnrollment")
	}
}
