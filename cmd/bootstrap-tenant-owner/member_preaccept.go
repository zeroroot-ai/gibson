// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	tenantnames "github.com/zeroroot-ai/gibson/pkg/platform/tenant"
)

// tenantMembersGVR is the GVR for the namespaced TenantMember CR.
var tenantMembersGVR = schema.GroupVersionResource{
	Group:    "gibson.zeroroot.ai",
	Version:  "v1alpha1",
	Resource: "tenantmembers",
}

// acceptedByField is the TenantMemberSpec.AcceptedByUserID json tag — the
// key the API server accepts. Anything else is silently PRUNED by the CRD
// schema while the patch reports success (hit live: "acceptedByUserID" with a
// capital D no-opped). A test reflects over the real type to pin this.
const acceptedByField = "acceptedByUserId"

// preAcceptOutcome says what the founding-member pre-accept did, for the log.
type preAcceptOutcome string

const (
	preAcceptDone       preAcceptOutcome = "pre_accepted"
	preAcceptAlreadySet preAcceptOutcome = "already_accepted"
	preAcceptCreated    preAcceptOutcome = "created_accepted"
)

// foundingMemberPreAcceptor is swapped in tests, same pattern as
// credentialWriter: the patch path must be exercisable without a live API
// server.
var foundingMemberPreAcceptor = preAcceptFoundingMemberViaConfig

// preAcceptFoundingMemberViaConfig builds the real dynamic client and
// delegates.
func preAcceptFoundingMemberViaConfig(ctx context.Context, cfg *rest.Config, tenantID, ownerEmail, userID string) (preAcceptOutcome, error) {
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return "", fmt.Errorf("build dynamic client: %w", err)
	}
	return preAcceptFoundingMember(ctx, dyn, tenantID, ownerEmail, userID)
}

// preAcceptFoundingMember stamps spec.acceptedByUserID on the founding-owner
// TenantMember CR, the same pre-acceptance the signup path writes at creation
// (pending_provisioning_controller.ensureFoundingMember): the owner this
// bootstrap just created IS the workspace owner, so there is no invitation to
// redeem. The TenantMember reconciler then promotes Invited→Active and writes
// the FGA membership and active_session tuples — WITHOUT the pre-accept, the
// owner can sign in (the FGA owner tuple is written directly below) but every
// tenant-scoped RPC fails closed at the session-revocation gate, because only
// the reconciler's Active branch seeds the active_session tuples.
//
// Idempotent and race-free: an already-accepted member is a no-op; an existing
// un-accepted member is patched; and a member CR that does not exist yet is
// CREATED already-accepted with the canonical name, so it no longer matters
// whether this bootstrap or the pending-provisioning reconcile runs first —
// both converge on an accepted founding member (the self-hosted first-run race,
// where the pre-accept ran before the reconcile created the CR and left it
// Invited forever).
func preAcceptFoundingMember(ctx context.Context, dyn dynamic.Interface, tenantID, ownerEmail, userID string) (preAcceptOutcome, error) {
	namespace := "tenant-" + tenantID
	members := dyn.Resource(tenantMembersGVR).Namespace(namespace)

	list, err := members.List(ctx, metav1.ListOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return "", fmt.Errorf("list TenantMembers in %s: %w", namespace, err)
	}

	// Match by spec.email + role rather than reconstructing the slugified CR
	// name: the email is the identity, the name is a derivation.
	var member *unstructured.Unstructured
	if list != nil {
		for i := range list.Items {
			email, _, _ := unstructured.NestedString(list.Items[i].Object, "spec", "email")
			role, _, _ := unstructured.NestedString(list.Items[i].Object, "spec", "role")
			if strings.EqualFold(email, ownerEmail) && role == "owner" {
				member = &list.Items[i]
				break
			}
		}
	}

	// No founding member CR yet: the pending-provisioning reconcile has not
	// created it, or this bootstrap raced its create. Rather than give up (which
	// left the member Invited forever whenever the pre-accept ran first — the
	// self-hosted first-run race), CREATE it already-accepted, keyed by the SAME
	// canonical name the reconcile uses. Whichever runs first, the end state is
	// an accepted founding member; the loser's create is an idempotent no-op.
	if member == nil {
		return createFoundingMemberAccepted(ctx, members, namespace, tenantID, ownerEmail, userID)
	}

	accepted, _, _ := unstructured.NestedString(member.Object, "spec", acceptedByField)
	if accepted != "" {
		return preAcceptAlreadySet, nil
	}
	if err := patchAcceptFoundingMember(ctx, members, namespace, member.GetName(), userID); err != nil {
		return "", err
	}
	return preAcceptDone, nil
}

// tenantMemberAPIVersion / tenantMemberKind identify the CR for an unstructured
// create. They match tenantMembersGVR (Group/Version) and the CRD kind.
const (
	tenantMemberAPIVersion = "gibson.zeroroot.ai/v1alpha1"
	tenantMemberKind       = "TenantMember"
)

// createFoundingMemberAccepted creates the founding-owner TenantMember already
// pre-accepted, with the canonical name + the exact spec the pending-provisioning
// reconcile writes (ensureFoundingMember). On a lost race — the reconcile created
// the same-named member between our find and our create — it accepts that member
// instead, so the two converge on Active.
func createFoundingMemberAccepted(ctx context.Context, members dynamic.ResourceInterface, namespace, tenantID, ownerEmail, userID string) (preAcceptOutcome, error) {
	name := tenantnames.FoundingMemberName(ownerEmail)
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": tenantMemberAPIVersion,
		"kind":       tenantMemberKind,
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]interface{}{
			"email":         ownerEmail,
			"role":          "owner",
			"tenantRef":     map[string]interface{}{"name": tenantID},
			acceptedByField: userID,
		},
	}}
	if _, err := members.Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			if perr := patchAcceptFoundingMember(ctx, members, namespace, name, userID); perr != nil {
				return "", perr
			}
			return preAcceptDone, nil
		}
		return "", fmt.Errorf("create founding TenantMember %s/%s: %w", namespace, name, err)
	}
	return preAcceptCreated, nil
}

// patchAcceptFoundingMember stamps spec.acceptedByUserId on an existing member.
func patchAcceptFoundingMember(ctx context.Context, members dynamic.ResourceInterface, namespace, name, userID string) error {
	patch := []byte(fmt.Sprintf(`{"spec":{%q:%q}}`, acceptedByField, userID))
	if _, err := members.Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("pre-accept TenantMember %s/%s: %w", namespace, name, err)
	}
	return nil
}
