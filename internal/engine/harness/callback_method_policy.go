// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// The three SPIFFE peers the chart configures in
// gibson.config.callback.spiffe.peerSvids (rendered as
// GIBSON_CALLBACK_PEER_SVIDS). Verified identical in every environment:
// enterprise/deploy helm/gibson/values.yaml and helm/gibson-workloads/
// values-kind.yaml, enterprise/gitops envs/dev (staging and prod inherit the
// umbrella default).
//
// These are constants for the same reason tenantOperatorSVID is a constant in
// internal/server/daemon/operator_method_policy.go: what a peer may call is a
// code-level security decision, not a deployment knob. A configured peer with no
// policy here is refused at callback-server start by
// validateCallbackPeerPolicies, so a chart that renames or adds an SVID fails
// loud at boot rather than silently denying every callback at request time.
const (
	// callbackDashboardSVID is the browser-path caller. Its policy grants ZERO
	// methods: HarnessCallbackService is an agent-only in-mission callback
	// surface (docs/how-to-add-a-rpc.md) and no dashboard caller exists for any
	// of its RPCs anywhere in this codebase. The main daemon listener excludes
	// the dashboard from its direct-dial allowlist for the identical reason.
	callbackDashboardSVID = "spiffe://zeroroot.ai/platform/dashboard"

	// callbackEnvoySVID is the INGRESS peer. It fronts two populations, and
	// this policy is the only thing that bounds either of them:
	//
	//   - the in-guest agent's callback traffic, and
	//   - off-cluster components authenticating with a CG-JWT, whose edge
	//     route (/gibson.harness.v1.HarnessCallbackService/) Envoy sends to
	//     this listener via the `gibson_daemon_callback` cluster (gibson#1450;
	//     before that fix the route landed on :50051 and every such call
	//     returned Unimplemented).
	//
	// Because Envoy is a shared front for external callers, "what Envoy may
	// call" is the external attack surface of this service, not an in-cluster
	// convenience. Widening this peer's grant widens the public API. The
	// per-caller half of the decision is made upstream by ext-authz (FGA, plus
	// a CG-JWT bound to a single method); this half decides which RPCs the
	// listener will serve to an Envoy-forwarded caller at all.
	callbackEnvoySVID = "spiffe://zeroroot.ai/platform/envoy"

	// callbackDaemonSVID is the daemon's own identity on a self/loopback dial of
	// the callback listener.
	callbackDaemonSVID = "spiffe://zeroroot.ai/platform/daemon"
)

// healthCheckMethod and healthWatchMethod are the gRPC health-probe methods the
// callback server registers alongside HarnessCallbackService (see
// CallbackServer.Start). They belong to the agent-callback surface because the
// probe traverses the same mTLS channel; denying them would fail the listener's
// readiness probe.
const (
	healthCheckMethod = "/grpc.health.v1.Health/Check"
	healthWatchMethod = "/grpc.health.v1.Health/Watch"
)

// callbackMethodDecision classifies a single HarnessCallbackService method for
// the agent-callback peers (Envoy, and the daemon's own loopback dial). Exactly
// one of two states applies:
//
//   - agentSurface == true  → an in-mission agent legitimately calls this RPC and
//     this daemon serves it; the peer policy authorises it.
//   - agentSurface == false → denied (least privilege). reason documents WHY.
//
// reason is required for both states so the policy reads as an auditable
// allow/deny table.
type callbackMethodDecision struct {
	agentSurface bool
	reason       string
}

// reasonAgentCallbackSurface is the allow reason for the RPCs that make up the
// in-mission agent callback surface: dialed by the SDK's CallbackHarness
// (opensource/sdk serve/callback_harness.go + serve/callback_client.go — the
// ONLY HarnessCallbackService client in the workspace; gibson-executor does not
// use this service at all) AND served by a handler in this package. The set was
// derived from those two facts, not guessed.
const reasonAgentCallbackSurface = "in-mission agent callback: dialed by the SDK CallbackHarness and served by a handler here"

// reasonUnimplemented denies the RPCs declared in the proto that this daemon has
// no handler for. They fall through to
// harnesspb.UnimplementedHarnessCallbackServiceServer and already return an
// error to every caller today, so denying them removes no working call path —
// it changes which error. The value is forward-looking: when a handler is
// added, the guard test below forces an explicit classification instead of the
// new RPC inheriting a standing grant.
const reasonUnimplemented = "no handler on this daemon (falls through to UnimplementedHarnessCallbackServiceServer); " +
	"classify explicitly when a handler is added"

// reasonUnimplementedJobSurface is reasonUnimplemented for the member-facing
// job callbacks the sdk bump declared. It names the slice that serves each, so
// the deny reads as "not yet, and here is who" rather than "never".
const reasonUnimplementedJobSurface = "job callback declared by the sdk bump; no handler yet " +
	"(gibson#1713 mirrors JobService for a dispatched agent). " +
	"Flip to agentSurface in the change that adds the handler"

// reasonMemberJobSurface is the allow reason for the four RPCs a bank member
// calls as itself, under its base grant. They are on the surface for the same
// reason the rest of it is — dialed by the driver and served by a handler here
// — and each is additionally bounded by the handler, which refuses a job the
// calling member does not hold.
const reasonMemberJobSurface = "bank member callback: the member acts as itself under its base grant, " +
	"and the handler refuses a job it does not hold (ADR-0019)"

// callbackMethodPolicy is the SINGLE SOURCE OF TRUTH classifying EVERY
// HarnessCallbackService method as agent-surface XOR denied.
//
// It replaces the callbackDeniedSVIDs DENYLIST this package used to hold, whose
// failure mode was the classic one: it named only the dashboard, so the Envoy
// and daemon-loopback peers retained unbounded (subject, tenant) assertion
// across every RPC — GetCredential included — and ANY newly-added peer SVID
// inherited that same unbounded power by default. An allowlist fails closed: an
// unknown peer gets nothing, and a known peer gets only its classified methods.
//
// Two tests in callback_method_policy_test.go keep this honest:
//
//  1. A descriptor-driven GUARD test enumerates the methods from the generated
//     HarnessCallbackService_ServiceDesc and fails if ANY method is missing from
//     this map. Adding an RPC to the proto without classifying it here FAILS CI
//     — it cannot silently inherit access, and it cannot silently lose it.
//
//  2. A RECONCILIATION test pins the agent-surface set to exactly the RPCs this
//     daemon implements, failing on BOTH a missing grant (which would break a
//     live callback) and a surplus grant (a standing over-grant).
//
// Keys are the fully-qualified gRPC method names generated alongside the service
// — exactly what the interceptors match against info.FullMethod.
var callbackMethodPolicy = map[string]callbackMethodDecision{
	// --- LLM operations ---
	harnesspb.HarnessCallbackService_LLMComplete_FullMethodName:           {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_LLMCompleteWithTools_FullMethodName:  {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_LLMCompleteStructured_FullMethodName: {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_LLMStream_FullMethodName:             {agentSurface: true, reason: reasonAgentCallbackSurface},

	// --- Tool operations ---
	harnesspb.HarnessCallbackService_CallToolProto_FullMethodName:       {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_CallToolProtoStream_FullMethodName: {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_ListTools_FullMethodName:           {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_QueueToolWork_FullMethodName:       {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_ToolResults_FullMethodName:         {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_SearchTools_FullMethodName: {
		agentSurface: true,
		reason: "served here (callback_searchtools.go) and enumerated by the in-guest agent to build " +
			"the connector catalog; not on the Go CallbackHarness surface, so it is reached by the " +
			"agent's meta-tool path rather than a generated harness method",
	},

	// --- Plugin / agent discovery and delegation ---
	harnesspb.HarnessCallbackService_QueryPlugin_FullMethodName:     {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_ListPlugins_FullMethodName:     {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_DelegateToAgent_FullMethodName: {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_ListAgents_FullMethodName:      {agentSurface: true, reason: reasonAgentCallbackSurface},

	// --- Findings and observations ---
	harnesspb.HarnessCallbackService_SubmitFinding_FullMethodName: {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_Observe_FullMethodName:       {agentSurface: true, reason: reasonAgentCallbackSurface},

	// --- Taxonomy / validation ---
	harnesspb.HarnessCallbackService_GetTaxonomySchema_FullMethodName:    {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_GenerateNodeID_FullMethodName:       {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_ValidateFinding_FullMethodName:      {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_ValidateGraphNode_FullMethodName:    {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_ValidateRelationship_FullMethodName: {agentSurface: true, reason: reasonAgentCallbackSurface},

	// --- Tracing ---
	harnesspb.HarnessCallbackService_RecordSpans_FullMethodName: {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_RecordSpan_FullMethodName: {
		agentSurface: true,
		reason: "single-span variant of RecordSpans and served here; identical capability over identical " +
			"data, so denying it narrows no privilege while risking span loss for agent builds that emit it",
	},

	// --- Credentials ---
	// Method-policy allow ONLY. Per-secret authorization is a separate and
	// mandatory gate inside the handler: authorizeCredentialResolve runs the
	// can_resolve FGA Check (callback_credential_authz.go, gibson#1245).
	// Reaching this RPC grants nothing on its own.
	harnesspb.HarnessCallbackService_GetCredential_FullMethodName: {
		agentSurface: true,
		reason:       reasonAgentCallbackSurface + "; per-secret can_resolve Check enforced in the handler",
	},

	// --- Sub-mission lifecycle ---
	harnesspb.HarnessCallbackService_CreateMission_FullMethodName:     {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_RunMission_FullMethodName:        {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_GetMissionStatus_FullMethodName:  {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_WaitForMission_FullMethodName:    {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_ListMissions_FullMethodName:      {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_CancelMission_FullMethodName:     {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_GetMissionResults_FullMethodName: {agentSurface: true, reason: reasonAgentCallbackSurface},

	// --- Component authz ---
	harnesspb.HarnessCallbackService_Authorize_FullMethodName: {agentSurface: true, reason: reasonAgentCallbackSurface},

	// --- Workspace ---
	harnesspb.HarnessCallbackService_WorkspaceList_FullMethodName:      {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_WorkspaceGetInfo_FullMethodName:   {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_WorkspaceReadFile_FullMethodName:  {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_WorkspaceWriteFile_FullMethodName: {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_WorkspaceListFiles_FullMethodName: {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_WorkspaceCommit_FullMethodName:    {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_WorkspacePush_FullMethodName:      {agentSurface: true, reason: reasonAgentCallbackSurface},

	// --- Denied: declared in the proto, no handler on this daemon ---
	harnesspb.HarnessCallbackService_GetPlanContext_FullMethodName:  {agentSurface: false, reason: reasonUnimplemented},
	harnesspb.HarnessCallbackService_ReportStepHints_FullMethodName: {agentSurface: false, reason: reasonUnimplemented},

	// --- Bank member callbacks: declared by the sdk bump, served by a later
	// slice of epic gibson#1706. They are the member-facing half of the job
	// surface — pull a job, follow the inbox, report state and deliverables,
	// and drive a job under a per-turn grant — so each becomes agent surface
	// in the same change that adds its handler, never before.
	// The four a MEMBER calls as itself, served by callback_job.go. They are
	// the base-grant surface: take work, follow the inbox, report state,
	// report a deliverable. Each is bounded twice — the peer policy admits it
	// here, and the handler refuses a job the caller does not hold.
	harnesspb.HarnessCallbackService_PullJob_FullMethodName:           {agentSurface: true, reason: reasonMemberJobSurface},
	harnesspb.HarnessCallbackService_SubscribeInput_FullMethodName:    {agentSurface: true, reason: reasonMemberJobSurface},
	harnesspb.HarnessCallbackService_ReportJobState_FullMethodName:    {agentSurface: true, reason: reasonMemberJobSurface},
	harnesspb.HarnessCallbackService_ReportDeliverable_FullMethodName: {agentSurface: true, reason: reasonMemberJobSurface},

	// The three a DISPATCHED AGENT calls to drive a bank. They mirror
	// JobService and land with the job node executor, gibson#1713 (slice C7).
	harnesspb.HarnessCallbackService_OpenJob_FullMethodName:   {agentSurface: false, reason: reasonUnimplementedJobSurface},
	harnesspb.HarnessCallbackService_SendInput_FullMethodName: {agentSurface: false, reason: reasonUnimplementedJobSurface},
	harnesspb.HarnessCallbackService_CloseJob_FullMethodName:  {agentSurface: false, reason: reasonUnimplementedJobSurface},

	// WorldView is the agent's only World read (ADR-0012 read half); the daemon
	// handler landed in gibson#1377 (worldview.go), projecting a mission-Scope-
	// limited, handle-named slice. It is part of the in-mission agent surface.
	harnesspb.HarnessCallbackService_WorldView_FullMethodName: {agentSurface: true, reason: reasonAgentCallbackSurface},

	// Knowledge reads (sdk#496/#498, zerocool-plugins#33). The in-mission agent
	// surface for reading what earlier work established: the tenant knowledge
	// graph, previously submitted findings, and mission run history.
	//
	// Agent-callable, and read-only by construction — the projector remains the
	// sole graph writer (ADR-0012), so there is no write counterpart here to
	// classify. Every one derives its tenant from the caller's identity and the
	// resolved mission record; none takes a tenant argument, so a caller cannot
	// name another tenant's graph.
	//
	// These existed on ComponentService and had no callback equivalent, which is
	// why a dispatched agent could not read the graph at all.
	harnesspb.HarnessCallbackService_QueryNodes_FullMethodName:          {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_FindSimilarAttacks_FullMethodName:  {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_GetAttackChains_FullMethodName:     {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_FindSimilarFindings_FullMethodName: {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_GetRelatedFindings_FullMethodName:  {agentSurface: true, reason: reasonAgentCallbackSurface},
	// The lifecycle read an agent cannot work without (gibson#1669): the open
	// Findings of one Application with whether a running Deployment actually
	// contains the code they affect. Agent surface for the same reason its
	// siblings above are — it is a read an agent performs about its own tenant,
	// and the tenant comes from the call context, never a payload.
	harnesspb.HarnessCallbackService_ApplicationFindings_FullMethodName:  {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_GetFindings_FullMethodName:          {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_GetRunFindings_FullMethodName:       {agentSurface: true, reason: reasonAgentCallbackSurface},
	harnesspb.HarnessCallbackService_GetMissionRunHistory_FullMethodName: {agentSurface: true, reason: reasonAgentCallbackSurface},

	// Session surface, sdk v0.162.0 (gibson#1183 / gibson#1184).
	//
	// The session-context store (gibson#1184) is served here
	// (callback_session_context.go): per-(tenant, session_id) opaque blob,
	// tenant derived from the caller's identity, per-tenant dataplane
	// storage. Like SearchTools, it is reached by an external component's
	// callback channel rather than a generated Go CallbackHarness method.
	harnesspb.HarnessCallbackService_PutSessionContext_FullMethodName: {
		agentSurface: true,
		reason: "served here (callback_session_context.go); tenant-scoped session-context store " +
			"write, etag-guarded (gibson#1184)",
	},
	harnesspb.HarnessCallbackService_GetSessionContext_FullMethodName: {
		agentSurface: true,
		reason: "served here (callback_session_context.go); tenant-scoped session-context store " +
			"read (gibson#1184)",
	},
	harnesspb.HarnessCallbackService_DeleteSessionContext_FullMethodName: {
		agentSurface: true,
		reason: "served here (callback_session_context.go); tenant-scoped session-context store " +
			"delete (gibson#1184)",
	},

	// DevboxExec (gibson#1183) is on the agent surface: setec's in-VM exec
	// channel landed (setec#239, SandboxService.Exec) and the handler in
	// callback_devbox_exec.go plumbs to it through the session-sandbox
	// registry, so a component's successive commands share one /workspace.
	//
	// Arbitrary argv inside the microVM is the product — this is a devbox for
	// a coding agent — and per ADR-0052 the microVM is the containment
	// boundary: an escape is a setec defect, not a gibson one. What gibson
	// owes is that the command reaches the RIGHT sandbox, which the
	// tenant-derived, length-prefixed session key enforces.
	harnesspb.HarnessCallbackService_DevboxExec_FullMethodName: {agentSurface: true, reason: reasonAgentCallbackSurface},
}

// callbackAgentSurfaceMethods returns the method set granted to the
// agent-callback peers: every agentSurface entry in callbackMethodPolicy plus
// the two gRPC health-probe methods the same listener serves. The interceptors
// consume this, so enforcement can never disagree with the classified policy.
func callbackAgentSurfaceMethods() map[string]bool {
	allowed := make(map[string]bool, len(callbackMethodPolicy)+2)
	for method, decision := range callbackMethodPolicy {
		if decision.agentSurface {
			allowed[method] = true
		}
	}
	allowed[healthCheckMethod] = true
	allowed[healthWatchMethod] = true
	return allowed
}

// callbackPeerMethodPolicies returns the per-SVID method allowlist for the
// harness callback listener. A peer that is NOT a key here has NO policy and is
// therefore DENIED at request time AND rejected at server start
// (validateCallbackPeerPolicies). There is no implicit allow-all fall-through.
//
// The dashboard is present with an EMPTY method set rather than absent: it is a
// legitimately configured TLS peer that must reach zero methods. Being present
// keeps startup validation green while every request-time decision denies.
//
// gRPC reflection (registered only under GIBSON_GRPC_REFLECTION=1) is
// deliberately absent from every policy: a dev-only debug surface gets no
// standing grant on a SPIFFE-pinned listener. Reflection against the plaintext
// loopback dev bind is unaffected — the interceptors do not enforce when SPIFFE
// is unwired (see callbackPeerAuthzInterceptors).
func callbackPeerMethodPolicies() map[string]map[string]bool {
	agentSurface := callbackAgentSurfaceMethods()
	return map[string]map[string]bool{
		callbackDashboardSVID: {},
		callbackEnvoySVID:     agentSurface,
		callbackDaemonSVID:    agentSurface,
	}
}

// validateCallbackPeerPolicies enforces — at callback-server start — that every
// mTLS-allow-listed peer (GIBSON_CALLBACK_PEER_SVIDS, parsed into
// CallbackServer.peerSVIDs) has an explicit method policy. The server fails loud
// otherwise, mirroring validateAllowedPeerPolicies on the main daemon listener
// (gibson#1052).
//
// This is what makes hardcoding the peer constants safe: a chart that renames or
// adds an SVID cannot produce a peer that is silently denied every call at
// request time — the daemon refuses to start and names the peer.
func validateCallbackPeerPolicies(peerSVIDs []spiffeid.ID, policies map[string]map[string]bool) error {
	var unpoliced []string
	for _, id := range peerSVIDs {
		if _, ok := policies[id.String()]; !ok {
			unpoliced = append(unpoliced, id.String())
		}
	}
	if len(unpoliced) == 0 {
		return nil
	}
	sort.Strings(unpoliced)
	return fmt.Errorf(
		"harness callback listener: GIBSON_CALLBACK_PEER_SVIDS entries %q have no method policy. "+
			"Every mTLS-allow-listed callback peer must be classified in "+
			"callbackPeerMethodPolicies (internal/engine/harness/callback_method_policy.go) "+
			"before it can be accepted; an unclassified peer is denied every method at request "+
			"time, which would silently break the callback path. Either give the peer an explicit "+
			"policy or remove it from gibson.config.callback.spiffe.peerSvids. The daemon refuses "+
			"to start with an unclassified callback peer",
		strings.Join(unpoliced, ", "))
}
