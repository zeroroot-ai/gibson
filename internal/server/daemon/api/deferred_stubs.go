// Package api — deferred_stubs.go contains handlers for RPCs that are
// defined in the proto but have deferred implementations.
//
// Each handler returns codes.Unimplemented with a message that identifies
// the deferred owner. These handlers ensure that proto registration is
// complete while clearly signalling "not yet implemented" to callers.
//
// Per admin-services-completion spec disposition table:
//   - DEFER-WITH-OWNER RPCs have their proto on the correct new service
//     and their call sites removed from the dashboard; the implementation
//     ships in a future spec with the named owner.
//
// Stubs that have existing Redis-backed implementations (ListAuditEvents,
// ListConversations, GetConversation, ListAlerts, MarkAlertRead,
// MarkAllAlertsRead) are in their respective handler files; they are NOT
// listed here because they already return real data.
package api

// No DEFER stubs currently registered.
//
// History:
//   - ExportFindings: implemented in export_findings.go (dashboard-neo4j-crud-removal Task 6).
//   - SaveMissionDraft / ListMissionDrafts / GetMissionDraft / DeleteMissionDraft:
//     wired to missiondraft.Store in mission_draft.go (mission-draft-dashboard-wiring).
//
// Add a new stub here if a future spec adds an RPC whose implementation is
// genuinely deferred — return codes.Unimplemented with an owner-named message.
