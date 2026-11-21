// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package fixloop reads the facts of the fix loop from the tools of the buyer
// and turns them into Timeline events (gibson#1458, #1463, #1465, #1464).
//
// # Trust
//
// An agent is the party that the gate controls. So the daemon never stores a
// fact that an agent states. An agent that reports a MergeRequest, a Deployment
// or a Pipeline through the entity path adds a node to the graph, and no
// brain System reads the state in its properties. The Watcher in this package
// reads each fact itself, through the Connector of the tenant, and then it
// submits the event with its own clock.
//
// An attacker who controls one agent can then do three things at most. It can
// name a wrong merge request on a finding, it can open and merge a harmless
// merge request, and it can break the service. None of these sets `verified`:
//
//  1. `verified` needs a rerun of the check that raised the finding. The daemon
//     runs the check. No agent writes a CheckRerun.
//  2. `verified` needs a "held" health signal. The daemon reads it from the
//     observability tool of the buyer, after the deploy that the daemon read.
//  3. A merge request that the agent names is only a pointer. The Git host
//     states whether it merged.
//
// The revert is the one action that the Watcher takes. It reverts only a merge
// request that a fix job delivered for a finding, and only after a failed
// health signal that the daemon read.
package fixloop
