// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import "context"

// scanMissionName is the name of the checked-in scan mission
// (internal/platform/missioncatalog/missions/scan.cue).
const scanMissionName = "scan"

// ScanAnchorSink receives the parameters of a scan mission that was originated
// by name, with the tenant of its parent mission and its id. The daemon wires it
// to the World of the tenant, which writes the Application, Repository and Image
// links of the scan (gibson#1469).
type ScanAnchorSink func(ctx context.Context, tenant, missionID string, params map[string]string)

// WithScanAnchorSink sets the sink of the scan anchors.
func WithScanAnchorSink(sink ScanAnchorSink) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.scanAnchorSink = sink
	}
}
