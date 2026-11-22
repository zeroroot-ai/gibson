// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fixloop

import (
	"context"
	"time"
)

// Merge request states that the Git host reports. They match the brain states.
const (
	MROpen    = "open"
	MRMerged  = "merged"
	MRClosed  = "closed"
	MRRefused = "refused"
)

// MergeFact is what the Git host says about one merge request.
type MergeFact struct {
	// State is open, merged, closed or refused. Refused means that the branch
	// protection of the host refused a merge that was tried.
	State string
	// PipelineGreen is true when the pipeline of the merge request passed.
	PipelineGreen bool
	// Reason is the text that the host gave for a refusal.
	Reason string
	// At is the time of the fact on the host.
	At time.Time
	// CreatedAt is when the merge request was opened on the host. SourceBranch
	// is the branch that it merges. The daemon reads both before it links the
	// merge request of a fix job to a finding (review B1).
	CreatedAt    time.Time
	SourceBranch string
	// SourceBranchReason is why the host gave no source branch, for example
	// a branch in a fork. It is empty when the host gave the branch.
	SourceBranchReason string
	// HeadSHA is the head commit of the merge request. ChangedFiles are the
	// files that it changes, with no content. The daemon reads both from the
	// host and gives them to the fix agent as the head and the files that the
	// agent must see again before it merges. ChangedFilesTruncated is true when
	// the merge request has more files than the host list holds, and
	// ChangedFilesError is not empty when the host gave no list. Then the files
	// are not known.
	HeadSHA               string
	ChangedFiles          []ChangedFile
	ChangedFilesTruncated bool
	ChangedFilesError     string
}

// ChangedFile is one file of a merge request as the host lists it. Change is
// added, modified, deleted or renamed. BlobSHA is empty for a deleted file.
// Mode is the git file mode of the new file (100644, 100755, 120000 or
// 160000), or empty when the host gives none.
type ChangedFile struct {
	Path         string
	Change       string
	PreviousPath string
	BlobSHA      string
	Mode         string
}

// RestartFact is what the deploy tool says about a restart that a deploy
// needed. A host patch can need one.
type RestartFact struct {
	Needed bool
	// Started and Ended are the times of the restart. Ended is zero while the
	// restart runs.
	Started time.Time
	Ended   time.Time
}

// DeployFact is what the deploy tool says about one merged merge request.
type DeployFact struct {
	Deployed       bool
	DeploymentKey  string
	ApplicationKey string
	At             time.Time
	Restart        RestartFact
}

// HealthFact is what the health signal of one service says.
type HealthFact struct {
	// Known is false when the service has no health signal. A finding of such
	// a service never becomes `verified`.
	Known bool
	// Done is true when the signal was read for the whole hold time, or when it
	// failed. Done is false while the hold time still runs.
	Done bool
	Held bool
	At   time.Time
}

// Reader reads the facts from the tools of the tenant. The implementation
// calls the Connector of the tenant with its own grant. The tenant comes from
// the caller of the Watcher and never from a finding. missionID is the mission
// of the fix, for the audit record and the flight recorder.
type Reader interface {
	MergeRequest(ctx context.Context, tenant, missionID, key string) (MergeFact, error)
	Deploy(ctx context.Context, tenant, missionID, mergeRequest string) (DeployFact, error)
	Health(ctx context.Context, tenant, missionID, application string, since time.Time, hold time.Duration) (HealthFact, error)
}

// RevertFact is what the Git host says after one call of the revert tool.
type RevertFact struct {
	// Merged is true when the revert merge request is merged. Until then the
	// fix is still in the code.
	Merged bool
	// RevertMergeRequest is the merge request of the revert. It can be empty
	// when the host has not opened it yet.
	RevertMergeRequest string
}

// Reverter reverts a merged merge request with a new merge request, and merges
// the revert. One call opens the revert merge request or reads it again, and
// merges it when its pipeline is green. The caller calls again until the fact
// says Merged. missionID is the mission of the fix, for the audit record and
// the flight recorder.
type Reverter interface {
	Revert(ctx context.Context, tenant, mergeRequest, missionID string) (RevertFact, error)
}

// Placer returns the Application or the Host that a finding touches.
type Placer interface {
	Application(ctx context.Context, tenant, findingID string) (string, error)
}
