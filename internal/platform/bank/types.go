// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package bank is the daemon's store for banks of always-on coding agents and
// their members (ADR-0019, gibson#1706).
//
// A bank is declarative: it names an owner, a desired member count, a login
// shape and a few policies. The reconciler makes the running member count match
// the desired one. A member is one long-lived sandbox in that bank.
//
// The types here are the daemon's own. The wire types in gibson.bank.v1 are
// mapped at the handler edge, so a proto rename never reaches the store and the
// store never carries a presentation concern.
package bank

import (
	"errors"
	"time"
)

// Sentinel errors returned by Store.
var (
	// ErrNotFound is returned when no bank or member has the given id.
	ErrNotFound = errors.New("bank not found")
	// ErrAlreadyExists is returned when a bank name is already in use in the
	// tenant. Names are unique so a person can name a bank rather than paste
	// an id.
	ErrAlreadyExists = errors.New("bank already exists")
	// ErrInvalid is returned when the input cannot describe a bank that could
	// ever run: an unknown login shape, a subscription bank with no person to
	// sign in, a third-party shape with no provider configuration.
	ErrInvalid = errors.New("invalid bank")
)

// OwnerKind is who owns a bank.
type OwnerKind string

const (
	// OwnerUser — one person owns the bank. A subscription sign-in is theirs,
	// so only this kind may take the subscription login shape.
	OwnerUser OwnerKind = "user"
	// OwnerTenant — the tenant owns the bank and it runs on the tenant's own
	// provider configuration. There is no sign-in step.
	OwnerTenant OwnerKind = "tenant"
)

// LoginShape is how a member authenticates to its model vendor. The values are
// the componentcatalog login shapes, so the launch resolver takes them
// unchanged (gibson#1714).
type LoginShape string

// The five login shapes. A subscription is the person's own and the platform
// stores nothing for it; the other four draw a credential from the tenant's
// provider configuration.
const (
	// LoginShapeSubscription — the owner signs in inside the sandbox.
	LoginShapeSubscription LoginShape = "subscription"
	// LoginShapeAPIKey — the tenant's own Anthropic key.
	LoginShapeAPIKey LoginShape = "api_key"
	// LoginShapeBedrock — Anthropic's models on Amazon Bedrock.
	LoginShapeBedrock LoginShape = "bedrock"
	// LoginShapeVertex — Anthropic's models on Google Vertex.
	LoginShapeVertex LoginShape = "vertex"
	// LoginShapeFoundry — Anthropic's models on Microsoft Foundry.
	LoginShapeFoundry LoginShape = "foundry"
)

// loginShapes is the closed set, and whether the shape needs a provider
// configuration to draw a credential from. A subscription needs none: the
// person signs in inside the sandbox and the platform stores nothing.
var loginShapes = map[LoginShape]bool{
	LoginShapeSubscription: false,
	LoginShapeAPIKey:       true,
	LoginShapeBedrock:      true,
	LoginShapeVertex:       true,
	LoginShapeFoundry:      true,
}

// IsLoginShape reports whether s names a login shape.
func IsLoginShape(s LoginShape) bool {
	_, ok := loginShapes[s]
	return ok
}

// NeedsProviderConfig reports whether s draws its credential from a tenant
// provider configuration.
func NeedsProviderConfig(s LoginShape) bool {
	return loginShapes[s]
}

// SpillPolicy is what a bank does with a job when no member has a free slot.
type SpillPolicy string

const (
	// SpillQueue — the job waits in the bank queue.
	SpillQueue SpillPolicy = "queue"
	// SpillEphemeral — the daemon launches a one-shot instance for the job.
	SpillEphemeral SpillPolicy = "ephemeral"
)

// IsSpillPolicy reports whether p names a spill policy.
func IsSpillPolicy(p SpillPolicy) bool {
	return p == SpillQueue || p == SpillEphemeral
}

// MemberState is where a member is in its life.
type MemberState string

const (
	// MemberLaunching — the sandbox is starting and has not reported yet.
	MemberLaunching MemberState = "launching"
	// MemberNeedsSignIn — the member waits for its owner to complete the
	// in-sandbox sign in. It takes no job.
	MemberNeedsSignIn MemberState = "needs_sign_in"
	// MemberIdle — the member has a free slot.
	MemberIdle MemberState = "idle"
	// MemberBusy — every slot is taken.
	MemberBusy MemberState = "busy"
	// MemberDraining — the member takes no new job and exits when its open
	// jobs close.
	MemberDraining MemberState = "draining"
	// MemberDead — heartbeats stopped or the sandbox died.
	MemberDead MemberState = "dead"
)

// IsMemberState reports whether s names a member state.
func IsMemberState(s MemberState) bool {
	switch s {
	case MemberLaunching, MemberNeedsSignIn, MemberIdle, MemberBusy, MemberDraining, MemberDead:
		return true
	default:
		return false
	}
}

// isReportableState reports whether a MEMBER may claim this state on a
// heartbeat. LAUNCHING, DRAINING and DEAD are the daemon's decisions about the
// member, not the member's about itself, so a member that reported one could
// undo a scale-down or hide its own death.
func isReportableState(s MemberState) bool {
	return s == MemberIdle || s == MemberBusy || s == MemberNeedsSignIn
}

// Bank is a pool of always-on coding agents with one owner.
type Bank struct {
	ID                 string
	Name               string
	OwnerKind          OwnerKind
	OwnerID            string
	DesiredCount       int32
	LoginShape         LoginShape
	ProviderConfigName string
	AgentName          string
	Model              string
	MaxJobsInFlight    int32
	StaleLimit         time.Duration
	SpillPolicy        SpillPolicy
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// Member is one always-on instance in a bank.
type Member struct {
	ID            string
	BankID        string
	MissionID     string
	MissionRunID  string
	AgentRunID    string
	SandboxID     string
	State         MemberState
	JobsInFlight  int32
	JobCap        int32
	ActiveJobIDs  []string
	ClaudeVersion string
	LastHeartbeat time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// CreateInput declares a new bank. The store validates it and fills the
// defaults, so a caller cannot store a bank that could never run.
type CreateInput struct {
	Name               string
	OwnerKind          OwnerKind
	OwnerID            string
	DesiredCount       int32
	LoginShape         LoginShape
	ProviderConfigName string
	AgentName          string
	Model              string
	MaxJobsInFlight    int32
	StaleLimit         time.Duration
	SpillPolicy        SpillPolicy
}

// UpdateInput changes what a bank's owner may change after creation. A nil
// field keeps its value. The login shape, the owner, the agent and the model
// are fixed at creation: changing them would change what the running members
// are, not how many of them run.
type UpdateInput struct {
	DesiredCount    *int32
	MaxJobsInFlight *int32
	StaleLimit      *time.Duration
	SpillPolicy     *SpillPolicy
}

// Page is one page of a listing.
type Page struct {
	// Size is the maximum number of rows to return. Zero takes DefaultPageSize.
	Size int32
	// Token is the NextToken of the previous page. Empty starts at the newest.
	Token string
}

// Page sizes. A listing is bounded so one call cannot pull a whole tenant.
const (
	DefaultPageSize int32 = 50
	MaxPageSize     int32 = 200
)

// Defaults the store fills when an input leaves a field zero.
const (
	// DefaultAgentName is the catalog agent a bank runs when it names none.
	DefaultAgentName = "claude"
	// DefaultMaxJobsInFlight is how many jobs one member holds at once. One,
	// because a member is one Claude Code process and a turn is not
	// concurrent with another turn of the same process.
	DefaultMaxJobsInFlight int32 = 1
	// DefaultStaleLimit is how long a job may go without input before it
	// closes with verdict abandoned.
	DefaultStaleLimit = 24 * time.Hour
)
