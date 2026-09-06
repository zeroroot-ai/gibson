// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mission

// reservation.go: the budget reservation ledger gibson#1358's mission-
// origination owner decision requires ("the daemon clamps [the requested
// budget] to min(requested, parent_remaining) and RESERVES it against the
// parent mission's envelope so parallel children can't over-commit the same
// money").
//
// Nothing in the codebase already does this. internal/platform/budget is a
// MONTHLY per-(tenant,user,team) token/spend ceiling, orthogonal to any one
// mission. The per-mission numbers that DO exist are Mission.Constraints
// (missionv1.MissionConstraints.MaxCost/MaxTokens — the ceiling) and
// Mission.Metrics (MissionMetrics.TotalCost/TotalTokens — actual spend so
// far); neither tracks "already promised to children". This file adds that
// bookkeeping as its own small, Redis-backed ledger rather than new Mission
// fields, so a reservation's lifetime (reserve → release) is independent of
// whatever else touches the mission record.
//
// Deliberately NOT read via RedisJSON: Reserve takes the parent *Mission as
// a Go value the caller already loaded (mission-origination's handler needs
// it anyway, for the gibson#1358 target-scope subset check), rather than
// the ledger re-reading it itself via JSON.GET. That keeps the ledger's own
// Redis footprint to one plain hash key per parent mission — no RedisJSON
// dependency, so it is fully exercisable against miniredis in tests, unlike
// ConnBoundMissionStore.Save/Get.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// ChildBudget is a per-dimension budget amount: a cost ceiling in USD cents
// and a token ceiling. A nil field means "unbounded on this dimension" —
// mirrors missionv1.MissionConstraints' own convention
// (max_cost == 0.0 / max_tokens == 0 both mean "no limit"), extended with an
// explicit nil rather than a numeric sentinel because mission-level zero
// already means the OPPOSITE of "reserve zero" (an actual zero-cent
// reservation is not a thing this ledger ever produces — see Reserve's
// exhaustion behavior below) and overloading it would silently collide with
// that meaning. Fields are independent: a mission can have a cost cap with
// unlimited tokens, or vice versa.
type ChildBudget struct {
	CostUSDCents *int64
	Tokens       *int64
}

// hasCost/hasTokens/costOr/tokensOr are small nil-safe accessors so the rest
// of this file (and its Lua bridge) never has to nil-check ChildBudget
// fields inline.
func (b ChildBudget) hasCost() bool   { return b.CostUSDCents != nil }
func (b ChildBudget) hasTokens() bool { return b.Tokens != nil }
func (b ChildBudget) costOr(d int64) int64 {
	if b.CostUSDCents == nil {
		return d
	}
	return *b.CostUSDCents
}
func (b ChildBudget) tokensOr(d int64) int64 {
	if b.Tokens == nil {
		return d
	}
	return *b.Tokens
}

func costPtr(v int64) *int64   { return &v }
func tokensPtr(v int64) *int64 { return &v }

// CostCentsFromDollars converts a proto MissionConstraints.max_cost /
// MissionMetrics.total_cost dollar amount to USD cents, rounding DOWN
// (floor). Used for both a ceiling (max_cost) and actual spend (total_cost)
// so that in either case the converted integer never overstates how much
// room is available — a ceiling rounded down is a stricter ceiling, and
// spend rounded down under-reports usage by at most half a cent, which
// Reserve's HSET-scoped arithmetic self-corrects at the next call since it
// always re-reads the authoritative parent Metrics rather than
// accumulating its own running total. A tiny epsilon guards against a
// value like 19.99 landing at 1998.9999999997 in float64 and flooring to
// 1998 instead of 1999.
func CostCentsFromDollars(dollars float64) int64 {
	if dollars <= 0 {
		return 0
	}
	return int64(math.Floor(dollars*100 + 1e-6))
}

// DollarsFromCostCents is CostCentsFromDollars' inverse, for writing a
// granted ChildBudget.CostUSDCents back into a proto max_cost field.
func DollarsFromCostCents(cents int64) float64 {
	return float64(cents) / 100
}

// ReservationLedger atomically clamps and reserves a share of a parent
// mission's budget envelope for a to-be-created child mission, and releases
// that reservation when the child no longer needs it. Implementations must
// be safe for concurrent use — the whole point is that concurrent Reserve
// calls against the same parent cannot together over-commit its envelope.
type ReservationLedger interface {
	// Reserve computes parent's remaining envelope — Constraints ceiling
	// minus Metrics actual spend minus every OTHER live reservation already
	// held against parent — and atomically reserves
	// min(requested, remaining) under childID, returning what was actually
	// granted. A dimension parent does not cap AND requested does not name
	// is granted unbounded (nil in the response); once EITHER side names a
	// number for a dimension, the response is always a concrete number for
	// it, per the owner decision's "explicit, clamped, reserved" — no
	// origination resolves to an ambiguous open commitment.
	//
	// Returns an error, reserving nothing, when a dimension parent caps IS
	// already fully consumed (by actual spend plus existing reservations) —
	// a reservation of a literal 0 is never returned as success, because
	// writing 0 back into a proto max_cost/max_tokens field would be
	// silently reinterpreted as "unlimited" by every reader of that field,
	// the exact opposite of exhausted.
	Reserve(ctx context.Context, parent *Mission, childID types.ID, requested ChildBudget) (ChildBudget, error)

	// Release returns childID's reservation against parentID to the
	// available envelope. Idempotent: releasing an unknown or
	// already-released child is a no-op, not an error, so a completion or
	// failure path can call it unconditionally without first checking
	// whether a reservation exists.
	Release(ctx context.Context, parentID, childID types.ID) error

	// Reserved returns the sum of every live reservation currently held
	// against parentID, across all of its children. Used by tests and by
	// anything that wants to report a parent's committed-but-unspent
	// envelope. A dimension with no live reservations naming it returns
	// nil, not zero — same "unbounded vs literal zero" distinction as
	// Reserve's inputs and outputs, here meaning "nothing reserved" rather
	// than "unbounded".
	Reserved(ctx context.Context, parentID types.ID) (ChildBudget, error)
}

// redisEntry is the JSON shape stored in one hash field of the reservations
// hash — one field per live child reservation, field name = child mission
// ID.
type redisEntry struct {
	HasCost   bool  `json:"has_cost"`
	CostCents int64 `json:"cost_cents"`
	HasTokens bool  `json:"has_tokens"`
	Tokens    int64 `json:"tokens"`
}

// cbMissionReservationsKey names the reservations hash for one parent
// mission. Follows the cbMission* naming/prefix convention in
// store_conn.go (no tenant prefix — the per-tenant Redis client is the
// isolation boundary) without depending on that file, so this ledger has no
// import-order coupling to ConnBoundMissionStore.
func cbMissionReservationsKey(parentID types.ID) string {
	return fmt.Sprintf("gibson:mission:%s:reservations", parentID)
}

// redisReservationLedger is the Redis-backed ReservationLedger
// implementation.
type redisReservationLedger struct {
	rdb        redis.UniversalClient
	reserveLua *redis.Script
}

// NewRedisReservationLedger constructs a ReservationLedger backed by rdb.
// rdb must already be scoped to the correct tenant's logical Redis DB (same
// contract as NewConnBoundMissionStore) — the ledger applies no tenant
// prefix of its own.
func NewRedisReservationLedger(rdb redis.UniversalClient) ReservationLedger {
	return &redisReservationLedger{
		rdb:        rdb,
		reserveLua: redis.NewScript(luaReserve),
	}
}

// luaReserve atomically sums every existing reservation against the parent
// (HVALS + cjson.decode, cheap — a mission's live children are not expected
// to number more than a handful at once), clamps the request to what
// remains per dimension, writes the grant as a new hash field, and returns
// it. Runs as a single EVAL so concurrent Reserve calls against the same
// parent serialize through Redis's single-threaded script execution —
// exactly the "parallel children can't over-commit" atomicity the owner
// decision requires.
//
// KEYS[1] = reservations hash key
// ARGV[1] = child ID (hash field name)
// ARGV[2] = has cost cap (0/1)      ARGV[3] = max cost cents
// ARGV[4] = used cost cents
// ARGV[5] = has token cap (0/1)     ARGV[6] = max tokens
// ARGV[7] = used tokens
// ARGV[8] = requested has cost (0/1) ARGV[9]  = requested cost cents
// ARGV[10] = requested has tokens (0/1) ARGV[11] = requested tokens
//
// returns {grantHasCost, grantCostCents, grantHasTokens, grantTokens} or a
// Redis error reply when a capped dimension is fully exhausted.
const luaReserve = `
local reservedCost = 0
local reservedTokens = 0
local vals = redis.call('HVALS', KEYS[1])
for i = 1, #vals do
  local entry = cjson.decode(vals[i])
  if entry.has_cost then reservedCost = reservedCost + (entry.cost_cents or 0) end
  if entry.has_tokens then reservedTokens = reservedTokens + (entry.tokens or 0) end
end

local hasCostCap = tonumber(ARGV[2]) == 1
local maxCostCents = tonumber(ARGV[3])
local usedCostCents = tonumber(ARGV[4])
local hasTokenCap = tonumber(ARGV[5]) == 1
local maxTokens = tonumber(ARGV[6])
local usedTokens = tonumber(ARGV[7])
local reqHasCost = tonumber(ARGV[8]) == 1
local reqCostCents = tonumber(ARGV[9])
local reqHasTokens = tonumber(ARGV[10]) == 1
local reqTokens = tonumber(ARGV[11])

local grantHasCost = false
local grantCostCents = 0
if hasCostCap then
  local remaining = maxCostCents - usedCostCents - reservedCost
  if remaining < 0 then remaining = 0 end
  grantHasCost = true
  grantCostCents = remaining
  if reqHasCost and reqCostCents < remaining then
    grantCostCents = reqCostCents
  end
  if grantCostCents <= 0 then
    return redis.error_reply('ERR parent mission cost budget exhausted')
  end
elseif reqHasCost then
  grantHasCost = true
  grantCostCents = reqCostCents
end

local grantHasTokens = false
local grantTokens = 0
if hasTokenCap then
  local remaining = maxTokens - usedTokens - reservedTokens
  if remaining < 0 then remaining = 0 end
  grantHasTokens = true
  grantTokens = remaining
  if reqHasTokens and reqTokens < remaining then
    grantTokens = reqTokens
  end
  if grantTokens <= 0 then
    return redis.error_reply('ERR parent mission token budget exhausted')
  end
elseif reqHasTokens then
  grantHasTokens = true
  grantTokens = reqTokens
end

redis.call('HSET', KEYS[1], ARGV[1], cjson.encode({
  has_cost = grantHasCost, cost_cents = grantCostCents,
  has_tokens = grantHasTokens, tokens = grantTokens,
}))

return {grantHasCost and 1 or 0, grantCostCents, grantHasTokens and 1 or 0, grantTokens}
`

func boolArg(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Reserve implements ReservationLedger.
func (l *redisReservationLedger) Reserve(ctx context.Context, parent *Mission, childID types.ID, requested ChildBudget) (ChildBudget, error) {
	if parent == nil {
		return ChildBudget{}, errors.New("mission: reservation ledger: parent mission is required")
	}
	if childID.IsZero() {
		return ChildBudget{}, errors.New("mission: reservation ledger: child mission ID is required")
	}

	var maxCostCents, usedCostCents int64
	hasCostCap := false
	if parent.Constraints.GetMaxCost() > 0 {
		hasCostCap = true
		maxCostCents = CostCentsFromDollars(parent.Constraints.GetMaxCost())
	}
	if parent.Metrics != nil {
		usedCostCents = CostCentsFromDollars(parent.Metrics.TotalCost)
	}

	var maxTokens, usedTokens int64
	hasTokenCap := false
	if parent.Constraints.GetMaxTokens() > 0 {
		hasTokenCap = true
		maxTokens = parent.Constraints.GetMaxTokens()
	}
	if parent.Metrics != nil {
		usedTokens = parent.Metrics.TotalTokens
	}

	res, err := l.reserveLua.Run(ctx, l.rdb,
		[]string{cbMissionReservationsKey(parent.ID)},
		childID.String(),
		boolArg(hasCostCap), maxCostCents, usedCostCents,
		boolArg(hasTokenCap), maxTokens, usedTokens,
		boolArg(requested.hasCost()), requested.costOr(0),
		boolArg(requested.hasTokens()), requested.tokensOr(0),
	).Result()
	if err != nil {
		return ChildBudget{}, fmt.Errorf("mission: reservation ledger: reserve against parent %s: %w", parent.ID, err)
	}

	fields, ok := res.([]any)
	if !ok || len(fields) != 4 {
		return ChildBudget{}, fmt.Errorf("mission: reservation ledger: unexpected reserve script reply: %#v", res)
	}
	grantHasCost, _ := fields[0].(int64)
	grantCostCents, _ := fields[1].(int64)
	grantHasTokens, _ := fields[2].(int64)
	grantTokens, _ := fields[3].(int64)

	granted := ChildBudget{}
	if grantHasCost == 1 {
		granted.CostUSDCents = costPtr(grantCostCents)
	}
	if grantHasTokens == 1 {
		granted.Tokens = tokensPtr(grantTokens)
	}
	return granted, nil
}

// Release implements ReservationLedger.
func (l *redisReservationLedger) Release(ctx context.Context, parentID, childID types.ID) error {
	if parentID.IsZero() || childID.IsZero() {
		// Nothing to release against — idempotent no-op rather than an
		// error, matching Release's documented "safe to call
		// unconditionally" contract.
		return nil
	}
	if err := l.rdb.HDel(ctx, cbMissionReservationsKey(parentID), childID.String()).Err(); err != nil {
		return fmt.Errorf("mission: reservation ledger: release child %s against parent %s: %w", childID, parentID, err)
	}
	return nil
}

// Reserved implements ReservationLedger.
func (l *redisReservationLedger) Reserved(ctx context.Context, parentID types.ID) (ChildBudget, error) {
	vals, err := l.rdb.HVals(ctx, cbMissionReservationsKey(parentID)).Result()
	if err != nil {
		return ChildBudget{}, fmt.Errorf("mission: reservation ledger: read reservations for parent %s: %w", parentID, err)
	}
	var totalCost, totalTokens int64
	var hasCost, hasTokens bool
	for _, raw := range vals {
		var entry redisEntry
		if unmarshalErr := json.Unmarshal([]byte(raw), &entry); unmarshalErr != nil {
			return ChildBudget{}, fmt.Errorf("mission: reservation ledger: decode reservation entry for parent %s: %w", parentID, unmarshalErr)
		}
		if entry.HasCost {
			hasCost = true
			totalCost += entry.CostCents
		}
		if entry.HasTokens {
			hasTokens = true
			totalTokens += entry.Tokens
		}
	}
	out := ChildBudget{}
	if hasCost {
		out.CostUSDCents = costPtr(totalCost)
	}
	if hasTokens {
		out.Tokens = tokensPtr(totalTokens)
	}
	return out, nil
}
