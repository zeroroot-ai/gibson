// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// writeSlot writes one slot of the mount. An empty kid and label write two
// empty files, the shape the chart projects for an empty slot.
func writeSlot(t *testing.T, dir, kidFile, seedFile, kid, label string) {
	t.Helper()
	seed := []byte{}
	if label != "" {
		seed = seedOf(label)
	}
	for name, body := range map[string][]byte{kidFile: []byte(kid), seedFile: seed} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

func kidOf(t *testing.T, tok string) string {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	kid, _ := parsed.Header["kid"].(string)
	return kid
}

// The chart projects each slot always. An empty slot is the steady state, not
// a broken mount, so it must load as "no key".
func TestEmptyOptionalSlotsAreNoKey(t *testing.T) {
	dir := writeSigningKeyMount(t, "cg-1", "a", "", "")
	writeSlot(t, dir, previousKeyIDFile, previousSeedFile, "", "")
	writeSlot(t, dir, nextKeyIDFile, nextSeedFile, "", "")
	set, err := LoadSigningKeySetFromDir(dir)
	if err != nil {
		t.Fatalf("empty optional slots must load: %v", err)
	}
	if set.Previous != nil || set.Next != nil {
		t.Fatalf("empty slots loaded as keys: next=%v previous=%v", set.Next, set.Previous)
	}
}

// A slot with a kid and no key is half written. It must stop the load.
func TestHalfWrittenOptionalSlotIsAnError(t *testing.T) {
	dir := writeSigningKeyMount(t, "cg-1", "a", "", "")
	writeSlot(t, dir, nextKeyIDFile, nextSeedFile, "cg-2", "")
	if _, err := LoadSigningKeySetFromDir(dir); err == nil {
		t.Fatal("a next slot with a kid and no key must be refused")
	}
	dir = writeSigningKeyMount(t, "cg-1", "a", "", "")
	writeSlot(t, dir, nextKeyIDFile, nextSeedFile, "", "b")
	if _, err := LoadSigningKeySetFromDir(dir); err == nil {
		t.Fatal("a next slot with a key and no kid must be refused")
	}
}

// One refresh can show a rotation step half done: the same key in two slots.
// That is one key, not an error.
func TestTheSameKeyInTwoSlotsIsOneKey(t *testing.T) {
	dir := writeSigningKeyMount(t, "cg-1", "a", "cg-1", "a")
	writeSlot(t, dir, nextKeyIDFile, nextSeedFile, "cg-1", "a")
	set, err := LoadSigningKeySetFromDir(dir)
	if err != nil {
		t.Fatalf("the same key in each slot must load: %v", err)
	}
	if got := set.KeyIDs(); len(got) != 1 || got[0] != "cg-1" {
		t.Fatalf("KeyIDs = %v, want [cg-1]", got)
	}
}

// A kid names one key. The same kid with another seed in a later slot is
// refused.
func TestAKidWithTwoKeysIsRefused(t *testing.T) {
	dir := writeSigningKeyMount(t, "cg-1", "a", "", "")
	writeSlot(t, dir, nextKeyIDFile, nextSeedFile, "cg-1", "b")
	if _, err := LoadSigningKeySetFromDir(dir); err == nil {
		t.Fatal("next reusing the current kid with another key must be refused")
	}
}

// The full rotation, as the chart runs it, on one Minter with no restart:
// publish next, promote it, then retire the old key. A token of the old key
// verifies until the last step and is refused after it.
func TestRotationRunsOnOneMinterWithNoRestart(t *testing.T) {
	dir := writeSigningKeyMount(t, "cg-old", "o", "", "")
	m := minterWithMount(t, dir)
	oldTok := mintBootstrap(t, m)

	// Step 1: next is published, and the old key still signs.
	writeSlot(t, dir, nextKeyIDFile, nextSeedFile, "cg-new", "n")
	if changed, err := m.ReloadSigningKeys(); err != nil || !changed {
		t.Fatalf("step 1 reload: changed=%v err=%v", changed, err)
	}
	if !m.KnowsKeyID("cg-new") {
		t.Fatal("step 1: the incoming kid must be published before it signs")
	}
	if kid := kidOf(t, mintBootstrap(t, m)); kid != "cg-old" {
		t.Fatalf("step 1: minted under %q, want cg-old", kid)
	}

	// Step 2: the new key signs, and the old key only verifies.
	writeSlot(t, dir, currentKeyIDFile, currentSeedFile, "cg-new", "n")
	writeSlot(t, dir, previousKeyIDFile, previousSeedFile, "cg-old", "o")
	writeSlot(t, dir, nextKeyIDFile, nextSeedFile, "", "")
	if _, err := m.ReloadSigningKeys(); err != nil {
		t.Fatalf("step 2 reload: %v", err)
	}
	if kid := kidOf(t, mintBootstrap(t, m)); kid != "cg-new" {
		t.Fatalf("step 2: minted under %q, want cg-new", kid)
	}
	if _, err := m.VerifyBootstrapToken(oldTok); err != nil {
		t.Fatalf("step 2: a token of the old key must still verify: %v", err)
	}

	// Step 3: the old key is retired.
	writeSlot(t, dir, previousKeyIDFile, previousSeedFile, "", "")
	if _, err := m.ReloadSigningKeys(); err != nil {
		t.Fatalf("step 3 reload: %v", err)
	}
	if _, err := m.VerifyBootstrapToken(oldTok); err == nil {
		t.Fatal("step 3: a token of the retired key must be refused")
	}
	if m.KnowsKeyID("cg-old") {
		t.Fatal("step 3: the retired kid must not be published")
	}
}

// A reload that fails keeps the set in force. A half-written rotation must
// never leave the daemon with no key.
func TestFailedReloadKeepsTheKeySetInForce(t *testing.T) {
	dir := writeSigningKeyMount(t, "cg-1", "a", "", "")
	m := minterWithMount(t, dir)
	writeSlot(t, dir, nextKeyIDFile, nextSeedFile, "cg-2", "")
	if changed, err := m.ReloadSigningKeys(); err == nil || changed {
		t.Fatalf("a half-written slot: changed=%v err=%v, want an error and no change", changed, err)
	}
	if kid := kidOf(t, mintBootstrap(t, m)); kid != "cg-1" {
		t.Fatalf("after a failed reload minted under %q, want cg-1", kid)
	}
}

// A reload with no change on disk reports no change.
func TestReloadWithNoChangeIsNoChange(t *testing.T) {
	m := minterWithMount(t, writeSigningKeyMount(t, "cg-1", "a", "", ""))
	if changed, err := m.ReloadSigningKeys(); err != nil || changed {
		t.Fatalf("changed=%v err=%v, want no change", changed, err)
	}
}

// WatchSigningKeys picks up a change and reports it, and stops with its
// context.
func TestWatchSigningKeysReportsAChange(t *testing.T) {
	dir := writeSigningKeyMount(t, "cg-1", "a", "", "")
	m := minterWithMount(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan []string, 1)
	done := make(chan struct{})
	go func() {
		m.WatchSigningKeys(ctx, 10*time.Millisecond, func(ids []string) {
			select {
			case got <- ids:
			default:
			}
		}, nil)
		close(done)
	}()
	writeSlot(t, dir, nextKeyIDFile, nextSeedFile, "cg-2", "b")
	select {
	case ids := <-got:
		if len(ids) != 2 || ids[0] != "cg-1" || ids[1] != "cg-2" {
			t.Fatalf("reported kids %v, want [cg-1 cg-2]", ids)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WatchSigningKeys reported no change in 5s")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("WatchSigningKeys did not stop with its context")
	}
}
