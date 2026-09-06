// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// seedOf builds a deterministic 32-byte Ed25519 seed from a label, so a test
// can name the key it means rather than carry a byte blob around.
func seedOf(label string) []byte {
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, strings.Repeat(label, ed25519.SeedSize))
	return seed
}

// writeSigningKeyMount lays out a projected-Secret-shaped signing key mount.
// A previous kid of "" writes no previous key, i.e. no rotation in progress.
func writeSigningKeyMount(t *testing.T, currentKID, currentLabel, previousKID, previousLabel string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, body []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write(currentKeyIDFile, []byte(currentKID))
	write(currentSeedFile, seedOf(currentLabel))
	if previousKID != "" {
		write(previousKeyIDFile, []byte(previousKID))
		write(previousSeedFile, seedOf(previousLabel))
	}
	return dir
}

func minterWithMount(t *testing.T, dir string) *Minter {
	t.Helper()
	m, err := NewMinter(context.Background(), Config{
		Issuer:        "https://test.daemon",
		Audience:      "test-daemon",
		SigningKeyDir: dir,
	})
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	return m
}

func mintBootstrap(t *testing.T, m *Minter) string {
	t.Helper()
	tok, err := m.MintBootstrapToken(BootstrapClaims{
		TenantID:    "acme",
		OwnerUserID: "user-1",
		PrincipalID: "agent-1",
		Kind:        "agent",
		Name:        "scanner",
	}, 10*time.Minute)
	if err != nil {
		t.Fatalf("MintBootstrapToken: %v", err)
	}
	return tok
}

// --- the signing key is not the master KEK ----------------------------------

// A dedicated signing key is what signs, and the master KEK plays no part in
// producing it. That is the whole point of GHSA-3957-8wcf-929q: holding the KEK
// must not be enough to mint a capability grant.
func TestSigningKeyMountIsIndependentOfTheMasterKEK(t *testing.T) {
	dir := writeSigningKeyMount(t, "cg-2026-08", "s", "", "")
	m, err := NewMinter(context.Background(), Config{
		Issuer:        "https://test.daemon",
		Audience:      "test-daemon",
		SigningKeyDir: dir,
		// A KEK is offered and must be ignored: the mount wins.
		KeyProvider: kpAdapter{[]byte(strings.Repeat("k", 32))},
		KeyID:       "kek-derived",
	})
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	if m.DerivedFromMasterKEK() {
		t.Fatal("a provisioned signing key mount must not fall back to the master KEK")
	}
	if got := m.KeyID(); got != "cg-2026-08" {
		t.Fatalf("kid: want the mounted key id cg-2026-08, got %q", got)
	}
	kekPriv, _, err := deriveEd25519FromMaster([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatalf("deriveEd25519FromMaster: %v", err)
	}
	if m.PublicKey().Equal(kekPriv.Public()) {
		t.Fatal("signing key is still the master-KEK-derived key; the KEK can mint grants")
	}
}

// The mount is missing, so the daemon has to keep working on the legacy
// derivation — an upgrade must not take capability grants down — but it has to
// be able to say that it is doing so.
func TestAbsentSigningKeyMountFallsBackAndAnnouncesIt(t *testing.T) {
	m, err := NewMinter(context.Background(), Config{
		Issuer:        "https://test.daemon",
		Audience:      "test-daemon",
		SigningKeyDir: filepath.Join(t.TempDir(), "not-mounted"),
		KeyProvider:   kpAdapter{[]byte(strings.Repeat("k", 32))},
		KeyID:         "cg-v1",
	})
	if err != nil {
		t.Fatalf("NewMinter must not fail closed when no signing key is provisioned: %v", err)
	}
	if !m.DerivedFromMasterKEK() {
		t.Fatal("the master-KEK fallback must report itself so the daemon can log it")
	}
}

// A mount that is present but broken is an operator error. Falling back to the
// KEK there would sign under one key while publishing another.
func TestHalfWrittenSigningKeyMountIsAnErrorNotAFallback(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, currentKeyIDFile), []byte("cg-2026-08"), 0o600); err != nil {
		t.Fatalf("write kid: %v", err)
	}
	_, err := NewMinter(context.Background(), Config{
		Issuer:        "https://test.daemon",
		Audience:      "test-daemon",
		SigningKeyDir: dir,
		KeyProvider:   kpAdapter{[]byte(strings.Repeat("k", 32))},
		KeyID:         "cg-v1",
	})
	if err == nil {
		t.Fatal("a kid with no key material must refuse construction, not fall back to the KEK")
	}
}

func TestLoadSigningKeySetRejectsAShortSeed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, currentKeyIDFile), []byte("cg-1"), 0o600); err != nil {
		t.Fatalf("write kid: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, currentSeedFile), []byte("too-short"), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	if _, err := LoadSigningKeySetFromDir(dir); err == nil {
		t.Fatal("a seed that is not 32 bytes must be refused")
	}
}

func TestLoadSigningKeySetAcceptsABase64Seed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, currentKeyIDFile), []byte("cg-1"), 0o600); err != nil {
		t.Fatalf("write kid: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(seedOf("z"))
	if err := os.WriteFile(filepath.Join(dir, currentSeedFile), []byte(encoded+"\n"), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	set, err := LoadSigningKeySetFromDir(dir)
	if err != nil {
		t.Fatalf("LoadSigningKeySetFromDir: %v", err)
	}
	want := ed25519.NewKeyFromSeed(seedOf("z")).Public().(ed25519.PublicKey)
	if !set.Current.Public().Equal(want) {
		t.Fatal("base64-encoded seed did not decode to the expected key")
	}
}

func TestLoadSigningKeySetRefusesADuplicateKeyID(t *testing.T) {
	dir := writeSigningKeyMount(t, "cg-1", "a", "cg-1", "b")
	if _, err := LoadSigningKeySetFromDir(dir); err == nil {
		t.Fatal("current and previous sharing a kid is not a rotation window and must be refused")
	}
}

func TestLoadSigningKeySetFromEmptyDirIsUnprovisioned(t *testing.T) {
	if _, err := LoadSigningKeySetFromDir(""); !errors.Is(err, ErrSigningKeyNotProvisioned) {
		t.Fatalf("want ErrSigningKeyNotProvisioned, got %v", err)
	}
}

// --- the rotation window ----------------------------------------------------

// Mid-rotation the JWKS has to carry both kids. A verifier that fetches the
// document while holding a token minted under the outgoing key needs to find
// that key in it, or the rotation is a mass invalidation rather than a window.
//
// This is the document the per-kid endpoint serves for a daemon kid
// (internal/server/daemon/capabilitygrant_keys.go): there is no separate
// JWKS-wide well-known document (ADR-0045) — resolution is fetch-by-kid only,
// and PublicKeyJWKS is what that per-kid fetch returns for either daemon kid.
func TestJWKSPublishesCurrentAndPreviousKid(t *testing.T) {
	m := minterWithMount(t, writeSigningKeyMount(t, "cg-new", "n", "cg-old", "o"))

	body, err := m.PublicKeyJWKS()
	if err != nil {
		t.Fatalf("PublicKeyJWKS: %v", err)
	}
	var set struct {
		Keys []struct{ Kid, X string } `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	published := map[string]string{}
	for _, k := range set.Keys {
		published[k.Kid] = k.X
	}
	if _, ok := published["cg-new"]; !ok {
		t.Fatalf("JWKS omits the current kid: %s", body)
	}
	if _, ok := published["cg-old"]; !ok {
		t.Fatalf("JWKS omits the previous kid, so a rotation invalidates every live token: %s", body)
	}
	// The published previous key must be the outgoing key, not a second copy of
	// the current one — a duplicated entry would look like a window and verify
	// nothing.
	wantOld := base64.RawURLEncoding.EncodeToString(
		ed25519.NewKeyFromSeed(seedOf("o")).Public().(ed25519.PublicKey))
	if published["cg-old"] != wantOld {
		t.Fatal("the previous JWKS entry is not the outgoing key")
	}
}

// Only the current key signs. Publishing the previous key must not turn it into
// a second minting key.
func TestMintStampsTheCurrentKidOnly(t *testing.T) {
	m := minterWithMount(t, writeSigningKeyMount(t, "cg-new", "n", "cg-old", "o"))
	tok := mintBootstrap(t, m)
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if kid, _ := parsed.Header["kid"].(string); kid != "cg-new" {
		t.Fatalf("minted under kid %q, want the current key cg-new", kid)
	}
}

// The window itself: a token minted before the rotation still verifies after
// it, because the key it was signed with is still in the set as `previous`.
func TestTokenSignedWithThePreviousKidStillVerifiesDuringTheWindow(t *testing.T) {
	before := minterWithMount(t, writeSigningKeyMount(t, "cg-old", "o", "", ""))
	tok := mintBootstrap(t, before)

	// The operator rotates: the new key signs, the old one moves to previous.
	after := minterWithMount(t, writeSigningKeyMount(t, "cg-new", "n", "cg-old", "o"))
	if _, err := after.VerifyBootstrapToken(tok); err != nil {
		t.Fatalf("a token minted under the outgoing key must survive the rotation window: %v", err)
	}
	if !after.KnowsKeyID("cg-old") {
		t.Fatal("the outgoing kid must still resolve so its key can be fetched")
	}
}

// The window closes: the operator drops `previous` from the mount and the kid
// is retired. Tokens signed with it stop being accepted.
func TestTokenSignedWithARetiredKidIsRefused(t *testing.T) {
	before := minterWithMount(t, writeSigningKeyMount(t, "cg-old", "o", "", ""))
	tok := mintBootstrap(t, before)

	// Window closed — only the new key is mounted.
	retired := minterWithMount(t, writeSigningKeyMount(t, "cg-new", "n", "", ""))
	if _, err := retired.VerifyBootstrapToken(tok); err == nil {
		t.Fatal("a token signed with a retired kid must be refused")
	}
	if retired.KnowsKeyID("cg-old") {
		t.Fatal("a retired kid must not resolve")
	}
	body, err := retired.PublicKeyJWKS()
	if err != nil {
		t.Fatalf("PublicKeyJWKS: %v", err)
	}
	if strings.Contains(string(body), "cg-old") {
		t.Fatalf("a retired kid must not stay published: %s", body)
	}
}

// A kid this daemon never issued resolves to no key at all, rather than being
// verified against whatever key happens to be current.
func TestUnknownKidIsRefused(t *testing.T) {
	m := minterWithMount(t, writeSigningKeyMount(t, "cg-new", "n", "cg-old", "o"))
	if m.KnowsKeyID("someone-elses-key") {
		t.Fatal("a foreign kid must not resolve")
	}
	if _, ok := m.keys.Verifier("someone-elses-key"); ok {
		t.Fatal("a foreign kid must not produce a verification key")
	}
}

func TestKeyIDsReportsCurrentFirst(t *testing.T) {
	m := minterWithMount(t, writeSigningKeyMount(t, "cg-new", "n", "cg-old", "o"))
	got := m.KeyIDs()
	if len(got) != 2 || got[0] != "cg-new" || got[1] != "cg-old" {
		t.Fatalf("KeyIDs: want [cg-new cg-old], got %v", got)
	}
}

// --- SigningKeySet nil-receiver safety ---------------------------------------
//
// A *SigningKeySet is nil before the Minter's key set is loaded (or on a
// zero-value Minter in tests). Every accessor must answer safely rather than
// panic, so a caller that races construction fails closed instead of crashing.

func TestNilSigningKeySet_VerifierDeniesEverything(t *testing.T) {
	var s *SigningKeySet
	if _, ok := s.Verifier("anything"); ok {
		t.Fatal("a nil key set must not verify any kid")
	}
	if _, ok := s.Verifier(""); ok {
		t.Fatal("a nil key set must not verify an empty kid either")
	}
}

func TestNilSigningKeySet_KeyIDsIsEmpty(t *testing.T) {
	var s *SigningKeySet
	if got := s.KeyIDs(); got != nil {
		t.Fatalf("KeyIDs on a nil set: got %v, want nil", got)
	}
}

func TestNilSigningKeySet_PublicKeysIsEmpty(t *testing.T) {
	var s *SigningKeySet
	if got := s.publicKeys(); got != nil {
		t.Fatalf("publicKeys on a nil set: got %v, want nil", got)
	}
}

// --- NewSigningKey validation -------------------------------------------------

func TestNewSigningKey_RejectsEmptyKeyID(t *testing.T) {
	if _, err := NewSigningKey("", seedOf("a")); err == nil {
		t.Fatal("an empty key id must be refused")
	}
}

func TestNewSigningKey_RejectsWrongSeedLength(t *testing.T) {
	if _, err := NewSigningKey("cg-1", []byte("short")); err == nil {
		t.Fatal("a seed that is not exactly SeedSize bytes must be refused")
	}
}

func TestSigningKey_KeyIDReturnsTheStampedKid(t *testing.T) {
	k, err := NewSigningKey("cg-1", seedOf("a"))
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}
	if got := k.KeyID(); got != "cg-1" {
		t.Fatalf("KeyID() = %q, want cg-1", got)
	}
}

// --- LoadSigningKeySetFromDir error paths ------------------------------------

// A current.kid that fails to read for a reason OTHER than "does not exist"
// (e.g. it is a directory, so the read is a permission/type error) must
// surface as a real error, not silently fall through as unprovisioned.
func TestLoadSigningKeySetFromDir_CurrentKIDUnreadableIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, currentKeyIDFile), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := LoadSigningKeySetFromDir(dir); err == nil {
		t.Fatal("an unreadable (non-missing) current.kid must be a hard error")
	}
}

// An empty current.kid file is refused by readMountedString's own
// empty-value check before NewSigningKey is ever reached.
func TestLoadSigningKeySetFromDir_EmptyCurrentKIDIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, currentKeyIDFile), []byte("   \n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadSigningKeySetFromDir(dir); err == nil {
		t.Fatal("an empty current.kid must be refused")
	}
}

// previous.kid exists (so a rotation is claimed to be in progress) but the
// read fails for a reason other than "missing" — a directory in its place.
func TestLoadSigningKeySetFromDir_PreviousKIDUnreadableIsAnError(t *testing.T) {
	dir := writeSigningKeyMount(t, "cg-1", "a", "", "")
	if err := os.Remove(filepath.Join(dir, previousKeyIDFile)); err != nil && !os.IsNotExist(err) {
		t.Fatalf("remove: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, previousKeyIDFile), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := LoadSigningKeySetFromDir(dir); err == nil {
		t.Fatal("an unreadable (non-missing) previous.kid must be a hard error")
	}
}

// previous.kid resolves but previous.key is unreadable for a reason other
// than "missing" — a broken rotation mount, not an absent one.
func TestLoadSigningKeySetFromDir_PreviousSeedUnreadableIsAnError(t *testing.T) {
	dir := writeSigningKeyMount(t, "cg-1", "a", "cg-2", "b")
	if err := os.Remove(filepath.Join(dir, previousSeedFile)); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, previousSeedFile), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := LoadSigningKeySetFromDir(dir); err == nil {
		t.Fatal("an unreadable (non-missing) previous.key must be a hard error")
	}
}

// A previous kid whose seed fails NewSigningKey's own validation must
// propagate, the same as an invalid current key does.
func TestLoadSigningKeySetFromDir_InvalidPreviousSeedPropagates(t *testing.T) {
	dir := writeSigningKeyMount(t, "cg-1", "a", "cg-2", "b")
	if err := os.WriteFile(filepath.Join(dir, previousSeedFile), []byte("too-short"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadSigningKeySetFromDir(dir); err == nil {
		t.Fatal("a previous seed that is not 32 bytes must be refused")
	}
}

// --- readMountedString / readMountedSeed edge cases --------------------------

func TestReadMountedString_RejectsAnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.kid")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := readMountedString(path); err == nil {
		t.Fatal("a whitespace-only mounted value must be refused as empty")
	}
}

func TestReadMountedSeed_RejectsUndecodableContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(path, []byte("not a valid seed in any supported encoding!"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := readMountedSeed(path); err == nil {
		t.Fatal("content that decodes to no 32-byte seed in any supported encoding must be refused")
	}
}

func TestReadMountedSeed_AcceptsHex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hex.key")
	seed := seedOf("h")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readMountedSeed(path)
	if err != nil {
		t.Fatalf("readMountedSeed: %v", err)
	}
	if !bytes.Equal(got, seed) {
		t.Fatal("hex-encoded seed did not decode to the expected bytes")
	}
}
