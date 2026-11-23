// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package taxonomy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// The Taxonomy version must change when a label or a relationship type is added or
// removed, so a projected graph can be attributed to the schema that produced it.
// This guard records the version beside the digest of the content of the two
// lists. A change of the lists with no change of the version fails, and so does a
// change of the version with no change of the lists. The key is the content of the
// lists, never a line number.
//
// To pass after a real change: bump Version, then set recordedVersion and
// recordedListsDigest to the values that the failure message prints.
const (
	recordedVersion     = 7
	recordedListsDigest = "bcf668e612c230c7ad5ff218caf7267cc369e86cc4e546978ca16d2cfdb21e07"
)

// listsDigest is the digest of the sorted node labels and relationship types.
func listsDigest(labels, relationships []string) string {
	l := slices.Clone(labels)
	r := slices.Clone(relationships)
	slices.Sort(l)
	slices.Sort(r)
	sum := sha256.Sum256([]byte("labels:" + strings.Join(l, ",") + "\nrelationships:" + strings.Join(r, ",")))
	return hex.EncodeToString(sum[:])
}

// versionDrift returns the reason that the recorded pair does not match the
// current lists and version, or "" when it matches.
func versionDrift(version int, labels, relationships []string, wantVersion int, wantDigest string) string {
	digest := listsDigest(labels, relationships)
	switch {
	case digest != wantDigest && version == wantVersion:
		return fmt.Sprintf("a label or a relationship type changed and Version is still %d: bump Version, "+
			"then record version %d and digest %s", version, version+1, digest)
	case digest == wantDigest && version != wantVersion:
		return fmt.Sprintf("Version is %d and the lists did not change since version %d", version, wantVersion)
	case digest != wantDigest:
		return fmt.Sprintf("Version moved to %d with a new list: record digest %s", version, digest)
	}
	return ""
}

func TestVersionMatchesTheTaxonomyLists(t *testing.T) {
	if msg := versionDrift(Version, coreNodeLabels, coreRelationshipTypes, recordedVersion, recordedListsDigest); msg != "" {
		t.Fatal(msg)
	}
}

// The guard can fail: a label added with no bump, a relationship type added with
// no bump, and a bump with no change each report a drift.
func TestVersionGuardCanFail(t *testing.T) {
	d := listsDigest(coreNodeLabels, coreRelationshipTypes)
	if msg := versionDrift(7, append(slices.Clone(coreNodeLabels), "NewLabel"), coreRelationshipTypes, 7, d); msg == "" {
		t.Error("a new label with no bump must fail")
	}
	if msg := versionDrift(7, coreNodeLabels, append(slices.Clone(coreRelationshipTypes), "NEW_EDGE"), 7, d); msg == "" {
		t.Error("a new relationship type with no bump must fail")
	}
	if msg := versionDrift(8, coreNodeLabels, coreRelationshipTypes, 7, d); msg == "" {
		t.Error("a bump with no change must fail")
	}
	if msg := versionDrift(7, coreNodeLabels, coreRelationshipTypes, 7, d); msg != "" {
		t.Errorf("an unchanged taxonomy must pass: %s", msg)
	}
	// The order of the lists does not matter.
	rev := slices.Clone(coreNodeLabels)
	slices.Reverse(rev)
	if listsDigest(rev, coreRelationshipTypes) != d {
		t.Error("the digest depends on the order of the list")
	}
}
