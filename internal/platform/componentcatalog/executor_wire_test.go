// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package componentcatalog

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The wire guard of the executor image (gibson#1343).
//
// Every first-party tool answers with a DiscoveryResult as JSON that the sdk
// of the executor image wrote. The daemon reads it with the sdk of the daemon
// and with no tolerance for an unknown field. So a field that the sdk removed
// between the two makes the whole result unreadable, and the run folds nothing.
// The catalog pinned an executor on sdk v0.191.0 for 20 days after sdk v0.202.0
// removed parent_type, and no check noticed.
//
// The rule has two parts, and both run on every pull request and merge group,
// because they read files and the descriptors in the binary only:
//
//  1. The executor image must be built on an sdk at or above the floor. The
//     floor is the sdk release that made the last removal in the graphrag
//     messages (graphrag-wire-floor.json).
//  2. The floor file must list every field that the daemon sdk reserves in the
//     graphrag messages. When a new sdk reserves another field, this part fails
//     and tells the author to raise the floor and repin the executor image.
//     Without part 2 the floor would stay where it is and part 1 would pass.

type executorSDK struct {
	Image      string `json:"image"`
	SDKVersion string `json:"sdk_version"`
}

type wireFloor struct {
	Floor    string   `json:"floor"`
	Reserved []string `json:"reserved"`
}

// parseSDKVersion reads vMAJOR.MINOR.PATCH and nothing else.
func parseSDKVersion(v string) ([3]int, error) {
	var out [3]int
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	if !strings.HasPrefix(v, "v") || len(parts) != 3 {
		return out, fmt.Errorf("sdk version %q is not vMAJOR.MINOR.PATCH", v)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, fmt.Errorf("sdk version %q is not vMAJOR.MINOR.PATCH", v)
		}
		out[i] = n
	}
	return out, nil
}

// reservedFields lists "Message.field" for each reserved name in the messages
// of the graphrag file, nested messages included, sorted.
func reservedFields() []string {
	var out []string
	var walk func(protoreflect.MessageDescriptors)
	walk = func(ms protoreflect.MessageDescriptors) {
		for i := range ms.Len() {
			m := ms.Get(i)
			names := m.ReservedNames()
			for j := range names.Len() {
				out = append(out, string(m.Name())+"."+string(names.Get(j)))
			}
			walk(m.Messages())
		}
	}
	walk(graphragpb.File_gibson_graphrag_v1_graphrag_proto.Messages())
	sort.Strings(out)
	return out
}

// checkExecutorWire returns the reasons the executor image cannot be read by
// the daemon. An empty result means the pin is safe.
func checkExecutorWire(catalogImage string, exec executorSDK, floor wireFloor, reserved []string) []string {
	var problems []string
	if exec.Image != catalogImage {
		problems = append(problems, fmt.Sprintf(
			"executor-sdk.json names image %s but the catalog pins %s: run `make tool-catalog-capture IMAGE=%s`",
			exec.Image, catalogImage, catalogImage))
	}
	have, errHave := parseSDKVersion(exec.SDKVersion)
	want, errWant := parseSDKVersion(floor.Floor)
	switch {
	case errHave != nil:
		problems = append(problems, "executor-sdk.json: "+errHave.Error())
	case errWant != nil:
		problems = append(problems, "graphrag-wire-floor.json: "+errWant.Error())
	case have[0] < want[0] || (have[0] == want[0] && (have[1] < want[1] || (have[1] == want[1] && have[2] < want[2]))):
		problems = append(problems, fmt.Sprintf(
			"the executor image is built on sdk %s, below the wire floor %s. Its tools write fields that the "+
				"daemon sdk removed, so every run folds nothing. Pin an executor release built on sdk %s or later "+
				"(make tool-catalog-capture IMAGE=...)", exec.SDKVersion, floor.Floor, floor.Floor))
	}
	listed := append([]string(nil), floor.Reserved...)
	sort.Strings(listed)
	if strings.Join(listed, ",") != strings.Join(reserved, ",") {
		problems = append(problems, fmt.Sprintf(
			"the daemon sdk reserves %d graphrag fields and graphrag-wire-floor.json lists %d. A new removal needs "+
				"three edits in one change: raise \"floor\" to the sdk release that made it, replace \"reserved\" with "+
				"the current list, and pin an executor image built on that sdk",
			len(reserved), len(listed)))
	}
	return problems
}

// TestCheckExecutorWire is the failing fixture of the guard: the skew that
// shipped, and each way the guard can be defeated.
func TestCheckExecutorWire(t *testing.T) {
	const img = "ghcr.io/zeroroot-ai/gibson-executor@sha256:aaaa"
	reserved := []string{"Finding.parent_type", "Host.os_version"}
	floor := wireFloor{Floor: "v0.202.0", Reserved: reserved}
	for name, tc := range map[string]struct {
		exec      executorSDK
		floor     wireFloor
		reserved  []string
		wantParts []string
	}{
		"current executor passes": {executorSDK{img, "v0.202.0"}, floor, reserved, nil},
		"a newer executor passes": {executorSDK{img, "v0.209.1"}, floor, reserved, nil},
		"the shipped skew fails":  {executorSDK{img, "v0.191.0"}, floor, reserved, []string{"below the wire floor v0.202.0"}},
		"a patch below the floor": {executorSDK{img, "v0.201.9"}, floor, reserved, []string{"below the wire floor"}},
		"another image fails":     {executorSDK{"other@sha256:bbbb", "v0.202.0"}, floor, reserved, []string{"names image other@sha256:bbbb"}},
		"a bad version fails":     {executorSDK{img, "latest"}, floor, reserved, []string{"not vMAJOR.MINOR.PATCH"}},
		"a new removal fails":     {executorSDK{img, "v0.202.0"}, floor, append([]string{"Host.hostname"}, reserved...), []string{"reserves 3 graphrag fields"}},
		"a stale list fails":      {executorSDK{img, "v0.202.0"}, wireFloor{Floor: "v0.202.0", Reserved: reserved[:1]}, reserved, []string{"lists 1"}},
	} {
		got := checkExecutorWire(img, tc.exec, tc.floor, sorted(tc.reserved))
		if len(tc.wantParts) == 0 && len(got) != 0 {
			t.Errorf("%s: want no problem, got %v", name, got)
		}
		for _, part := range tc.wantParts {
			if !strings.Contains(strings.Join(got, "\n"), part) {
				t.Errorf("%s: want a problem with %q, got %v", name, part, got)
			}
		}
	}
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// TestExecutorImageIsWireCompatible is the guard on the committed files.
func TestExecutorImageIsWireCompatible(t *testing.T) {
	var cat struct {
		Image string `json:"image"`
	}
	var exec executorSDK
	var floor wireFloor
	for file, into := range map[string]any{
		"executor-catalog.json":    &cat,
		"executor-sdk.json":        &exec,
		"graphrag-wire-floor.json": &floor,
	} {
		raw, err := fs.ReadFile(os.DirFS("."), file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if err := json.Unmarshal(raw, into); err != nil {
			t.Fatalf("decode %s: %v", file, err)
		}
	}
	if len(reservedFields()) == 0 {
		t.Fatal("the daemon sdk reserves no graphrag field: the descriptor walk found nothing, so the guard would pass for the wrong reason")
	}
	for _, p := range checkExecutorWire(cat.Image, exec, floor, reservedFields()) {
		t.Error(p)
	}
}
