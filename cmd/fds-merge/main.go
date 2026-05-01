// Command fds-merge concatenates the `file` arrays of two or more
// FileDescriptorSet binaries into a single output FDS. Used by
// `make authz-registry` to feed the SDK protos AND the daemon-local
// protos into authz-registry-gen in one shot.
//
// Why: authz-registry-gen takes a single -input FDS, but the daemon
// registers RPC methods from both the pinned-SDK protos
// (gibson.admin.v1.*, gibson.daemon.v1.*) AND a set of daemon-local
// protos that aren't in the SDK (gibson.tenant.v1.*, gibson.user.v1.*,
// gibson.platform.v1.*). The runtime registry coverage check fails fast
// on any registered method that's missing from the registry, so both
// sets must be in the FDS the codegen tool processes.
//
// File-level dedup: if the same file path appears in multiple input
// FDSes, the FIRST occurrence wins (later inputs are skipped for that
// path) — a conservative "first one home" rule that preserves
// determinism. In practice the SDK and gibson-local protos don't
// overlap; the dedup is belt-and-suspenders.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func main() {
	var inputs flagList
	flag.Var(&inputs, "input", "FileDescriptorSet binary path (repeatable)")
	output := flag.String("output", "", "output FileDescriptorSet binary path")
	flag.Parse()

	if len(inputs) < 1 {
		fail("at least one -input is required")
	}
	if *output == "" {
		fail("-output is required")
	}

	combined := &descriptorpb.FileDescriptorSet{}
	seen := map[string]bool{}
	for _, in := range inputs {
		data, err := os.ReadFile(in)
		if err != nil {
			fail("read %s: %v", in, err)
		}
		var fds descriptorpb.FileDescriptorSet
		if err := proto.Unmarshal(data, &fds); err != nil {
			fail("unmarshal %s: %v", in, err)
		}
		for _, f := range fds.File {
			path := f.GetName()
			if seen[path] {
				continue
			}
			seen[path] = true
			combined.File = append(combined.File, f)
		}
	}

	out, err := proto.Marshal(combined)
	if err != nil {
		fail("marshal combined: %v", err)
	}
	if err := os.WriteFile(*output, out, 0o644); err != nil {
		fail("write %s: %v", *output, err)
	}
}

type flagList []string

func (l *flagList) String() string { return strings.Join(*l, ",") }
func (l *flagList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "fds-merge: "+format+"\n", args...)
	os.Exit(1)
}
