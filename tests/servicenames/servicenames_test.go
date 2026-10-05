// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package servicenames

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	// The sdk packages that declare a service.
	_ "github.com/zeroroot-ai/sdk/api/gen/gibson/agent/v1"
	_ "github.com/zeroroot-ai/sdk/api/gen/gibson/agentidentity/v1"
	_ "github.com/zeroroot-ai/sdk/api/gen/gibson/bank/v1"
	_ "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	_ "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	_ "github.com/zeroroot-ai/sdk/api/gen/gibson/graph/v1"
	_ "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	_ "github.com/zeroroot-ai/sdk/api/gen/gibson/identity/v1"
	_ "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	_ "github.com/zeroroot-ai/sdk/api/gen/gibson/plugin/v1"
	_ "github.com/zeroroot-ai/sdk/api/gen/gibson/pluginadmin/v1"
	_ "github.com/zeroroot-ai/sdk/api/gen/gibson/secrets/v1"
	_ "github.com/zeroroot-ai/sdk/api/gen/gibson/tool/v1"

	// The daemon-local packages. TestEachLocalProtoIsLoaded fails when a
	// tracked proto file is not in the registry, so this list cannot go stale
	// with no signal.
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/agentconsole/v1"
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/destructiveauthz/v1"
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/discovery/v1"
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/logs/v1"
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/session/v1"
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	_ "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
)

const protoRoot = "internal/server/daemon/api"

// The floors. A run below them read the wrong set and must not pass.
const (
	minLocalFiles = 20
	minServices   = 30
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory; cannot locate the repo root")
		}
		dir = parent
	}
}

func localProtoPaths(t *testing.T) []string {
	t.Helper()
	root := filepath.Join(repoRoot(t), protoRoot)
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}
		if d.IsDir() || !strings.HasSuffix(path, ".proto") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return fmt.Errorf("relativize %s against %s: %w", path, root, relErr)
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// mergedFiles returns each registered proto file under the gibson/ prefix: the
// sdk files and the daemon-local files.
func mergedFiles() []protoreflect.FileDescriptor {
	var out []protoreflect.FileDescriptor
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if strings.HasPrefix(fd.Path(), "gibson/") {
			out = append(out, fd)
		}
		return true
	})
	return out
}

// TestEachLocalProtoIsLoaded holds the floor for the daemon-local half.
func TestEachLocalProtoIsLoaded(t *testing.T) {
	paths := localProtoPaths(t)
	for _, path := range paths {
		if _, err := protoregistry.GlobalFiles.FindFileByPath(path); err != nil {
			t.Errorf("%s is a tracked proto file, and the registry does not hold it: %v. "+
				"Add a blank import of its Go package to servicenames_test.go.", path, err)
		}
	}
	if len(paths) < minLocalFiles {
		t.Fatalf("found %d daemon-local proto files, want at least %d", len(paths), minLocalFiles)
	}
}

// TestOneDeclarationForEachServiceName is the guard of gibson#531.
func TestOneDeclarationForEachServiceName(t *testing.T) {
	files := mergedFiles()
	services := 0
	for _, fd := range files {
		services += fd.Services().Len()
	}
	if services < minServices {
		t.Fatalf("read %d services, want at least %d. The test read the wrong set.", services, minServices)
	}
	for _, line := range Duplicates(files) {
		t.Errorf("%s. Keep one declaration: the sdk copy for a component surface, "+
			"the daemon-local copy for a control surface (ADR-0058).", line)
	}
}

func fixtureFile(t *testing.T, path, pkg string) protoreflect.FileDescriptor {
	t.Helper()
	file := &descriptorpb.FileDescriptorProto{
		Name:        proto.String(path),
		Package:     proto.String(pkg),
		Syntax:      proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Empty")}},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("SecretsService"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:       proto.String("ListSecrets"),
				InputType:  proto.String("." + pkg + ".Empty"),
				OutputType: proto.String("." + pkg + ".Empty"),
			}},
		}},
	}
	fd, err := protodesc.NewFile(file, new(protoregistry.Files))
	if err != nil {
		t.Fatalf("build the fixture file %s: %v", path, err)
	}
	return fd
}

// TestGuardFixture is the failing fixture: the state before gibson#531.
func TestGuardFixture(t *testing.T) {
	old := fixtureFile(t, "fixture/tenant/v1/secrets.proto", "fixture.tenant.v1")
	sdk := fixtureFile(t, "fixture/secrets/v1/secrets.proto", "fixture.secrets.v1")

	got := Duplicates([]protoreflect.FileDescriptor{old, sdk})
	want := "the service name SecretsService is declared 2 times: " +
		"[fixture.secrets.v1.SecretsService fixture.tenant.v1.SecretsService]"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %q, want [%q]", got, want)
	}

	if got := Duplicates([]protoreflect.FileDescriptor{sdk}); len(got) != 0 {
		t.Fatalf("one declaration was refused: %q", got)
	}
}
