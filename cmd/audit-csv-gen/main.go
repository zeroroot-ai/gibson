// Command audit-csv-gen walks a combined FileDescriptorSet, extracts the
// (gibson.auth.v1.authz) annotation on every method, and emits a CSV
// row per RPC. The CSV is the human-friendly companion to registry.yaml
// — it carries the same data plus the source proto file path so an
// auditor can answer "where is rule X authored?" in one column.
//
// Run via `make authz-registry` (which writes both the registry artifacts
// and this CSV in one shot from the same FDS). The CI drift gate diffs
// the regenerated CSV against the committed copy.
//
// Spec: unified-authz-regen Req 1.4.
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	authzv1 "github.com/zero-day-ai/sdk/api/gen/gibson/auth/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func main() {
	input := flag.String("input", "", "combined FileDescriptorSet binary path")
	output := flag.String("output", "", "output CSV path")
	flag.Parse()

	if *input == "" || *output == "" {
		fail("-input and -output are required")
	}

	data, err := os.ReadFile(*input)
	if err != nil {
		fail("read %s: %v", *input, err)
	}
	var fds descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(data, &fds); err != nil {
		fail("unmarshal %s: %v", *input, err)
	}

	type row struct {
		rpc, relation, objectType, deriver, identities string
		unauthenticated                                bool
		self                                           bool
		sourceFile                                     string
	}
	var rows []row

	for _, f := range fds.File {
		pkg := f.GetPackage()
		for _, svc := range f.Service {
			for _, mth := range svc.Method {
				rule, ok := getAuthRule(mth.Options)
				if !ok {
					continue
				}
				method := fmt.Sprintf("/%s.%s/%s", pkg, svc.GetName(), mth.GetName())
				rows = append(rows, row{
					rpc:             method,
					relation:        rule.GetRelation(),
					objectType:      rule.GetObjectType(),
					deriver:         rule.GetObjectDeriver(),
					identities:      formatIdentities(rule.GetAllowedIdentities()),
					unauthenticated: rule.GetUnauthenticated(),
					self:            rule.GetSelf(),
					sourceFile:      f.GetName(),
				})
			}
		}
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].rpc < rows[j].rpc })

	out, err := os.Create(*output)
	if err != nil {
		fail("create %s: %v", *output, err)
	}
	defer out.Close()
	w := csv.NewWriter(out)
	// mode column is at the END for positional compatibility (self-mode-authz design.md decision).
	if err := w.Write([]string{"rpc", "relation", "object_type", "deriver", "identities", "source_proto_file", "mode"}); err != nil {
		fail("write header: %v", err)
	}
	for _, r := range rows {
		if err := w.Write([]string{
			r.rpc, r.relation, r.objectType, r.deriver, r.identities,
			r.sourceFile, csvMode(r.unauthenticated, r.self),
		}); err != nil {
			fail("write row: %v", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		fail("flush: %v", err)
	}
}

// csvMode returns the mode string for a CSV row.
// Values: "unauthenticated" | "self" | "rule".
// Spec: self-mode-authz Req 5.1, 5.2, 5.3.
func csvMode(unauthenticated, self bool) string {
	switch {
	case unauthenticated:
		return "unauthenticated"
	case self:
		return "self"
	default:
		return "rule"
	}
}

func getAuthRule(opts *descriptorpb.MethodOptions) (*authzv1.AuthOptions, bool) {
	if opts == nil {
		return nil, false
	}
	if !proto.HasExtension(opts, authzv1.E_Authz) {
		return nil, false
	}
	rule, ok := proto.GetExtension(opts, authzv1.E_Authz).(*authzv1.AuthOptions)
	if !ok || rule == nil {
		return nil, false
	}
	return rule, true
}

// allowed_identities is a bitfield: USER=1, SERVICE=2, COMPONENT=4,
// PLATFORM_OPERATOR=8. Render in stable order.
func formatIdentities(bits int32) string {
	if bits == 0 {
		return ""
	}
	var parts []string
	if bits&int32(authzv1.IdentityClass_IDENTITY_CLASS_USER) != 0 {
		parts = append(parts, "USER")
	}
	if bits&int32(authzv1.IdentityClass_IDENTITY_CLASS_SERVICE) != 0 {
		parts = append(parts, "SERVICE")
	}
	if bits&int32(authzv1.IdentityClass_IDENTITY_CLASS_COMPONENT) != 0 {
		parts = append(parts, "COMPONENT")
	}
	if bits&int32(authzv1.IdentityClass_IDENTITY_CLASS_PLATFORM_OPERATOR) != 0 {
		parts = append(parts, "PLATFORM_OPERATOR")
	}
	return strings.Join(parts, "|")
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "audit-csv-gen: "+format+"\n", args...)
	os.Exit(1)
}
