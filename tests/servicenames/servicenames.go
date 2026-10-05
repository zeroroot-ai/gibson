// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package servicenames checks that one gRPC service name is declared one time
// across the merged proto set of the daemon: the sdk protos and the
// daemon-local protos (gibson#531).
//
// gibson.tenant.v1.SecretsService and gibson.secrets.v1.SecretsService once
// declared the same ten RPCs in two packages. The authz registry then held two
// entries for one surface, and clients could not tell which package the
// daemon served. This package refuses that state.
package servicenames

import (
	"fmt"
	"sort"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// Duplicates returns one line for each simple service name that more than one
// file declares. The lines are sorted.
func Duplicates(files []protoreflect.FileDescriptor) []string {
	byName := map[protoreflect.Name][]string{}
	for _, fd := range files {
		services := fd.Services()
		for i := range services.Len() {
			svc := services.Get(i)
			byName[svc.Name()] = append(byName[svc.Name()], string(svc.FullName()))
		}
	}
	var out []string
	for name, full := range byName {
		if len(full) < 2 {
			continue
		}
		sort.Strings(full)
		out = append(out, fmt.Sprintf("the service name %s is declared %d times: %v", name, len(full), full))
	}
	sort.Strings(out)
	return out
}
