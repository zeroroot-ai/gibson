// gen-fga-model-json converts internal/platform/authz/model.fga (OpenFGA DSL) into
// the JSON form expected by OpenFGA's /authorization-models HTTP API. It is
// invoked by the Helm chart's `make sync-fga-model` target to regenerate
// enterprise/deploy/helm/gibson/files/fga-model.json from the DSL source of
// truth, eliminating the drift between model.fga and the hand-written JSON
// that previously lived inline in the fga-init-job.yaml template.
//
// Usage:
//
//	go run ./cmd/gen-fga-model-json path/to/model.fga > fga-model.json
package main

import (
	"fmt"
	"os"

	"github.com/openfga/language/pkg/go/transformer"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen-fga-model-json <path/to/model.fga>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		os.Exit(1)
	}
	model, err := transformer.TransformDSLToProto(string(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "transform: %v\n", err)
		os.Exit(1)
	}
	marshaler := protojson.MarshalOptions{
		Multiline:     true,
		Indent:        "  ",
		UseProtoNames: true,
	}
	out, err := marshaler.Marshal(model)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}
	// Trailing newline for POSIX friendliness.
	fmt.Println(string(out))
}
