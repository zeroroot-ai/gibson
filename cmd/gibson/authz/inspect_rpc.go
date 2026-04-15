package authz

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/internal/auth"
)

// inspect-rpc / list-rpcs are OFFLINE: they parse the binary's embedded YAML
// (or the file at --registry) and never dial the daemon. This is deliberate
// — operators debugging a `PermissionDenied` need an answer even when the
// daemon is in CrashLoopBackOff. Both subcommands share loadRegistryForCLI.

// loadRegistryForCLI returns the YAML entries plus a human source label
// ("embedded" or "override:<path>") for either the embedded YAML or the file
// at overridePath.
func loadRegistryForCLI(overridePath string) ([]auth.RegistryEntryView, string, error) {
	if overridePath == "" {
		return auth.LoadRegistryView(auth.EmbeddedRpcRegistry, "")
	}
	return auth.LoadRegistryView(nil, overridePath)
}

// printSpec formats a single entry block. Layout is fixed-key/value to make
// `grep`-and-pipe usage convenient.
func printSpec(out io.Writer, e auth.RegistryEntryView, source string) {
	fmt.Fprintln(out, e.Method)
	fmt.Fprintf(out, "  source:          %s\n", source)
	if e.Unauthenticated {
		fmt.Fprintln(out, "  unauthenticated: true")
	} else {
		fmt.Fprintf(out, "  relation:        %s\n", e.Relation)
		switch {
		case e.Object != "":
			fmt.Fprintf(out, "  object:          %s\n", e.Object)
		case e.ObjectFrom != "":
			fmt.Fprintf(out, "  object_from:     %s\n", e.ObjectFrom)
		default:
			fmt.Fprintln(out, "  object:          (tenant from request context)")
		}
		fmt.Fprintln(out, "  unauthenticated: false")
	}
	if e.Description != "" {
		fmt.Fprintf(out, "  description:     %s\n", e.Description)
	}
}

// newInspectRpcCmd returns the `gibson authz inspect-rpc <full-method>` command.
func newInspectRpcCmd() *cobra.Command {
	var override string
	cmd := &cobra.Command{
		Use:   "inspect-rpc <full-method>",
		Short: "Print the resolved authz spec for a gRPC method",
		Long: `Inspects the embedded RPC registry (or an override file) and prints the
authorization spec the daemon enforces for the given gRPC FullMethod.

Examples:

  gibson authz inspect-rpc /grpc.health.v1.Health/Check
  gibson authz inspect-rpc /gibson.daemon.admin.v1.DaemonAdminService/Shutdown
  gibson authz inspect-rpc /pkg.Service/Method --registry /etc/gibson/authz/rpc_registry.yaml

Both subcommands work OFFLINE — they never dial the daemon.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			entries, source, err := loadRegistryForCLI(override)
			if err != nil {
				return err
			}
			method := args[0]
			for _, e := range entries {
				if e.Method == method {
					printSpec(c.OutOrStdout(), e, source)
					return nil
				}
			}
			return fmt.Errorf("no entry for %q (default-deny applies)", method)
		},
	}
	cmd.Flags().StringVar(&override, "registry", "",
		"path to override YAML (defaults to embedded)")
	return cmd
}

// newListRpcsCmd returns the `gibson authz list-rpcs` command.
func newListRpcsCmd() *cobra.Command {
	var override string
	cmd := &cobra.Command{
		Use:   "list-rpcs",
		Short: "Print every registered RPC and its authz spec",
		Long: `Lists every entry in the embedded RPC registry (or override file), sorted
by gRPC FullMethod. Works OFFLINE — no daemon connection required.

Pipe to grep / less / awk for ad-hoc analysis:

  gibson authz list-rpcs | grep -A4 platform_operator
  gibson authz list-rpcs | grep ComponentService | wc -l`,
		RunE: func(c *cobra.Command, args []string) error {
			entries, source, err := loadRegistryForCLI(override)
			if err != nil {
				return err
			}
			// Stable, sorted output — independent of YAML row order.
			sort.SliceStable(entries, func(i, j int) bool {
				return entries[i].Method < entries[j].Method
			})
			out := c.OutOrStdout()
			for i, e := range entries {
				if i > 0 {
					fmt.Fprintln(out)
				}
				printSpec(out, e, source)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&override, "registry", "",
		"path to override YAML (defaults to embedded)")
	return cmd
}

// silenceUnusedImport keeps `strings` available — referenced in test format
// helpers and convenient for future formatting work.
var _ = strings.HasPrefix
