#!/bin/sh
# The exit test replaces the four values below when it packs this folder.
# The first scan names the pod of the daemon, a host that the reserved ranges of
# a sandbox network always block. The second scan names a public host. The
# network scope of the node of the agent excludes it, and the mode external-only
# would allow it, so a sandbox that took the class default instead of the scope
# of its node leaves no drop record for it.
nmap -Pn -p @EGRESS_PORT@ @EGRESS_HOST@
nmap -Pn -p @PUBLIC_PORT@ @PUBLIC_HOST@
