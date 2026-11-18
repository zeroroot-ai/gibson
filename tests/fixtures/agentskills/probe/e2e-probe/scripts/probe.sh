#!/bin/sh
# The exit test replaces the two values below when it packs this folder.
nmap -Pn -p @EGRESS_PORT@ @EGRESS_HOST@
