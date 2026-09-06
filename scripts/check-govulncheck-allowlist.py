#!/usr/bin/env python3
"""Check govulncheck findings against .govulncheck-allowlist.yaml.

gibson scans twice, and both scans must agree:

  - `heavy` in go-ci.yml, via zeroroot-ai/.github reusable-go-ci.yml, SOURCE
    mode over ./...
  - `govulncheck` in security.yaml, BINARY mode over the built daemon, because
    source mode crashes the go/ssa analysis under this toolchain (gibson#758).

The first eviction of gibson#1483 was exactly this gap: the allowlist was wired
into the reusable heavy tier only, so `heavy` passed and `security` still failed
on the same seven advisories. Two scanners with one policy means one
implementation of that policy, which is this file.

Reads `govulncheck -format json` (a stream of JSON objects, one per line) and
fails on any of:

  - a reachable advisory not in the allowlist
  - an allowlist entry past its `expires` date
  - an allowlist entry that no longer matches a reachable finding
  - an allowlist that parses to zero entries

Only SYMBOL-level findings count: a trace frame carrying a `function` is code
actually reachable, which is what "your code is affected" means. Verified
against golang/vuln@v1.1.4 — Finding.OSV is `osv`, Finding.Trace is `trace`,
Frame.Function is `function`.

The allowlist argument is optional. With no allowlist, nothing is exempted and
any reachable advisory fails — the normal state, and the state gibson is in.

Usage:
  govulncheck -format json ./... > report.json
  scripts/check-govulncheck-allowlist.py report.json                       # exempt nothing
  scripts/check-govulncheck-allowlist.py .govulncheck-allowlist.yaml report.json
"""

import datetime
import json
import pathlib
import sys

# The allowlist is OPTIONAL. Called with one argument, the policy is "exempt
# nothing": any reachable advisory fails. That is the normal state — an
# allowlist exists only while a reachable advisory has no release to bump to.
# Keeping the symbol-level reachability rule here, rather than deferring to
# govulncheck's own exit code, is why this stays one implementation for both
# scanners even when there is nothing to exempt.
if len(sys.argv) == 2:
    allowlist_path, report_path = None, pathlib.Path(sys.argv[1])
elif len(sys.argv) == 3:
    allowlist_path, report_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
else:
    sys.exit(f"usage: {sys.argv[0]} [allowlist.yaml] report.json")

if allowlist_path is not None and not allowlist_path.is_file():
    sys.exit(f"FAIL: vuln-allowlist {allowlist_path} does not exist")

# Deliberately not PyYAML: the runner may not have it, and a parser
# this file's shape does not need is a dependency that can break the
# gate for a reason unrelated to security.
entries = {}
current = None
for raw in (allowlist_path.read_text().splitlines() if allowlist_path else []):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if line.startswith("- id:"):
        current = line.split(":", 1)[1].strip().strip('"')
        entries[current] = {}
    elif current and ":" in line:
        k, v = line.split(":", 1)
        entries[current][k.strip()] = v.strip().strip('"')

if allowlist_path is not None and not entries:
    sys.exit(f"FAIL: parsed zero entries from {allowlist_path} — the file shape changed. "
             "Refusing to run, because an empty parse would silently tolerate every finding.")

# govulncheck -format json emits a STREAM of pretty-printed JSON objects,
# concatenated — NOT one object per line. Reading it line-by-line finds
# nothing, which is what evicted gibson#1483 the first time: zero findings
# parsed, so all seven allowlist entries looked stale and the gate failed with
# "no longer reachable" seven times. That the failure was loud rather than a
# silent pass is the design working; the parser was still wrong.
raw = report_path.read_text()
decoder, idx, messages = json.JSONDecoder(), 0, []
while idx < len(raw):
    while idx < len(raw) and raw[idx].isspace():
        idx += 1
    if idx >= len(raw):
        break
    try:
        msg, end = decoder.raw_decode(raw, idx)
    except json.JSONDecodeError:
        break
    messages.append(msg)
    idx = end

if not messages:
    sys.exit("FAIL: parsed zero JSON messages from the govulncheck report. "
             "Treating this as a broken scan, not a clean one.")

findings = set()
for msg in messages:
    f = msg.get("finding")
    # Symbol-level only: a trace frame with a function is code actually
    # reachable, which is what "your code is affected" means.
    if f and any(fr.get("function") for fr in (f.get("trace") or [])):
        findings.add(f["osv"])

today = datetime.date.today()
problems = []

for osv in sorted(findings - set(entries)):
    problems.append(f"  {osv}: reachable and NOT allowlisted")

for osv, meta in sorted(entries.items()):
    expires = meta.get("expires", "")
    if not expires:
        problems.append(f"  {osv}: allowlist entry has no expires date")
        continue
    try:
        when = datetime.date.fromisoformat(expires)
    except ValueError:
        problems.append(f"  {osv}: expires {expires!r} is not YYYY-MM-DD")
        continue
    if when < today:
        problems.append(f"  {osv}: EXPIRED on {expires} — re-review it or fix the vulnerability")
    elif osv not in findings:
        # The verify-chart-signature.sh rule: a stale exemption is a
        # failure, so the debt cannot outlive itself.
        problems.append(f"  {osv}: no longer reachable — delete this allowlist entry")

if problems:
    print("FAIL: govulncheck allowlist check", file=sys.stderr)
    print("\n".join(problems), file=sys.stderr)
    sys.exit(1)

if not entries:
    print("OK — no reachable advisories, and nothing is exempted.")
else:
    print(f"OK — {len(findings)} reachable advisory(ies), all allowlisted and unexpired:")
    for osv in sorted(findings):
        print(f"  {osv}  expires {entries[osv]['expires']}  {entries[osv].get('reason', '')}")
