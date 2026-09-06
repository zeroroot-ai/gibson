#!/usr/bin/env python3
"""Self-test for scripts/check-govulncheck-allowlist.py.

This guard had no test until gibson#1491. That is how the original
line-by-line report parser shipped: it found zero findings in a report that
had seven, so every allowlist entry looked stale and the gate failed for the
wrong reason (the docstring on the checker records that eviction).

The cases that matter are the ones where a WRONG answer is silent:

  - exempt-nothing must still FAIL on a reachable advisory. Deleting the
    allowlist must not defang the gate — that is the whole risk of gibson#1491.
  - an informational, module-level finding must NOT fail. govulncheck reports
    advisories for modules in the build graph whose vulnerable symbols are
    never called; failing on those makes the gate unmeetable.
  - an empty or unparseable report must FAIL. A broken scan reads exactly like
    a clean one, and treating it as clean is the failure mode this whole file
    exists to prevent.

No pytest, no PyYAML: the runner is not guaranteed to have either, and a
dependency that can break the gate for a reason unrelated to security is the
thing the checker itself deliberately avoids.

Run: python3 scripts/tests/test_check_govulncheck_allowlist.py
"""

import pathlib
import subprocess
import sys
import tempfile

CHECKER = pathlib.Path(__file__).resolve().parents[1] / "check-govulncheck-allowlist.py"

REACHABLE = '{"finding":{"osv":"GO-0000-0001","trace":[{"module":"m","function":"F"}]}}'
INFORMATIONAL = '{"finding":{"osv":"GO-0000-0002","trace":[{"module":"m"}]}}'
ALLOWLIST = '- id: "GO-0000-0001"\n  expires: "2099-01-01"\n  reason: "fixture"\n'
EXPIRED = '- id: "GO-0000-0001"\n  expires: "2000-01-01"\n  reason: "fixture"\n'
STALE = '- id: "GO-0000-0003"\n  expires: "2099-01-01"\n  reason: "fixture"\n'

CASES = [
    # (name, allowlist or None, report body, expect_failure)
    ("exempt-nothing fails on a reachable advisory", None, REACHABLE, True),
    ("exempt-nothing passes an informational finding", None, INFORMATIONAL, False),
    ("exempt-nothing passes a report with no findings", None, '{"config":{}}', False),
    ("an allowlist still exempts its entry", ALLOWLIST, REACHABLE, False),
    ("an expired entry fails", EXPIRED, REACHABLE, True),
    ("a stale entry fails", STALE, INFORMATIONAL, True),
    ("an empty report fails as a broken scan", None, "", True),
    ("an unparseable report fails as a broken scan", None, "not json", True),
    ("an allowlist that parses to zero entries fails", "# only a comment\n", REACHABLE, True),
    ("a missing allowlist file fails", "<<MISSING>>", REACHABLE, True),
]


def run_case(tmp, allowlist, report, index):
    report_path = tmp / f"report{index}.json"
    report_path.write_text(report)
    argv = [sys.executable, str(CHECKER)]
    if allowlist == "<<MISSING>>":
        argv.append(str(tmp / "does-not-exist.yaml"))
    elif allowlist is not None:
        allowlist_path = tmp / f"allow{index}.yaml"
        allowlist_path.write_text(allowlist)
        argv.append(str(allowlist_path))
    argv.append(str(report_path))
    return subprocess.run(argv, capture_output=True, text=True)


def main():
    failures = []
    with tempfile.TemporaryDirectory() as raw_tmp:
        tmp = pathlib.Path(raw_tmp)
        for index, (name, allowlist, report, expect_failure) in enumerate(CASES):
            proc = run_case(tmp, allowlist, report, index)
            failed = proc.returncode != 0
            if failed != expect_failure:
                want = "fail" if expect_failure else "pass"
                failures.append(
                    f"  {name}: expected {want}, got exit {proc.returncode}\n"
                    f"    stdout: {proc.stdout.strip()}\n"
                    f"    stderr: {proc.stderr.strip()}"
                )
            else:
                print(f"ok — {name}")

    if failures:
        print("\nFAIL: check-govulncheck-allowlist.py self-test", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"\nOK — {len(CASES)} cases passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
