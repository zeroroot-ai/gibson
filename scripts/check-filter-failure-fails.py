#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0
# Copyright 2026 Zero Root AI
"""check-filter-failure-fails.py: a failed change filter fails the gate.

gibson#807 condition 7. A gate job that `needs:` a change-filter job is
SKIPPED by GitHub when the filter fails, and a skipped required check reads
as a pass. So a red filter made the gate green.

The rule, for each workflow under .github/workflows that has a job named
`changes`:

  - When the workflow has a `queue-gate` aggregator, that aggregator holds
    `changes` to success (scripts/check-queue-gate-coverage.sh checks it).
  - Otherwise each job that needs `changes` runs when the filter did not
    succeed, and then either fails or runs in full:
      * a job with steps: its `if:` holds `!cancelled()` and
        `needs.changes.result != 'success'`, and a step with
        `if: needs.changes.result != 'success'` runs `exit 1`. Such a job
        also needs `changes` to carry no `if:`, or the filter would skip in
        one lane and the job would fail there.
      * a job that calls a reusable workflow: its `if:` holds `always()` or
        `!cancelled()` and no other condition, and an input holds
        `needs.changes.result != 'success'`, so a failed filter means a full
        run.

  check-filter-failure-fails.py              check .github/workflows
  check-filter-failure-fails.py --selftest   prove each rule can fail
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
FILTER = "changes"
FAILS = f"needs.{FILTER}.result != 'success'"


def needs_of(job: dict) -> list[str]:
    n = job.get("needs") or []
    return [n] if isinstance(n, str) else list(n)


def problems(path: Path) -> list[str]:
    doc = yaml.safe_load(path.read_text()) or {}
    jobs = doc.get("jobs") or {}
    if FILTER not in jobs:
        return []
    out = []
    if "queue-gate" in jobs:
        return out
    for name, job in jobs.items():
        if FILTER not in needs_of(job):
            continue
        cond = str(job.get("if") or "").replace("${{", "").replace("}}", "").strip()
        if "uses" in job:
            inputs = " ".join(str(v) for v in (job.get("with") or {}).values())
            if cond not in ("always()", "!cancelled()"):
                out.append(f"{path.name}: job `{name}` does not run when `{FILTER}` fails "
                           f"(a reusable call needs `if: always()` or `!cancelled()` alone, found {cond!r})")
            if FAILS not in inputs:
                out.append(f"{path.name}: job `{name}` has no input that runs it in full when `{FILTER}` fails "
                           f"(`{FAILS}`)")
            continue
        if jobs[FILTER].get("if") is not None:
            out.append(f"{path.name}: `{FILTER}` has an `if:`, so it skips in one lane, and job `{name}` "
                       f"then fails or skips there")
        if "!cancelled()" not in cond or FAILS not in cond:
            out.append(f"{path.name}: job `{name}` does not run when `{FILTER}` fails "
                       f"(its `if:` needs `!cancelled()` and `{FAILS}`)")
        steps = job.get("steps") or []
        if not any(str(st.get("if", "")).strip() == FAILS and "exit 1" in str(st.get("run", ""))
                   for st in steps):
            out.append(f"{path.name}: job `{name}` has no step that fails when `{FILTER}` fails")
    return out


def check(root: Path) -> int:
    files = sorted((root / ".github" / "workflows").glob("*.yml"))
    if not files:
        print("::error::check-filter-failure-fails: found no workflow to check")
        return 1
    found = [p for f in files for p in problems(f)]
    for p in found:
        print(f"::error::{p}")
    if found:
        return 1
    n = sum(1 for f in files if FILTER in ((yaml.safe_load(f.read_text()) or {}).get("jobs") or {}))
    print(f"ok  check-filter-failure-fails: {n} workflow(s) with a `{FILTER}` filter fail when it fails")
    return 0


GOOD = """
on: {pull_request: null, merge_group: null}
jobs:
  changes: {runs-on: ubuntu-latest}
  gate:
    needs: changes
    if: "${{ !cancelled() && (needs.changes.result != 'success' || needs.changes.outputs.relevant == 'true') }}"
    runs-on: ubuntu-latest
    steps:
      - {if: "needs.changes.result != 'success'", run: "echo bad; exit 1"}
      - {run: "make check"}
"""


REUSE = """
on: {pull_request: null, merge_group: null}
jobs:
  changes: {if: "github.event_name == 'pull_request'", runs-on: ubuntu-latest}
  analyze:
    needs: changes
    if: always()
    uses: o/r/.github/workflows/x.yml@v1
    with:
      scan: "${{ github.event_name != 'pull_request' || needs.changes.result != 'success' || needs.changes.outputs.hit == 'true' }}"
"""


def selftest() -> int:
    cases = [
        ("a gate that fails on a failed filter", GOOD, 0),
        ("MUTATION the filter skips in one lane", GOOD.replace("changes: {runs-on: ubuntu-latest}",
         "changes: {if: \"github.event_name == 'pull_request'\", runs-on: ubuntu-latest}"), 1),
        ("MUTATION the gate skips on a failed filter (old if)", GOOD.replace(
            "${{ !cancelled() && (needs.changes.result != 'success' || needs.changes.outputs.relevant == 'true') }}",
            "needs.changes.outputs.relevant == 'true'"), 1),
        ("MUTATION no step fails on a failed filter", GOOD.replace(
            "      - {if: \"needs.changes.result != 'success'\", run: \"echo bad; exit 1\"}\n", ""), 1),
        ("MUTATION the failing step does not exit", GOOD.replace("echo bad; exit 1", "echo bad"), 1),
        ("a reusable call that runs in full on a failed filter", REUSE, 0),
        ("MUTATION the reusable call skips on a failed filter", REUSE.replace(
            "if: always()", "if: always() && needs.changes.result != 'failure'"), 1),
        ("MUTATION the reusable call scans less on a failed filter", REUSE.replace(
            "needs.changes.result != 'success' || ", ""), 1),
        ("an aggregator workflow is left to the coverage check", """
on: {pull_request: null}
jobs:
  changes: {runs-on: ubuntu-latest}
  fast: {needs: changes, runs-on: ubuntu-latest}
  queue-gate: {if: always(), needs: [changes, fast], runs-on: ubuntu-latest}
""", 0),
    ]
    failed = 0
    with tempfile.TemporaryDirectory() as d:
        wf = Path(d) / ".github" / "workflows"
        wf.mkdir(parents=True)
        for desc, text, want in cases:
            (wf / "x.yml").write_text(text)
            got = 1 if problems(wf / "x.yml") else 0
            ok = got == want
            failed += not ok
            print(f"  {'ok  ' if ok else 'FAIL'}  {desc} -> {'fail' if got else 'pass'}")
        (wf / "x.yml").unlink()
        if check(Path(d)) != 1:
            print("  FAIL  an empty workflow directory must fail")
            failed += 1
    print(f"check-filter-failure-fails --selftest: {len(cases) + 1 - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(check(ROOT))
