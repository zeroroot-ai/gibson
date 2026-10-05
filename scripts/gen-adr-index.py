#!/usr/bin/env python3
"""Write docs/adr-index.md, the public index of ADR numbers.

The ADR records live in the private repo zeroroot-ai/docs. A code comment in a
public repo cites a record by its number. This index gives each live number
with its one-line rule, and each retired number with the numbers that hold its
rule now. A public reader turns a citation into one sentence. The gaps and the
file paths of a record stay private.

The source is `adr/README.md` of the docs repo. This script copies three things
from it and nothing else: the number and the rule of each live ADR, and the
number, the subject and the successor numbers of each retired ADR. It drops the
status column and each file path.

USAGE

  python3 scripts/gen-adr-index.py <path to docs/adr/README.md>   # write
  python3 scripts/gen-adr-index.py --check                        # validate
  python3 scripts/gen-adr-index.py --selftest                     # fixtures

`--check` validates the committed file with no access to the docs repo: each
row parses, no number appears two times, and the live table holds at least
MIN_LIVE rows. `make check-adr-index` runs `--selftest` and then `--check`.

Exit codes: 0 clean, 1 a finding or a failed self-test, 2 usage error.
"""

from __future__ import annotations

import pathlib
import re
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
INDEX = REPO / "docs" / "adr-index.md"

# A truncated source or a wrong file would write a short index, and each
# citation guard would then fail on correct numbers. The series held 110 live
# records on 2026-10-05.
MIN_LIVE = 100

HEADER = """\
# ADR index

This file lists each architecture decision record (ADR) of the `zeroroot-ai`
organization by number. A code comment cites a record as `ADR-NNNN`. Read the
rule of that number here.

The full records are private. This file is the public part: one line for each
decision.

- A number in the first table is live. A citation of it is correct.
- A number in the second table is retired. Cite the number in its last column.
- A number in neither table matches no record. A citation of it is an error.

The shared workflow `adr-citations.yml` of `zeroroot-ai/.github` checks each
citation in a repo against this file. `gibson` holds the one source copy. Each
other repo keeps a copy at `docs/adr-index.md`.

To update this file after a change of an ADR in `zeroroot-ai/docs`:

1. In `gibson`, run `python3 scripts/gen-adr-index.py <path to docs/adr/README.md>`.
2. Make sure that no rule line reveals a security finding that is still open.
3. Merge the change in `gibson`. Then copy the file into each other repo.

Do not edit the tables by hand.
"""

LIVE_ROW = re.compile(r"^\| \[(\d{4})\]\(\./[^)]+\) \| (.+?) \| [^|]+ \|\s*$")
RETIRED_ROW = re.compile(r"^\| (\d{4}) \| ([^|]*?) \|(?:\s*([^|]*?)\s*\|)?\s*$")
SUCCESSOR = re.compile(r"\[(\d{4})\]\(")

OUT_LIVE = re.compile(r"^\| ADR-(\d{4}) \| (.+) \|$")
OUT_RETIRED = re.compile(r"^\| ADR-(\d{4}) \| (.+) \| (.+) \|$")


def parse_source(text: str) -> tuple[dict[str, str], dict[str, tuple[str, list[str]]]]:
    """Return (live, retired) from the README of the docs repo."""
    live: dict[str, str] = {}
    retired: dict[str, tuple[str, list[str]]] = {}
    section = ""
    for line in text.splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        if section == "Live ADRs":
            m = LIVE_ROW.match(line)
            if m:
                number, rule = m.group(1), m.group(2).strip()
                if number in live:
                    raise ValueError(f"{number} is in the live tables two times")
                live[number] = rule
        elif section == "Retired numbers":
            m = RETIRED_ROW.match(line)
            if m:
                number, subject = m.group(1), m.group(2).strip()
                successors = SUCCESSOR.findall(m.group(3) or "")
                if number in retired:
                    raise ValueError(f"{number} is in the retired table two times")
                retired[number] = (subject, successors)
    both = sorted(set(live) & set(retired))
    if both:
        raise ValueError(f"live and retired at the same time: {', '.join(both)}")
    for number, (_, successors) in retired.items():
        for s in successors:
            if s not in live:
                raise ValueError(f"retired {number} points at {s}, which is not live")
    return live, retired


def render(live: dict[str, str], retired: dict[str, tuple[str, list[str]]]) -> str:
    out = [HEADER, "## Live", "", "| ADR | Rule |", "|---|---|"]
    for number in sorted(live):
        out.append(f"| ADR-{number} | {live[number]} |")
    out += ["", "## Retired", "", "| ADR | What it decided | Cite this number |", "|---|---|---|"]
    for number in sorted(retired):
        subject, successors = retired[number]
        now = ", ".join(f"ADR-{s}" for s in successors) if successors else "None. No ADR holds this rule."
        out.append(f"| ADR-{number} | {subject or 'Never used'} | {now} |")
    return "\n".join(out) + "\n"


def check_index(text: str, min_live: int = MIN_LIVE) -> list[str]:
    """Return the findings for a rendered index. An empty list means clean."""
    findings: list[str] = []
    live: set[str] = set()
    retired: dict[str, str] = {}
    section = ""
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        if not line.startswith("| ADR-"):
            if line.startswith("| ") and section in ("Live", "Retired") and "ADR |" not in line:
                findings.append(f"line {lineno}: the row does not start with an ADR number")
            continue
        if section == "Live":
            m = OUT_LIVE.match(line)
            if not m or "|" in m.group(2):
                findings.append(f"line {lineno}: the live row does not have two cells")
                continue
            number = m.group(1)
        elif section == "Retired":
            m = OUT_RETIRED.match(line)
            if not m:
                findings.append(f"line {lineno}: the retired row does not have three cells")
                continue
            number = m.group(1)
            retired[number] = m.group(3)
        else:
            findings.append(f"line {lineno}: an ADR row is outside the two tables")
            continue
        if number in live or (section == "Live" and number in retired) or (
            section == "Retired" and list(retired).count(number) > 1
        ):
            findings.append(f"line {lineno}: ADR-{number} appears two times")
        if section == "Live":
            live.add(number)
    seen: set[str] = set()
    for lineno, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\| ADR-(\d{4}) \|", line)
        if not m:
            continue
        if m.group(1) in seen:
            findings.append(f"line {lineno}: ADR-{m.group(1)} appears two times")
        seen.add(m.group(1))
    for number, now in retired.items():
        for s in re.findall(r"ADR-(\d{4})", now):
            if s not in live:
                findings.append(f"ADR-{number} is retired and points at ADR-{s}, which is not live")
    if len(live) < min_live:
        findings.append(f"the live table holds {len(live)} rows, and the floor is {min_live}")
    return sorted(set(findings))


SELFTEST_SOURCE = """\
## Live ADRs

| ADR | Rule | Status |
|---|---|---|
| [0003](./0003-one-code-path.md) | One code path | Accepted |
| [0092](./0092-x.md) | A service connects by cluster DNS | Partly built |

## Retired numbers

| Number | What it decided | Where the rule lives now |
|---|---|---|
| 0005 | Shared Argo resources | Nowhere. The subject is gone. |
| 0008 | Register the service name | [0092](./0092-x.md) |
| 0062 | Never used | |
"""


def selftest() -> int:
    failures: list[str] = []

    def expect(name: str, ok: bool) -> None:
        if not ok:
            failures.append(name)

    live, retired = parse_source(SELFTEST_SOURCE)
    text = render(live, retired)
    expect("the fixture source gives two live rows", sorted(live) == ["0003", "0092"])
    expect("the fixture source gives three retired rows", sorted(retired) == ["0005", "0008", "0062"])
    expect("a successor becomes a citation",
           "| ADR-0008 | Register the service name | ADR-0092 |" in text)  # adr-citations-exempt: fixture
    expect("a file path never reaches the index", "./0092-x.md" not in text and "Partly built" not in text)
    expect("a clean index passes", check_index(text, min_live=2) == [])

    # Each fixture below must FAIL. A guard that passes one of them cannot fail.
    expect("a short index fails", check_index(text, min_live=3) != [])
    expect("a number in both tables fails",
           check_index(text.replace("| ADR-0005 |", "| ADR-0003 |"),  # adr-citations-exempt: fixture
                       min_live=2) != [])
    expect("a duplicate live number fails",
           check_index(text.replace("| ADR-0092 | A service", "| ADR-0003 | A service"), min_live=1) != [])
    expect("a retired number that points at a number that is not live fails",
           check_index(text.replace("| ADR-0092 |\n", "| ADR-0777 |\n"),  # adr-citations-exempt: fixture
                       min_live=2) != [])
    expect("a live row with three cells fails",
           check_index(text.replace("| One code path |", "| One | code path |"), min_live=2) != [])
    for bad, name in (
        (SELFTEST_SOURCE.replace("| 0005 |", "| 0003 |"), "a source with one number live and retired fails"),
        (SELFTEST_SOURCE.replace("[0092](./0092-x.md) |\n| 0062", "[0777](./0777-x.md) |\n| 0062"),
         "a source with a successor that is not live fails"),
    ):
        try:
            parse_source(bad)
            expect(name, False)
        except ValueError:
            pass

    with tempfile.TemporaryDirectory() as tmp:
        p = pathlib.Path(tmp) / "README.md"
        p.write_text("## Live ADRs\n\nno table here\n")
        try:
            l2, r2 = parse_source(p.read_text())
            expect("an empty source fails the floor", check_index(render(l2, r2)) != [])
        except ValueError:
            pass

    if failures:
        for f in failures:
            print(f"gen-adr-index: selftest FAILED: {f}", file=sys.stderr)
        return 1
    print("gen-adr-index: selftest OK (12 cases)")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "--selftest":
        return selftest()
    if argv[1] == "--check":
        if not INDEX.is_file():
            print(f"gen-adr-index: {INDEX} does not exist", file=sys.stderr)
            return 1
        findings = check_index(INDEX.read_text())
        for f in findings:
            print(f"gen-adr-index: docs/adr-index.md: {f}", file=sys.stderr)
        if findings:
            return 1
        rows = sum(1 for line in INDEX.read_text().splitlines() if line.startswith("| ADR-"))
        print(f"gen-adr-index: docs/adr-index.md is well formed ({rows} numbers)")
        return 0
    source = pathlib.Path(argv[1])
    if not source.is_file():
        print(f"gen-adr-index: {source} is not a file", file=sys.stderr)
        return 2
    try:
        live, retired = parse_source(source.read_text())
    except ValueError as e:
        print(f"gen-adr-index: {e}", file=sys.stderr)
        return 1
    text = render(live, retired)
    findings = check_index(text)
    for f in findings:
        print(f"gen-adr-index: {f}", file=sys.stderr)
    if findings:
        return 1
    INDEX.write_text(text)
    print(f"gen-adr-index: wrote {INDEX.relative_to(REPO)}: {len(live)} live, {len(retired)} retired")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
