#!/usr/bin/env python3
"""Write the weekly report of the open issues of the organization.

The report is ONE issue in this repo, with the title REPORT_TITLE. Each run
replaces its body. The run opens no issue for a finding (gibson#806, D44).

WHAT THE REPORT HOLDS

  1. The open issues of each repo, grouped by tier and sorted by age, with the
     oldest first.
  2. Each open issue with no activity for STALE_DAYS days.
  3. The number of issues and repos that the run read, and each repo that it
     did not read.

THE SOURCE OF A TIER

The body of the epic (EPIC) lists each issue under a line `Tier N:`. An issue
with the label `tier-N` uses the label. An issue that neither source names is
in the group "No tier".

TOKENS

  READ_TOKEN   reads the issues of each repo. A token with no access to a
               private repo gives a report that names that repo as not read.
  GH_TOKEN     writes the report issue in this repo only.

The run fails when it reads no issue, so an empty report never looks correct.

USAGE

  python3 scripts/ci/issue-report.py            # read, render, write the issue
  python3 scripts/ci/issue-report.py --dry-run  # read, render, print
  python3 scripts/ci/issue-report.py --selftest # fixtures, no network
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import sys

ORG = "zeroroot-ai"
HOME_REPO = os.environ.get("GITHUB_REPOSITORY", f"{ORG}/gibson")
EPIC = (f"{ORG}/gibson", 747)
REPORT_TITLE = "Weekly report: open issues by tier and age"
STALE_DAYS = 30
BODY_LIMIT = 60000  # GitHub refuses a body above 65536 characters.
TITLE_WIDTH = 80

TIER_HEADING = re.compile(r"^Tier ([1-5]):\s*$")
EPIC_REF = re.compile(r"zeroroot-ai/([A-Za-z0-9._-]+)#(\d+)")
TIER_LABEL = re.compile(r"^tier[-: ]?([1-5])$", re.IGNORECASE)


def parse_epic_tiers(body: str) -> dict[tuple[str, int], int]:
    """Map (repo, number) to the tier that the epic body gives it."""
    tiers: dict[tuple[str, int], int] = {}
    current = 0
    for line in body.splitlines():
        m = TIER_HEADING.match(line.strip())
        if m:
            current = int(m.group(1))
            continue
        if line.startswith("#"):
            current = 0
            continue
        if current and line.lstrip().startswith("- ["):
            ref = EPIC_REF.search(line)
            if ref:
                tiers.setdefault((ref.group(1), int(ref.group(2))), current)
    return tiers


def tier_of(issue: dict, epic_tiers: dict[tuple[str, int], int]) -> int:
    for label in issue["labels"]:
        m = TIER_LABEL.match(label)
        if m:
            return int(m.group(1))
    return epic_tiers.get((issue["repo"], issue["number"]), 0)


def days(now: dt.datetime, stamp: str) -> int:
    then = dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    return max(0, (now - then).days)


def clip(title: str, width: int) -> str:
    title = title.replace("|", "/").replace("\n", " ").strip()
    return title if len(title) <= width else title[: width - 1] + "…"


def ref(issue: dict) -> str:
    """The reference of an issue, as a code span.

    A plain `org/repo#N` makes GitHub write a cross-reference event on the
    issue. That event is activity, so the first report would make each stale
    issue look fresh. A code span makes no link and no event.
    """
    return f"`{issue['repo']}#{issue['number']}`"


def render(issues: list[dict], epic_tiers: dict[tuple[str, int], int], now: dt.datetime,
           repos_read: list[str], repos_not_read: list[str], title_width: int = TITLE_WIDTH) -> str:
    if not issues:
        raise ValueError("the run read no issue")
    out = [
        f"Updated: {now.strftime('%Y-%m-%d %H:%M')} UTC. The next run replaces this text.",
        "",
        f"The run read {len(issues)} open issues in {len(repos_read)} repos.",
    ]
    if repos_not_read:
        out.append(f"The run did not read these repos: {', '.join(sorted(repos_not_read))}.")
    out += ["", f"The tier of an issue comes from a `tier-N` label, or from the epic `gibson#{EPIC[1]}`.",
            f"Each reference is a code span and not a link, so the report adds no activity to an issue. "
            f"Each repo is in the organization `{ORG}`.", ""]

    by_tier: dict[int, list[dict]] = {}
    for issue in issues:
        by_tier.setdefault(tier_of(issue, epic_tiers), []).append(issue)

    out += ["## Count by tier", "", "| Tier | Open issues | Oldest, in days |", "|---|---|---|"]
    order = [t for t in (1, 2, 3, 4, 5, 0) if t in by_tier]
    for tier in order:
        group = by_tier[tier]
        oldest = max(days(now, i["created_at"]) for i in group)
        out.append(f"| {tier if tier else 'No tier'} | {len(group)} | {oldest} |")

    for tier in order:
        group = sorted(by_tier[tier], key=lambda i: (i["repo"], i["created_at"], i["number"]))
        out += ["", f"## {'Tier ' + str(tier) if tier else 'No tier'}", ""]
        repo = None
        for i in group:
            if i["repo"] != repo:
                repo = i["repo"]
                out += [f"**{repo}**", ""] if out[-1] == "" else ["", f"**{repo}**", ""]
            text = f" {clip(i['title'], title_width)}" if title_width else ""
            out.append(f"- {ref(i)}, {days(now, i['created_at'])} days:{text}"
                       if text else f"- {ref(i)}, {days(now, i['created_at'])} days")

    stale = sorted((i for i in issues if days(now, i["updated_at"]) >= STALE_DAYS),
                   key=lambda i: (-days(now, i["updated_at"]), i["repo"], i["number"]))
    out += ["", f"## No activity for {STALE_DAYS} days", ""]
    if stale:
        out += [f"- {ref(i)}: {days(now, i['updated_at'])} days with no activity"
                for i in stale]
    else:
        out.append("No open issue is in this group.")
    return "\n".join(out) + "\n"


def render_within_limit(*args, **kwargs) -> str:
    """Render, and drop the titles when the text is above the body limit."""
    for width in (TITLE_WIDTH, 40, 0):
        text = render(*args, title_width=width, **kwargs)
        if len(text) <= BODY_LIMIT:
            return text
    raise ValueError(f"the report is above {BODY_LIMIT} characters with no titles")


# --- GitHub ------------------------------------------------------------------

def gh(args: list[str], token: str) -> tuple[int, str]:
    env = dict(os.environ, GH_TOKEN=token)
    p = subprocess.run(["gh", *args], capture_output=True, text=True, env=env, check=False)
    return p.returncode, p.stdout if p.returncode == 0 else p.stderr


def gh_json_pages(path: str, token: str) -> list | None:
    """Return each item of a paginated list, or None when the read fails.

    `--jq '.[]'` prints one compact JSON object for each line. The flag
    `--slurp` is not in each gh version.
    """
    code, text = gh(["api", "--paginate", path, "--jq", ".[]"], token)
    if code != 0:
        return None
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def read_org(read_token: str) -> tuple[list[dict], list[str], list[str]]:
    repos = gh_json_pages(f"orgs/{ORG}/repos?per_page=100&type=all", read_token)
    if not repos:
        raise SystemExit("issue-report: the run did not read the list of repos")
    issues: list[dict] = []
    read: list[str] = []
    not_read: list[str] = []
    for repo in sorted(r["name"] for r in repos if not r.get("archived")):
        rows = gh_json_pages(f"repos/{ORG}/{repo}/issues?state=open&per_page=100", read_token)
        if rows is None:
            not_read.append(repo)
            continue
        read.append(repo)
        for row in rows:
            if "pull_request" in row:
                continue
            if f"{ORG}/{repo}" == HOME_REPO and row["title"] == REPORT_TITLE:
                continue
            issues.append({
                "repo": repo, "number": row["number"], "title": row["title"],
                "created_at": row["created_at"], "updated_at": row["updated_at"],
                "labels": [label["name"] for label in row["labels"]],
            })
    return issues, read, not_read


def write_report(body: str, token: str) -> str:
    rows = gh_json_pages(f"repos/{HOME_REPO}/issues?state=open&creator=app/github-actions&per_page=100", token) or []
    existing = [r for r in rows if r["title"] == REPORT_TITLE and "pull_request" not in r]
    if existing:
        number = existing[0]["number"]
        code, text = gh(["api", "-X", "PATCH", f"repos/{HOME_REPO}/issues/{number}", "-f", f"body={body}",
                         "--jq", ".html_url"], token)
    else:
        code, text = gh(["api", "-X", "POST", f"repos/{HOME_REPO}/issues", "-f", f"title={REPORT_TITLE}",
                         "-f", f"body={body}", "--jq", ".html_url"], token)
    if code != 0:
        raise SystemExit(f"issue-report: the write of the report failed: {text.strip()}")
    return text.strip()


# --- self-test ---------------------------------------------------------------

def selftest() -> int:
    now = dt.datetime(2026, 10, 5, 12, 0, tzinfo=dt.timezone.utc)
    epic = "## Lanes\n\nTier 2:\n\n- [ ] zeroroot-ai/gibson#10 A\n- [x] zeroroot-ai/adk#3 B\n\nTier 4:\n\n" \
           "- [ ] zeroroot-ai/gibson#11 C\n\n## Other\n\n- [ ] zeroroot-ai/gibson#12 not in a tier\n"
    tiers = parse_epic_tiers(epic)

    def issue(repo, number, created, updated, labels=()):
        return {"repo": repo, "number": number, "title": f"title {number} | x", "created_at": created,
                "updated_at": updated, "labels": list(labels)}

    issues = [
        issue("gibson", 10, "2026-09-01T00:00:00Z", "2026-10-04T00:00:00Z"),
        issue("gibson", 11, "2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z"),
        issue("gibson", 12, "2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z"),
        issue("adk", 3, "2026-07-01T00:00:00Z", "2026-10-05T00:00:00Z"),
        issue("sdk", 7, "2026-10-02T00:00:00Z", "2026-10-02T00:00:00Z", ["tier-1"]),
    ]
    text = render(issues, tiers, now, ["adk", "gibson", "sdk"], ["hosted"])
    failures = []

    def expect(name, ok):
        if not ok:
            failures.append(name)

    expect("the epic gives a tier", tiers == {("gibson", 10): 2, ("adk", 3): 2, ("gibson", 11): 4})
    expect("a line after a new heading has no tier", ("gibson", 12) not in tiers)
    expect("the count is stated", "read 5 open issues in 3 repos" in text)
    expect("a repo that was not read is named", "did not read these repos: hosted" in text)
    expect("a label gives a tier", "## Tier 1\n\n**sdk**\n\n- `sdk#7`, 3 days" in text)
    expect("tier 2 holds two repos, sorted",
           text.index("## Tier 2") < text.index("`adk#3`, 96 days") < text.index("`gibson#10`, 34 days"))
    expect("an issue in no tier is listed", "## No tier" in text and "`gibson#12`, 4 days" in text)
    expect("the oldest age of a tier is stated", "| 2 | 2 | 96 |" in text)
    expect("a stale issue is listed", "`gibson#11`: 64 days with no activity" in text)
    expect("a fresh issue is not stale", "`gibson#10`:" not in text)
    expect("no reference is a link", "zeroroot-ai/gibson#" not in text and "zeroroot-ai/adk#" not in text)
    expect("a pipe in a title does not break a table", "title 10 / x" in text)
    # The fixtures below must FAIL.
    try:
        render([], tiers, now, [], [])
        expect("an empty read fails", False)
    except ValueError:
        pass
    many = [issue("gibson", n, "2026-09-01T00:00:00Z", "2026-10-04T00:00:00Z") for n in range(1, 2500)]
    try:
        render_within_limit(many, {}, now, ["gibson"], [])
        expect("a report above the limit with no titles fails", False)
    except ValueError:
        pass
    medium = [issue("gibson", n, "2026-09-01T00:00:00Z", "2026-10-04T00:00:00Z") for n in range(1, 900)]
    expect("a large report drops the titles and fits",
           len(render_within_limit(medium, {}, now, ["gibson"], [])) <= BODY_LIMIT)
    if failures:
        for f in failures:
            print(f"issue-report: selftest FAILED: {f}", file=sys.stderr)
        return 1
    print("issue-report: selftest OK (15 cases)")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--selftest"]:
        return selftest()
    dry = argv[1:] == ["--dry-run"]
    if argv[1:] and not dry:
        print(__doc__, file=sys.stderr)
        return 2
    write_token = os.environ.get("GH_TOKEN", "")
    read_token = os.environ.get("READ_TOKEN") or write_token
    if not read_token:
        print("issue-report: set READ_TOKEN or GH_TOKEN", file=sys.stderr)
        return 2
    code, epic_json = gh(["api", f"repos/{EPIC[0]}/issues/{EPIC[1]}", "--jq", ".body"], read_token)
    if code != 0:
        print(f"issue-report: the run did not read the epic: {epic_json.strip()}", file=sys.stderr)
        return 1
    issues, read, not_read = read_org(read_token)
    now = dt.datetime.now(dt.timezone.utc)
    try:
        body = render_within_limit(issues, parse_epic_tiers(epic_json), now, read, not_read)
    except ValueError as e:
        print(f"issue-report: {e}", file=sys.stderr)
        return 1
    if dry:
        print(body)
    else:
        print(f"issue-report: wrote {write_report(body, write_token)}")
    print(f"issue-report: read {len(issues)} open issues in {len(read)} repos; not read: {len(not_read)}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
