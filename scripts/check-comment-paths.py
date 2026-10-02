#!/usr/bin/env python3
"""Check that every repo-relative path named in a comment exists.

A comment naming a file reads as coverage. "A CI guard
(scripts/check-operator-rbac-scope.sh) fails the build if any of those resources
reappear in this ClusterRole" tells the next reader that an invariant is
enforced, and they stop looking. The script does not exist, so the sentence is
the only thing holding the invariant up. gibson#557 has two of those, and a peer
session found 92 of the same shape in `charts`.

The milder version is a comment pointing at code that moved: a reader following
it finds nothing and has to guess whether the behaviour moved or went away.

Scope is comment lines only. A path in a string literal is usually test data or a
name a program builds at runtime, and that is the program's business.

THREE RULES THAT KEEP IT OFF CORRECT COMMENTS

1. It scans the files git TRACKS. CI checks sibling repositories out inside the
   tree -- `org-dot-github/` is a checkout of zeroroot-ai/.github, whose own
   comments correctly name its own paths. An untracked checkout disappears for
   the right reason, rather than by a directory-name pattern that the next
   checkout location would defeat. (charts#322 failed its first CI run on
   exactly this.)

2. A candidate resolves against the repo root OR any enclosing PROJECT ROOT -- a
   directory carrying its own go.mod, Makefile or kubebuilder PROJECT file. A
   comment in operators/tenant/ naming "cmd/main.go" means that subtree's cmd/
   and is correct. Note gibson has ONE go.mod, so "nearest enclosing module" is
   not the rule that works here: operators/tenant/ is a subtree with its own
   Makefile and PROJECT, not a separate module, and 66 correct comments resolve
   only against it.

3. A comment BLOCK that names another repository, or an upstream dependency, is
   that tree's business. "sdk docs/adr/0001-...md", "charts
   helm/gibson/values.yaml" and "Zitadel v4.18.0's cmd/defaults.yaml" are correct
   comments about trees that are not here. The whole contiguous block is checked,
   not one line, because a block names its subject once and then refers to paths
   inside it.

4. A candidate also resolves against the commenting FILE'S OWN DIRECTORY, because
   a comment naming a sibling or an embedded path inside its own package is
   normal and correct -- `migrationID("migrations/0003_....cypher")` names the
   embed path relative to that package.

5. A comment BLOCK that marks the path as HISTORY is not a claim to go and look.
   "the deleted internal/server/daemon/recover_missions.go" and "the methods that
   previously hung off the hand-written mirror at ..." are accurate records of
   something that is gone. Only a LIVE claim -- "set by X", "see the note in X",
   "the CI job in X" -- is a finding, because only a live claim sends a reader
   somewhere that is not there. Block-scoped for the same reason as rule 3: the
   word that makes it history is often on the line above the path.

AND ONE THAT KEEPS IT FROM PASSING BY NOT LOOKING

A scan that reads fewer than MIN_FILES files raises instead of reporting
success. A detached worktree, a shallow checkout or the wrong cwd otherwise
produces a green check that read nothing.

Exit codes:
  0  Every path named in a comment exists.
  1  At least one does not, or the scan was too small to trust.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

# The floor below which the scan is not believable. gibson tracks thousands of Go
# files; 200 is far under the real count and far over anything a broken checkout
# produces.
MIN_FILES = int(os.environ.get("MIN_FILES", "200"))

# Extensions worth checking. Anchoring on these keeps the pattern off an import
# path, a URL, or a Go selector that happens to look extension-shaped.
EXTS = (
    "go|sh|py|md|yaml|yml|cue|json|sql|proto|ts|tsx|bats|cypher|tf"
)

# A comment line, per language. Go block comments continue with `*`.
GO_COMMENT = re.compile(r"^\s*(//|\*)")
HASH_COMMENT = re.compile(r"^\s*#")

# Built in main() from the repo's own top-level directories; the self-test swaps
# in a fixed one so it does not depend on the tree it runs in.
PATH_RE: re.Pattern[str] = re.compile(r"(?!)")

# A line carrying one of these is recording history, not pointing at something to
# read. The distinction is the whole point: a dead reference marked dead is
# documentation, and an unmarked dead reference sends the next reader nowhere.
HISTORY_MARKERS = (
    "deleted",
    "removed",
    "retired",
    "previously",
    "used to",
    "formerly",
    "former ",
    "replaces",
    "replaced",
    "migrated from",
    "moved from",
    "legacy",
    "no longer",
    "superseded",
)
# "pre-" is deliberately absent: it matches pre-commit, pre-flight and prefix.

# Upstream dependencies. A block naming one is describing that project's tree.
#
# ONLY markers that unambiguously name another tree. A technology name does not
# qualify: "kubebuilder", "envoy", "openfga" and "zitadel" appear constantly in
# comments about OUR code, and putting them here made the guard pass by not
# looking -- it suppressed the `scripts/check-operator-rbac-scope.sh` finding in
# tenant_controller.go, which is the single most important one in the repo,
# because that block also says "Kubebuilder markers cannot represent dynamic
# per-tenant scope". A comment about an upstream path says "upstream" or gives
# the module path; if it does not, it should.
UPSTREAM_MARKERS = (
    "upstream",
    "github.com/",
    "gitlab.com/",
    "k8s.io/",
)

# Other repositories in the org. A block naming one is about that tree.
OTHER_REPOS = (
    "zeroroot-ai/",
    "sdk ",
    "charts ",
    "hosted ",
    "setec ",
    "adk ",
    "dashboard ",
    "gibson-executor ",
    "zitadel-login ",
    "docs-site ",
)


def comment_blocks(lines: list[str], comment_re: re.Pattern[str]) -> dict[int, str]:
    """Map each comment line number to the text of its whole contiguous block.

    A block names its subject once -- "Zitadel v4.18.0's" or "the deleted" -- and
    then refers to paths inside it over the following lines. Checking one line in
    isolation reads the reference without its subject, which is how a correct
    comment about an upstream tree looks like a broken one.
    """
    out: dict[int, str] = {}
    start = None
    for i, line in enumerate(lines):
        if comment_re.match(line):
            if start is None:
                start = i
        else:
            if start is not None:
                text = "".join(lines[start:i])
                for n in range(start + 1, i + 1):
                    out[n] = text
                start = None
    if start is not None:
        text = "".join(lines[start:])
        for n in range(start + 1, len(lines) + 1):
            out[n] = text
    return out


def git(*args: str) -> list[str]:
    out = subprocess.run(
        ["git", *args], capture_output=True, text=True, check=True
    ).stdout
    return [line for line in out.splitlines() if line]


def log_info(msg: str) -> None:
    print(f"[check-comment-paths] INFO:  {msg}")


def log_error(msg: str) -> None:
    print(f"[check-comment-paths] ERROR: {msg}", file=sys.stderr)


def findings_for(
    path: str,
    lines: list[str],
    comment_re: re.Pattern[str],
    anchors: list[str],
    exists: "callable[[str], bool]",
) -> list[str]:
    """Every finding in one file. Split out so --selftest can drive it directly."""
    out: list[str] = []
    blocks = comment_blocks(lines, comment_re)
    for lineno, text in enumerate(lines, start=1):
        if not comment_re.match(text):
            continue
        if "..." in text:
            continue
        block = blocks[lineno].lower()
        if any(marker.lower() in block for marker in OTHER_REPOS):
            continue
        if any(marker in block for marker in UPSTREAM_MARKERS):
            continue
        if any(marker in block for marker in HISTORY_MARKERS):
            continue
        for candidate in PATH_RE.findall(text):
            if exists(candidate):
                continue
            if any(exists(f"{anchor}/{candidate}") for anchor in anchors):
                continue
            where = ", ".join(["the repo root", *(f"{a}/" for a in anchors)])
            out.append(
                f"{path}:{lineno} names {candidate}, which exists under none of: {where}"
            )
    return out


def selftest() -> int:
    """One fixture per rule, each asserting the REASON surfaces.

    A guard that cannot fail is worse than no guard, and a guard whose failure
    does not say why sends the next reader to read its source. Both happened to
    this script while it was being written: an over-broad upstream marker
    ("kubebuilder") silently suppressed the single most important finding in the
    repo, because the block that named the missing script also mentioned
    Kubebuilder markers.
    """
    global PATH_RE
    saved = PATH_RE
    PATH_RE = re.compile(
        r"(?:^|[^A-Za-z0-9_./-])((?:internal|scripts|cmd)/[A-Za-z0-9_./-]+\.(?:%s))\b"
        % EXTS
    )
    try:
        real = {"internal/real/here.go", "pkg/sibling/scripts/near.go"}

        def exists(p: str) -> bool:
            return p in real

        cases = [
            (
                "a live claim naming a file that is gone fails, naming the path",
                ["// See internal/gone/missing.go for the format.\n"],
                True,
                "internal/gone/missing.go",
            ),
            (
                "a path that exists passes",
                ["// See internal/real/here.go for the format.\n"],
                False,
                "",
            ),
            (
                "a reference marked as history passes",
                [
                    "// This replaces the previous model in\n",
                    "// internal/gone/missing.go, which iterated every CR.\n",
                ],
                False,
                "",
            ),
            (
                "a reference marked upstream passes",
                ["// Upstream Zitadel v4.18.0's cmd/defaults.yaml mapping.\n"],
                False,
                "",
            ),
            (
                "a sibling path resolves against the file's own directory",
                ["// Mirrors scripts/near.go in this package.\n"],
                False,
                "",
            ),
            (
                "an elided path is left alone",
                ["// See internal/.../missing.go for the shape.\n"],
                False,
                "",
            ),
            (
                "a technology name does NOT suppress a finding",
                [
                    "// Kubebuilder markers cannot express per-tenant scope, so\n",
                    "// scripts/check-gone.sh fails the build instead.\n",
                ],
                True,
                "scripts/check-gone.sh",
            ),
        ]

        failures = 0
        for name, lines, want_finding, want_in_message in cases:
            got = findings_for(
                "pkg/sibling/file.go", lines, GO_COMMENT, ["pkg/sibling"], exists
            )
            if want_finding and not got:
                log_error("Self-test FAILED: %s -- no finding reported." % name)
                failures += 1
                continue
            if not want_finding and got:
                log_error("Self-test FAILED: %s -- reported %s" % (name, got))
                failures += 1
                continue
            if want_finding and want_in_message not in got[0]:
                log_error(
                    "Self-test FAILED: %s -- the refusal does not name %s: %s"
                    % (name, want_in_message, got[0])
                )
                failures += 1
                continue
            log_info("Self-test: %s" % name)

        if MIN_FILES <= 1:
            log_error("Self-test FAILED: MIN_FILES is too low to be a floor.")
            failures += 1
        else:
            log_info("Self-test: the floor is %d file(s)" % MIN_FILES)

        if failures:
            log_error("Self-test: %d failure(s)." % failures)
            return 1
        log_info("Self-test: %d passed." % (len(cases) + 1))
        return 0
    finally:
        PATH_RE = saved


def main() -> int:
    repo_root = git("rev-parse", "--show-toplevel")[0]
    os.chdir(repo_root)

    tracked = git("ls-files")
    tracked_set = set(tracked)

    # Top-level directories derived from what is here, not listed. A hardcoded
    # list fires on `helm/` and `charts/`, which are another repository's.
    top_dirs = sorted({p.split("/", 1)[0] for p in tracked if "/" in p})
    if not top_dirs:
        log_error("git ls-files returned no nested paths; refusing to pass.")
        return 1

    global PATH_RE
    PATH_RE = re.compile(
        r"(?:^|[^A-Za-z0-9_./-])((?:%s)/[A-Za-z0-9_./-]+\.(?:%s))\b"
        % ("|".join(re.escape(d) for d in top_dirs), EXTS)
    )

    # Project roots: directories carrying their own go.mod, Makefile or
    # kubebuilder PROJECT. Derived from the tree rather than listed, so a new
    # operator is covered the day it lands.
    root_markers = {"go.mod", "Makefile", "PROJECT"}
    project_roots = {
        os.path.dirname(p)
        for p in tracked
        if os.path.basename(p) in root_markers and os.path.dirname(p)
    }

    def anchors_for(path: str) -> list[str]:
        """Every project root enclosing path, deepest first."""
        out = []
        parent = os.path.dirname(path)
        while parent:
            if parent in project_roots:
                out.append(parent)
            parent = os.path.dirname(parent)
        return out

    go_files = [
        p
        for p in tracked
        if p.endswith(".go")
        and not p.endswith(".pb.go")
        and not p.endswith("_grpc.pb.go")
    ]
    sh_files = [
        p
        for p in tracked
        if p.endswith((".sh", ".mk")) or os.path.basename(p) == "Makefile"
    ]

    findings: list[str] = []
    scanned = 0

    for files, comment_re in ((go_files, GO_COMMENT), (sh_files, HASH_COMMENT)):
        for path in files:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
            except OSError as err:
                # An unreadable tracked file is not a licence to skip it.
                log_error(f"{path}: cannot read ({err})")
                findings.append(path)
                continue
            scanned += 1
            # The file's own directory first: a sibling or embedded path inside
            # the package is the most local reading and the most often correct.
            anchors = [os.path.dirname(path)] + anchors_for(path)
            anchors = [a for a in anchors if a]
            blocks = comment_blocks(lines, comment_re)
            for lineno, text in enumerate(lines, start=1):
                if not comment_re.match(text):
                    continue
                if "..." in text:
                    # The author elided part of the path on purpose.
                    continue
                block = blocks[lineno].lower()
                if any(marker.lower() in block for marker in OTHER_REPOS):
                    continue
                if any(marker in block for marker in UPSTREAM_MARKERS):
                    continue
                if any(marker in block for marker in HISTORY_MARKERS):
                    continue
                for candidate in PATH_RE.findall(text):
                    if candidate in tracked_set or os.path.exists(candidate):
                        continue
                    if any(
                        f"{anchor}/{candidate}" in tracked_set
                        or os.path.exists(f"{anchor}/{candidate}")
                        for anchor in anchors
                    ):
                        continue
                    where = ", ".join(["the repo root", *(f"{a}/" for a in anchors)])
                    findings.append(
                        f"{path}:{lineno} names {candidate}, which exists under "
                        f"none of: {where}"
                    )

    if scanned < MIN_FILES:
        log_error(f"scanned only {scanned} file(s), below the floor of {MIN_FILES}.")
        log_error(
            "A detached worktree, a shallow checkout or the wrong cwd reads almost "
            "nothing and would otherwise report success. Refusing to pass."
        )
        return 1

    if findings:
        for finding in findings:
            log_error(finding)
        log_error(f"{len(findings)} comment path(s) name a file that does not exist.")
        log_error(
            "Write the file, delete the claim, or name the repository it lives in. "
            "A sentence is not a guard."
        )
        return 1

    log_info(f"OK -- {scanned} file(s) scanned, every path named in a comment exists.")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv[1:]:
        sys.exit(selftest())
    sys.exit(main())
