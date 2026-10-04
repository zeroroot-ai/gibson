#!/usr/bin/env bash
#
# check-proto-field-consumers.sh — a served proto field must have a consumer.
#
# ADR-0094 layer 5 (#502). The daemon-owned protos under
# internal/server/daemon/api are served to seven first-party consumers:
# gibson itself, sdk, adk, gibson-executor, setec, dashboard and sdk-ts. A
# field that none of them reads is a promise on the wire that nothing keeps.
# gibson#502 measured 60 of them: a caller could not tell whether an ack, a
# tuple write or a revoke did anything, because the field that said so was
# never read.
#
# WHAT COUNTS AS A CONSUMER
#
#   A read of the field in hand-written source of any consumer:
#     Go          `.GetFoo()` or `.Foo` on the generated struct, resolved by
#                 the type checker (tools/protofieldreads), so two messages
#                 that both declare `acked` are told apart
#     TypeScript  the lowerCamel name (`foo`, `fooBar`) as an identifier
#     Python      the snake_case name as an identifier
#
# A WRITE IS NOT A READ. The daemon fills every response field it declares;
# counting `Foo: x` in a composite literal or `.Foo = x` would report every
# field as live. Only a read counts.
#
# GENERATED CODE IS NEVER A CONSUMER. `*.pb.go`, `*_pb.ts`, `*_pb2.py` and the
# gen/ trees touch every field. Tests are not consumers either: a test that
# reads a field proves the field can be read, not that anything does.
#
# THE TS AND PYTHON MATCH IS BY NAME, NOT BY TYPE. A read of `acked` on any
# message keeps every `acked` alive. That errs toward "live", never toward a
# false deletion. Go reads outside gibson are matched by <Type>.<Field>:
# those modules cannot import gibson's internal packages, so a generated copy
# of the same message is the only way they could read it.
#
# WHY NIGHTLY, NOT THE MERGE GATE
#
# The consumer set spans seven repositories. A PR gate would need every
# checkout at every merge. ADR-0094 puts this layer on main and on a
# schedule (.github/workflows/proto-field-consumers.yml). The fixture that
# proves the decision half can fail runs on every PR
# (scripts/__tests__/check-proto-field-consumers.test.sh).
#
# Usage:
#   CONSUMER_ROOTS=". ../sdk ../adk ..." check-proto-field-consumers.sh
#
# GO_READS_FILE replaces the type-resolved Go scan with a file of
# <import path>.<Type>.<Field> lines; the fixture uses it so the decision
# half is tested without loading a module.
#
# Exit 0 = every served field has a consumer or a recorded verdict.
# Exit 1 = at least one does not, a verdict is stale, or a root is missing.
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

PROTO_DIR="${PROTO_DIR:-internal/server/daemon/api}"
EXEMPT_FILE="${EXEMPT_FILE:-scripts/proto-field-consumers-exempt.txt}"
# Space-separated checkouts. The gate FAILS when one is missing: a run that
# never looked at a consumer would report that consumer's fields as dead.
CONSUMER_ROOTS="${CONSUMER_ROOTS:?set CONSUMER_ROOTS to the seven consumer checkouts (gibson sdk adk gibson-executor setec dashboard sdk-ts)}"
# MIN_FIELDS is the plausibility floor: the daemon protos declare over a
# thousand fields, so a run that parsed fewer measured nothing.
MIN_FIELDS="${MIN_FIELDS:-1000}"
GO_PREFIX="${GO_PREFIX:-github.com/zeroroot-ai/gibson/internal/server/daemon/api/}"
GO_READS_FILE="${GO_READS_FILE:-}"

for root in $CONSUMER_ROOTS; do
  if [ ! -d "$root" ]; then
    echo "check-proto-field-consumers: consumer root $root does not exist" >&2
    exit 1
  fi
done

# The Go half: one type-resolved pass per Go consumer root. The gibson root
# is the module that declares the types, so its reads are keyed by the full
# import path; any other module can only hold a generated copy, so its reads
# are keyed by <Type>.<Field>.
GO_READS="$(mktemp)"
trap 'rm -f "$GO_READS"' EXIT
if [ -n "$GO_READS_FILE" ]; then
  cp "$GO_READS_FILE" "$GO_READS"
else
  for root in $CONSUMER_ROOTS; do
    [ -f "$root/go.mod" ] || continue
    if [ "$(cd "$root" && pwd)" = "$(pwd)" ]; then
      go run ./tools/protofieldreads -dir "$root" -prefix "$GO_PREFIX" >>"$GO_READS"
    else
      go run ./tools/protofieldreads -dir "$root" -prefix "" \
        | sed -E 's#^.*/([^/.]+\.[^.]+\.[^.]+)$#\1#' >>"$GO_READS"
    fi
  done
fi

PROTO_DIR="$PROTO_DIR" EXEMPT_FILE="$EXEMPT_FILE" CONSUMER_ROOTS="$CONSUMER_ROOTS" \
MIN_FIELDS="$MIN_FIELDS" GO_READS="$GO_READS" GO_PREFIX="$GO_PREFIX" python3 - <<'PY'
import os, re, sys

proto_dir = os.environ["PROTO_DIR"]
exempt_file = os.environ["EXEMPT_FILE"]
roots = os.environ["CONSUMER_ROOTS"].split()
min_fields = int(os.environ["MIN_FIELDS"])

def go_name(f):
    # protoc-gen-go's GoCamelCase: an underscore is dropped and the letter
    # after it is capitalized, and so is a letter after a digit
    # (store_neo4j -> StoreNeo4J).
    out, cap = [], True
    for c in f:
        if c == "_":
            cap = True
            continue
        if c.isdigit():
            out.append(c)
            cap = True
            continue
        out.append(c.upper() if cap else c)
        cap = False
    return "".join(out)

def ts_name(f):
    # protobuf-es keeps a letter after a digit lowercase (store_neo4j ->
    # storeNeo4j), unlike protoc-gen-go. Measured in the dashboard's gen tree.
    parts = [p for p in f.split("_") if p]
    return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:]) if parts else f

# --- 1. The declared set: every field of every message, nested included. ---
field_re = re.compile(
    r'^\s*(?:repeated\s+|optional\s+)?(?:map\s*<[^>]+>|[A-Za-z_][\w.]*)\s+'
    r'([a-z_][a-z0-9_]*)\s*=\s*(\d+)')
declared = {}  # key -> (file, line, go_key)
go_prefix = os.environ["GO_PREFIX"]
for dirpath, _, files in os.walk(proto_dir):
    for fn in sorted(files):
        if not fn.endswith(".proto"):
            continue
        path = os.path.join(dirpath, fn)
        pkg = ""
        go_pkg = ""
        stack = []  # (kind, name)
        in_block_comment = False
        with open(path, encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw
                if in_block_comment:
                    if "*/" in line:
                        line = line.split("*/", 1)[1]
                        in_block_comment = False
                    else:
                        continue
                if "/*" in line:
                    line = line.split("/*", 1)[0]
                    in_block_comment = True
                line = line.split("//", 1)[0]
                m = re.match(r'^\s*package\s+([\w.]+)\s*;', line)
                if m:
                    pkg = m.group(1)
                    continue
                m = re.match(r'^\s*option\s+go_package\s*=\s*"([^";]+)', line)
                if m:
                    go_pkg = m.group(1)
                    continue
                m = re.match(r'^\s*(message|enum|oneof|service|extend)\s+([\w.]+)\s*\{', line)
                if m:
                    stack.append((m.group(1), m.group(2)))
                    # `message Empty {}` opens and closes on one line.
                    for _ in range(line.count("}")):
                        if stack:
                            stack.pop()
                    continue
                if re.match(r'^\s*\}', line):
                    if stack:
                        stack.pop()
                    continue
                if not stack:
                    continue
                kinds = [k for k, _ in stack]
                if "enum" in kinds or "service" in kinds or "extend" in kinds:
                    continue
                if re.match(r'^\s*(reserved|option|extensions)\b', line):
                    continue
                m = field_re.match(line)
                if not m:
                    continue
                msgs = [n for k, n in stack if k == "message"]
                key = f"{pkg}.{'.'.join(msgs)}.{m.group(1)}"
                go_key = f"{go_pkg}.{'_'.join(msgs)}.{go_name(m.group(1))}"
                declared[key] = (path, lineno, go_key)

if len(declared) < min_fields:
    print(f"check-proto-field-consumers: parsed {len(declared)} fields under "
          f"{proto_dir}, below the floor of {min_fields}; the run measured nothing",
          file=sys.stderr)
    sys.exit(1)

# --- 2. The consumer set: identifiers read in hand-written source. ---
TS_SKIP = ("_pb.ts", "_pb.js", "_connect.ts", "_connect.js", ".d.ts",
           ".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx", ".stories.tsx")
PY_SKIP = ("_pb2.py", "_pb2_grpc.py", "_test.py")
SKIP_DIRS = {"node_modules", "vendor", "gen", "generated", "dist", "build",
             ".next", "testdata", "__tests__", "__pycache__", ".git",
             ".worktrees", "cue.mod"}
generated_marker = re.compile(r"Code generated .* DO NOT EDIT|@generated|AUTO-GENERATED", re.I)

ts_reads, py_reads = set(), set()
go_reads = set()
with open(os.environ["GO_READS"], encoding="utf-8") as fh:
    go_reads.update(l.strip() for l in fh if l.strip())
ts_pat = re.compile(r'\b([a-z]\w*)\b')
py_pat = re.compile(r'\b([a-z_]\w*)\b')

def strip_comments(text, line_marker):
    if line_marker == "//":
        text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
        return re.sub(r'(?m)//[^\n]*', '', text)
    return re.sub(r'(?m)#[^\n]*', '', text)

def scan(root):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in files:
            path = os.path.join(dirpath, fn)
            if fn.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs")):
                if fn.endswith(TS_SKIP) or fn.startswith("test_"):
                    continue
                pat, bucket = ts_pat, ts_reads
            elif fn.endswith(".py"):
                if fn.endswith(PY_SKIP) or fn.startswith("test_"):
                    continue
                pat, bucket = py_pat, py_reads
            else:
                continue
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    head = fh.read(2048)
                    if generated_marker.search(head):
                        continue
                    text = head + fh.read()
            except OSError:
                continue
            # A comment naming a consumer is not evidence (ADR-0094 rule 6).
            text = strip_comments(text, "#" if pat is py_pat else "//")
            bucket.update(pat.findall(text))

for root in roots:
    scan(root)

# --- 3. The verdicts. ---
exempt = {}
if os.path.exists(exempt_file):
    with open(exempt_file, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) != 3 or not parts[1] or not parts[2]:
                print(f"check-proto-field-consumers: malformed verdict: {line}", file=sys.stderr)
                sys.exit(1)
            if not re.search(r'#\d+|ADR-\d+', parts[1]):
                print(f"check-proto-field-consumers: verdict for {parts[0]} names no issue or ADR", file=sys.stderr)
                sys.exit(1)
            exempt[parts[0]] = parts[1]

def is_read(field, go_key):
    f = field.rsplit(".", 1)[1]
    if go_key in go_reads:
        return True
    # A read in another Go module, keyed <Type>.<Field>.
    short = ".".join(go_key.rsplit(".", 2)[1:])
    return short in go_reads or ts_name(f) in ts_reads or f in py_reads

dead, stale = [], []
for key, (path, lineno, go_key) in sorted(declared.items()):
    read = is_read(key, go_key)
    if key in exempt:
        if read:
            stale.append(f"{key} now has a consumer; drop its verdict ({exempt[key]})")
        continue
    if not read:
        dead.append(f"dead\t{key}\t{path}:{lineno}")
for key in sorted(exempt):
    if key not in declared:
        stale.append(f"{key} is not a declared field; drop its verdict ({exempt[key]})")

for line in dead:
    print(line)
for line in stale:
    print(f"stale\t{line}")
served = len(declared)
print(f"check-proto-field-consumers: {served} fields served, {len(dead)} without a consumer, "
      f"{len(exempt)} verdicts, {len(stale)} stale, {len(roots)} consumer roots")
sys.exit(1 if dead or stale else 0)
PY
