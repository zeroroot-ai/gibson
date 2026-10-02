#!/usr/bin/env bash
#
# check-config-field-readers.sh — a config key the loader fills must have a reader.
#
# ADR-0094 layer 1, gibson#501.
#
# internal/infra/config parses the daemon config file into structs. A struct
# field with a mapstructure or yaml tag is a key an operator can set and the
# chart can render. When no production code reads it, the value is produced,
# shipped, parsed and dropped: gibson#501 found 46 such keys, four of them
# rendered by the chart as controls that were on (security.ssl_validation,
# security.audit_logging, security.encryption_algorithm,
# authz.enforcement_source).
#
# WHAT COUNTS AS A READER
#
#   A Go read of the field, resolved by the type checker, outside
#   internal/infra/config itself. The loader and defaults WRITE fields; a
#   write is not a read, which is exactly why these 46 looked live.
#
# ${VAR} INTERPOLATION
#
#   loader.go expands ${VAR} and ${VAR:-default} inside raw YAML string values
#   (interpolateEnvVars) before applyInterpolation copies them into struct
#   fields. Interpolation rewrites a value on its way IN; it never reads a
#   struct field. So an interpolated key still needs a reader, and this guard
#   measures the struct field the key lands in, which is the only place a
#   reader can exist. gibson#501 asked that an interpolated key not be
#   reported; the measurement shows interpolation cannot make one live, so
#   nothing is skipped on that account.
#
# HOW THE READS ARE COUNTED
#
#   By ast-checks/cmd/unwired at the version go.mod pins, the same analyzer
#   the CRD field guard and the deadcode burndown use. One measurer, one
#   answer to "is this read".
#
# Usage:
#   check-config-field-readers.sh            run the gate
#   check-config-field-readers.sh --selftest prove the rules can fail
#
# Exit 0 = every tagged config field has a reader or a recorded verdict.
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

CONFIG_DIR="${CONFIG_DIR:-internal/infra/config}"
EXEMPT_FILE="${EXEMPT_FILE:-scripts/config-field-readers-exempt.txt}"
# The plausibility floor: the config package carries well over a hundred
# tagged fields. A run that resolves fewer measured nothing.
MIN_SERVED="${MIN_SERVED:-100}"

UNWIRED_VERSION="$(awk '$1=="github.com/zeroroot-ai/ast-checks"{print $2; exit}' go.mod)"
case "$UNWIRED_VERSION" in
  v*) ;;
  *) echo "::error::no ast-checks version in go.mod, so field reads have no pinned measurer" >&2; exit 1 ;;
esac

if [ "${1:-}" = "--selftest" ]; then
  exec bash scripts/__tests__/check-config-field-readers.test.sh
fi

if [ -n "${FIELD_READS:-}" ]; then
  reads_out="$FIELD_READS"
elif [ -n "${FIELD_READS_FILE:-}" ]; then
  reads_out="$(cat "$FIELD_READS_FILE")"
else
  reads_out="$(go run "github.com/zeroroot-ai/ast-checks/cmd/unwired@${UNWIRED_VERSION}" \
    -dir . -kinds field -all 2>/dev/null)"
fi

reads_file="$(mktemp)"
trap 'rm -f "$reads_file"' EXIT
printf '%s\n' "$reads_out" > "$reads_file"

python3 - "$CONFIG_DIR" "$EXEMPT_FILE" "$reads_file" "$MIN_SERVED" <<'PY'
import os, re, sys

config_dir, exempt_file, reads_file = sys.argv[1], sys.argv[2], sys.argv[3]
min_served = int(sys.argv[4])

# 1. The keyed schema: every struct field with a mapstructure or yaml tag.
FIELD = re.compile(r'^\t(?P<name>[A-Z]\w*)\s+(?P<type>[^\s].*?)(?:\s+`(?P<tags>[^`]*)`)?\s*$')
KEYTAG = re.compile(r'(?:mapstructure|yaml):"(?P<v>[^",]*)')
keyed = {}  # Type.Field -> key
for fname in sorted(os.listdir(config_dir)):
    if not fname.endswith('.go') or fname.endswith('_test.go'):
        continue
    cur = None
    for line in open(os.path.join(config_dir, fname)).read().split('\n'):
        m = re.match(r'^type (?P<n>\w+) struct \{', line)
        if m:
            cur = m.group('n')
            continue
        if line == '}' or line.startswith('type '):
            cur = None
            continue
        if cur is None:
            continue
        fm = FIELD.match(line)
        if not fm or not fm.group('tags'):
            continue
        kt = KEYTAG.search(fm.group('tags'))
        if kt and kt.group('v') not in ('', '-'):
            keyed['%s.%s' % (cur, fm.group('name'))] = kt.group('v')

# 2. Exemptions: <pkg>.<Type>.<Field> | <#issue or ADR> | <reason>
exempt = {}
if os.path.exists(exempt_file):
    for n, raw in enumerate(open(exempt_file), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        parts = [p.strip() for p in line.split('|')]
        if len(parts) != 3 or not all(parts):
            print('::error::%s:%d: expected "<pkg>.<Type>.<Field> | <reference> | <reason>"' % (exempt_file, n))
            sys.exit(1)
        key, ref, reason = parts
        if not re.search(r'(#\d+|ADR-\d+|https?://)', ref):
            print('::error::%s:%d: %s has no issue or ADR reference' % (exempt_file, n, key))
            sys.exit(1)
        exempt[key] = (ref, reason)

# 3. Judge.
served, unread = set(), []
for line in open(reads_file):
    p = line.rstrip('\n').split('\t')
    if len(p) < 4 or p[0] != 'field':
        continue
    key, loc, counts = p[1], p[2], ' '.join(p[3:])
    path = loc.split(':')[0]
    if os.path.normpath(os.path.dirname(path)) != os.path.normpath(config_dir) or path.endswith('_test.go'):
        continue
    short = key.split('.', 1)[1] if '.' in key else key
    if short not in keyed:
        continue  # an untagged field is not a config key
    served.add(key)
    reads = int(re.search(r'reads=(\d+)', counts).group(1))
    if reads == 0:
        unread.append((key, loc, counts, keyed[short]))

unread_keys = {u[0] for u in unread}
rc = 0
stale = [k for k in exempt if k not in served]
satisfied = [k for k in exempt if k in served and k not in unread_keys]
if stale:
    rc = 1
    print('::error::%s names %d field(s) that no longer exist: %s' % (exempt_file, len(stale), ', '.join(sorted(stale))))
if satisfied:
    rc = 1
    print('::error::%s records a verdict for %d field(s) that now HAVE a reader: %s' % (exempt_file, len(satisfied), ', '.join(sorted(satisfied))))

blocking = [u for u in unread if u[0] not in exempt]
if blocking:
    rc = 1
    print('')
    print('BLOCKED: %d config key(s) parsed and read by nothing.' % len(blocking))
    print('')
    for key, loc, counts, yamlkey in sorted(blocking):
        print('  %-48s key %-28s %s  %s' % (key, yamlkey, counts, loc))
    print('')
    print('Each is a key an operator can set that the daemon drops after parsing.')
    print('ADR-0094 rule 5: build the reader, or delete the field, its default, its')
    print('loader copy and the chart line that renders it. To record a verdict, add')
    print('"<pkg>.<Type>.<Field> | <#issue or ADR> | <why>" to %s.' % exempt_file)
    print('')

if rc == 0:
    print('ok  %d keyed config field(s) checked, %d verdict(s) recorded' % (len(served), len(exempt)))
    if len(served) < min_served:
        print('::error::only %d keyed field(s) were found, below the floor of %d; the analyzer output is not reaching %s' % (len(served), min_served, config_dir))
        rc = 1
sys.exit(rc)
PY
