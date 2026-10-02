#!/usr/bin/env bash
# Fixture for check-config-field-readers.sh: every rule has a RED case that
# asserts the message, so a rule failing for another reason is a failure here.
# Offline: FIELD_READS supplies a crafted analyzer output, CONFIG_DIR a crafted
# package.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
GATE=scripts/check-config-field-readers.sh
PASS=0 FAIL=0
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/cfg"
cat > "$tmp/cfg/config.go" <<'GO'
package config

type Config struct {
	Core CoreConfig `mapstructure:"core" yaml:"core"`
}

type CoreConfig struct {
	HomeDir  string `mapstructure:"home_dir" yaml:"home_dir"`
	Debug    bool   `mapstructure:"debug" yaml:"debug"`
	Untagged string
}
GO
reads() { printf 'field\tconfig.%s\t%s/cfg/config.go:9\t%s\n' "$1" "$tmp" "$2"; }
run() { CONFIG_DIR="$tmp/cfg" EXEMPT_FILE="$tmp/exempt.txt" MIN_SERVED=1 FIELD_READS="$2" bash "$GATE" 2>&1; }
check() { # name expect-rc substring exempt-contents analyzer-lines
  printf '%s' "$4" > "$tmp/exempt.txt"
  out="$(run "$4" "$5")"; rc=$?
  if [ "$rc" -eq "$2" ] && [[ "$out" == *"$3"* ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL: $1 (rc=$rc)"; echo "$out" | sed 's/^/    /'; fi
}
check "a read key passes" 0 "ok  1 keyed" "" "$(reads CoreConfig.HomeDir 'reads=3 writes=2')"
check "an unread key is BLOCKED and named with its yaml key" 1 "BLOCKED: 1 config key(s)" "" "$(reads CoreConfig.Debug 'reads=0 writes=2')"
check "a write is not a read" 1 "key debug" "" "$(reads CoreConfig.Debug 'reads=0 writes=9')"
check "an untagged field is not a key" 0 "ok  1 keyed" "" "$(reads CoreConfig.HomeDir 'reads=1'; reads CoreConfig.Untagged 'reads=0')"
check "a verdict with a reference clears a key" 0 "1 verdict(s) recorded" "config.CoreConfig.Debug | #501 | kept while the reader lands" "$(reads CoreConfig.Debug 'reads=0')"
check "a verdict without a reference is refused" 1 "has no issue or ADR reference" "config.CoreConfig.Debug | because | kept" "$(reads CoreConfig.Debug 'reads=0')"
check "a verdict for a key that now has a reader fails" 1 "now HAVE a reader" "config.CoreConfig.Debug | #501 | kept" "$(reads CoreConfig.Debug 'reads=2')"
check "a verdict for a key that no longer exists fails" 1 "no longer exist" "config.CoreConfig.Gone | #501 | kept" "$(reads CoreConfig.HomeDir 'reads=1')"
out="$(CONFIG_DIR="$tmp/cfg" EXEMPT_FILE=/dev/null MIN_SERVED=5 FIELD_READS="$(reads CoreConfig.HomeDir 'reads=1')" bash "$GATE" 2>&1)"; rc=$?
if [ "$rc" -eq 1 ] && [[ "$out" == *"below the floor"* ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL: the floor fails a run that measured too little (rc=$rc)"; fi
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
