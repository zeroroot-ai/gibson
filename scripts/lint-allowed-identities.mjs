#!/usr/bin/env node
/**
 * lint-allowed-identities.mjs — Gibson daemon-local proto named-bitfield lint
 *
 * Spec: cross-repo-cohesion-fixes Requirement 6.1, D3.
 *
 * Enforces that every `allowed_identities: <int>` line in the Gibson
 * daemon-local proto tree carries an inline `//` comment (trailing or on
 * the preceding non-blank line) naming the IdentityClass bits.
 *
 * Self-test (D5):
 *   At startup the script reads the IdentityClass enum from the SDK's
 *   options.proto (resolved via `go list -m`) and verifies its internal
 *   bit-table covers every defined value. If the enum has new values not
 *   in the table, the script exits 1 with a FATAL message.
 *
 * NOTE: This script is intentionally duplicated from core/sdk/scripts/ with
 * a different proto root (D3 — do not abstract into a shared package).
 *
 * Usage:
 *   node core/gibson/scripts/lint-allowed-identities.mjs
 *   node scripts/lint-allowed-identities.mjs   (from core/gibson/ directory)
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const PROTO_ROOT = join(REPO_ROOT, 'internal/daemon/api');

// Resolve the SDK's options.proto via go list so we don't hard-code a path.
function resolveOptionsProto() {
  try {
    const sdkDir = execSync(
      'go list -m -f {{.Dir}} github.com/zero-day-ai/sdk',
      { cwd: REPO_ROOT, encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] },
    ).trim();
    return join(sdkDir, 'api/proto/gibson/auth/v1/options.proto');
  } catch {
    // Fall back to the workspace-relative path for CI where go list works.
    return join(REPO_ROOT, '../../core/sdk/api/proto/gibson/auth/v1/options.proto');
  }
}

const OPTIONS_PROTO = resolveOptionsProto();

// ---------------------------------------------------------------------------
// Internal bit-table (source of truth for comment rendering).
// Keys are the integer values; values are the human-readable names.
// This table MUST match the IdentityClass enum in options.proto.
// The self-test below verifies they are in sync.
//
// Bit-table: USER=1, SERVICE=2, COMPONENT=4, PLATFORM_OPERATOR=8.
// Spec: cross-repo-cohesion-fixes Requirement 6.4, D5.
// ---------------------------------------------------------------------------
const BIT_TABLE = new Map([
  [1,  'USER'],
  [2,  'SERVICE'],
  [4,  'COMPONENT'],
  [8,  'PLATFORM_OPERATOR'],
]);

// ---------------------------------------------------------------------------
// D5 Self-test: parse IdentityClass from options.proto and verify BIT_TABLE
// ---------------------------------------------------------------------------

function selfTest() {
  let optionsText;
  try {
    optionsText = readFileSync(OPTIONS_PROTO, 'utf8');
  } catch (e) {
    console.error(`[lint-allowed-identities] FATAL: cannot read ${OPTIONS_PROTO}: ${e.message}`);
    process.exit(1);
  }

  // Extract the IdentityClass enum block.
  const enumMatch = /enum\s+IdentityClass\s*\{([\s\S]*?)\}/.exec(optionsText);
  if (!enumMatch) {
    console.error('[lint-allowed-identities] FATAL: IdentityClass enum not found in options.proto');
    process.exit(1);
  }
  const enumBlock = enumMatch[1];

  // Parse enum values: lines like "IDENTITY_CLASS_USER = 1;"
  const valueRe = /IDENTITY_CLASS_(\w+)\s*=\s*(\d+)\s*;/g;
  let m;
  const enumValues = new Map(); // value -> name (without prefix)
  while ((m = valueRe.exec(enumBlock)) !== null) {
    const name = m[1];
    const val = parseInt(m[2], 10);
    if (name === 'UNSPECIFIED') continue; // 0 is intentionally absent from BIT_TABLE
    enumValues.set(val, name);
  }

  // Check every enum value is in our BIT_TABLE.
  let ok = true;
  for (const [val, name] of enumValues) {
    if (!BIT_TABLE.has(val)) {
      console.error(
        `[lint-allowed-identities] FATAL: IdentityClass has new values; update the lint table. ` +
        `Missing: IDENTITY_CLASS_${name} = ${val}. ` +
        `Add { ${val}: '${name}' } to BIT_TABLE in core/gibson/scripts/lint-allowed-identities.mjs.`
      );
      ok = false;
    }
  }
  // Check every BIT_TABLE entry corresponds to a real enum value.
  for (const [val, name] of BIT_TABLE) {
    if (!enumValues.has(val)) {
      console.error(
        `[lint-allowed-identities] FATAL: BIT_TABLE entry { ${val}: '${name}' } has no matching ` +
        `IDENTITY_CLASS_${name} = ${val} in options.proto IdentityClass enum. Remove the stale entry.`
      );
      ok = false;
    }
  }
  if (!ok) {
    process.exit(1);
  }
}

/**
 * Build the expected comment string for a given integer value.
 * E.g. 3 -> "USER | SERVICE", 1 -> "USER", 12 -> "COMPONENT | PLATFORM_OPERATOR".
 */
function renderBits(value) {
  const names = [];
  for (const bit of [1, 2, 4, 8]) {
    if (value & bit) {
      names.push(BIT_TABLE.get(bit) ?? `BIT_${bit}`);
    }
  }
  return names.join(' | ') || `UNKNOWN(${value})`;
}

// ---------------------------------------------------------------------------
// Proto file walker
// ---------------------------------------------------------------------------

function findProtos(dir) {
  const results = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      results.push(...findProtos(full));
    } else if (entry.endsWith('.proto')) {
      results.push(full);
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Lint logic
// ---------------------------------------------------------------------------

/**
 * For a given file's lines, check every `allowed_identities: <int>` line.
 * Returns an array of violation objects: { lineNo, value }.
 *
 * Acceptance rules (Requirement 6.2):
 *   (a) trailing inline comment on the same line:
 *       allowed_identities: 3  // USER | SERVICE
 *   (b) preceding non-blank line is a comment:
 *       // USER | SERVICE
 *       allowed_identities: 3
 */
function checkFile(lines) {
  const violations = [];
  const FIELD_RE = /^\s*allowed_identities:\s*(\d+)\s*/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = FIELD_RE.exec(line);
    if (!m) continue;

    const value = parseInt(m[1], 10);
    // Check trailing comment on same line.
    const trailingComment = line.slice(m[0].length);
    if (trailingComment.startsWith('//')) continue;

    // Check preceding non-blank line is a comment.
    let prevIdx = i - 1;
    while (prevIdx >= 0 && lines[prevIdx].trim() === '') {
      prevIdx--;
    }
    if (prevIdx >= 0 && /^\s*\/\//.test(lines[prevIdx])) continue;

    violations.push({ lineNo: i + 1, value });
  }
  return violations;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

// D5: self-test runs before any file scanning.
selfTest();

const protoFiles = findProtos(PROTO_ROOT);
let totalViolations = 0;

for (const absPath of protoFiles) {
  const relPath = relative(PROTO_ROOT, absPath);
  const text = readFileSync(absPath, 'utf8');
  const lines = text.split('\n');
  const violations = checkFile(lines);

  for (const v of violations) {
    const rendered = renderBits(v.value);
    console.error(
      `[lint-allowed-identities] ${relPath}:${v.lineNo}: ` +
      `allowed_identities: ${v.value} missing inline name comment ` +
      `(expected: // ${rendered})`
    );
    totalViolations++;
  }
}

if (totalViolations > 0) {
  console.error(
    `[lint-allowed-identities] FAIL: ${totalViolations} violation(s). ` +
    `Add an inline // comment naming the bits to each flagged line. ` +
    `See core/sdk/docs/how-to-add-a-rpc.md for the bit-table.`
  );
  process.exit(1);
}

console.log('[lint-allowed-identities] Gibson daemon-local protos: all allowed_identities lines have inline name comments.');
process.exit(0);
