#!/usr/bin/env node
// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

/**
 * lint-pagination.mjs - Gibson daemon-local proto pagination lint (ADR-0028 rule 3)
 *
 * Walks every *.proto under internal/server/daemon/api/ and checks every unary
 * RPC, whatever its name:
 *
 *   1. The request message has no field named "limit" or "offset".
 *   2. When the response message has a top-level repeated field, the request
 *      has page_size and page_token, and the response has next_page_token.
 *
 * A violation fails the run (exit 1), unless the RPC is in the baseline file
 * (scripts/lint-pagination.baseline). The baseline holds the RPCs that broke
 * the rules before this check covered them. Each line is "<proto path> <Rpc>".
 * The key is content, never a line number. The baseline can only shrink:
 * an entry for an RPC that now passes, or that no longer exists, fails the
 * run, so a fixed RPC leaves the file in the same PR.
 *
 * Usage:
 *   node scripts/lint-pagination.mjs
 *   node scripts/lint-pagination.mjs --root <proto dir> --baseline <file>
 */

import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, relative, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i > -1 && process.argv[i + 1] ? resolve(process.argv[i + 1]) : fallback;
}

const PROTO_ROOT = arg('--root', join(REPO_ROOT, 'internal/server/daemon/api'));
const BASELINE = arg('--baseline', join(__dirname, 'lint-pagination.baseline'));

/** Collect all *.proto file paths under dir. */
function findProtos(dir) {
  const results = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      results.push(...findProtos(full));
    } else if (entry.endsWith('.proto')) {
      results.push(full);
    }
  }
  return results;
}

/** Remove comments, so commented-out code does not count. */
function stripComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
}

/** Return the unary RPCs of a proto: [{ name, request, response }]. */
function parseUnaryRpcs(text) {
  const rpcs = [];
  const re = /rpc\s+(\w+)\s*\(\s*(stream\s+)?([\w.]+)\s*\)\s*returns\s*\(\s*(stream\s+)?([\w.]+)\s*\)/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m[2] || m[4]) continue; // streaming RPCs page by their stream
    rpcs.push({ name: m[1], request: m[3].split('.').pop(), response: m[5].split('.').pop() });
  }
  return rpcs;
}

/** Return the top-level body of a message (nested messages removed), or null. */
function messageBody(text, name) {
  const m = new RegExp(`\\bmessage\\s+${name}\\s*\\{`).exec(text);
  if (!m) return null;
  let depth = 1;
  let i = m.index + m[0].length;
  let body = '';
  while (i < text.length && depth > 0) {
    const ch = text[i];
    if (ch === '{') depth++;
    else if (ch === '}') depth--;
    else if (depth === 1) body += ch;
    i++;
  }
  return body;
}

const hasField = (body, field) => new RegExp(`\\b${field}\\s*=\\s*\\d+`).test(body);

/** Return the violations of every unary RPC in one proto text. */
export function checkProto(text) {
  const t = stripComments(text);
  const found = [];
  for (const rpc of parseUnaryRpcs(t)) {
    const req = messageBody(t, rpc.request);
    const resp = messageBody(t, rpc.response);
    if (req !== null && (hasField(req, 'limit') || hasField(req, 'offset'))) {
      found.push({ rpc: rpc.name, why: 'the request has a limit or offset field; use page_size and page_token' });
      continue;
    }
    if (resp !== null && /\brepeated\b/.test(resp)) {
      const ok = req !== null && hasField(req, 'page_size') && hasField(req, 'page_token') &&
        hasField(resp, 'next_page_token');
      if (!ok) {
        found.push({ rpc: rpc.name, why: 'the response is a list; the request needs page_size and page_token and the response needs next_page_token' });
      }
    }
  }
  return found;
}

function readBaseline(file) {
  if (!existsSync(file)) return new Set();
  return new Set(
    readFileSync(file, 'utf8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')),
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const baseline = readBaseline(BASELINE);
const live = new Set();
let failures = 0;

for (const absPath of findProtos(PROTO_ROOT)) {
  const relPath = relative(PROTO_ROOT, absPath);
  for (const v of checkProto(readFileSync(absPath, 'utf8'))) {
    const key = `${relPath} ${v.rpc}`;
    live.add(key);
    if (baseline.has(key)) continue;
    console.error(`[lint-pagination] ${key}: ${v.why} (ADR-0028 rule 3).`);
    failures++;
  }
}

for (const key of baseline) {
  if (!live.has(key)) {
    console.error(`[lint-pagination] baseline entry "${key}" no longer violates the rules or no longer exists. Delete it from ${relative(REPO_ROOT, BASELINE)}.`);
    failures++;
  }
}

if (failures > 0) {
  console.error(`[lint-pagination] FAIL: ${failures} problem(s). See above.`);
  process.exit(1);
}

console.log(`[lint-pagination] every unary RPC pages its lists (${baseline.size} baselined).`);
