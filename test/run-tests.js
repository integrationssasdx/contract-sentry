'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const BIN = path.join(ROOT, 'bin', 'contract-sentry.js');
const FIXTURES = path.join(__dirname, 'fixtures');

let passed = 0;
let failed = 0;

function check(name, condition, detail) {
  if (condition) {
    passed += 1;
    console.log(`ok   ${name}`);
  } else {
    failed += 1;
    console.log(`FAIL ${name}${detail ? `\n     ${detail}` : ''}`);
  }
}

function runAudit(args) {
  const res = spawnSync(process.execPath, [BIN, 'audit', ...args], { encoding: 'utf8' });
  let json = null;
  try { json = JSON.parse(res.stdout); } catch (e) { /* leave null */ }
  return { status: res.status, stdout: res.stdout, json };
}

// ---- 1. directory audit: rules, reachability, ordering ----
{
  const { status, json, stdout } = runAudit([path.join(FIXTURES, 'audit')]);
  check('directory audit exits 0', status === 0, `status=${status} stdout=${stdout}`);
  check('report has files and findings arrays', json && Array.isArray(json.files) && Array.isArray(json.findings));
  check('files are sorted relative paths', json && JSON.stringify(json.files) === JSON.stringify(['Reach.sol', 'Safe.sol', 'Vulnerable.sol']),
    json && JSON.stringify(json.files));

  const safe = json ? json.findings.filter((f) => f.location.file === 'Safe.sol') : [];
  check('Safe.sol produces no findings', safe.length === 0, JSON.stringify(safe, null, 2));

  const vuln = json ? json.findings.filter((f) => f.location.file === 'Vulnerable.sol') : [];
  const ruleIds = vuln.map((f) => f.ruleId);
  check('Vulnerable.sol: two delegatecall findings', vuln.filter((f) => f.ruleId === 'DELEGATECALL_UNTRUSTED_TARGET').length === 2, JSON.stringify(ruleIds));
  check('Vulnerable.sol: unchecked call + send findings',
    vuln.filter((f) => f.ruleId === 'UNCHECKED_EXTERNAL_CALL').length === 2, JSON.stringify(ruleIds));
  check('Vulnerable.sol: one state-update-after-call finding',
    vuln.filter((f) => f.ruleId === 'STATE_UPDATE_AFTER_CALL').length === 1, JSON.stringify(ruleIds));

  const severities = new Set((json ? json.findings : []).map((f) => f.severity));
  check('severities limited to high/medium', [...severities].every((s) => s === 'high' || s === 'medium'));

  const delegate = vuln.find((f) => f.ruleId === 'DELEGATECALL_UNTRUSTED_TARGET');
  check('finding shape: ruleId/severity/message/location/reachable/evidence',
    !!delegate && typeof delegate.message === 'string'
    && delegate.location.startLine >= 1 && delegate.location.startColumn >= 1
    && delegate.location.endLine >= delegate.location.startLine
    && typeof delegate.reachable === 'boolean'
    && Array.isArray(delegate.evidence.entryPoints) && Array.isArray(delegate.evidence.callChain));
  check('entry function finding is reachable with itself as chain',
    !!delegate && delegate.reachable === true
    && delegate.evidence.entryPoints.length > 0
    && delegate.evidence.callChain.length >= 1);

  // Reach.sol: execute reachable via run, orphan unreachable, execute2 via inheritance
  const reach = json ? json.findings.filter((f) => f.location.file === 'Reach.sol') : [];
  check('Reach.sol: three delegatecall findings (deduped across Base/Child)',
    reach.filter((f) => f.ruleId === 'DELEGATECALL_UNTRUSTED_TARGET').length === 3,
    JSON.stringify(reach.map((f) => [f.ruleId, f.location.startLine, f.reachable])));
  const orphanFinding = reach.find((f) => f.location.startLine === 20);
  check('orphan internal function is unreachable with empty evidence',
    !!orphanFinding && orphanFinding.reachable === false
    && orphanFinding.evidence.entryPoints.length === 0
    && orphanFinding.evidence.callChain.length === 0,
    JSON.stringify(orphanFinding));
  const execFinding = reach.find((f) => f.location.startLine === 16);
  check('execute reachable through run with call chain [run, execute]',
    !!execFinding && execFinding.reachable === true
    && execFinding.evidence.entryPoints.includes('run')
    && JSON.stringify(execFinding.evidence.callChain) === JSON.stringify(['run', 'execute']),
    JSON.stringify(execFinding));
  const exec2Finding = reach.find((f) => f.location.startLine === 26);
  check('inherited state var taint applies in Child (execute2 via kick)',
    !!exec2Finding && exec2Finding.reachable === true
    && exec2Finding.evidence.entryPoints.includes('kick'),
    JSON.stringify(exec2Finding));

  // findings sorted by file then position
  const sorted = json ? json.findings.every((f, i, arr) => {
    if (i === 0) return true;
    const p = arr[i - 1];
    const fo = json.files.indexOf(f.location.file);
    const po = json.files.indexOf(p.location.file);
    if (fo !== po) return fo >= po;
    if (f.location.startLine !== p.location.startLine) return f.location.startLine >= p.location.startLine;
    return f.location.startColumn >= p.location.startColumn;
  }) : false;
  check('findings ordered by file then position', sorted);
}

// ---- 2. single file audit ----
{
  const { status, json } = runAudit([path.join(FIXTURES, 'audit', 'Safe.sol')]);
  check('single file audit exits 0', status === 0);
  check('single file report lists that file', json && json.files.length === 1 && json.files[0].endsWith('Safe.sol'));
  check('single file: empty findings for safe contract', json && json.findings.length === 0, JSON.stringify(json && json.findings));
}

// ---- 3. parse error -> exit 3 ----
{
  const { status, json } = runAudit([path.join(FIXTURES, 'invalid')]);
  check('parse error exits 3', status === 3, `status=${status}`);
  check('parse error payload has code/file/startLine/startColumn',
    json && json.error && json.error.code === 'SOLIDITY_PARSE_ERROR'
    && json.error.file === 'Broken.sol'
    && typeof json.error.startLine === 'number' && json.error.startLine >= 1
    && typeof json.error.startColumn === 'number' && json.error.startColumn >= 1,
    JSON.stringify(json));
}

// ---- 4. no input files -> exit 4 ----
{
  const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentry-empty-'));
  const { status, json } = runAudit([emptyDir]);
  check('empty directory exits 4', status === 4, `status=${status}`);
  check('empty directory payload code NO_INPUT_FILES', json && json.error && json.error.code === 'NO_INPUT_FILES');
  fs.rmSync(emptyDir, { recursive: true, force: true });
}

// ---- 5. read errors -> exit 2 ----
{
  const badDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentry-utf8-'));
  fs.writeFileSync(path.join(badDir, 'Bad.sol'), Buffer.from([0xff, 0xfe, 0x41, 0x80]));
  const r1 = runAudit([badDir]);
  check('invalid UTF-8 exits 2', r1.status === 2, `status=${r1.status}`);
  check('invalid UTF-8 payload code INPUT_READ_ERROR', r1.json && r1.json.error && r1.json.error.code === 'INPUT_READ_ERROR');
  fs.rmSync(badDir, { recursive: true, force: true });

  const r2 = runAudit([path.join(FIXTURES, 'does-not-exist')]);
  check('missing path exits 2', r2.status === 2, `status=${r2.status}`);
  check('missing path payload code INPUT_READ_ERROR', r2.json && r2.json.error && r2.json.error.code === 'INPUT_READ_ERROR');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
