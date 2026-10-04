// Zero-dependency test runner. Spawns the CLI as a subprocess so exit
// codes and stdout shape are exercised exactly as users see them.

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(__dirname, '..', 'bin', 'contract-sentry.js');

let passed = 0;
let failed = 0;
const failures = [];

function assert(cond, message) {
  if (cond) { passed++; }
  else { failed++; failures.push(message); console.error(`  ✗ ${message}`); }
}

function makeSandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'contract-sentry-'));
  return {
    dir,
    write(name, content) {
      const full = path.join(dir, name);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
      return full;
    },
    remove() { fs.rmSync(dir, { recursive: true, force: true }); },
  };
}

function run(target) {
  try {
    const stdout = execFileSync(process.execPath, [BIN, 'audit', target], {
      encoding: 'utf8',
    });
    return { code: 0, json: JSON.parse(stdout), stdout };
  } catch (e) {
    return {
      code: e.status,
      json: e.stdout ? JSON.parse(e.stdout) : null,
      stdout: e.stdout || '',
      stderr: e.stderr || '',
    };
  }
}

function rules(findings, id) {
  return findings.filter((f) => f.ruleId === id);
}

// ---------------------------------------------------------------------------

function testCleanContract() {
  const sb = makeSandbox();
  sb.write('clean.sol', `
pragma solidity ^0.8.0;
contract Safe {
    mapping(address => uint256) private balances;
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
`);
  const r = run(path.join(sb.dir, 'clean.sol'));
  assert(r.code === 0, `clean: exit code 0 (got ${r.code})`);
  assert(Array.isArray(r.json.files) && r.json.files.length === 1, 'clean: files array');
  assert(Array.isArray(r.json.findings), 'clean: findings array present');
  const unchecked = rules(r.json.findings, 'UNCHECKED_EXTERNAL_CALL');
  assert(unchecked.length === 0, 'clean: require(ok) suppresses UNCHECKED_EXTERNAL_CALL');
  const state = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL');
  assert(state.length === 0, 'clean: effects-before-call suppresses STATE_UPDATE_AFTER_CALL');
  sb.remove();
}

function testDelegatecall() {
  const sb = makeSandbox();
  sb.write('dc.sol', `
pragma solidity ^0.8.0;
contract DC {
    address constant FIXED = address(0x123);
    address impl;
    function byParam(address target, bytes calldata data) external {
        target.delegatecall(data);
    }
    function byMsgData() external {
        impl.delegatecall(msg.data);
    }
    function bySender() external {
        msg.sender.delegatecall("");
    }
    function fixed(bytes memory data) external {
        FIXED.delegatecall(data);
    }
    function localTaint(address t) external {
        address x = t;
        address(impl).delegatecall(abi.encode());
    }
    function hidden(address u) internal {
        u.delegatecall("");
    }
}
`);
  const r = run(path.join(sb.dir, 'dc.sol'));
  assert(r.code === 0, `delegatecall: exit 0 (got ${r.code} ${r.stdout})`);
  const hits = rules(r.json.findings, 'DELEGATECALL_UNTRUSTED_TARGET');
  const reachableHits = hits.filter((h) => h.reachable);
  const unreachableHits = hits.filter((h) => !h.reachable);
  const lines = reachableHits.map((h) => h.location.startLine).sort((a, b) => a - b);
  assert(lines.join(',') === '7,10,13,20', `delegatecall: expected reachable lines 7,10,13,20 got ${lines}`);
  for (const h of reachableHits) {
    assert(h.severity === 'high', 'delegatecall: severity high');
    assert(h.evidence.entryPoints.length >= 1, 'delegatecall: has entry point evidence');
    assert(h.evidence.callChain.length >= 1, 'delegatecall: has call chain evidence');
    assert(h.location.startColumn >= 1 && h.location.endColumn >= h.location.startColumn,
      'delegatecall: valid 1-based location span');
  }
  assert(unreachableHits.length === 1 && unreachableHits[0].location.startLine === 23,
    `delegatecall: internal-only hidden() unreachable at line 23, got ${unreachableHits.map((h) => h.location.startLine)}`);
  const unreach = unreachableHits[0];
  if (unreach) {
    assert(unreach.evidence.entryPoints.length === 0, 'unreachable: empty entryPoints');
    assert(unreach.evidence.callChain.length === 0, 'unreachable: empty callChain');
  }
  sb.remove();
}

function testUncheckedCallVariants() {
  const sb = makeSandbox();
  sb.write('u.sol', `
pragma solidity ^0.8.0;
contract U {
    function bare(address a) public {
        a.call("");
    }
    function checkedRequire(address a) public {
        (bool ok,) = a.call("");
        require(ok);
    }
    function checkedIf(address a) public {
        (bool ok,) = a.staticcall("");
        if (!ok) { revert(); }
    }
    function orRevert(address a) public returns (bool) {
        bool ok;
        (ok,) = a.send(1);
        ok || revert();
        return ok;
    }
    function transferUnchecked(address payable a) public {
        a.transfer(1);
    }
    function lateUnused(address a) public {
        (bool ok,) = a.call("");
        uint256 x = 1;
        require(x == 1);
    }
}
`);
  const r = run(path.join(sb.dir, 'u.sol'));
  assert(r.code === 0, `unchecked: exit 0 (got ${r.code})`);
  const hits = rules(r.json.findings, 'UNCHECKED_EXTERNAL_CALL');
  const lines = hits.map((h) => h.location.startLine).sort((a, b) => a - b);
  // Fixture line 1 is blank: bare(5), transferUnchecked(22), lateUnused(25).
  assert(lines.join(',') === '5,22,25', `unchecked: expected 5,22,25 got ${lines}`);
  for (const h of hits) {
    assert(h.severity === 'medium', 'unchecked: severity medium');
    assert(h.reachable === true, 'unchecked: public functions reachable');
  }
  sb.remove();
}

function testStateUpdate() {
  const sb = makeSandbox();
  sb.write('s.sol', `
pragma solidity ^0.8.0;
contract Reentry {
    mapping(address => uint256) balances;
    uint256 total;
    function bad(address to, uint256 v) public {
        to.call{value: v}("");
        balances[msg.sender] = 0;
    }
    function good(address to, uint256 v) public {
        balances[msg.sender] = 0;
        to.call{value: v}("");
    }
    function transferThenWrite(address payable to) public {
        to.transfer(1);
        total += 1;
    }
    function internalOnly(address to) internal {
        to.call("");
        total = 1;
    }
}
`);
  const r = run(path.join(sb.dir, 's.sol'));
  assert(r.code === 0, `state: exit 0 (got ${r.code})`);
  const hits = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL');
  const lines = hits.map((h) => h.location.startLine).sort((a, b) => a - b);
  // Fixture line 1 is blank: bad write(8), transferThenWrite total+=1 (16),
  // internalOnly write(20) reported but unreachable.
  assert(lines.join(',') === '8,16,20', `state: expected 8,16,20 got ${lines}`);
  assert(hits.every((h) => h.severity === 'high'), 'state: severity high');
  const reachableLines = hits.filter((h) => h.reachable).map((h) => h.location.startLine);
  assert(reachableLines.join(',') === '8,16',
    `state: only entry-rooted findings are reachable, got ${reachableLines}`);
  // internalOnly: ordering violation exists but no entry reaches it.
  const internalState = hits.find((h) => h.location.startLine === 20);
  assert(internalState && internalState.reachable === false,
    'state: internal helper write reachable=false');
  assert(internalState.evidence.entryPoints.length === 0,
    'state: unreachable entryPoints empty');
  assert(internalState.evidence.callChain.length === 0,
    'state: unreachable callChain empty');
  assert(internalState.evidence.interaction.callChain.length === 0,
    'state: unreachable interaction.callChain empty');
  assert(internalState.evidence.interaction.location.startLine === 19,
    'state: unreachable interaction.location retained');
  // internalOnly's call() is still an unchecked call, reachable=false.
  const internalUnchecked = rules(r.json.findings, 'UNCHECKED_EXTERNAL_CALL')
    .find((f) => f.location.startLine === 19);
  assert(internalUnchecked && internalUnchecked.reachable === false,
    'state: internal helper call reachable=false');
  sb.remove();
}

function testReachabilityChain() {
  const sb = makeSandbox();
  sb.write('chain.sol', `
pragma solidity ^0.8.0;
contract C {
    function entry(address a) external {
        mid(a);
    }
    function mid(address a) internal {
        leaf(a);
    }
    function leaf(address a) internal {
        a.call("");
    }
}
`);
  const r = run(path.join(sb.dir, 'chain.sol'));
  const f = rules(r.json.findings, 'UNCHECKED_EXTERNAL_CALL')[0];
  assert(!!f, 'chain: finding exists');
  assert(f.reachable === true, 'chain: reachable through entry->mid->leaf');
  const names = f.evidence.callChain.map((c) => c.name).join('->');
  assert(names === 'entry->mid->leaf', `chain: callChain entry->mid->leaf got ${names}`);
  assert(f.evidence.entryPoints[0].name === 'entry', 'chain: entryPoint is entry');
  sb.remove();
}

function testInheritanceOverride() {
  const sb = makeSandbox();
  sb.write('inh.sol', `
pragma solidity ^0.8.0;
contract Parent {
    mapping(address => uint256) bal;
    function work(address to) public virtual {
        to.call("");
        bal[msg.sender] = 0;
    }
}
contract Child is Parent {
    function work(address to) public override {
        bal[msg.sender] = 0;
        (bool ok,) = to.call("");
        require(ok);
    }
}
`);
  const r = run(path.join(sb.dir, 'inh.sol'));
  assert(r.code === 0, `inheritance: exit 0`);
  const stateHits = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL');
  // Only Parent.work (line 7); Child's final override is safe.
  assert(stateHits.length === 1 && stateHits[0].location.startLine === 7,
    `inheritance: only final declarations count, got ${stateHits.map((h) => h.location.startLine)}`);
  const parentEntry = stateHits[0].evidence.entryPoints
    .find((e) => e.contract === 'Parent' && e.name === 'work');
  assert(!!parentEntry, 'inheritance: Parent.work is its own entry');
  sb.remove();
}

function testConstructorEntry() {
  const sb = makeSandbox();
  sb.write('ctor.sol', `
pragma solidity ^0.8.0;
contract A {
    address admin;
    constructor(address _a) {
        _a.call("");
        admin = _a;
    }
}
`);
  const r = run(path.join(sb.dir, 'ctor.sol'));
  const state = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL');
  assert(state.length === 1 && state[0].reachable === true,
    'constructor: treated as entry, write-after-call flagged');
  assert(state[0].evidence.entryPoints[0].kind === 'constructor',
    'constructor: evidence entry kind is constructor');
  sb.remove();
}

function testDirectoryRecursion() {
  const sb = makeSandbox();
  sb.write('ignore.txt', 'not solidity');
  sb.write('z.sol', 'pragma solidity ^0.8.0; contract Z {}');
  sb.write('sub/a.sol', 'pragma solidity ^0.8.0; contract A {}');
  const r = run(sb.dir);
  assert(r.code === 0, `directory: exit 0 (got ${r.code})`);
  const base = path.basename(sb.dir);
  assert(r.json.files.length === 2, `directory: 2 sol files got ${r.json.files.length}`);
  assert(r.json.files[0] === `${base}/sub/a.sol`, `directory: order a first got ${r.json.files[0]}`);
  assert(r.json.files[1] === `${base}/z.sol`, `directory: order z second got ${r.json.files[1]}`);
  assert(r.json.findings.length === 0, 'directory: empty findings');
  sb.remove();
}

function testNoInputFiles() {
  const sb = makeSandbox();
  sb.write('notes.txt', 'hello');
  const r = run(sb.dir);
  assert(r.code === 4, `no-input dir: exit 4 got ${r.code}`);
  assert(r.json && r.json.error === 'NO_INPUT_FILES', 'no-input dir: JSON error code');
  const r2 = run(path.join(sb.dir, 'notes.txt'));
  assert(r2.code === 4, `no-input file: exit 4 got ${r2.code}`);
  assert(r2.json.error === 'NO_INPUT_FILES', 'no-input file: JSON error code');
  sb.remove();
}

function testReadError() {
  const sb = makeSandbox();
  const missing = path.join(sb.dir, 'missing.sol');
  const r = run(missing);
  assert(r.code === 2, `read error: exit 2 got ${r.code}`);
  assert(r.json.error === 'INPUT_READ_ERROR', 'read error: code');
  assert(typeof r.json.file === 'string', 'read error: file field');

  const bad = sb.write('badutf8.sol', Buffer.from([0x70, 0x72, 0x61, 0x67, 0x6d, 0x61, 0x20, 0xff, 0xfe]));
  const r3 = run(bad);
  assert(r3.code === 2, `utf8 error: exit 2 got ${r3.code}`);
  assert(r3.json.error === 'INPUT_READ_ERROR', 'utf8 error: code');
  sb.remove();
}

function testParseError() {
  const sb = makeSandbox();
  sb.write('broken.sol', 'pragma solidity ^0.8.0;\ncontract Broken { function () }');
  const r = run(path.join(sb.dir, 'broken.sol'));
  assert(r.code === 3, `parse error: exit 3 got ${r.code}`);
  assert(r.json.error === 'SOLIDITY_PARSE_ERROR', 'parse error: code');
  assert(typeof r.json.file === 'string', 'parse error: file');
  assert(Number.isInteger(r.json.startLine) && r.json.startLine >= 1,
    'parse error: startLine >= 1');
  assert(Number.isInteger(r.json.startColumn) && r.json.startColumn >= 1,
    'parse error: startColumn >= 1');
  sb.remove();
}

function testSingleJsonObject() {
  const sb = makeSandbox();
  sb.write('a.sol', 'pragma solidity ^0.8.0; contract A {}');
  const r = run(path.join(sb.dir, 'a.sol'));
  // stdout must be exactly one JSON object
  const trimmed = r.stdout.trim();
  assert(trimmed.startsWith('{') && trimmed.endsWith('}'), 'output: single JSON object');
  assert(Object.prototype.hasOwnProperty.call(r.json, 'files'), 'output: files key');
  assert(Object.prototype.hasOwnProperty.call(r.json, 'findings'), 'output: findings key');
  assert(Object.keys(r.json).length === 2, 'output: exactly files/findings');
  sb.remove();
}

function testModifiersAndChecks() {
  const sb = makeSandbox();
  sb.write('m.sol', `
pragma solidity ^0.8.0;
contract M {
    mapping(address => uint256) bal;
    modifier writesAfter {
        _;
        bal[msg.sender] = 0;
    }
    modifier noop { _; }
    function a(address to) public noop {
        to.transfer(1);
    }
    function b(address to) public writesAfter {
        to.transfer(1);
    }
    function directIf(address to) public {
        (bool ok,) = to.call("");
        if (ok) {}
    }
    function overwritten(address to) public {
        (bool ok,) = to.call("");
        ok = true;
        if (ok) {}
    }
}
`);
  const r = run(path.join(sb.dir, 'm.sol'));
  assert(r.code === 0, `modifiers: exit 0 (got ${r.code} ${r.stdout})`);
  const state = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL');
  assert(state.length === 1 && state[0].location.startLine === 7 &&
    state[0].evidence.entryPoints[0].name === 'b',
    `modifiers: modifier-inlined post-body write flagged for b only, got ${state.map((f) => f.location.startLine)}`);
  const unchecked = rules(r.json.findings, 'UNCHECKED_EXTERNAL_CALL');
  const lines = unchecked.map((u) => u.location.startLine).sort((x, y) => x - y);
  // a's transfer (11) and b's transfer (14) unchecked; directIf (17)
  // checked via if(ok); overwritten (21) clobbered var -> unchecked.
  assert(lines.join(',') === '11,14,21', `modifiers: unchecked lines 11,14,21 got ${lines}`);
  sb.remove();
}

function testTryCatchAndModernSyntax() {
  const sb = makeSandbox();
  sb.write('t.sol', `
pragma solidity ^0.8.23;
interface IT { function f() external returns (bool); }
error Boom();
contract T {
    IT token;
    mapping(address => uint256) bal;
    function safe() external {
        try token.f() returns (bool ok) {
            bal[msg.sender] = 1;
        } catch {
            revert Boom();
        }
    }
    function deposits(address to) external {
        uint256[] memory arr = new uint256[](1);
        arr[0] = 1;
        to.transfer(1);
    }
}
`);
  const r = run(path.join(sb.dir, 't.sol'));
  assert(r.code === 0, `try/catch: parses (got ${r.code} ${r.stdout})`);
  // try call with catch is NOT unchecked (the transfer in deposits() is a
  // separate, genuinely unchecked call).
  const onTry = rules(r.json.findings, 'UNCHECKED_EXTERNAL_CALL')
    .filter((u) => u.location.startLine === 9);
  assert(onTry.length === 0, 'try/catch: tried call considered checked');
  const state = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL');
  assert(state.length === 1 && state[0].location.startLine === 10,
    `try/catch: success-block write after call flagged, got ${state.map((f) => f.location.startLine)}`);
  sb.remove();
}

function testEmptyAndInterfaceOnly() {
  const sb = makeSandbox();
  sb.write('i.sol', `
pragma solidity ^0.8.0;
interface I { function f(address a) external; }
library L { function g(address a) internal { a.call(""); } }
`);
  const r = run(path.join(sb.dir, 'i.sol'));
  assert(r.code === 0, 'interface/library: parses');
  // Library internal helpers are not entry points, so the call is
  // unreachable from any public entry.
  const u = rules(r.json.findings, 'UNCHECKED_EXTERNAL_CALL');
  assert(u.length === 1 && u[0].reachable === false,
    'library: internal helper finding reachable=false');
  assert(u[0].evidence.entryPoints.length === 0, 'library: empty entryPoints');
  sb.remove();
}

function testCrossFunctionRelay() {
  const sb = makeSandbox();
  sb.write('relay.sol', `
pragma solidity ^0.8.0;
contract C {
    uint256 x;
    // interaction in entry, write in callee (caller -> callee relay)
    function callerRelay(address a) public {
        a.call("");
        doWrite();
    }
    // interaction in callee, write in callee (entry -> multi-level -> leaf)
    function chainEntry(address a) public {
        l1(a);
    }
    function l1(address a) internal { l2(a); }
    function l2(address a) internal {
        a.call("");
        x = 2;
    }
    function doWrite() internal {
        x = 1;
    }
}
`);
  const r = run(path.join(sb.dir, 'relay.sol'));
  assert(r.code === 0, `relay: exit 0 (got ${r.code} ${r.stdout})`);
  const hits = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL');
  assert(hits.length === 2, `relay: 2 findings got ${hits.length}`);

  // Fixture line 1 is blank: doWrite body x=1 is line 20, l2 write x=2 line 17.
  const callerWrite = hits.find((h) => h.location.startLine === 20);
  assert(!!callerWrite, 'relay: caller-interaction witnesses callee write');
  assert(callerWrite.evidence.callChain.map((c) => c.name).join('->') ===
    'callerRelay->doWrite', 'relay: callChain entry->doWrite');
  assert(callerWrite.evidence.interaction.location.startLine === 7,
    'relay: interaction at entry call line 7');
  assert(callerWrite.evidence.interaction.callChain.map((c) => c.name).join('->') ===
    'callerRelay', 'relay: interaction chain stops at entry');

  const chainWrite = hits.find((h) => h.location.startLine === 17);
  assert(!!chainWrite, 'relay: multi-level internal call chain detected');
  assert(chainWrite.evidence.callChain.map((c) => c.name).join('->') ===
    'chainEntry->l1->l2', 'relay: multi-level callChain');
  assert(chainWrite.evidence.interaction.callChain.map((c) => c.name).join('->') ===
    'chainEntry->l1->l2', 'relay: interaction chain through to leaf');
  sb.remove();
}

function testPathSensitiveBranches() {
  const sb = makeSandbox();
  sb.write('paths.sol', `
pragma solidity ^0.8.0;
interface IT { function f() external; }
contract C {
    uint256 x;
    function mutex(address a, bool b) public {
        if (b) { x = 1; } else { a.call(""); }
    }
    function sameBranch(address a, bool b) public {
        if (b) { a.call(""); x = 2; }
    }
    function loopCase(address a) public {
        for (uint256 i = 0; i < 2; i++) {
            if (i == 0) { a.call(""); }
            if (i == 1) { x = 3; }
        }
    }
    function tryCatch() public {
        try IT(address(0)).f() {
            x = 4;
        } catch {
            x = 5;
        }
    }
    function earlyReturn(address a, bool b) public {
        a.call("");
        if (b) { return; }
        x = 6;
    }
    function writeBefore(address a) public {
        x = 7;
        a.call("");
    }
}
`);
  const r = run(path.join(sb.dir, 'paths.sol'));
  assert(r.code === 0, `paths: exit 0 (got ${r.code} ${r.stdout})`);
  const lines = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL')
    .map((h) => h.location.startLine).sort((a, b) => a - b);
  // Reported: sameBranch(10), loop later-iteration write(15), try body(20),
  // catch body(22), post-return fall-through(28).
  // Excluded: mutex write(7, exclusive else-branch interaction) and
  // writeBefore(31, store precedes the interaction).
  assert(lines.join(',') === '10,15,20,22,28',
    `paths: path-sensitive lines 10,15,20,22,28 got ${lines}`);
  sb.remove();
}

function testWitnessSelectionAndEntries() {
  const sb = makeSandbox();
  sb.write('wit.sol', `
pragma solidity ^0.8.0;
contract C {
    uint256 x;
    function direct(address a) public {
        a.call("");
        shared();
    }
    function viaMiddle(address a) public {
        middle(a);
    }
    function middle(address a) internal {
        a.call("");
        shared();
    }
    function shared() internal { x = 1; }
}
`);
  const r = run(path.join(sb.dir, 'wit.sol'));
  assert(r.code === 0, `witness: exit 0 (got ${r.code} ${r.stdout})`);
  const hits = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL');
  // Same write location (line 14) across two entries: one finding only.
  assert(hits.length === 1, `witness: one finding per source location got ${hits.length}`);
  const f = hits[0];
  const entries = f.evidence.entryPoints.map((e) => e.name).sort().join(',');
  assert(entries === 'direct,viaMiddle', `witness: both entries collected got ${entries}`);
  // Winning witness: direct (fewer function levels).
  assert(f.evidence.interaction.callChain.map((c) => c.name).join('->') === 'direct',
    'witness: fewest function levels wins');
  assert(f.evidence.callChain.map((c) => c.name).join('->') === 'direct->shared',
    'witness: callChain follows winning entry to write function');
  sb.remove();
}

function testFreeAndConstructorChain() {
  const sb = makeSandbox();
  sb.write('fc.sol', `
pragma solidity ^0.8.0;
contract Base {
    constructor(address a) { a.call(""); }
}
contract C is Base {
    uint256 x;
    constructor(address a) Base(a) {
        x = 1;
    }
    function viaFree(address a) public {
        a.call("");
        freeEffect();
    }
}
function freeEffect() { x = 2; }
`);
  const r = run(path.join(sb.dir, 'fc.sol'));
  assert(r.code === 0, `free/ctor: exit 0 (got ${r.code} ${r.stdout})`);
  const hits = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL');
  // Blank line 1: derived ctor x=1 (9), free fn x=2 (16).
  const byLine = Object.fromEntries(hits.map((h) => [h.location.startLine, h]));
  const ctor = byLine[9];
  assert(!!ctor && ctor.reachable, 'free/ctor: base constructor interaction witnesses derived write');
  assert(ctor.evidence.entryPoints[0].kind === 'constructor', 'free/ctor: entry is constructor');
  assert(ctor.evidence.interaction.callChain.length === 2,
    'free/ctor: interaction chain reaches into base constructor');
  const free = byLine[16];
  assert(!!free && free.reachable, 'free/ctor: free function write detected');
  assert(free.evidence.callChain.map((c) => `${c.contract || ''}:${c.name}`).join('->') ===
    'C:viaFree->:freeEffect', 'free/ctor: callChain includes free function');
  sb.remove();
}

function testInheritanceDedup() {
  const sb = makeSandbox();
  sb.write('dedup.sol', `
pragma solidity ^0.8.0;
contract Parent {
    uint256 p;
    function work(address a) public {
        a.call("");
        p = 1;
    }
}
contract Child is Parent {
    function other(address a) public {
        work(a);
    }
}
`);
  const r = run(path.join(sb.dir, 'dedup.sol'));
  assert(r.code === 0, `dedup: exit 0 (got ${r.code} ${r.stdout})`);
  const hits = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL');
  // Blank line 1: Parent.work write is line 7. Visited from Parent's own
  // view and Child's inherited view, but reported exactly once.
  assert(hits.length === 1 && hits[0].location.startLine === 7,
    `dedup: same inherited source location reported once, got ${hits.map((h) => h.location.startLine)}`);
  const entries = hits[0].evidence.entryPoints.map((e) => `${e.contract}.${e.name}`).sort();
  assert(entries.join(',') === 'Child.other,Parent.work',
    `dedup: entries across inherited views collected, got ${entries}`);
  sb.remove();
}

const tests = [
  testCleanContract,
  testDelegatecall,
  testUncheckedCallVariants,
  testStateUpdate,
  testCrossFunctionRelay,
  testPathSensitiveBranches,
  testWitnessSelectionAndEntries,
  testFreeAndConstructorChain,
  testInheritanceDedup,
  testReachabilityChain,
  testInheritanceOverride,
  testConstructorEntry,
  testModifiersAndChecks,
  testTryCatchAndModernSyntax,
  testEmptyAndInterfaceOnly,
  testDirectoryRecursion,
  testNoInputFiles,
  testReadError,
  testParseError,
  testSingleJsonObject,
];

for (const t of tests) {
  process.stdout.write(`• ${t.name}\n`);
  t();
}

process.stdout.write(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
