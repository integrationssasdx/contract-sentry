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
  // internalOnly write(20). The internal-helper pattern is reported too
  // but is unreachable from any public entry.
  assert(lines.join(',') === '8,16,20', `state: expected 8,16,20 got ${lines}`);
  assert(hits.every((h) => h.severity === 'high'), 'state: severity high');
  // internalOnly must not be an entry finding for the state rule,
  // but its call() is still an unchecked call, reachable=false.
  const internalUnchecked = rules(r.json.findings, 'UNCHECKED_EXTERNAL_CALL')
    .find((f) => f.location.startLine === 19);
  assert(internalUnchecked && internalUnchecked.reachable === false,
    'state: internal helper call reachable=false');
  const internalState = hits.find((h) => h.location.startLine === 20);
  assert(internalState && internalState.reachable === false,
    'state: internal helper write reported reachable=false');
  assert(internalState.evidence.entryPoints.length === 0,
    'state: unreachable empty entryPoints');
  assert(internalState.evidence.callChain.length === 0,
    'state: unreachable empty callChain');
  assert(Array.isArray(internalState.evidence.interaction.callChain) &&
    internalState.evidence.interaction.callChain.length === 0,
    'state: unreachable empty interaction.callChain');
  assert(internalState.evidence.interaction.location &&
    internalState.evidence.interaction.location.startLine === 19,
    'state: unreachable interaction.location retained at call site');
  // Reachable findings carry the witness interaction and its chain.
  const bad = hits.find((h) => h.location.startLine === 8);
  assert(bad.evidence.interaction.location.startLine === 7,
    'state: interaction.location points at the preceding call');
  assert(bad.evidence.interaction.callChain.length === 1 &&
    bad.evidence.interaction.callChain[0].name === 'bad',
    'state: interaction.callChain entry to interaction fn');
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

function testStateRelayChains() {
  const sb = makeSandbox();
  sb.write('relay.sol', `
pragma solidity ^0.8.0;
contract Relay {
    uint256 a;
    uint256 b;
    function forward(address to) public {
        to.call("");
        fw();
    }
    function fw() internal { a = 1; }
    function backward(address to) public {
        bw(to);
        b = 2;
    }
    function bw(address to) internal { to.transfer(1); }
    function deep(address to) public { d1(to); }
    function d1(address to) internal { d2(to); }
    function d2(address to) internal { d3(to); }
    function d3(address to) internal { to.send(1); a = 3; }
}
`);
  const r = run(path.join(sb.dir, 'relay.sol'));
  assert(r.code === 0, `relay: exit 0 (got ${r.code} ${r.stdout})`);
  const hits = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL');
  const byLine = Object.fromEntries(hits.map((h) => [h.location.startLine, h]));
  // Fixture line 1 blank: fw write(10), backward write(13), d3 write(19).
  assert(Object.keys(byLine).sort((x, y) => x - y).join(',') === '10,13,19',
    `relay: writes at 10,13,19 got ${Object.keys(byLine)}`);

  // Caller interacts, callee writes: interaction stays in the caller.
  const fwd = byLine[10];
  assert(fwd.reachable === true, 'relay: forward reachable');
  assert(fwd.evidence.callChain.map((c) => c.name).join('->') === 'forward->fw',
    'relay: write chain forward->fw');
  assert(fwd.evidence.interaction.location.startLine === 7,
    'relay: forward interaction at caller call line 7');
  assert(fwd.evidence.interaction.callChain.map((c) => c.name).join('->') === 'forward',
    'relay: interaction chain is entry only');

  // Callee interacts, caller writes: chain reaches into the callee.
  const back = byLine[13];
  assert(back.evidence.interaction.location.startLine === 15,
    'relay: backward interaction at callee transfer line 15');
  assert(back.evidence.interaction.callChain.map((c) => c.name).join('->') === 'backward->bw',
    'relay: interaction chain backward->bw');

  // Multi-level internal chain.
  const dp = byLine[19];
  const deepNames = 'deep->d1->d2->d3';
  assert(dp.evidence.callChain.map((c) => c.name).join('->') === deepNames,
    'relay: deep write chain');
  assert(dp.evidence.interaction.callChain.map((c) => c.name).join('->') === deepNames,
    'relay: deep interaction chain');
  assert(dp.evidence.interaction.location.startLine === 19,
    'relay: deep interaction at send in d3');
  sb.remove();
}

function testStateBranchOrdering() {
  const sb = makeSandbox();
  sb.write('flow.sol', `
pragma solidity ^0.8.0;
contract Flow {
    uint256 a;
    function mutex(address to, bool ok) public {
        if (ok) { to.call(""); } else { a = 1; }
    }
    function sameBranch(address to, bool ok) public {
        if (ok) { to.call(""); a = 2; }
    }
    function afterIf(address to, bool ok) public {
        if (ok) { to.call(""); }
        a = 3;
    }
    function loopWitness(address to) public {
        for (uint i = 0; i < 2; i++) {
            if (i > 0) { a = 4; }
            to.call("");
        }
    }
    function retFlow(address to, bool ok) public {
        if (ok) { to.call(""); return; }
        a = 5;
    }
}
`);
  const r = run(path.join(sb.dir, 'flow.sol'));
  assert(r.code === 0, `flow: exit 0 (got ${r.code} ${r.stdout})`);
  const hits = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL');
  // Fixture line 1 blank: sameBranch write(9), afterIf write(13),
  // loopWitness write(17). mutex else-write (6) and retFlow write (23)
  // are on mutually exclusive / terminated paths and must NOT appear.
  const lines = hits.map((h) => h.location.startLine).sort((x, y) => x - y);
  assert(lines.join(',') === '9,13,17', `flow: expected 9,13,17 got ${lines}`);
  assert(hits.every((h) => h.reachable), 'flow: all branch findings reachable');
  sb.remove();
}

function testStateWitnessDepthAndEntries() {
  const sb = makeSandbox();
  sb.write('depth.sol', `
pragma solidity ^0.8.0;
contract Depth {
    uint256 a;
    function h(address to) internal { to.send(1); }
    function e(address to) public {
        to.transfer(2);
        h(to);
        a = 1;
    }
    function alsoCallsH(address to) public {
        h(to);
        a = 2;
    }
}
`);
  const r = run(path.join(sb.dir, 'depth.sol'));
  assert(r.code === 0, `depth: exit 0 (got ${r.code} ${r.stdout})`);
  const hits = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL');
  const byLine = Object.fromEntries(hits.map((h) => [h.location.startLine, h]));
  // Fixture line 1 blank: writes at 9 and 13.
  assert(Object.keys(byLine).sort((x, y) => x - y).join(',') === '9,13',
    `depth: writes at 9,13 got ${Object.keys(byLine)}`);
  // Shallow (same-function) interaction beats the deeper callee one.
  assert(byLine[9].evidence.interaction.location.startLine === 7,
    'depth: write 9 witnessed by depth-1 transfer at line 7');
  // Only path is through the helper.
  assert(byLine[13].evidence.interaction.location.startLine === 5,
    'depth: write 13 witnessed by helper send at line 5');
  assert(byLine[13].evidence.interaction.callChain.map((c) => c.name).join('->') ===
    'alsoCallsH->h', 'depth: interaction chain through helper');
  sb.remove();
}

function testStateFreeFnAndCtorChain() {
  const sb = makeSandbox();
  sb.write('cross.sol', `
pragma solidity ^0.8.0;
function freeDo(address to) { to.call(""); }
contract P { uint256 q; constructor(address a) { a.transfer(1); } }
contract C is P {
    uint256 s;
    constructor(address a) P(a) {
        s = 1;
    }
    function viaFree(address to) public {
        freeDo(to);
        s = 2;
    }
}
`);
  const r = run(path.join(sb.dir, 'cross.sol'));
  assert(r.code === 0, `cross: exit 0 (got ${r.code} ${r.stdout})`);
  const hits = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL');
  const byLine = Object.fromEntries(hits.map((h) => [h.location.startLine, h]));
  // Fixture line 1 blank: ctor write(8), viaFree write(12).
  assert(Object.keys(byLine).sort((x, y) => x - y).join(',') === '8,12',
    `cross: writes at 8,12 got ${Object.keys(byLine)}`);

  const ctor = byLine[8];
  assert(ctor.evidence.entryPoints[0].kind === 'constructor',
    'cross: ctor entry kind');
  assert(ctor.evidence.interaction.location.startLine === 4,
    'cross: ctor write witnessed by base-constructor transfer at line 4');
  assert(ctor.evidence.interaction.callChain.map((c) => c.kind).join('->') ===
    'constructor->constructor', 'cross: interaction chain through base ctor');

  const vf = byLine[12];
  assert(vf.evidence.interaction.location.startLine === 3,
    'cross: free-function interaction at line 3');
  const ic = vf.evidence.interaction.callChain;
  assert(ic[0].name === 'viaFree' && ic[1].name === 'freeDo' && ic[1].contract === null,
    'cross: interaction chain viaFree -> free function');
  sb.remove();
}

function testStateTerminationAndModifiers() {
  const sb = makeSandbox();
  sb.write('term.sol', `
pragma solidity ^0.8.0;
contract Term {
    uint256 a;
    uint256 b;
    address to;
    modifier postEffect {
        _;
        a = 1;
    }
    function bodyReturns() public postEffect {
        to.call("");
        return;
    }
    function retHandsBack(address t) public {
        helper(t);
        b = 2;
    }
    function helper(address t) internal { t.call(""); return; }
    function revHandsBack(address t) public {
        revHelper(t);
        b = 3;
    }
    function revHelper(address t) internal { t.call(""); revert("x"); }
}
`);
  const r = run(path.join(sb.dir, 'term.sol'));
  assert(r.code === 0, `term: exit 0 (got ${r.code} ${r.stdout})`);
  const hits = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL');
  // Fixture line 1 blank: modifier-post a=1 (9), retHandsBack b=2 (17).
  // revHandsBack b=3 (22) is unreachable across a reverting callee.
  const lines = hits.map((h) => h.location.startLine).sort((x, y) => x - y);
  assert(lines.join(',') === '9,17', `term: expected 9,17 got ${lines}`);
  // Modifier suffix runs after the body's early return (EVM semantics).
  const post = hits.find((h) => h.location.startLine === 9);
  assert(post.evidence.entryPoints[0].name === 'bodyReturns',
    'term: modifier suffix reachable after body return');
  assert(post.evidence.interaction.location.startLine === 12,
    'term: suffix write witnessed by pre-return body interaction');
  // A normal `return` in a callee still hands effects back to the caller.
  const rb = hits.find((h) => h.location.startLine === 17);
  assert(rb.evidence.interaction.callChain.map((c) => c.name).join('->') ===
    'retHandsBack->helper', 'term: callee normal return hands effects back');
  sb.remove();
}

function testStateMultipleEntries() {
  const sb = makeSandbox();
  sb.write('multi.sol', `
pragma solidity ^0.8.0;
contract Base {
    uint256 s;
    function core(address to) internal { to.call(""); s = 1; }
}
contract Mid is Base {
    function viaA(address to) public { core(to); }
    function viaB(address to) external { core(to); }
}
`);
  const r = run(path.join(sb.dir, 'multi.sol'));
  assert(r.code === 0, `multi: exit 0 (got ${r.code} ${r.stdout})`);
  const hits = rules(r.json.findings, 'STATE_UPDATE_AFTER_CALL');
  // One write source position -> exactly one finding across inheritance views.
  assert(hits.length === 1, `multi: single finding for one write got ${hits.length}`);
  const f = hits[0];
  const names = f.evidence.entryPoints.map((e) => e.name).sort();
  assert(names.join(',') === 'viaA,viaB', `multi: both entries collected got ${names}`);
  assert(f.evidence.callChain.map((c) => c.name).join('->') === 'viaA->core',
    'multi: shortest write chain is primary callChain');
  assert(f.evidence.interaction.callChain.map((c) => c.name).join('->') === 'viaA->core',
    'multi: interaction chain reaches the shared helper');
  sb.remove();
}

function testSelfdestructTaintSources() {
  const sb = makeSandbox();
  sb.write('sd.sol', `
pragma solidity ^0.8.0;
contract SD {
    address constant FIXED = address(0x123);
    address immutable IMM;
    address owner;
    constructor(address i) { IMM = i; }
    function byParam(address beneficiary) external {
        selfdestruct(beneficiary);
    }
    function bySender() external {
        selfdestruct(msg.sender);
    }
    function byOrigin() external {
        suicide(tx.origin);
    }
    function byMsgData() external {
        selfdestruct(msg.data);
    }
    function byDecode(bytes calldata data) external {
        selfdestruct(abi.decode(data, (address)));
    }
    function byState() external {
        selfdestruct(owner);
    }
    function byLocal(address a) external {
        address b = a;
        address c = b;
        selfdestruct(c);
    }
    function byCompute(address a) external {
        selfdestruct(address(uint160(uint256(uint160(a)) + 0)));
    }
    function fixed() external {
        selfdestruct(FIXED);
    }
    function immutableB() external {
        selfdestruct(IMM);
    }
    function literal() external {
        selfdestruct(address(0xdead));
    }
    function cleanCompute() external {
        selfdestruct(address(uint160(123)));
    }
    function unreachableHelper(address a) internal {
        selfdestruct(a);
    }
}
`);
  const r = run(path.join(sb.dir, 'sd.sol'));
  assert(r.code === 0, `selfdestruct: exit 0 (got ${r.code} ${r.stdout})`);
  const hits = rules(r.json.findings, 'SELFDESTRUCT_UNTRUSTED_BENEFICIARY');
  // Fixture line 1 blank.
  const reachable = hits.filter((h) => h.reachable);
  const unreachable = hits.filter((h) => !h.reachable);
  const lines = reachable.map((h) => h.location.startLine).sort((a, b) => a - b);
  assert(lines.join(',') === '9,12,15,18,21,24,29,32',
    `selfdestruct: expected tainted lines 9,12,15,18,21,24,29,32 got ${lines}`);
  for (const h of reachable) {
    assert(h.severity === 'high', 'selfdestruct: severity high');
    assert(h.evidence.entryPoints.length === 1, 'selfdestruct: one entry point');
    assert(h.evidence.callChain.length === 1, 'selfdestruct: single-frame call chain');
  }
  // Negative cases must not fire: constant(35), immutable(38),
  // literal(41), clean computation(44).
  for (const ln of [35, 38, 41, 44]) {
    assert(!hits.some((h) => h.location.startLine === ln),
      `selfdestruct: no finding for fixed/immutable/literal/clean source at line ${ln}`);
  }
  // Internal-only helper is reported but unreachable.
  assert(unreachable.length === 1 && unreachable[0].location.startLine === 47,
    `selfdestruct: internal helper unreachable at 47, got ${unreachable.map((h) => h.location.startLine)}`);
  assert(unreachable[0].evidence.entryPoints.length === 0,
    'selfdestruct: unreachable empty entryPoints');
  assert(unreachable[0].evidence.callChain.length === 0,
    'selfdestruct: unreachable empty callChain');
  sb.remove();
}

function testSelfdestructLocationSpan() {
  const sb = makeSandbox();
  sb.write('span.sol', `
pragma solidity ^0.8.0;
contract Span {
    function kill(address a) external {
        selfdestruct(a);
    }
    function old(address a) external {
        suicide(a);
    }
}
`);
  const r = run(path.join(sb.dir, 'span.sol'));
  const hits = rules(r.json.findings, 'SELFDESTRUCT_UNTRUSTED_BENEFICIARY')
    .sort((a, b) => a.location.startLine - b.location.startLine);
  assert(hits.length === 2, `selfdestruct span: two findings got ${hits.length}`);
  // Full call from keyword through the closing parenthesis.
  const sd = hits[0];
  assert(sd.location.startLine === 5 && sd.location.endLine === 5,
    'selfdestruct span: single line');
  assert(sd.location.startColumn === 9, 'selfdestruct span: starts at keyword column');
  assert(sd.location.endColumn === 23,
    `selfdestruct span: ends after ')' col 23 got ${sd.location.endColumn}`);
  const su = hits[1];
  assert(su.location.startColumn === 9 && su.location.endColumn === 18,
    `selfdestruct span: suicide(...) span got ${su.location.startColumn}-${su.location.endColumn}`);
  sb.remove();
}

function testSelfdestructReachability() {
  const sb = makeSandbox();
  sb.write('reach.sol', `
pragma solidity ^0.8.0;
contract R {
    function entry(address a) external {
        mid(a);
    }
    function mid(address a) internal {
        leaf(a);
    }
    function leaf(address a) internal {
        selfdestruct(a);
    }
    function dead(address a) private {
        selfdestruct(a);
    }
}
`);
  const r = run(path.join(sb.dir, 'reach.sol'));
  assert(r.code === 0, `selfdestruct reach: exit 0 (got ${r.code} ${r.stdout})`);
  const hits = rules(r.json.findings, 'SELFDESTRUCT_UNTRUSTED_BENEFICIARY');
  assert(hits.length === 2, `selfdestruct reach: two sinks got ${hits.length}`);
  const live = hits.find((h) => h.location.startLine === 11);
  const dead = hits.find((h) => h.location.startLine === 14);
  assert(live && live.reachable === true, 'selfdestruct reach: chain sink reachable');
  assert(live.evidence.callChain.map((c) => c.name).join('->') === 'entry->mid->leaf',
    'selfdestruct reach: callChain entry->mid->leaf');
  assert(dead && dead.reachable === false, 'selfdestruct reach: private sink unreachable');
  assert(dead.evidence.entryPoints.length === 0 && dead.evidence.callChain.length === 0,
    'selfdestruct reach: unreachable evidence empty');
  sb.remove();
}

function testSelfdestructInheritanceModifierFree() {
  const sb = makeSandbox();
  sb.write('cross.sol', `
pragma solidity ^0.8.0;
function freeKill(address a) { selfdestruct(a); }
contract Base {
    function kill(address a) internal virtual { selfdestruct(a); }
}
contract Child is Base {
    function go(address a) external { kill(a); }
    function viaFree(address a) public { freeKill(a); }
}
contract Mod {
    modifier killMod(address a) {
        selfdestruct(a);
        _;
    }
    function m(address a) public killMod(a) {}
}
contract Ctor {
    constructor(address a) { selfdestruct(a); }
}
`);
  const r = run(path.join(sb.dir, 'cross.sol'));
  assert(r.code === 0, `selfdestruct cross: exit 0 (got ${r.code} ${r.stdout})`);
  const hits = rules(r.json.findings, 'SELFDESTRUCT_UNTRUSTED_BENEFICIARY');
  // Inheritance-expanded internal call: the operation stays located in Base.
  const inherited = hits.find((h) => h.location.startLine === 5);
  assert(inherited && inherited.reachable === true,
    'selfdestruct cross: inherited internal sink reachable from Child.go');
  assert(inherited.evidence.callChain.map((c) => c.name).join('->') === 'go->kill',
    'selfdestruct cross: chain through inherited kill');
  // Free function reached from a contract entry.
  const free = hits.find((h) => h.location.startLine === 3);
  assert(free && free.reachable === true,
    'selfdestruct cross: free function sink reachable');
  assert(free.evidence.callChain[1].contract === null &&
         free.evidence.callChain[1].name === 'freeKill',
    'selfdestruct cross: chain ends at free function');
  // Modifier-inlined sink: original operation in the modifier, reach via m.
  const mod = hits.find((h) => h.location.startLine === 13);
  assert(mod && mod.reachable === true,
    'selfdestruct cross: modifier sink reachable from m');
  assert(mod.evidence.entryPoints[0].name === 'm',
    'selfdestruct cross: modifier entry is m');
  // Constructor entry.
  const ctor = hits.find((h) => h.location.startLine === 19);
  assert(ctor && ctor.reachable === true &&
         ctor.evidence.entryPoints[0].kind === 'constructor',
    'selfdestruct cross: constructor sink reachable');
  sb.remove();
}

function testSelfdestructMultipleEntriesDedup() {
  const sb = makeSandbox();
  sb.write('multi.sol', `
pragma solidity ^0.8.0;
contract Base {
    function core(address a) internal { selfdestruct(a); }
}
contract Mid is Base {
    function viaA(address a) public { core(a); }
    function viaB(address a) external { core(a); }
}
`);
  const r = run(path.join(sb.dir, 'multi.sol'));
  const hits = rules(r.json.findings, 'SELFDESTRUCT_UNTRUSTED_BENEFICIARY');
  // One sink position -> exactly one finding across entries/inheritance.
  assert(hits.length === 1, `selfdestruct multi: one finding got ${hits.length}`);
  const names = hits[0].evidence.entryPoints.map((e) => e.name).sort();
  assert(names.join(',') === 'viaA,viaB',
    `selfdestruct multi: both entries got ${names}`);
  assert(hits[0].evidence.callChain.map((c) => c.name).join('->') === 'viaA->core',
    'selfdestruct multi: shortest chain primary');
  sb.remove();
}

function testSelfdestructDoesNotChangeBaselines() {
  const sb = makeSandbox();
  // A contract exercising all four rules confirms the original three keep
  // firing (counts unchanged) alongside the new rule.
  sb.write('mix.sol', `
pragma solidity ^0.8.0;
contract Mix {
    address impl;
    function dc(address t) external { t.delegatecall(""); }
    function uc(address a) public { a.call(""); }
    function sd(address a) public { selfdestruct(a); }
}
`);
  const r = run(path.join(sb.dir, 'mix.sol'));
  assert(r.code === 0, `selfdestruct mix: exit 0`);
  const count = (id) => rules(r.json.findings, id).length;
  assert(count('DELEGATECALL_UNTRUSTED_TARGET') === 1, 'mix: delegatecall still fires');
  assert(count('UNCHECKED_EXTERNAL_CALL') === 1, 'mix: unchecked still fires');
  assert(count('STATE_UPDATE_AFTER_CALL') === 0, 'mix: no state finding');
  assert(count('SELFDESTRUCT_UNTRUSTED_BENEFICIARY') === 1, 'mix: selfdestruct fires');
  assert(r.json.findings.every((f) => f.severity === 'high' || f.severity === 'medium'),
    'mix: severity domain unchanged');
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

const tests = [
  testCleanContract,
  testDelegatecall,
  testUncheckedCallVariants,
  testStateUpdate,
  testStateRelayChains,
  testStateBranchOrdering,
  testStateWitnessDepthAndEntries,
  testStateFreeFnAndCtorChain,
  testStateTerminationAndModifiers,
  testStateMultipleEntries,
  testReachabilityChain,
  testInheritanceOverride,
  testConstructorEntry,
  testModifiersAndChecks,
  testTryCatchAndModernSyntax,
  testEmptyAndInterfaceOnly,
  testSelfdestructTaintSources,
  testSelfdestructLocationSpan,
  testSelfdestructReachability,
  testSelfdestructInheritanceModifierFree,
  testSelfdestructMultipleEntriesDedup,
  testSelfdestructDoesNotChangeBaselines,
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
