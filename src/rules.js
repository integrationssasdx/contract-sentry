'use strict';

// The three audit rules. Each finding carries ruleId, severity, message,
// location, reachable and evidence {entryPoints, callChain}.

const { visit, unwrap, LOW_LEVEL_METHODS } = require('./model');

const CHECKED_METHODS = new Set(['call', 'staticcall', 'send', 'transfer']);
const DELEGATE_METHODS = new Set(['delegatecall', 'callcode']);

function locOf(node) {
  return {
    startLine: node.loc.startLine,
    startColumn: node.loc.startColumn,
    endLine: node.loc.endLine,
    endColumn: node.loc.endColumn,
  };
}

function compareLoc(a, b) {
  if (a.startLine !== b.startLine) return a.startLine - b.startLine;
  return a.startColumn - b.startColumn;
}

// Root identifier of a member/index chain: a.b[c].d -> a
function baseIdentifier(node) {
  let current = unwrap(node);
  while (current && (current.type === 'Member' || current.type === 'Index')) {
    current = unwrap(current.object);
  }
  return current && current.type === 'Identifier' ? current.name : null;
}

function isStateVarWrite(node, stateVarNames) {
  if (node.type === 'Assignment') {
    const base = baseIdentifier(node.left);
    if (base && stateVarNames.has(base)) return base;
  }
  if (node.type === 'Unary' && (node.operator === '++' || node.operator === '--' || node.operator === 'delete')) {
    const base = baseIdentifier(node.argument);
    if (base && stateVarNames.has(base)) return base;
  }
  if (node.type === 'Call') {
    const callee = unwrap(node.callee);
    if (callee.type === 'Member' && (callee.property === 'push' || callee.property === 'pop')) {
      const base = baseIdentifier(callee.object);
      if (base && stateVarNames.has(base)) return base;
    }
  }
  return null;
}

function isExternalCall(node, stateVarNames, paramNames) {
  if (node.type !== 'Call') return false;
  const callee = unwrap(node.callee);
  if (callee.type !== 'Member') return false;
  if (LOW_LEVEL_METHODS.has(callee.property)) return true;
  const obj = unwrap(callee.object);
  if (obj.type === 'Identifier') {
    if (obj.name === 'this') return true;
    if (stateVarNames.has(obj.name)) return true; // e.g. token.transfer(...)
    if (paramNames && paramNames.has(obj.name)) return true; // e.g. token passed in
  }
  return false;
}

// ---------------------------------------------------------------------------
// Taint engine (shared by rule 1 and by the controllable-storage fixpoint).
// Taint sources: function parameters, msg.sender, msg.data, tx.origin and
// storage values that earlier writes made attacker-controllable.
// ---------------------------------------------------------------------------

function isTaintSourceMember(node) {
  // msg.sender / msg.data / msg.sig / tx.origin
  if (node.type !== 'Member') return false;
  const obj = unwrap(node.object);
  if (obj.type !== 'Identifier') return false;
  if (obj.name === 'msg' && (node.property === 'sender' || node.property === 'data' || node.property === 'sig')) return true;
  if (obj.name === 'tx' && node.property === 'origin') return true;
  return false;
}

function makeTaint(context) {
  const { controllableState } = context;

  function exprTaint(node) {
    if (!node) return false;
    node = unwrap(node);
    switch (node.type) {
      case 'Identifier':
        return context.locals.has(node.name) || controllableState.has(node.name);
      case 'Member':
        if (isTaintSourceMember(node)) return true;
        return exprTaint(node.object);
      case 'Index':
        return exprTaint(node.object) || exprTaint(node.index);
      case 'Call': {
        if (exprTaint(node.callee)) return true;
        return node.args.some(exprTaint);
      }
      case 'Assignment':
        return exprTaint(node.right);
      case 'Binary':
      case 'Logical':
        return exprTaint(node.left) || exprTaint(node.right);
      case 'Unary':
        return exprTaint(node.argument);
      case 'Conditional':
        return exprTaint(node.condition) || exprTaint(node.consequent) || exprTaint(node.alternate);
      case 'Tuple':
        return node.elements.some(exprTaint);
      case 'ArrayLiteral':
        return node.elements.some(exprTaint);
      case 'New':
        return false;
      default:
        return false;
    }
  }

  // Forward walk over statements, updating local taint on assignments and
  // reporting tainted state-var writes / delegatecall targets.
  function walkStatement(stmt, out) {
    visit(stmt, (node) => {
      if (node.type === 'VarDecl') {
        if (node.name && node.init && exprTaint(node.init)) context.locals.add(node.name);
        return;
      }
      if (node.type === 'TupleAssign') {
        const tainted = exprTaint(node.value);
        if (tainted) {
          for (const item of node.items) {
            if (!item) continue;
            if (item.type === 'VarDecl' && item.name) context.locals.add(item.name);
            else if (item.type === 'Identifier') context.locals.add(item.name);
          }
        }
        return;
      }
      if (node.type === 'Assignment') {
        const tainted = exprTaint(node.right);
        const left = unwrap(node.left);
        if (left.type === 'Identifier') {
          if (tainted) context.locals.add(left.name);
          else context.locals.delete(left.name);
        } else if (left.type === 'Tuple') {
          for (const el of left.elements) {
            if (el && el.type === 'Identifier') {
              if (tainted) context.locals.add(el.name);
              else context.locals.delete(el.name);
            }
          }
        }
        const base = baseIdentifier(node.left);
        if (base && context.stateVarNames.has(base) && tainted) out.taintedStateWrites.add(base);
        return;
      }
      if (node.type === 'Call') {
        const callee = unwrap(node.callee);
        if (callee.type === 'Member' && DELEGATE_METHODS.has(callee.property)) {
          if (exprTaint(callee.object)) out.delegatecalls.push(node);
        }
      }
    });
  }

  function run(fnNode) {
    const out = { taintedStateWrites: new Set(), delegatecalls: [] };
    for (const param of fnNode.params || []) {
      if (param.name) context.locals.add(param.name);
    }
    if (fnNode.body) walkStatement(fnNode.body, out);
    return out;
  }

  return { run };
}

// Compute the set of state variables an attacker can control: any non-constant
// state variable assigned (outside constructors) from a tainted expression,
// iterated to a fixpoint so taint flows variable -> variable.
function computeControllableState(model, contractName) {
  const eff = model.effective(contractName);
  const stateVarNames = new Set();
  for (const sv of eff.stateVars.values()) {
    if (!sv.isConstant && !sv.isImmutable) stateVarNames.add(sv.name);
  }
  const members = [];
  for (const fn of eff.functions.values()) {
    if (fn.body && fn.kind !== 'constructor') members.push(fn);
  }
  for (const mod of eff.modifiers.values()) {
    if (mod.body) members.push(mod);
  }
  let controllable = new Set();
  let changed = true;
  while (changed) {
    changed = false;
    for (const fn of members) {
      const taint = makeTaint({
        locals: new Set(),
        controllableState: controllable,
        stateVarNames,
      });
      const out = taint.run(fn);
      for (const name of out.taintedStateWrites) {
        if (!controllable.has(name)) {
          controllable.add(name);
          changed = true;
        }
      }
    }
  }
  return controllable;
}

// ---------------------------------------------------------------------------
// Rule 1: DELEGATECALL_UNTRUSTED_TARGET
// ---------------------------------------------------------------------------

function ruleDelegatecall(model, contract, addFinding) {
  const eff = model.effective(contract.name);
  const stateVarNames = new Set();
  for (const sv of eff.stateVars.values()) {
    if (!sv.isConstant && !sv.isImmutable) stateVarNames.add(sv.name);
  }
  const controllable = computeControllableState(model, contract.name);
  const members = [];
  for (const fn of eff.functions.values()) if (fn.body) members.push(fn);
  for (const mod of eff.modifiers.values()) if (mod.body) members.push(mod);
  const seen = new Set();
  for (const fn of members) {
    const taint = makeTaint({
      locals: new Set(),
      controllableState: controllable,
      stateVarNames,
    });
    const out = taint.run(fn);
    for (const callNode of out.delegatecalls) {
      const key = `${callNode.loc.startLine}:${callNode.loc.startColumn}`;
      if (seen.has(key)) continue;
      seen.add(key);
      addFinding({
        ruleId: 'DELEGATECALL_UNTRUSTED_TARGET',
        severity: 'high',
        message: 'delegatecall target is influenced by untrusted input (function parameters, calldata, msg.sender, tx.origin or attacker-controllable storage)',
        location: locOf(callNode),
        fnNode: fn,
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Rule 2: UNCHECKED_EXTERNAL_CALL
// ---------------------------------------------------------------------------

// Collect identifiers used in "check" positions: if/loop/ternary conditions
// and require/assert arguments.
function collectCheckIdentifiers(fnNode) {
  const uses = []; // {name, loc}
  function harvest(expr) {
    visit(expr, (n) => {
      if (n.type === 'Identifier') uses.push({ name: n.name, loc: n.loc });
    });
  }
  visit(fnNode.body, (node, parents) => {
    if (node.type === 'If') harvest(node.condition);
    else if (node.type === 'While' || node.type === 'DoWhile') harvest(node.condition);
    else if (node.type === 'For') { if (node.condition) harvest(node.condition); }
    else if (node.type === 'Conditional') harvest(node.condition);
    else if (node.type === 'Call') {
      const callee = unwrap(node.callee);
      if (callee.type === 'Identifier' && (callee.name === 'require' || callee.name === 'assert')) {
        for (const arg of node.args) harvest(arg);
      }
    }
  });
  return uses;
}

function ruleUncheckedCall(model, contract, addFinding) {
  const eff = model.effective(contract.name);
  const members = [];
  for (const fn of eff.functions.values()) if (fn.body) members.push(fn);
  for (const mod of eff.modifiers.values()) if (mod.body) members.push(mod);
  for (const fn of members) {
    const checkUses = collectCheckIdentifiers(fn);
    const calls = [];
    visit(fn.body, (node, parents) => {
      if (node.type !== 'Call') return;
      const callee = unwrap(node.callee);
      if (callee.type === 'Member' && CHECKED_METHODS.has(callee.property)) {
        calls.push({ node, parents });
      }
    });
    for (const { node, parents } of calls) {
      const method = unwrap(node.callee).property;
      if (isCallResultChecked(node, parents, checkUses)) continue;
      addFinding({
        ruleId: 'UNCHECKED_EXTERNAL_CALL',
        severity: 'medium',
        message: `return value of low-level '${method}' is not checked in the subsequent control flow of this function`,
        location: locOf(node),
        fnNode: fn,
      });
    }
  }
}

function isCallResultChecked(callNode, parents, checkUses) {
  // Walk outwards from the call to find how its value is consumed.
  const assignedVars = [];
  for (let i = parents.length - 1; i >= 0; i -= 1) {
    const p = parents[i];
    if (p.type === 'CallOptions') continue;
    if (p.type === 'If' || p.type === 'While' || p.type === 'DoWhile' || p.type === 'Conditional') return true;
    if (p.type === 'For' && p.condition && containsNode(p.condition, callNode)) return true;
    if (p.type === 'Return') return true;
    if (p.type === 'Call') {
      const callee = unwrap(p.callee);
      if (callee.type === 'Identifier' && (callee.name === 'require' || callee.name === 'assert')) return true;
      // result passed into some other call: not a check, keep walking out
    }
    if (p.type === 'VarDecl') {
      if (p.name) assignedVars.push(p.name);
      break;
    }
    if (p.type === 'TupleAssign') {
      for (const item of p.items) {
        if (!item) continue;
        if (item.type === 'VarDecl' && item.name) assignedVars.push(item.name);
        else if (item.type === 'Identifier') assignedVars.push(item.name);
      }
      break;
    }
    if (p.type === 'Assignment') {
      const left = unwrap(p.left);
      if (left.type === 'Identifier') assignedVars.push(left.name);
      else if (left.type === 'Tuple') {
        for (const el of left.elements) {
          if (el && el.type === 'Identifier') assignedVars.push(el.name);
        }
      }
      break;
    }
    if (p.type === 'ExpressionStatement') return false;
    if (p.type === 'Block' || p.type === 'Function') break;
  }
  if (assignedVars.length === 0) return false;
  // Checked if any assigned variable is later used in a check position.
  return checkUses.some((use) => assignedVars.includes(use.name) && compareLoc(use.loc, callNode.loc) > 0);
}

function containsNode(root, target) {
  let found = false;
  visit(root, (n) => { if (n === target) found = true; });
  return found;
}

// ---------------------------------------------------------------------------
// Rule 3: STATE_UPDATE_AFTER_CALL
// ---------------------------------------------------------------------------

function ruleStateUpdateAfterCall(model, contract, addFinding) {
  const eff = model.effective(contract.name);
  const stateVarNames = new Set();
  for (const sv of eff.stateVars.values()) {
    if (!sv.isConstant && !sv.isImmutable) stateVarNames.add(sv.name);
  }
  const entries = model.entryPoints(contract.name);
  const entryNodes = new Set(entries.filter((e) => e.node).map((e) => e.node));
  for (const fn of eff.functions.values()) {
    if (!fn.body || fn.kind === 'constructor') continue;
    if (!entryNodes.has(fn)) continue; // only public entry points
    const paramNames = new Set((fn.params || []).map((p) => p.name).filter(Boolean));
    const callLocs = [];
    const writes = [];
    visit(fn.body, (node) => {
      if (isExternalCall(node, stateVarNames, paramNames)) callLocs.push(node.loc);
      const written = isStateVarWrite(node, stateVarNames);
      if (written) writes.push({ name: written, node });
    });
    if (callLocs.length === 0) continue;
    const seenWrites = new Set();
    for (const write of writes) {
      const afterCall = callLocs.some((cl) => compareLoc(cl, write.node.loc) < 0);
      if (!afterCall) continue;
      const key = `${write.node.loc.startLine}:${write.node.loc.startColumn}`;
      if (seenWrites.has(key)) continue;
      seenWrites.add(key);
      addFinding({
        ruleId: 'STATE_UPDATE_AFTER_CALL',
        severity: 'high',
        message: `state variable '${write.name}' is updated after an external call or transfer, which may allow reentrancy`,
        location: locOf(write.node),
        fnNode: fn,
      });
    }
  }
}

// ---------------------------------------------------------------------------

const RULES = [ruleDelegatecall, ruleUncheckedCall, ruleStateUpdateAfterCall];

function analyze(model) {
  const findings = [];
  const dedupe = new Map();
  for (const contract of model.contracts) {
    if (contract.kind === 'interface') continue;
    for (const rule of RULES) {
      rule(model, contract, (finding) => {
        const reach = model.reachabilityOf(contract.name, finding.fnNode);
        const file = fileOfNode(model, contract, finding.fnNode);
        const key = `${finding.ruleId}|${file}|${finding.location.startLine}|${finding.location.startColumn}`;
        const record = {
          ruleId: finding.ruleId,
          severity: finding.severity,
          message: finding.message,
          location: Object.assign({ file }, finding.location),
          reachable: reach.reachable,
          evidence: {
            entryPoints: reach.entryPoints.slice(),
            callChain: reach.callChain ? reach.callChain.slice() : [],
          },
        };
        const existing = dedupe.get(key);
        if (existing) {
          for (const ep of record.evidence.entryPoints) {
            if (!existing.evidence.entryPoints.includes(ep)) existing.evidence.entryPoints.push(ep);
          }
          if (record.reachable && !existing.reachable) {
            existing.reachable = true;
            existing.evidence.callChain = record.evidence.callChain;
          }
        } else {
          dedupe.set(key, record);
          findings.push(record);
        }
      });
    }
  }
  return findings;
}

function fileOfNode(model, contract, fnNode) {
  // A function may be inherited from a base contract declared in another file.
  for (const c of model.contracts) {
    if (c.functions.includes(fnNode) || c.modifiers.includes(fnNode)) return c.filePath;
  }
  return contract.filePath;
}

module.exports = { analyze };
