// Core static analysis: registry/inheritance, entry points, reachability
// via the intra-contract call graph, and the three audit rules.

export const RULES = {
  DELEGATECALL_UNTRUSTED_TARGET: { severity: 'high' },
  UNCHECKED_EXTERNAL_CALL: { severity: 'medium' },
  STATE_UPDATE_AFTER_CALL: { severity: 'high' },
};

const LOW_LEVEL_CALLS = new Set(['call', 'staticcall', 'send', 'transfer']);
const DELEGATE_CALLS = new Set(['delegatecall']);
const ALL_LOW_LEVEL = new Set([...LOW_LEVEL_CALLS, ...DELEGATE_CALLS]);
const BUILTIN_CALLS = new Set([
  'require', 'assert', 'revert', 'keccak256', 'sha256', 'ripemd160',
  'ecrecover', 'addmod', 'mulmod', 'blockhash', 'selfdestruct', 'suicide',
  'gasleft', 'blake2f160',
]);

// ---- descriptors -----------------------------------------------------------

const methodKey = (name, arity) => `${name}/${arity}`;
const descKey = (d) => `${d.file}::${d.contract || ''}::${d.kind}:${d.name}/${d.arity}`;
const entryKey = (d) => `${d.contract || ''}:${d.kind}:${d.name}/${d.arity}`;

function descriptorFor(node, file, contractName, arity) {
  return {
    file,
    contract: contractName,
    name: node.functionKind === 'function' ? node.name : node.functionKind,
    kind: node.functionKind,
    arity,
    visibility: node.visibility,
  };
}
const stripNode = (d) => ({ file: d.file, contract: d.contract, name: d.name, kind: d.kind });

// ---- expression walking ----------------------------------------------------

const SKIP = Symbol('skip-children');

function walkExpr(node, cb) {
  if (!node || typeof node !== 'object') return;
  cb(node);
  switch (node.kind) {
    case 'binary': walkExpr(node.left, cb); walkExpr(node.right, cb); break;
    case 'unary': walkExpr(node.operand, cb); break;
    case 'assign': walkExpr(node.target, cb); walkExpr(node.value, cb); break;
    case 'conditional': walkExpr(node.test, cb); walkExpr(node.cons, cb); walkExpr(node.alt, cb); break;
    case 'member': walkExpr(node.object, cb); break;
    case 'index': walkExpr(node.object, cb); if (node.index) walkExpr(node.index, cb); break;
    case 'call':
      walkExpr(node.callee, cb);
      for (const a of node.args || []) walkExpr(a, cb);
      for (const o of node.options || []) walkExpr(o.value, cb);
      break;
    case 'tuple': for (const it of node.items || []) walkExpr(it, cb); break;
    case 'newExpr': break;
    case 'structLiteral': for (const f of node.fields || []) walkExpr(f.value, cb); break;
    default: break;
  }
}

// Contextual expression walk: 'normal' | 'check' (boolean control position)
// | 'drop' (result value is irrelevant, e.g. returned/assigned).
function walkExprCtx(node, ctx, cb) {
  if (!node || typeof node !== 'object') return;
  if (cb(node, ctx) === SKIP) return;
  switch (node.kind) {
    case 'binary':
      if (node.op === '&&' || node.op === '||') {
        walkExprCtx(node.left, 'check', cb);
        walkExprCtx(node.right, 'check', cb);
      } else {
        walkExprCtx(node.left, ctx, cb);
        walkExprCtx(node.right, ctx, cb);
      }
      break;
    case 'unary':
      walkExprCtx(node.operand, node.op === '!' ? 'check' : ctx, cb);
      break;
    case 'assign':
      walkExprCtx(node.target, 'drop', cb);
      walkExprCtx(node.value, ctx, cb);
      break;
    case 'conditional':
      walkExprCtx(node.test, 'check', cb);
      walkExprCtx(node.cons, ctx, cb);
      walkExprCtx(node.alt, ctx, cb);
      break;
    case 'member': walkExprCtx(node.object, ctx, cb); break;
    case 'index': walkExprCtx(node.object, ctx, cb); if (node.index) walkExprCtx(node.index, ctx, cb); break;
    case 'call':
      if (node.callee.kind === 'ident' &&
          (node.callee.name === 'require' || node.callee.name === 'assert')) {
        (node.args || []).forEach((a, i) => walkExprCtx(a, i === 0 ? 'check' : 'drop', cb));
      } else {
        walkExprCtx(node.callee, ctx, cb);
        for (const a of node.args || []) walkExprCtx(a, 'normal', cb);
        for (const o of node.options || []) walkExprCtx(o.value, 'normal', cb);
      }
      break;
    case 'tuple': for (const it of node.items || []) walkExprCtx(it, ctx, cb); break;
    case 'structLiteral': for (const f of node.fields || []) walkExprCtx(f.value, ctx, cb); break;
    default: break;
  }
}

function walkStatement(stmt, cb) {
  if (!stmt) return;
  cb(stmt);
  const rec = (s) => walkStatement(s, cb);
  switch (stmt.kind) {
    case 'block': (stmt.statements || []).forEach(rec); break;
    case 'unchecked': rec(stmt.body); break;
    case 'if':
      rec(stmt.consequent);
      if (stmt.alternate) rec(stmt.alternate);
      break;
    case 'while': case 'doWhile': rec(stmt.body); break;
    case 'for':
      if (stmt.init) rec(stmt.init);
      rec(stmt.body);
      break;
    case 'try':
      rec(stmt.body);
      (stmt.clauses || []).forEach(rec);
      break;
    default: break;
  }
}

// Iterate every statement (origin annotated), depth-first in source order.
function eachStatement(wrapped, cb) {
  const rec = (s, origin) => {
    cb(s, origin);
    switch (s.kind) {
      case 'block': case 'unchecked':
        (s.kind === 'block' ? s.statements : s.body ? [s.body] : []).forEach((c) => rec(c, origin));
        break;
      case 'if':
        if (s.consequent) rec(s.consequent, origin);
        if (s.alternate) rec(s.alternate, origin);
        break;
      case 'while': case 'doWhile': rec(s.body, origin); break;
      case 'for':
        if (s.init) rec(s.init, origin);
        rec(s.body, origin);
        break;
      case 'try':
        rec(s.body, origin);
        (s.clauses || []).forEach((c) => rec(c, origin));
        break;
      default: break;
    }
  };
  for (const { stmt, origin } of wrapped) rec(stmt, origin);
}

// Flatten to an ordered list of simple "execution steps" (origin annotated).
// Control-flow tests appear as synthetic expression steps in textual order.
function linearSteps(wrapped) {
  const out = [];
  const exprStep = (expr, origin) => ({ stmt: { kind: 'expression', expr }, origin });
  const condStep = (expr, origin) => ({ stmt: { kind: '__cond__', expr }, origin });
  const rec = (s, origin) => {
    switch (s.kind) {
      case 'block': (s.statements || []).forEach((c) => rec(c, origin)); return;
      case 'unchecked': rec(s.body, origin); return;
      case 'if':
        if (s.test) out.push(condStep(s.test, origin));
        rec(s.consequent, origin);
        if (s.alternate) rec(s.alternate, origin);
        return;
      case 'while':
        if (s.test) out.push(condStep(s.test, origin));
        rec(s.body, origin);
        return;
      case 'doWhile':
        rec(s.body, origin);
        if (s.test) out.push(condStep(s.test, origin));
        return;
      case 'for':
        if (s.init) rec(s.init, origin);
        if (s.test) out.push(condStep(s.test, origin));
        rec(s.body, origin);
        if (s.update) out.push(exprStep(s.update, origin));
        return;
      case 'try':
        // A tried external call is checked: a catch clause handles
        // failure, and without one the failure propagates (reverts).
        out.push({ stmt: { kind: 'tryCall', expr: s.externalCall,
          hasCatch: (s.clauses || []).length > 0 }, origin });
        rec(s.body, origin);
        (s.clauses || []).forEach((c) => rec(c, origin));
        return;
      default:
        out.push({ stmt: s, origin });
    }
  };
  for (const { stmt, origin } of wrapped) rec(stmt, origin);
  return out;
}

const isLowLevelCall = (expr, set = ALL_LOW_LEVEL) =>
  expr && expr.kind === 'call' &&
  expr.callee && expr.callee.kind === 'member' &&
  set.has(expr.callee.property);

// Span covering the dangerous operation: `<target>.<method>` for a
// low-level call (excludes the argument list).
function operationSpan(callNode) {
  const mem = callNode.callee;
  return {
    startOffset: mem.object.loc.startOffset,
    endOffset: mem.propertyLoc.endOffset,
    startLine: mem.object.loc.startLine,
    startColumn: mem.object.loc.startColumn,
    endLine: mem.propertyLoc.endLine,
    endColumn: mem.propertyLoc.endColumn,
  };
}

function statementExpressions(stmt) {
  const out = [];
  switch (stmt.kind) {
    case 'expression': if (stmt.expr) out.push(stmt.expr); break;
    case 'varDecl': if (stmt.initializer) out.push(stmt.initializer); break;
    case 'return': if (stmt.expr) out.push(stmt.expr); break;
    case 'emit': if (stmt.expr) out.push(stmt.expr); break;
    case 'if': case 'while': case 'doWhile': if (stmt.test) out.push(stmt.test); break;
    case '__cond__': out.push(stmt.expr); break;
    case 'for':
      if (stmt.test) out.push(stmt.test);
      if (stmt.update) out.push(stmt.update);
      if (stmt.init && stmt.init.kind === 'expression') out.push(stmt.init.expr);
      if (stmt.init && stmt.init.kind === 'varDecl' && stmt.init.initializer) out.push(stmt.init.initializer);
      break;
    default: break;
  }
  return out;
}

function lvalueNames(expr) {
  if (!expr) return [];
  if (expr.kind === 'ident') return [expr.name];
  if (expr.kind === 'member' || expr.kind === 'index') return lvalueNames(expr.object);
  if (expr.kind === 'tuple') return (expr.items || []).flatMap(lvalueNames);
  return [];
}

// ---- view construction (inheritance + override final declaration) ----------

class View {
  constructor(desc, registry, linearized, stateVars, methods, modifiers, freeFunctions, entries) {
    this.desc = desc;
    this.registry = registry;
    this.linearized = linearized;
    this.stateVars = stateVars;
    this.methods = methods;
    this.modifiers = modifiers;
    this.freeFunctions = freeFunctions;
    this.entries = entries;
    this._modifierPieces = new Map();
  }

  resolveMethod(name, arity) {
    return this.methods.get(methodKey(name, arity)) ||
      this.freeFunctions.get(methodKey(name, arity)) || null;
  }

  // Body statements with the modifier chain inlined. Rightmost modifier is
  // innermost (modA modB => A.pre, B.pre, body, B.post, A.post).
  effectiveStatements(desc) {
    const node = desc.node;
    if (!node.body) return [];
    let composed = node.body.statements.map((stmt) => ({ stmt, origin: desc }));
    const mods = node.modifiers || [];
    for (let i = mods.length - 1; i >= 0; i--) {
      const pieces = this.modifierPieces(mods[i]);
      if (pieces) composed = [...pieces.pre, ...composed, ...pieces.post];
    }
    return composed;
  }

  modifierPieces(name) {
    if (this._modifierPieces.has(name)) return this._modifierPieces.get(name);
    const mod = this.modifiers.get(name);
    if (!mod) { this._modifierPieces.set(name, null); return null; }
    this._modifierPieces.set(name, undefined); // recursion guard

    const stmts = mod.node.body ? mod.node.body.statements : [];
    let pre = [];
    let post = [];
    let part = 0;
    const push = (s) => { (part === 0 ? pre : post).push({ stmt: s, origin: mod }); };
    for (const s of stmts) {
      if (s.kind === 'placeholder') { part = 1; continue; }
      if (s.kind === 'block') { (s.statements || []).forEach(push); continue; }
      push(s);
    }
    for (const innerName of mod.node.modifiers || []) {
      const inner = this.modifierPieces(innerName);
      if (inner) { pre = [...inner.pre, ...pre]; post = [...post, ...inner.post]; }
    }
    const pieces = { pre, post };
    this._modifierPieces.set(name, pieces);
    return pieces;
  }
}

export class Registry {
  constructor(parsedFiles) {
    this.files = parsedFiles;
    this.contractByName = new Map();
    this.allContracts = [];
    this.freeFunctions = new Map();

    for (const { file, ast } of parsedFiles) {
      for (const contract of ast.contracts) {
        const entry = { file, contract };
        this.allContracts.push(entry);
        if (!this.contractByName.has(contract.name)) this.contractByName.set(contract.name, []);
        this.contractByName.get(contract.name).push(entry);
      }
      for (const fn of ast.freeFunctions || []) {
        const arity = (fn.params || []).length;
        this.freeFunctions.set(
          methodKey(fn.name, arity),
          { ...descriptorFor(fn, file, null, arity), node: fn });
      }
    }
  }

  resolveBaseName(name, fromFile) {
    return (this.contractByName.get(name) || []).find((c) => c.file === fromFile) ||
      (this.contractByName.get(name) || [])[0] || null;
  }

  buildViews() {
    return this.allContracts.map((entry) => this.buildView(entry));
  }

  buildView(entry) {
    const { file, contract } = entry;
    // Most-derived-first DFS linearization of declared bases.
    const ordered = [];
    const seen = new Set();
    const visit = (f, c) => {
      const k = `${f}::${c.name}`;
      if (seen.has(k)) return;
      seen.add(k);
      ordered.push({ file: f, contract: c });
      for (const baseName of c.bases || []) {
        const base = this.resolveBaseName(baseName, f);
        if (base) visit(base.file, base.contract);
      }
    };
    visit(file, contract);

    // Inheritance + override: first (most-derived) declaration wins.
    const methods = new Map();
    const modifiers = new Map();
    const stateVars = new Map();
    for (const { file: f, contract: c } of ordered) {
      for (const node of c.nodes || []) {
        if (node.functionKind === 'modifier') {
          if (!modifiers.has(node.name)) {
            modifiers.set(node.name, {
              file: f, contract: c.name, name: node.name, kind: 'modifier',
              arity: (node.params || []).length, node,
            });
          }
          continue;
        }
        const arity = (node.params || []).length;
        const name = node.functionKind === 'function' ? node.name : node.functionKind;
        const key = methodKey(name, arity);
        if (!methods.has(key)) {
          methods.set(key, { ...descriptorFor(node, f, c.name, arity), node });
        }
      }
      for (const sv of c.stateVariables || []) {
        if (!stateVars.has(sv.name)) {
          stateVars.set(sv.name, {
            file: f, contract: c.name, name: sv.name, kind: 'stateVariable',
            visibility: sv.visibility, node: sv,
          });
        }
      }
    }

    const entries = [];
    if (contract.kind !== 'library') {
      for (const m of methods.values()) {
        if (m.kind === 'constructor' || m.kind === 'fallback' || m.kind === 'receive') {
          entries.push(m);
        } else if (m.kind === 'function' &&
                   (m.visibility === 'public' || m.visibility === 'external')) {
          entries.push(m);
        }
      }
      for (const sv of stateVars.values()) {
        if (sv.visibility === 'public') {
          entries.push({ file: sv.file, contract: sv.contract, name: sv.name,
            kind: 'getter', arity: 0, node: null });
        }
      }
    }

    const desc = { file, contract: contract.name, name: contract.name, kind: 'contract', arity: 0 };
    return new View(desc, this, ordered, stateVars, methods, modifiers, this.freeFunctions, entries);
  }
}

// ---- reachability ----------------------------------------------------------

function findMethodInContract(view, c, file, name, arity) {
  const node = (c.nodes || []).find((fn) =>
    (fn.functionKind === 'function' ? fn.name : fn.functionKind) === name &&
    (fn.params || []).length === arity && fn.functionKind !== 'modifier');
  if (!node) return null;
  return { ...descriptorFor(node, file, c.name, arity), node };
}

function collectEdges(view, desc) {
  const edges = [];
  const seen = new Set();
  const add = (target) => {
    if (!target) return;
    const k = descKey(target);
    if (!seen.has(k)) { seen.add(k); edges.push(target); }
  };

  const wrapped = view.effectiveStatements(desc);
  eachStatement(wrapped, (stmt) => {
    for (const expr of statementExpressions(stmt)) {
      walkExpr(expr, (n) => {
        if (n.kind !== 'call') return;
        const callee = n.callee;
        const argc = (n.args || []).length;
        if (callee.kind === 'ident') {
          if (BUILTIN_CALLS.has(callee.name)) return;
          add(view.resolveMethod(callee.name, argc));
        } else if (callee.kind === 'member' && callee.object.kind === 'ident' &&
                   callee.object.name === 'super') {
          let started = false;
          for (const { file: f, contract: c } of view.linearized) {
            if (!started) { if (c.name === desc.contract) started = true; continue; }
            add(findMethodInContract(view, c, f, callee.property, argc));
          }
        }
      });
    }
  });

  // Constructors chain into linearized base constructors.
  if (desc.kind === 'constructor') {
    let passedSelf = false;
    for (const { file: f, contract: c } of view.linearized) {
      if (!passedSelf) { if (c.name === desc.contract) passedSelf = true; continue; }
      const node = (c.nodes || []).find((fn) => fn.functionKind === 'constructor');
      if (node) add({ ...descriptorFor(node, f, c.name, (node.params || []).length), node });
    }
  }
  return edges;
}

function computeReachability(view) {
  // descKey -> entryKey -> chain (descriptors, entry first)
  const result = new Map();
  const ensure = (k) => {
    if (!result.has(k)) result.set(k, new Map());
    return result.get(k);
  };

  for (const entry of view.entries) {
    if (!entry.node) continue;
    const startChain = [stripNode(entry)];
    const queue = [{ desc: entry, chain: startChain }];
    const visited = new Set([descKey(entry)]);
    ensure(descKey(entry)).set(entryKey(entry), startChain);
    while (queue.length) {
      const { desc, chain } = queue.shift();
      for (const target of collectEdges(view, desc)) {
        const tk = descKey(target);
        const newChain = [...chain, stripNode(target)];
        const slot = ensure(tk);
        const prior = slot.get(entryKey(entry));
        if (!prior || prior.length > newChain.length) slot.set(entryKey(entry), newChain);
        if (!visited.has(tk)) {
          visited.add(tk);
          queue.push({ desc: target, chain: newChain });
        }
      }
    }
  }

  for (const m of view.methods.values()) ensure(descKey(m));
  return result;
}

// ---- rule 1: tainted delegatecall target -----------------------------------

function buildTaint(view, fnNode) {
  const tainted = new Set((fnNode.params || []).map((p) => p.name).filter(Boolean));

  const stateVarControllable = (name) => {
    // Any mutable storage value feeding a delegatecall target is treated as
    // attacker-influenceable ("可控存储值"); constants/immutables are fixed.
    const sv = view.stateVars.get(name);
    if (!sv) return false;
    return !sv.node.isConstant && !sv.node.isImmutable;
  };

  const isTaintedExpr = (expr) => {
    if (!expr) return false;
    let bad = false;
    walkExpr(expr, (n) => {
      if (bad) return;
      if (n.kind === 'ident') {
        if (tainted.has(n.name) || stateVarControllable(n.name)) bad = true;
      } else if (n.kind === 'member' && n.object.kind === 'ident') {
        if ((n.object.name === 'msg' && (n.property === 'sender' || n.property === 'data')) ||
            (n.object.name === 'tx' && n.property === 'origin')) {
          bad = true;
        }
      }
    });
    return bad;
  };

  // Fixed point: locals deriving from tainted sources become tainted.
  const stmts = fnNode.body ? fnNode.body.statements : [];
  let changed = true;
  let guard = 0;
  while (changed && guard++ < 20) {
    changed = false;
    for (const s of stmts) {
      walkStatement(s, (st) => {
        let names = null;
        let value = null;
        if (st.kind === 'varDecl' && st.initializer) {
          names = st.names || [];
          value = st.initializer;
        } else if (st.kind === 'expression' && st.expr && st.expr.kind === 'assign') {
          names = lvalueNames(st.expr.target);
          value = st.expr.op === '=' ? st.expr.value : st.expr;
        }
        if (names && value && isTaintedExpr(value)) {
          for (const nm of names) {
            if (!tainted.has(nm)) { tainted.add(nm); changed = true; }
          }
        }
      });
    }
  }
  return { isTaintedExpr };
}

function unwrapAddressCast(obj) {
  if (obj.kind === 'call' && obj.callee.kind === 'ident' &&
      obj.callee.name === 'address' && (obj.args || []).length === 1) {
    return obj.args[0];
  }
  return obj;
}

function runDelegatecallRule(view, desc, wrapped) {
  const findings = [];
  // Taint scopes follow origins: modifier bodies only see their own
  // parameters plus state/global sources, never the function's locals.
  const cache = new Map();
  const taintFor = (origin) => {
    const k = descKey(origin);
    if (!cache.has(k)) cache.set(k, buildTaint(view, origin.node));
    return cache.get(k);
  };
  eachStatement(wrapped, (stmt, origin) => {
    const o = origin || desc;
    const { isTaintedExpr } = taintFor(o);
    for (const expr of statementExpressions(stmt)) {
      walkExpr(expr, (n) => {
        if (!isLowLevelCall(n, DELEGATE_CALLS)) return;
        const target = unwrapAddressCast(n.callee.object);
        if (isTaintedExpr(target)) {
          findings.push({
            ruleId: 'DELEGATECALL_UNTRUSTED_TARGET',
            origin: o,
            location: operationSpan(n),
          });
        }
      });
    }
  });
  return findings;
}

// ---- rule 2: unchecked external call result --------------------------------

function isRevertCall(n) {
  return n.kind === 'call' && n.callee.kind === 'ident' &&
    (n.callee.name === 'revert' || n.callee.name === 'throw');
}

function runUncheckedCallRule(view, desc, wrapped) {
  const findings = [];
  const steps = linearSteps(wrapped);
  const bindings = []; // {name, call, index, origin}

  const record = (callNode, origin) => {
    findings.push({
      ruleId: 'UNCHECKED_EXTERNAL_CALL',
      origin,
      location: operationSpan(callNode),
      prop: callNode.callee.property,
    });
  };

  const collector = (origin) => (n, ctx) => {
    if (isLowLevelCall(n, LOW_LEVEL_CALLS)) {
      if (ctx === 'check') return SKIP;
      record(n, origin);
      return SKIP;
    }
    return undefined;
  };

  const analyzeStep = (stmt, origin, idx) => {
    switch (stmt.kind) {
      case '__cond__':
        walkExprCtx(stmt.expr, 'check', collector(origin));
        break;
      case 'tryCall':
        walkExprCtx(stmt.expr, 'check', collector(origin));
        break;
      case 'return':
        if (stmt.expr) walkExprCtx(stmt.expr, 'drop', collector(origin));
        break;
      case 'varDecl': {
        const init = stmt.initializer;
        if (!init) break;
        if (isLowLevelCall(init, LOW_LEVEL_CALLS) && init.callee.property !== 'transfer') {
          const firstName = (stmt.components || []).find((c) => c && c.name);
          if (firstName) bindings.push({ name: firstName.name, call: init, index: idx, origin });
          else record(init, origin);
        } else {
          walkExprCtx(init, 'normal', collector(origin));
        }
        break;
      }
      case 'expression': {
        const e = stmt.expr;
        if (!e) break;
        if (e.kind === 'assign' && isLowLevelCall(e.value, LOW_LEVEL_CALLS)) {
          if (e.op === '=' && e.value.callee.property !== 'transfer') {
            const names = lvalueNames(e.target);
            if (names.length) {
              bindings.push({ name: names[0], call: e.value, index: idx, origin });
              break;
            }
          }
          record(e.value, origin);
          break;
        }
        // `call(...) || revert()` / `call(...) && revert(...)` patterns.
        if (e.kind === 'binary' && (e.op === '||' || e.op === '&&')) {
          const sides = [];
          const flatten = (x) => {
            if (x.kind === 'binary' && x.op === e.op) { flatten(x.left); flatten(x.right); }
            else sides.push(x);
          };
          flatten(e);
          if (sides.some((s) => { let r = false; walkExpr(s, (n) => { if (isRevertCall(n)) r = true; }); return r; })) {
            for (const s of sides) {
              let reverts = false;
              walkExpr(s, (n) => { if (isRevertCall(n)) reverts = true; });
              if (!reverts) walkExprCtx(s, 'check', collector(origin));
            }
            break;
          }
        }
        walkExprCtx(e, 'normal', collector(origin));
        break;
      }
      default:
        for (const expr of statementExpressions(stmt)) {
          walkExprCtx(expr, 'normal', collector(origin));
        }
    }
  };

  steps.forEach(({ stmt, origin }, idx) => analyzeStep(stmt, origin, idx));

  // Bound results must appear in a checking position of a later step;
  // an intervening reassignment of the bound name invalidates it, since
  // the later check no longer tests the call result.
  for (const b of bindings) {
    let checked = false;
    let invalidated = false;
    for (let i = b.index + 1; i < steps.length; i++) {
      const { stmt } = steps[i];
      if (!invalidated && writesVar(stmt, b.name)) invalidated = true;
      if (!invalidated && varChecked(stmt, b.name)) { checked = true; break; }
    }
    if (!checked) record(b.call, b.origin);
  }

  const seen = new Set();
  return findings.filter((f) => {
    const k = `${f.origin.file}:${f.location.startOffset}:${f.location.endOffset}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

// True when the statement (lexically) assigns to a variable named `name`.
function writesVar(stmt, name) {
  let found = false;
  walkStatement(stmt, (s) => {
    if (found) return;
    if (s.kind === 'expression' && s.expr && s.expr.kind === 'assign') {
      if (lvalueNames(s.expr.target).includes(name)) found = true;
    }
    if (s.kind === 'varDecl' && (s.names || []).includes(name)) found = true;
  });
  return found;
}

function varChecked(stmt, name) {
  let found = false;
  const cb = (n, ctx) => {
    if (!found && ctx === 'check' && n.kind === 'ident' && n.name === name) found = true;
  };
  const rec = (s) => {
    if (found) return;
    switch (s.kind) {
      case '__cond__':
        walkExprCtx(s.expr, 'check', cb);
        break;
      case 'if':
        walkExprCtx(s.test, 'check', cb);
        rec(s.consequent);
        if (s.alternate) rec(s.alternate);
        break;
      case 'while': case 'doWhile':
        walkExprCtx(s.test, 'check', cb);
        if (s.body) rec(s.body);
        break;
      case 'for':
        if (s.test) walkExprCtx(s.test, 'check', cb);
        if (s.init) rec(s.init);
        rec(s.body);
        break;
      case 'return': if (s.expr) walkExprCtx(s.expr, 'drop', cb); break;
      case 'expression':
        if (s.expr) {
          const e = s.expr;
          if (e.kind === 'binary' && (e.op === '&&' || e.op === '||')) {
            const sides = [];
            const flatten = (x) => {
              if (x.kind === 'binary' && x.op === e.op) { flatten(x.left); flatten(x.right); }
              else sides.push(x);
            };
            flatten(e);
            if (sides.some((sd) => { let r = false; walkExpr(sd, (n) => { if (isRevertCall(n)) r = true; }); return r; })) {
              for (const sd of sides) walkExprCtx(sd, 'check', cb);
              break;
            }
          }
          walkExprCtx(e, 'normal', cb);
        }
        break;
      case 'varDecl': if (s.initializer) walkExprCtx(s.initializer, 'normal', cb); break;
      case 'block': (s.statements || []).forEach(rec); break;
      case 'unchecked': rec(s.body); break;
      case 'try':
        walkExprCtx(s.externalCall, 'normal', cb);
        rec(s.body);
        (s.clauses || []).forEach(rec);
        break;
      default:
        for (const expr of statementExpressions(s)) walkExprCtx(expr, 'normal', cb);
    }
  };
  rec(stmt);
  return found;
}

// ---- rule 3: state update after external interaction -----------------------

function isExternalInteraction(view, n) {
  if (n.kind !== 'call') return false;
  if (n.callee.kind === 'newExpr') return true; // contract creation
  const callee = n.callee;
  if (callee.kind !== 'member') return false;
  if (ALL_LOW_LEVEL.has(callee.property)) return true;
  // Array/map storage built-ins are never external calls.
  if (callee.property === 'push' || callee.property === 'pop') return false;
  const obj = callee.object;
  if (obj.kind === 'ident') {
    if (obj.name === 'this') return true;       // this.foo() is external
    if (obj.name === 'super') return false;     // super.foo() is internal
    // Calls rooted in a state variable are external only when the state
    // variable has a contract type; storage of array/mapping/struct/
    // primitive kind has no external methods.
    const sv = view.stateVars.get(obj.name);
    if (sv) {
      const t = sv.node.typeNode;
      if (t && t.kind === 'typeElementary' &&
          view.registry.contractByName.has(t.path[0])) {
        return true;
      }
      return false;
    }
    // Explicitly qualified call to a contract in the project is treated
    // as internal dispatch (library functions / same-type helpers).
    if (view.registry.contractByName.has(obj.name)) {
      const target = view.resolveMethod(callee.property, (n.args || []).length);
      if (target && target.kind === 'function') return false;
    }
  }
  return true;
}

function stateWriteRoot(view, expr) {
  let e = expr;
  while (e) {
    if (e.kind === 'ident') return view.stateVars.get(e.name) || null;
    if (e.kind === 'member' || e.kind === 'index') { e = e.object; continue; }
    return null;
  }
  return null;
}

function runStateUpdateRule(view, desc, wrapped, isEntry) {
  if (!isEntry || !desc.node.body) return [];
  const findings = [];
  const steps = linearSteps(wrapped);
  let interactionBefore = false;
  let fired = false;

  for (const { stmt, origin } of steps) {
    const exprs = statementExpressions(stmt);
    if (stmt.kind === 'tryCall') exprs.push(stmt.expr);

    // External interactions textually present in this step.
    let hasInteraction = false;
    for (const expr of exprs) {
      walkExpr(expr, (n) => {
        if (isExternalInteraction(view, n)) hasInteraction = true;
      });
    }

    // Any storage store in this statement executes only after every
    // expression (including external calls) has been evaluated, so a write
    // in a statement containing an interaction is always post-call.
    if ((interactionBefore || hasInteraction) && !fired) {
      walkStatement(stmt, (st) => {
        if (fired) return;
        let writes = [];
        if (st.kind === 'expression' && st.expr) {
          const e = st.expr;
          if (e.kind === 'assign') writes = [[e.target.loc, e.target]];
          else if (e.kind === 'unary' && (e.op === '++' || e.op === '--' || e.op === 'delete')) {
            writes = [[e.operand.loc, e.operand]];
          }
        }
        for (const [loc, target] of writes) {
          const sv = stateWriteRoot(view, target);
          if (sv) {
            fired = true;
            findings.push({
              ruleId: 'STATE_UPDATE_AFTER_CALL',
              origin: origin || desc,
              location: loc,
              stateVar: sv.name,
            });
            break;
          }
        }
      });
    }

    if (hasInteraction) interactionBefore = true;
  }
  return findings;
}

// ---- driver ----------------------------------------------------------------

export function analyze(parsedFiles) {
  const registry = new Registry(parsedFiles);
  const views = registry.buildViews();
  const acc = new Map();

  for (const view of views) {
    const reach = computeReachability(view);
    for (const desc of view.methods.values()) {
      if (!desc.node || !desc.node.body) continue;
      const wrapped = view.effectiveStatements(desc);
      const isEntry = view.entries.some((e) => e.node && descKey(e) === descKey(desc));

      const raw = [
        ...runDelegatecallRule(view, desc, wrapped),
        ...runUncheckedCallRule(view, desc, wrapped),
        ...runStateUpdateRule(view, desc, wrapped, isEntry),
      ];
      const reachMap = reach.get(descKey(desc)) || new Map();

      for (const r of raw) {
        const key = `${r.ruleId}:${r.origin.file}:${r.location.startOffset}:${r.location.endOffset}`;
        let f = acc.get(key);
        if (!f) {
          f = { ruleId: r.ruleId, severity: RULES[r.ruleId].severity,
            file: r.origin.file, location: r.location, detail: r, entries: new Map() };
          acc.set(key, f);
        }
        // Modifier-originated findings inherit the reachability of the
        // enclosing method (modifier code is inlined into it).
        const effectiveReach = (r.origin.kind === 'modifier') ? reachMap :
          (reach.get(descKey(r.origin)) || reachMap);
        for (const [ek, chain] of effectiveReach.entries()) {
          const prior = f.entries.get(ek);
          if (!prior || prior.chain.length > chain.length) f.entries.set(ek, { chain });
        }
      }
    }
  }

  return finalize(acc);
}

function finalize(acc) {
  const findings = [];
  for (const f of acc.values()) {
    const chains = [...f.entries.values()].map((v) => v.chain)
      .sort((a, b) => a.length - b.length);
    const entryPoints = [];
    const callChains = [];
    for (const chain of chains) {
      const entry = chain[0];
      if (!entryPoints.some((e) => e.name === entry.name && e.contract === entry.contract &&
                                  e.kind === entry.kind)) {
        entryPoints.push(entry);
        callChains.push(chain);
      }
    }
    const reachable = entryPoints.length > 0;
    const d = f.detail;
    let message;
    if (d.ruleId === 'DELEGATECALL_UNTRUSTED_TARGET') {
      message = 'delegatecall 的目标受函数参数、calldata、msg.sender、tx.origin 或可控存储值影响，可能执行攻击者指定的合约代码';
    } else if (d.ruleId === 'UNCHECKED_EXTERNAL_CALL') {
      message = `底层调用 ${d.prop} 的返回结果未在同函数后续控制流中检查，失败会被静默忽略`;
    } else {
      message = `公开入口在外部调用或转账之后写入重入敏感状态 ${d.stateVar}，违反 checks-effects-interactions 顺序`;
    }
    findings.push({
      ruleId: f.ruleId,
      severity: f.severity,
      message,
      location: {
        file: f.file,
        startLine: f.location.startLine,
        startColumn: f.location.startColumn,
        endLine: f.location.endLine,
        endColumn: f.location.endColumn,
      },
      reachable,
      evidence: {
        entryPoints: reachable ? entryPoints : [],
        callChain: reachable ? callChains[0] : [],
      },
    });
  }
  return findings;
}
