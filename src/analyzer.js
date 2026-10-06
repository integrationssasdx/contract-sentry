// Core static analysis: registry/inheritance, entry points, reachability
// via the intra-contract call graph, and the audit rules.

export const RULES = {
  DELEGATECALL_UNTRUSTED_TARGET: { severity: 'high' },
  UNCHECKED_EXTERNAL_CALL: { severity: 'medium' },
  STATE_UPDATE_AFTER_CALL: { severity: 'high' },
  SELFDESTRUCT_UNTRUSTED_BENEFICIARY: { severity: 'high' },
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

// ---- rule 2: tainted selfdestruct beneficiary ------------------------------

const SELFDESTRUCT_CALLS = new Set(['selfdestruct', 'suicide']);

// Span covering the whole `selfdestruct(beneficiary)` call: from the
// `selfdestruct`/`suicide` keyword through the closing parenthesis.
function selfdestructSpan(callNode) {
  const callee = callNode.callee;
  return {
    startOffset: callee.loc.startOffset,
    endOffset: callNode.loc.endOffset,
    startLine: callee.loc.startLine,
    startColumn: callee.loc.startColumn,
    endLine: callNode.loc.endLine,
    endColumn: callNode.loc.endColumn,
  };
}

function runSelfdestructRule(view, desc, wrapped) {
  const findings = [];
  // Same taint scopes as the delegatecall rule: each origin (function or
  // modifier) seeds its own parameters plus state/global sources.
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
        if (n.kind !== 'call' || !n.callee || n.callee.kind !== 'ident' ||
            !SELFDESTRUCT_CALLS.has(n.callee.name)) return;
        const args = n.args || [];
        if (args.length !== 1) return;
        if (isTaintedExpr(args[0])) {
          findings.push({
            ruleId: 'SELFDESTRUCT_UNTRUSTED_BENEFICIARY',
            origin: o,
            location: selfdestructSpan(n),
          });
        }
      });
    }
  });
  return findings;
}

// ---- rule 3: unchecked external call result --------------------------------

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

// ---- rule 4: state update after external interaction -----------------------
//
// Path-sensitive, cross-function, built on BOUNDED PROCEDURAL INLINING:
// the engine starts once at every method as a root frame and, walking in
// evaluation order, inlines every statically resolved internal call as a
// new function frame one level deeper. Modifier code is inlined by the
// view already and keeps sharing the enclosing function's frame; linearized
// base constructors run as a deeper prefix of their derived constructor.
//
// Inlining calls in place makes both relay directions fall out naturally:
//   caller: interact(); callee(): write;   -> interaction precedes write
//   callee(): interact(); caller: write;   -> interaction precedes write
//
// Ordering is decided on a may-CFG:
//   * a write is witnessed by every external interaction (low-level calls,
//     transfers, contract-typed member calls, `new X(...)`) occurring on
//     the SAME static path before it;
//   * if/else branches never merge before a write: an interaction in one
//     branch cannot witness a write in the mutually exclusive other
//     branch; events do flow to statements following the construct;
//   * loops reach a fixed point, so an interaction in an earlier iteration
//     witnesses a write in a later one;
//   * try: the tried call precedes success and every catch clause, while
//     the clauses stay mutually exclusive;
//   * revert/throw abort the path; a normal `return` hands control (and
//     the interactions evaluated so far) back to the caller. Inside a
//     function, `return` resumes the enclosing modifier suffix, while a
//     modifier's own `return` skips that suffix.
//
// Each witness records:
//   depth    - function layers between interaction and write
//               (same function = 1, one internal call apart = 2, ...);
//   frameKey - the function actually containing the interaction point
//               (inlined modifier code anchors to its enclosing function);
//   byRoot   - map from the root frame whose walk proved this ordered
//               path to the depth seen on that walk. An entry reaches the
//               pattern iff it reaches one of those roots.

const MAX_INLINE_DEPTH = 8;
const MAX_LOOP_ITERS = 32;

function stateWriteRoot(view, expr) {
  let e = expr;
  while (e) {
    if (e.kind === 'ident') return view.stateVars.get(e.name) || null;
    if (e.kind === 'member' || e.kind === 'index') { e = e.object; continue; }
    return null;
  }
  return null;
}

function superTargets(view, callerDesc, name, argc) {
  const out = [];
  let started = false;
  for (const { file, contract } of view.linearized) {
    if (!started) { if (contract.name === callerDesc.contract) started = true; continue; }
    const t = findMethodInContract(view, contract, file, name, argc);
    if (t) out.push(t);
  }
  return out;
}

// Classify a member call and resolve internal dispatch targets when it is
// not an external interaction. Mirrors the interaction predicate used by
// the baseline rules.
function classifyMemberCall(view, callerDesc, n) {
  const callee = n.callee;
  const argc = (n.args || []).length;
  if (ALL_LOW_LEVEL.has(callee.property)) return { external: true };
  if (callee.property === 'push' || callee.property === 'pop') {
    return { external: false, targets: [] };
  }
  const obj = callee.object;
  if (obj.kind === 'ident') {
    if (obj.name === 'this') return { external: true };
    if (obj.name === 'super') {
      return { external: false, targets: superTargets(view, callerDesc, callee.property, argc) };
    }
    const sv = view.stateVars.get(obj.name);
    if (sv) {
      const t = sv.node.typeNode;
      const isContract = t && t.kind === 'typeElementary' &&
        view.registry.contractByName.has(t.path[0]);
      return { external: isContract, targets: [] };
    }
    if (view.registry.contractByName.has(obj.name)) {
      const target = view.resolveMethod(callee.property, argc);
      if (target && target.kind === 'function' && target.node && target.node.body) {
        return { external: false, targets: [target] };
      }
    }
  }
  return { external: true };
}

function runStateEngine(view) {
  // write key -> {file, location, stateVar, frameKey, witnesses: Map(k->w)}
  const writes = new Map();

  const atomKey = (a) => `${a.frameKey}:${a.file}:${a.loc.startOffset}`;
  // Merge interaction sets, keeping the smallest frame depth per point.
  const mergeA = (...lists) => {
    const best = new Map();
    for (const list of lists) {
      if (!list) continue;
      for (const a of list) {
        const k = atomKey(a);
        const prior = best.get(k);
        if (!prior || prior.di > a.di) best.set(k, { ...a });
      }
    }
    return [...best.values()];
  };

  const writesOf = (stmt) => {
    if (stmt.kind !== 'expression' || !stmt.expr) return [];
    const e = stmt.expr;
    if (e.kind === 'assign') return [[e.target.loc, e.target]];
    if (e.kind === 'unary' && (e.op === '++' || e.op === '--' || e.op === 'delete')) {
      return [[e.operand.loc, e.operand]];
    }
    return [];
  };

  // Per-root-walk state.
  function makeWalker(rootDesc) {
    const rootKey = descKey(rootDesc);

    // atoms: {file, loc, di, frameKey}
    const makeAtom = (file, loc, frame) =>
      ({ file, loc, di: frame.depth, frameKey: descKey(frame.desc) });

    const recordWrite = (loc, target, origin, frame, ws) => {
      const sv = stateWriteRoot(view, target);
      if (!sv) return;
      const key = `${origin.file}:${loc.startOffset}:${loc.endOffset}`;
      let entry = writes.get(key);
      if (!entry) {
        entry = {
          file: origin.file, location: loc, stateVar: sv.name,
          frameKey: descKey(frame.desc), witnesses: new Map(),
        };
        writes.set(key, entry);
      }
      for (const a of ws) {
        // Function layers separating interaction and write on this path;
        // recorded per root since the same point can sit at a different
        // frame depth when reached from different roots.
        const depth = Math.abs(a.di - frame.depth) + 1;
        const wk = atomKey(a);
        let w = entry.witnesses.get(wk);
        if (!w) {
          w = { file: a.file, loc: a.loc, frameKey: a.frameKey, byRoot: new Map() };
          entry.witnesses.set(wk, w);
        }
        const priorDepth = w.byRoot.get(rootKey);
        if (priorDepth === undefined || depth < priorDepth) w.byRoot.set(rootKey, depth);
      }
    };

    // Inline a set of resolved callees at the current evaluation point.
    // `carry` holds interactions already evaluated. A callee that completes
    // normally (falls off the end OR hits a `return`) hands its effects
    // back to the caller; a callee that only reverts contributes nothing.
    const invoke = (targets, frame, carry) => {
      const produced = [];
      for (const t of targets) {
        if (!t.node || !t.node.body) continue;
        const tk = descKey(t);
        if (frame.stack.has(tk) || frame.depth + 1 > MAX_INLINE_DEPTH) continue;
        const inner = {
          desc: t, depth: frame.depth + 1, rootKey,
          stack: new Set(frame.stack).add(tk),
        };
        const prefix = t.kind === 'constructor' ? ctorPrefix(inner, carry) : [];
        const r = walk(t, inner, mergeA(carry, prefix));
        if (r.fall) produced.push(...r.fall);
        if (r.ret) produced.push(...r.ret);
      }
      return produced;
    };

    // Evaluate one expression in order: threading `carry`, collecting
    // external-interaction atoms and inlining internal calls.
    const evalExpr = (expr, origin, frame, carry) => {
      const out = [];
      let cur = carry;
      const atom = (a) => { out.push(a); cur = mergeA(cur, [a]); };
      const ev = (x) => {
        if (!x || typeof x !== 'object') return;
        switch (x.kind) {
          case 'binary': ev(x.left); ev(x.right); break;
          case 'unary': ev(x.operand); break;
          case 'assign': ev(x.target); ev(x.value); break;
          case 'conditional': ev(x.test); ev(x.cons); ev(x.alt); break;
          case 'member': ev(x.object); break;
          case 'index': ev(x.object); if (x.index) ev(x.index); break;
          case 'tuple': for (const it of x.items || []) ev(it); break;
          case 'structLiteral':
            for (const fld of x.fields || []) ev(fld.value); break;
          case 'call': {
            ev(x.callee);
            for (const a of x.args || []) ev(a);
            for (const o of x.options || []) ev(o.value);
            const callee = x.callee;
            if (callee.kind === 'newExpr') { atom(makeAtom(origin.file, x.loc, frame)); break; }
            if (callee.kind === 'ident') {
              if (BUILTIN_CALLS.has(callee.name)) break;
              const t = view.resolveMethod(callee.name, (x.args || []).length);
              const got = invoke(t ? [t] : [], frame, cur);
              out.push(...got); cur = mergeA(cur, got);
              break;
            }
            if (callee.kind === 'member') {
              const cls = classifyMemberCall(view, frame.desc, x);
              if (cls.external) {
                atom(makeAtom(origin.file, operationSpan(x), frame));
              } else {
                const got = invoke(cls.targets, frame, cur);
                out.push(...got); cur = mergeA(cur, got);
              }
            }
            break;
          }
          default: break;
        }
      };
      ev(expr);
      return out;
    };

    const atomsOf = (expr, origin, frame, carry) =>
      expr ? evalExpr(expr, origin, frame, carry) : [];

    // Effective region honoring modifier placeholder semantics: the
    // function body sits inside nested modifier regions, and a `return`
    // inside the body only leaves the body — the suffixes after each `_`
    // still execute (EVM return jumps to after the placeholder).
    const regionItemsOf = (desc) => {
      const bodyItems = (desc.node.body ? desc.node.body.statements : [])
        .map((stmt) => ({ stmt, origin: desc }));
      // The function body is a body-region (its `return` resumes the
      // innermost modifier suffix); every applied modifier wraps it in a
      // mod-region that lets a `return` in modifier code escape all
      // remaining suffixes.
      let region = { kind: 'bodyRegion', items: bodyItems };
      const mods = desc.node.modifiers || [];
      for (let i = mods.length - 1; i >= 0; i--) {
        const mod = view.modifiers.get(mods[i]);
        const pieces = mod ? view.modifierPieces(mods[i]) : null;
        const items = [];
        if (pieces) items.push(...pieces.pre);
        items.push({ stmt: region, origin: mod || desc });
        if (pieces) items.push(...pieces.post);
        region = { kind: 'modRegion', items };
      }
      return [{ stmt: region, origin: desc }];
    };

    // Linearized base constructors preceding `frame`'s constructor body.
    // Solidity runs them most-base-first, i.e. the reverse of the
    // most-derived-first linearization; their effects accumulate in order.
    const ctorPrefix = (frame, carry) => {
      const chain = [];
      let passedSelf = false;
      for (const { file, contract } of view.linearized) {
        if (!passedSelf) { if (contract.name === frame.desc.contract) passedSelf = true; continue; }
        const node = (contract.nodes || []).find((fn) => fn.functionKind === 'constructor');
        if (node && node.body) {
          chain.push({ ...descriptorFor(node, file, contract.name, (node.params || []).length), node });
        }
      }
      let acc = carry;
      for (const b of chain.reverse()) {
        const bk = descKey(b);
        if (frame.stack.has(bk) || frame.depth + 1 > MAX_INLINE_DEPTH) continue;
        const inner = { desc: b, depth: frame.depth + 1, rootKey, stack: new Set(frame.stack).add(bk) };
        const r = walk(b, inner, acc);
        // Base constructors complete normally before the derived body.
        if (r.fall) acc = mergeA(acc, r.fall);
        if (r.ret) acc = mergeA(acc, r.ret);
      }
      return acc === carry ? [] : acc;
    };

    // A flow result carries four disjoint exit channels, each holding the
    // interaction set visible on that exit (or null = unreachable):
    //   fall - runs to the end of the region and continues after it;
    //   ret  - leaves the whole function via `return`;
    //   brk/cont - transfer control to the enclosing loop.
    // `revert`/`throw` produce no exit (the path is aborted).
    const flow = (fall = null, ret = null, brk = null, cont = null) =>
      ({ fall, ret, brk, cont });
    const mkFall = (a) => flow(a, null, null, null);
    const dead = () => flow(null, null, null, null);

    // Walk one frame's effective (modifier-inlined) statements.
    const walk = (desc, frame, pre) => {
      const recList = (list, carryP) => {
        let carry = carryP;
        let ret = null;
        let brk = null;
        let cont = null;
        for (const { stmt, origin } of list) {
          const r = rec(stmt, origin, carry);
          if (r.ret) ret = mergeA(ret, r.ret);
          if (r.brk) brk = mergeA(brk, r.brk);
          if (r.cont) cont = mergeA(cont, r.cont);
          if (r.fall === null) return flow(null, ret, brk, cont);
          carry = r.fall;
        }
        return flow(carry, ret, brk, cont);
      };

      const rec = (s, origin, carryP) => {
        switch (s.kind) {
          case 'block':
            return recList((s.statements || []).map((stmt) => ({ stmt, origin })), carryP);
          case 'unchecked':
            return rec(s.body, origin, carryP);

          case 'bodyRegion': {
            // A function-body return resumes the enclosing modifier
            // suffix, so the ret channel becomes fall-through here.
            const r = recList(s.items, carryP);
            return flow(mergeA(r.fall, r.ret), null, r.brk, r.cont);
          }
          case 'modRegion':
            // Returns originating in this modifier's own code escape all
            // remaining suffixes; pass every channel through unchanged.
            return recList(s.items, carryP);

          case 'if': {
            const preC = mergeA(carryP, atomsOf(s.test, origin, frame, carryP));
            const rt = rec(s.consequent, origin, preC);
            if (!s.alternate) {
              // False-condition path (preC) merges with a falling then.
              const fallParts = [preC];
              if (rt.fall) fallParts.push(rt.fall);
              return flow(mergeA(...fallParts), rt.ret, rt.brk, rt.cont);
            }
            const re = rec(s.alternate, origin, preC);
            return flow(
              mergeA(...[rt.fall, re.fall].filter(Boolean)),
              mergeA(...[rt.ret, re.ret].filter(Boolean)),
              mergeA(...[rt.brk, re.brk].filter(Boolean)),
              mergeA(...[rt.cont, re.cont].filter(Boolean)),
            );
          }

          case 'while':
          case 'doWhile':
          case 'for':
            return recLoop(s, origin, frame, carryP);

          case 'try': {
            const preTry = mergeA(carryP, atomsOf(s.externalCall, origin, frame, carryP));
            const rb = rec(s.body, origin, preTry);
            const clauses = s.clauses || [];
            const rcList = clauses.map((c) => rec(c, origin, preTry));
            const pick = (chan) =>
              mergeA(...[rb[chan], ...rcList.map((x) => x[chan])].filter(Boolean));
            // With no catch clause, a failed call reverts: only the success
            // body's exits survive.
            if (clauses.length === 0) return rb;
            return flow(pick('fall'), pick('ret'), pick('brk'), pick('cont'));
          }

          case 'return': {
            // The returned expression is evaluated before control leaves.
            const atoms = atomsOf(s.expr, origin, frame, carryP);
            return flow(null, mergeA(carryP, atoms), null, null);
          }

          case 'throw':
            return dead();

          case 'break':
            return flow(null, null, carryP, null);
          case 'continue':
            return flow(null, null, null, carryP);

          case 'varDecl':
            return mkFall(mergeA(carryP, atomsOf(s.initializer, origin, frame, carryP)));

          case 'emit':
            return mkFall(mergeA(carryP, atomsOf(s.expr, origin, frame, carryP)));

          case 'expression': {
            if (isRevertCall(s.expr)) return dead();
            const atoms = atomsOf(s.expr, origin, frame, carryP);
            const ws = mergeA(carryP, atoms);
            for (const [loc, target] of writesOf(s)) {
              recordWrite(loc, target, origin, frame, ws);
            }
            return mkFall(ws);
          }

          default:
            return mkFall(carryP);
        }
      };

      // Loop handling as a monotone fixed point over the set of
      // interactions that may be live when entering the body. Earlier
      // iterations therefore witness later-iteration body writes; the
      // false-test / break exits witness writes after the loop.
      const recLoop = (s, origin, frame, carryP) => {
        let enter = carryP;
        let ret = null;
        let exited = null;

        if (s.kind === 'for' && s.init) {
          const ri = rec(s.init, origin, enter);
          if (ri.ret) ret = mergeA(ret, ri.ret);
          if (ri.fall === null) return flow(null, ret, null, null);
          enter = ri.fall;
        }

        const addTest = (c) => s.test ? mergeA(c, atomsOf(s.test, origin, frame, c)) : c;

        for (let i = 0; i < MAX_LOOP_ITERS; i++) {
          let bodyInput;
          if (s.kind === 'doWhile') {
            bodyInput = enter; // condition is at the bottom
          } else {
            const atTest = addTest(enter);
            exited = mergeA(exited, atTest); // exit via false condition
            bodyInput = atTest;
          }

          const rb = rec(s.body, origin, bodyInput);
          if (rb.ret) ret = mergeA(ret, rb.ret);
          if (rb.brk) exited = mergeA(exited, rb.brk);

          // Body fall-through and `continue` feed the next iteration.
          let repeat = mergeA(...[rb.fall, rb.cont].filter(Boolean));
          if (repeat) {
            if (s.kind === 'for' && s.update) {
              repeat = mergeA(repeat, atomsOf(s.update, origin, frame, repeat));
            }
            if (s.test) {
              repeat = addTest(repeat);
              // Bottom/re-test may also be false -> exit carries it.
              exited = mergeA(exited, repeat);
            }
          }

          const nextEnter = mergeA(enter, repeat || []);
          if (nextEnter.length === enter.length) { enter = nextEnter; break; }
          enter = nextEnter;
        }
        return flow(exited, ret, null, null);
      };

      return recList(regionItemsOf(desc), pre);
    };

    return { rootKey, walk, ctorPrefix };
  }

  // One root walk per method (entries and non-entries alike): a pattern
  // provable only inside an unreachable helper is still reported, then
  // marked reachable=false by the driver.
  for (const root of view.methods.values()) {
    if (!root.node || !root.node.body) continue;
    const rk = descKey(root);
    const frame = { desc: root, depth: 1, rootKey: rk, stack: new Set([rk]) };
    const walker = makeWalker(root);
    const initial = root.kind === 'constructor' ? walker.ctorPrefix(frame, []) : [];
    walker.walk(root, frame, initial);
  }

  // A storage write with no preceding interaction on any path is not the
  // pattern at all.
  for (const [k, entry] of writes) {
    if (entry.witnesses.size === 0) writes.delete(k);
  }
  return writes;
}

// ---- driver ----------------------------------------------------------------

export function analyze(parsedFiles) {
  const registry = new Registry(parsedFiles);
  const views = registry.buildViews();
  const acc = new Map();

  for (const view of views) {
    const reach = computeReachability(view);

    const absorb = (r, reachMap) => {
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
    };

    for (const desc of view.methods.values()) {
      if (!desc.node || !desc.node.body) continue;
      const wrapped = view.effectiveStatements(desc);
      const reachMap = reach.get(descKey(desc)) || new Map();

      for (const r of [
        ...runDelegatecallRule(view, desc, wrapped),
        ...runSelfdestructRule(view, desc, wrapped),
        ...runUncheckedCallRule(view, desc, wrapped),
      ]) {
        absorb(r, reachMap);
      }
    }

    // File-level (free) functions are scanned for the selfdestruct rule as
    // well: an entry may reach a destroy operation through one.
    for (const desc of view.freeFunctions.values()) {
      if (!desc.node || !desc.node.body) continue;
      const wrapped = view.effectiveStatements(desc);
      const reachMap = reach.get(descKey(desc)) || new Map();
      for (const r of runSelfdestructRule(view, desc, wrapped)) {
        absorb(r, reachMap);
      }
    }

    // STATE_UPDATE_AFTER_CALL: one path-sensitive, cross-function walk per
    // view. Reachability of an ordered (interaction ... write) path is
    // "an entry reaches the root frame whose walk proved the path".
    for (const wEntry of runStateEngine(view).values()) {
      const key = `STATE_UPDATE_AFTER_CALL:${wEntry.file}:${wEntry.location.startOffset}:${wEntry.location.endOffset}`;
      let f = acc.get(key);
      if (!f) {
        f = {
          ruleId: 'STATE_UPDATE_AFTER_CALL',
          severity: RULES.STATE_UPDATE_AFTER_CALL.severity,
          file: wEntry.file, location: wEntry.location,
          detail: { ruleId: 'STATE_UPDATE_AFTER_CALL', stateVar: wEntry.stateVar },
          kind: 'state',
          cands: [],    // reachable witnesses: {ek, depth, chainWrite, chainInter, wFile, wLoc}
          fallback: [], // {depth, wFile, wLoc} for the unreachable case
        };
        acc.set(key, f);
      }
      const reachWrite = reach.get(wEntry.frameKey) || new Map();
      for (const w of wEntry.witnesses.values()) {
        const reachInter = reach.get(w.frameKey) || new Map();
        for (const [rootKey, depth] of w.byRoot) {
          const rootReach = reach.get(rootKey);
          if (rootReach) {
            for (const ek of rootReach.keys()) {
              const chainWrite = reachWrite.get(ek);
              const chainInter = reachInter.get(ek);
              if (!chainWrite || !chainInter) continue;
              f.cands.push({
                ek, depth, chainWrite, chainInter, wFile: w.file, wLoc: w.loc,
              });
            }
          }
          f.fallback.push({ depth, wFile: w.file, wLoc: w.loc });
        }
      }
    }
  }

  return finalize(acc);
}

function locOf(file, loc) {
  return {
    file,
    startLine: loc.startLine,
    startColumn: loc.startColumn,
    endLine: loc.endLine,
    endColumn: loc.endColumn,
  };
}

function finalize(acc) {
  const findings = [];
  for (const f of acc.values()) {
    if (f.kind === 'state') {
      findings.push(finalizeState(f));
      continue;
    }
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
    } else if (d.ruleId === 'SELFDESTRUCT_UNTRUSTED_BENEFICIARY') {
      message = 'selfdestruct/suicide 的受益人受函数参数、calldata、msg.sender、tx.origin 或可控存储值影响，合约销毁时资金可能流向攻击者控制的地址';
    } else if (d.ruleId === 'UNCHECKED_EXTERNAL_CALL') {
      message = `底层调用 ${d.prop} 的返回结果未在同函数后续控制流中检查，失败会被静默忽略`;
    } else {
      message = `公开入口在外部调用或转账之后写入重入敏感状态 ${d.stateVar}，违反 checks-effects-interactions 顺序`;
    }
    findings.push({
      ruleId: f.ruleId,
      severity: f.severity,
      message,
      location: locOf(f.file, f.location),
      reachable,
      evidence: {
        entryPoints: reachable ? entryPoints : [],
        callChain: reachable ? callChains[0] : [],
      },
    });
  }
  return findings;
}

// State-update findings carry an `interaction` witness: the external
// interaction that, on the same static path, precedes the storage write.
function finalizeState(f) {
  const d = f.detail;
  const message = `公开入口在外部调用或转账之后写入重入敏感状态 ${d.stateVar}，违反 checks-effects-interactions 顺序`;

  const entryCmp = (a, b) => {
    if (a.contract !== b.contract) return (a.contract || '') < (b.contract || '') ? -1 : 1;
    if (a.kind !== b.kind) return a.kind < b.kind ? -1 : 1;
    return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
  };

  // One row per entry: shortest write chain decides entry order, then the
  // entry identity (matching the generic finalizer's chain ordering).
  const perEntry = new Map();
  for (const c of f.cands) {
    const prev = perEntry.get(c.ek);
    if (!prev ||
        prev.chainWrite.length > c.chainWrite.length ||
        (prev.chainWrite.length === c.chainWrite.length &&
         entryCmp(prev.chainWrite[0], c.chainWrite[0]) > 0)) {
      perEntry.set(c.ek, c);
    }
  }
  const entryRows = [...perEntry.values()].sort((a, b) => {
    if (a.chainWrite.length !== b.chainWrite.length) {
      return a.chainWrite.length - b.chainWrite.length;
    }
    return entryCmp(a.chainWrite[0], b.chainWrite[0]);
  });

  const entryPoints = [];
  for (const c of entryRows) {
    const e = c.chainWrite[0];
    if (!entryPoints.some((x) => x.name === e.name && x.contract === e.contract &&
                                x.kind === e.kind)) {
      entryPoints.push(e);
    }
  }
  const reachable = entryPoints.length > 0;

  // Single witness across all (entry, witness) pairs: fewest function
  // frames; ties follow entry order, then the earliest interaction point.
  let chosen = null;
  if (reachable) {
    const entryIndex = (e) =>
      entryPoints.findIndex((x) => x.name === e.name && x.contract === e.contract &&
                                  x.kind === e.kind);
    const ranked = [...f.cands].sort((a, b) => {
      if (a.depth !== b.depth) return a.depth - b.depth;
      const ia = entryIndex(a.chainWrite[0]);
      const ib = entryIndex(b.chainWrite[0]);
      if (ia !== ib) return ia - ib;
      if (a.wFile !== b.wFile) return a.wFile < b.wFile ? -1 : 1;
      return a.wLoc.startOffset - b.wLoc.startOffset;
    });
    chosen = ranked[0];
  } else {
    const best = new Map();
    for (const x of f.fallback) {
      const k = `${x.wFile}:${x.wLoc.startOffset}`;
      const prior = best.get(k);
      if (!prior || prior.depth > x.depth) best.set(k, x);
    }
    const ranked = [...best.values()].sort((a, b) => {
      if (a.depth !== b.depth) return a.depth - b.depth;
      if (a.wFile !== b.wFile) return a.wFile < b.wFile ? -1 : 1;
      return a.wLoc.startOffset - b.wLoc.startOffset;
    });
    chosen = ranked[0] || null;
  }

  const interaction = {
    location: chosen ? locOf(chosen.wFile, chosen.wLoc) : null,
    callChain: reachable && chosen ? chosen.chainInter : [],
  };

  return {
    ruleId: f.ruleId,
    severity: f.severity,
    message,
    location: locOf(f.file, f.location),
    reachable,
    evidence: {
      entryPoints: reachable ? entryPoints : [],
      callChain: reachable ? entryRows[0].chainWrite : [],
      interaction,
    },
  };
}
