'use strict';

// Contract model: effective (inheritance-flattened) members, entry points and
// the static call graph used for reachability. The most derived declaration
// wins when a base contract member is overridden.

const LOW_LEVEL_METHODS = new Set(['call', 'staticcall', 'send', 'transfer', 'delegatecall', 'callcode']);

function unwrap(node) {
  while (node && node.type === 'CallOptions') node = node.expression;
  return node;
}

// Generic pre-order visitor over the AST. cb receives (node, parents).
function visit(node, cb, parents = []) {
  if (!node || typeof node.type !== 'string') return;
  cb(node, parents);
  const nextParents = parents.concat(node);
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'type') continue;
    const value = node[key];
    if (Array.isArray(value)) {
      for (const item of value) visit(item, cb, nextParents);
    } else if (value && typeof value === 'object' && typeof value.type === 'string') {
      visit(value, cb, nextParents);
    }
  }
}

class ContractModel {
  constructor(contractNode, filePath) {
    this.node = contractNode;
    this.name = contractNode.name;
    this.kind = contractNode.kind;
    this.filePath = filePath;
    this.bases = contractNode.bases.map((b) => b.split('.').pop());
    this.stateVars = contractNode.stateVars;
    this.functions = contractNode.functions;
    this.modifiers = contractNode.modifiers;
  }
}

class Model {
  constructor(parsedFiles) {
    // parsedFiles: [{ path, ast }]
    this.contracts = [];
    this.byName = new Map();
    for (const { path, ast } of parsedFiles) {
      for (const contractNode of ast.contracts) {
        const model = new ContractModel(contractNode, path);
        model.fileAst = ast;
        this.contracts.push(model);
        if (!this.byName.has(model.name)) this.byName.set(model.name, model);
      }
    }
    this._effectiveCache = new Map();
    this._reachabilityCache = new Map();
  }

  // Effective members of a contract: own declarations override inherited ones
  // (final declaration wins), bases are merged left-to-right first.
  effective(contractName) {
    if (this._effectiveCache.has(contractName)) return this._effectiveCache.get(contractName);
    const result = {
      functions: new Map(), // name -> fn node (most derived)
      stateVars: new Map(), // name -> state var node
      modifiers: new Map(), // name -> modifier node
    };
    const self = this;
    const seen = new Set();
    function merge(name, into) {
      if (seen.has(name)) return;
      seen.add(name);
      const contract = self.byName.get(name);
      if (!contract) return;
      for (const base of contract.bases) merge(base, into);
      for (const fn of contract.functions) into.functions.set(fn.name, fn);
      for (const sv of contract.stateVars) into.stateVars.set(sv.name, sv);
      for (const mod of contract.modifiers) into.modifiers.set(mod.name, mod);
    }
    merge(contractName, result);
    this._effectiveCache.set(contractName, result);
    return result;
  }

  // Entry points: public/external functions, receive/fallback, constructors
  // and public state variable getters.
  entryPoints(contractName) {
    const eff = this.effective(contractName);
    const entries = [];
    for (const fn of eff.functions.values()) {
      if (fn.kind === 'constructor' || fn.kind === 'receive' || fn.kind === 'fallback') {
        entries.push({ name: fn.name, node: fn });
      } else if (fn.visibility === 'public' || fn.visibility === 'external') {
        entries.push({ name: fn.name, node: fn });
      }
    }
    for (const sv of eff.stateVars.values()) {
      if (sv.visibility === 'public') entries.push({ name: sv.name, node: null });
    }
    return entries;
  }

  // Internal call edges from one function/modifier body to other members of
  // the same contract (direct calls, this.f(), super.f(), modifiers).
  callTargets(contractName, fnNode) {
    const eff = this.effective(contractName);
    const targets = [];
    for (const inv of fnNode.modifierInvocations || []) {
      const mod = eff.modifiers.get(inv.name);
      if (mod && mod.body) targets.push(mod);
    }
    if (!fnNode.body) return targets;
    visit(fnNode.body, (node) => {
      if (node.type !== 'Call') return;
      const callee = unwrap(node.callee);
      if (callee.type === 'Identifier') {
        const target = eff.functions.get(callee.name);
        if (target && target !== fnNode && target.body) targets.push(target);
      } else if (callee.type === 'Member') {
        const obj = unwrap(callee.object);
        if (obj.type === 'Identifier' && obj.name === 'this') {
          const target = eff.functions.get(callee.property);
          if (target && target.body) targets.push(target);
        } else if (obj.type === 'Identifier' && obj.name === 'super') {
          const contract = this.byName.get(contractName);
          if (contract) {
            for (const base of contract.bases) {
              const baseEff = this.effective(base);
              const target = baseEff.functions.get(callee.property);
              if (target && target.body) { targets.push(target); break; }
            }
          }
        }
      }
    });
    return targets;
  }

  // BFS from every entry point over the static call graph.
  // Returns Map<fnNode, {reachable, entryPoints, callChain}>.
  reachability(contractName) {
    if (this._reachabilityCache.has(contractName)) return this._reachabilityCache.get(contractName);
    const info = new Map();
    const queue = [];
    for (const entry of this.entryPoints(contractName)) {
      if (!entry.node || !entry.node.body) continue;
      let rec = info.get(entry.node);
      if (!rec) {
        rec = { reachable: true, entryPoints: [], callChain: null };
        info.set(entry.node, rec);
        queue.push(entry.node);
      }
      if (!rec.entryPoints.includes(entry.name)) rec.entryPoints.push(entry.name);
      if (!rec.callChain) rec.callChain = [entry.name];
    }
    const chainOf = new Map();
    for (const [node, rec] of info) chainOf.set(node, rec.callChain);
    while (queue.length > 0) {
      const current = queue.shift();
      const currentRec = info.get(current);
      for (const target of this.callTargets(contractName, current)) {
        let rec = info.get(target);
        if (!rec) {
          rec = { reachable: true, entryPoints: [], callChain: null };
          info.set(target, rec);
          queue.push(target);
        }
        for (const ep of currentRec.entryPoints) {
          if (!rec.entryPoints.includes(ep)) rec.entryPoints.push(ep);
        }
        if (!rec.callChain) {
          const targetName = target.name;
          rec.callChain = currentRec.callChain.concat(targetName);
        }
      }
    }
    this._reachabilityCache.set(contractName, info);
    return info;
  }

  reachabilityOf(contractName, fnNode) {
    const info = this.reachability(contractName);
    const rec = info.get(fnNode);
    if (!rec) return { reachable: false, entryPoints: [], callChain: [] };
    return rec;
  }
}

module.exports = { Model, visit, unwrap, LOW_LEVEL_METHODS };
