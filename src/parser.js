// Hand-written recursive-descent parser for the Solidity subset the
// analyzer needs. Tolerant by design: anything irrelevant to the three
// rules (events, structs, pragmas, imports, ...) is skipped structurally.

import { lex } from './lexer.js';

export class ParseError extends Error {
  constructor(message, token) {
    super(message);
    this.name = 'ParseError';
    this.startLine = token.startLine;
    this.startColumn = token.startColumn;
    this.startOffset = token.start;
  }
}

const PUNCT = (t, v) => t.type === 'punct' && t.value === v;
const IS = (t, v) => t.type === 'punct' && t.value === v;
const KW = (t, v) => t.type === 'keyword' && t.value === v;
const TYPE_KEYWORDS = new Set(['address']);
const LOCATION_KEYWORDS = new Set(['memory', 'storage', 'calldata']);
const STATE_VAR_KEYWORDS = new Set([
  'public', 'private', 'internal', 'constant', 'immutable', 'override',
]);

function spanOf(startTok, endTok) {
  return {
    startOffset: startTok.start,
    endOffset: endTok.end,
    startLine: startTok.startLine,
    startColumn: startTok.startColumn,
    endLine: endTok.endLine,
    endColumn: Math.max(1, endTok.endColumn - 1),
  };
}

export function parse(source) {
  const tokens = lex(source.charCodeAt(0) === 0xfeff ? source.slice(1) : source);
  const p = new Parser(tokens);
  return p.parseSourceUnit();
}

class Parser {
  constructor(tokens) {
    this.tokens = tokens;
    this.pos = 0;
  }

  peek(k = 0) { return this.tokens[this.pos + k]; }
  cur() { return this.tokens[this.pos]; }
  atEnd() { return this.cur().type === 'eof'; }
  is(v) { return IS(this.cur(), v); }
  isKw(v) { return KW(this.cur(), v); }
  nextIs(v, k = 0) { const t = this.peek(k); return t && IS(t, v); }
  nextIsKw(v, k = 0) { const t = this.peek(k); return t && KW(t, v); }

  eat(v) {
    if (!this.is(v)) {
      throw new ParseError(`Expected '${v}' but found '${this.cur().value || this.cur().type}'`, this.cur());
    }
    this.pos++;
  }
  eatKw(v) {
    if (!this.isKw(v)) {
      throw new ParseError(`Expected '${v}' but found '${this.cur().value || this.cur().type}'`, this.cur());
    }
    this.pos++;
  }
  accept(v) {
    if (this.is(v)) { this.pos++; return true; }
    return false;
  }
  acceptKw(v) {
    if (this.isKw(v)) { this.pos++; return true; }
    return false;
  }
  expectIdent() {
    const t = this.cur();
    if (t.type !== 'ident' && !(t.type === 'keyword' && TYPE_KEYWORDS.has(t.value))) {
      throw new ParseError(`Expected identifier but found '${t.value || t.type}'`, t);
    }
    this.pos++;
    return t.value;
  }

  loc(startTok, endTok = this.tokens[this.pos - 1]) {
    return spanOf(startTok, endTok);
  }

  // ---- Top level -------------------------------------------------------

  parseSourceUnit() {
    const node = { kind: 'sourceUnit', contracts: [], freeFunctions: [], freeVariables: [] };
    while (!this.atEnd()) {
      const t = this.cur();
      if (this.isKw('pragma')) { this.skipToSemicolon(); continue; }
      if (this.isKw('import')) { this.skipImport(); continue; }
      if (this.isKw('abstract')) {
        const save = this.pos;
        this.pos++;
        if (this.isKw('contract')) {
          this.pos++;
          node.contracts.push(this.parseContract('abstract contract'));
        } else {
          this.pos = save;
          throw new ParseError(`Unexpected token 'abstract'`, t);
        }
        continue;
      }
      if (this.isKw('contract') || this.isKw('interface') || this.isKw('library')) {
        const kind = this.cur().value;
        this.pos++;
        node.contracts.push(this.parseContract(kind));
        continue;
      }
      if (this.isKw('using')) { this.skipToSemicolon(); continue; }
      if (this.isKw('type')) { this.skipToSemicolon(); continue; }
      if (this.isKw('function')) {
        node.freeFunctions.push(this.parseFunction(null, 'function'));
        continue;
      }
      // free constant variable / error / anything type-led
      if (this.isKw('error') || this.isKw('event') || this.isKw('struct') || this.isKw('enum')) {
        this.skipMemberDeclaration();
        continue;
      }
      // file-level constant variable e.g. `uint256 constant X = ...;`
      if (this.tryParseStateVariable(null)) continue;
      throw new ParseError(`Unexpected token '${t.value || t.type}' at top level`, t);
    }
    return node;
  }

  skipToSemicolon() {
    let depth = 0;
    while (!this.atEnd()) {
      const t = this.cur();
      if (IS(t, '(') || IS(t, '[') || IS(t, '{')) depth++;
      else if (IS(t, ')') || IS(t, ']') || IS(t, '}')) depth--;
      else if (IS(t, ';') && depth === 0) { this.pos++; return; }
      this.pos++;
    }
  }

  skipImport() {
    // import ... ;  (may contain braces)
    let depth = 0;
    while (!this.atEnd()) {
      const t = this.cur();
      if (IS(t, '{')) depth++;
      else if (IS(t, '}')) depth--;
      else if (IS(t, ';') && depth === 0) { this.pos++; return; }
      this.pos++;
    }
  }

  parseContract(kind) {
    const startTok = this.tokens[this.pos - 1];
    const name = this.expectIdent();
    const bases = [];
    if (this.acceptKw('is')) {
      for (;;) {
        const path = [this.expectIdent()];
        while (this.accept('.')) path.push(this.expectIdent());
        // base constructor arguments
        if (this.is('(')) this.skipBalancedParens();
        bases.push(path[path.length - 1]);
        if (!this.accept(',')) break;
      }
    }
    this.eat('{');
    const contract = {
      kind, name, bases, nodes: [], stateVariables: [], loc: this.loc(startTok),
    };
    while (!this.is('}') && !this.atEnd()) {
      if (this.isKw('function')) { contract.nodes.push(this.parseFunction(name, 'function')); continue; }
      if (this.isKw('constructor')) { contract.nodes.push(this.parseFunction(name, 'constructor')); continue; }
      if (this.isKw('fallback')) { contract.nodes.push(this.parseFunction(name, 'fallback')); continue; }
      if (this.isKw('receive')) { contract.nodes.push(this.parseFunction(name, 'receive')); continue; }
      if (this.isKw('modifier')) { contract.nodes.push(this.parseFunction(name, 'modifier')); continue; }
      if (this.tryParseStateVariable(name, contract)) continue;
      this.skipMemberDeclaration();
    }
    this.eat('}');
    contract.loc = this.loc(startTok);
    return contract;
  }

  skipBalancedParens() {
    this.eat('(');
    let depth = 1;
    while (!this.atEnd() && depth > 0) {
      const t = this.cur();
      if (IS(t, '(')) depth++;
      else if (IS(t, ')')) depth--;
      this.pos++;
    }
  }

  skipMemberDeclaration() {
    // Skips event/error/struct/enum/using/type declarations to ';' or
    // balanced '{}'.
    const start = this.pos;
    if (this.isKw('using')) { this.skipToSemicolon(); return; }
    if (this.isKw('type')) { this.skipToSemicolon(); return; }
    if (this.isKw('error') || this.isKw('event')) { this.skipToSemicolon(); return; }
    if (this.isKw('struct') || this.isKw('enum') || this.isKw('contract') ||
        this.isKw('interface') || this.isKw('library')) {
      this.pos = start;
      // name then brace body
      this.pos++; // keyword
      if (this.cur().type === 'ident') this.pos++;
      while (!this.is('{') && !this.atEnd()) this.pos++;
      if (this.is('{')) {
        let depth = 0;
        do {
          const t = this.cur();
          if (IS(t, '{')) depth++;
          else if (IS(t, '}')) depth--;
          this.pos++;
        } while (!this.atEnd() && depth > 0);
      }
      this.accept(';');
      return;
    }
    // Unknown member: skip to ; or }, consuming balanced braces/parens.
    let depth = 0;
    while (!this.atEnd()) {
      const t = this.cur();
      if (IS(t, '(') || IS(t, '{') || IS(t, '[')) depth++;
      else if (IS(t, ')') || IS(t, '}') || IS(t, ']')) {
        if (depth === 0) return;
        depth--;
      } else if (IS(t, ';') && depth === 0) { this.pos++; return; }
      this.pos++;
    }
  }

  // ---- State variables --------------------------------------------------

  tryParseStateVariable(contractName, contract = null) {
    const save = this.pos;
    let typeNode;
    try {
      typeNode = this.parseTypeName();
    } catch (e) {
      this.pos = save;
      return false;
    }
    if (this.pos === save) { this.pos = save; return false; }

    // modifiers can appear between type and name: `mapping(..) public x`
    while (this.cur().type === 'keyword' && STATE_VAR_KEYWORDS.has(this.cur().value)) {
      this.pos++;
      if (this.is('(')) this.skipBalancedParens(); // override(...)
    }
    if (this.cur().type !== 'ident') { this.pos = save; return false; }
    // Reject things that are clearly not declarations.
    const nameTok = this.cur();
    const after = this.peek(1);
    if (after && (IS(after, '('))) { this.pos = save; return false; }

    const name = nameTok.value;
    this.pos++;
    let visibility = 'internal';
    // Visibility was consumed above; recover it:
    // (simpler: re-scan consumed tokens) -- track via keyword loop redo:
    // Instead inspect declaration by a lightweight rescan below.
    let initializer = null;
    if (this.accept('=')) initializer = this.parseExpression();
    const endTok = this.tokens[this.pos - 1];
    this.accept(';');

    // Recover visibility / mutability by rescanning consumed tokens.
    visibility = 'internal';
    let isConstant = false;
    let isImmutable = false;
    for (let i = save + 1; i < this.pos; i++) {
      const tk = this.tokens[i];
      if (tk.type === 'keyword' && tk.value === 'public') visibility = 'public';
      if (tk.type === 'keyword' && tk.value === 'private') visibility = 'private';
      if (tk.type === 'keyword' && tk.value === 'external') visibility = 'external';
      if (tk.type === 'keyword' && tk.value === 'constant') isConstant = true;
      if (tk.type === 'keyword' && tk.value === 'immutable') isImmutable = true;
    }

    const sv = {
      kind: 'stateVariable', name, visibility, isConstant, isImmutable,
      typeNode,
      contractName,
    };
    sv.loc = this.loc(this.tokens[save], endTok);
    if (contract) contract.stateVariables.push(sv);
    return true;
  }

  // ---- Functions --------------------------------------------------------

  parseFunction(contractName, kind) {
    const startTok = this.cur();
    this.pos++; // keyword

    let name = null;
    if (kind === 'function' || kind === 'modifier') {
      if (this.cur().type === 'ident') {
        name = this.cur().value;
        this.pos++;
      } else if (kind === 'function') {
        // unnamed function: old-style fallback
        kind = 'fallback';
      }
    }

    const params = (kind === 'modifier' && !this.is('(')) ? [] : this.parseParameterList();
    let returnParams = [];
    if (this.acceptKw('returns')) returnParams = this.parseParameterList();

    let visibility = null;
    let stateMutability = null;
    let isVirtual = false;
    const modifiers = [];
    while (!this.is('{') && !this.is(';') && !this.atEnd()) {
      const t = this.cur();
      if (t.type === 'keyword') {
        if (t.value === 'public' || t.value === 'external' ||
            t.value === 'internal' || t.value === 'private') {
          visibility = t.value; this.pos++; continue;
        }
        if (t.value === 'pure' || t.value === 'view' || t.value === 'payable') {
          stateMutability = t.value; this.pos++; continue;
        }
        if (t.value === 'virtual') { isVirtual = true; this.pos++; continue; }
        if (t.value === 'constant') { this.pos++; continue; }
        if (t.value === 'override') {
          this.pos++;
          if (this.is('(')) this.skipBalancedParens();
          continue;
        }
        if (t.value === 'returns') {
          this.pos++;
          returnParams = this.parseParameterList();
          continue;
        }
      }
      // modifier invocation: path optionally followed by args
      const modName = this.parseModifierInvocation();
      modifiers.push(modName);
    }
    if (visibility === null) {
      if (kind === 'fallback' || kind === 'receive') visibility = 'external';
      else visibility = 'internal';
    }

    let body = null;
    if (this.is('{')) body = this.parseBlock();
    else this.accept(';');

    return {
      kind: 'function', functionKind: kind, name, contractName,
      params, returnParams, visibility, stateMutability, isVirtual,
      modifiers, body, loc: this.loc(startTok),
    };
  }

  parseModifierInvocation() {
    let name = this.expectIdent();
    while (this.accept('.')) name = this.expectIdent();
    if (this.is('(')) this.skipBalancedParens();
    return name;
  }

  parseParameterList() {
    this.eat('(');
    const params = [];
    while (!this.is(')') && !this.atEnd()) {
      const typeNode = this.parseTypeName();
      const keywords = [];
      while (this.cur().type === 'keyword' &&
             (LOCATION_KEYWORDS.has(this.cur().value) || this.cur().value === 'indexed' ||
              this.cur().value === 'payable')) {
        keywords.push(this.cur().value);
        this.pos++;
      }
      let name = null;
      if (this.cur().type === 'ident') { name = this.cur().value; this.pos++; }
      // rare: location keyword after name
      while (this.cur().type === 'keyword' && LOCATION_KEYWORDS.has(this.cur().value)) this.pos++;
      params.push({
        name,
        typeNode,
        dataLocation: keywords.includes('calldata') ? 'calldata'
          : keywords.includes('memory') ? 'memory'
          : keywords.includes('storage') ? 'storage' : null,
      });
      if (!this.accept(',')) break;
    }
    this.eat(')');
    return params;
  }

  // ---- Type names -------------------------------------------------------

  parseTypeName() {
    const startTok = this.cur();
    if (this.isKw('mapping')) {
      this.pos++;
      this.eat('(');
      const keyType = this.parseTypeName();
      // '=>' is lexed as a single token; tolerate '=' '>' as well.
      if (this.is('=>')) this.pos++;
      else { this.eat('='); this.eat('>'); }
      const valueType = this.parseTypeName();
      this.eat(')');
      return { kind: 'typeMapping', keyType, valueType, loc: this.loc(startTok) };
    }
    if (this.isKw('function')) {
      // function type, e.g. function(uint) external view returns (uint)
      this.pos++;
      this.parseParameterList();
      if (this.acceptKw('returns')) this.parseParameterList();
      while (this.cur().type === 'keyword' &&
             ['internal', 'external', 'pure', 'view', 'payable'].includes(this.cur().value)) {
        this.pos++;
      }
      return { kind: 'typeFunction', loc: this.loc(startTok) };
    }
    const path = [this.typePathIdent()];
    while (this.accept('.')) path.push(this.expectIdent());
    this.acceptKw('payable');
    let node = { kind: 'typeElementary', path, loc: this.loc(startTok) };
    while (this.is('[')) {
      this.pos++;
      let length = null;
      if (!this.is(']')) length = this.parseExpression();
      this.eat(']');
      node = { kind: 'typeArray', base: node, length, loc: spanOf(startTok, this.tokens[this.pos - 1]) };
    }
    return node;
  }

  typePathIdent() {
    const t = this.cur();
    if (t.type === 'ident' || (t.type === 'keyword' && TYPE_KEYWORDS.has(t.value))) {
      this.pos++;
      return t.value;
    }
    throw new ParseError(`Expected type name but found '${t.value || t.type}'`, t);
  }

  // ---- Statements -------------------------------------------------------

  parseBlock() {
    const startTok = this.cur();
    this.eat('{');
    const statements = [];
    while (!this.is('}') && !this.atEnd()) {
      const s = this.parseStatement();
      if (s) statements.push(s);
    }
    this.eat('}');
    return { kind: 'block', statements, loc: this.loc(startTok) };
  }

  parseStatement() {
    const t = this.cur();
    if (IS(t, '{')) return this.parseBlock();
    if (IS(t, ';')) { this.pos++; return null; }
    if (KW(t, 'if')) return this.parseIf();
    if (KW(t, 'while')) return this.parseWhile();
    if (KW(t, 'do')) return this.parseDoWhile();
    if (KW(t, 'for')) return this.parseFor();
    if (KW(t, 'return')) return this.parseReturn();
    if (KW(t, 'break') || KW(t, 'continue')) {
      const startTok = t; this.pos++; this.eat(';');
      return { kind: t.value, loc: this.loc(startTok) };
    }
    if (KW(t, 'throw')) {
      const startTok = t; this.pos++; this.accept(';');
      return { kind: 'throw', loc: this.loc(startTok) };
    }
    if (KW(t, 'unchecked')) {
      const startTok = t; this.pos++;
      const body = this.parseBlock();
      return { kind: 'unchecked', body, loc: this.loc(startTok) };
    }
    if (KW(t, 'assembly')) return this.parseAssembly();
    if (KW(t, 'try')) return this.parseTry();
    if (KW(t, 'emit')) {
      const startTok = t; this.pos++;
      const expr = this.parseExpression();
      this.eat(';');
      return { kind: 'emit', expr, loc: this.loc(startTok) };
    }
    if (KW(t, 'revert')) {
      // revert; | revert("msg") | revert CustomError(args)
      const startTok = t; this.pos++;
      let args = [];
      if (this.cur().type === 'ident' && this.peek(1) && this.nextIs('(', 1)) {
        this.pos++; // error name
      }
      if (this.is('(')) args = this.parseCallArguments();
      this.eat(';');
      const expr = {
        kind: 'call',
        callee: { kind: 'ident', name: 'revert', loc: this.loc(startTok) },
        args, options: null, loc: this.loc(startTok),
      };
      return { kind: 'expression', expr, loc: this.loc(startTok) };
    }
    if (KW(t, 'delete')) {
      const startTok = t; this.pos++;
      const expr = this.parseExpression();
      this.eat(';');
      return { kind: 'expression', expr: { kind: 'unary', op: 'delete', prefix: true, operand: expr, loc: this.loc(startTok) }, loc: this.loc(startTok) };
    }
    if (t.type === 'ident' && t.value === '_' && this.peek(1) && IS(this.peek(1), ';')) {
      this.pos += 2;
      return { kind: 'placeholder', loc: this.loc(t) };
    }

    const varDecl = this.tryParseVariableDeclaration();
    if (varDecl) return varDecl;

    const startTok = t;
    const expr = this.parseExpression();
    this.eat(';');
    return { kind: 'expression', expr, loc: this.loc(startTok) };
  }

  parseIf() {
    const startTok = this.cur();
    this.pos++;
    this.eat('(');
    const test = this.parseExpression();
    this.eat(')');
    const consequent = this.parseStatement();
    let alternate = null;
    if (this.acceptKw('else')) alternate = this.parseStatement();
    return { kind: 'if', test, consequent, alternate, loc: this.loc(startTok) };
  }
  parseWhile() {
    const startTok = this.cur();
    this.pos++;
    this.eat('(');
    const test = this.parseExpression();
    this.eat(')');
    const body = this.parseStatement();
    return { kind: 'while', test, body, loc: this.loc(startTok) };
  }
  parseDoWhile() {
    const startTok = this.cur();
    this.pos++;
    const body = this.parseStatement();
    this.eatKw('while');
    this.eat('(');
    const test = this.parseExpression();
    this.eat(')');
    this.eat(';');
    return { kind: 'doWhile', body, test, loc: this.loc(startTok) };
  }
  parseFor() {
    const startTok = this.cur();
    this.pos++;
    this.eat('(');
    let init = null;
    if (!this.is(';')) {
      init = this.tryParseVariableDeclaration({ noSemicolon: true });
      if (!init) {
        const expr = this.parseExpression();
        init = { kind: 'expression', expr, loc: expr.loc };
      }
    }
    this.eat(';');
    let test = null;
    if (!this.is(';')) test = this.parseExpression();
    this.eat(';');
    let update = null;
    if (!this.is(')')) update = this.parseExpression();
    this.eat(')');
    const body = this.parseStatement();
    return { kind: 'for', init, test, update, body, loc: this.loc(startTok) };
  }
  parseReturn() {
    const startTok = this.cur();
    this.pos++;
    let expr = null;
    if (!this.is(';')) expr = this.parseExpression();
    this.eat(';');
    return { kind: 'return', expr, loc: this.loc(startTok) };
  }
  parseAssembly() {
    const startTok = this.cur();
    this.pos++;
    // optional quoted dialect / quoted name list
    if (this.cur().type === 'string') this.pos++;
    // optional identifier (assembly name)
    if (this.cur().type === 'ident') this.pos++;
    if (this.cur().type === 'string') this.pos++;
    this.eat('{');
    let depth = 1;
    while (!this.atEnd() && depth > 0) {
      const t = this.cur();
      if (IS(t, '{')) depth++;
      else if (IS(t, '}')) depth--;
      if (depth === 0) { this.pos++; break; }
      this.pos++;
    }
    return { kind: 'assembly', loc: this.loc(startTok) };
  }
  parseTry() {
    const startTok = this.cur();
    this.pos++;
    const externalCall = this.parseExpression();
    let returns = null;
    if (this.acceptKw('returns')) returns = this.parseParameterList();
    const body = this.parseBlock();
    const clauses = [];
    while (this.isKw('catch')) {
      this.pos++;
      if (this.cur().type === 'ident') this.pos++; // Error / Panic keyword-ish name
      if (this.is('(')) this.parseParameterList();
      clauses.push(this.parseBlock());
    }
    return { kind: 'try', externalCall, returns, body, clauses, loc: this.loc(startTok) };
  }

  tryParseVariableDeclaration(opts = {}) {
    const noSemicolon = !!opts.noSemicolon;
    const startTok = this.cur();

    // Tuple declaration: (Type a, Type b) = ...  /  (Type a, ...)
    if (this.is('(')) {
      const save = this.pos;
      this.pos++;
      const components = [];
      let ok = true;
      while (!this.is(')') && !this.atEnd()) {
        if (this.is(',')) { components.push(null); this.pos++; continue; }
        const cs = this.pos;
        let typeNode;
        try { typeNode = this.parseTypeName(); } catch (e) { ok = false; break; }
        if (this.pos === cs) { ok = false; break; }
        const kws = [];
        while (this.cur().type === 'keyword' &&
               (LOCATION_KEYWORDS.has(this.cur().value) || this.cur().value === 'constant')) {
          kws.push(this.cur().value); this.pos++;
        }
        if (this.cur().type !== 'ident') { ok = false; break; }
        const nameTok = this.cur(); this.pos++;
        components.push({
          name: nameTok.value, typeNode,
          dataLocation: kws.includes('storage') ? 'storage'
            : kws.includes('memory') ? 'memory'
            : kws.includes('calldata') ? 'calldata' : null,
        });
        if (this.is(',')) continue;
        break;
      }
      if (ok && this.is(')') && components.some((c) => c !== null)) {
        this.pos++;
        while (this.cur().type === 'keyword' && LOCATION_KEYWORDS.has(this.cur().value)) this.pos++;
        let initializer = null;
        if (this.accept('=')) initializer = this.parseExpression();
        if (!noSemicolon) this.eat(';');
        return {
          kind: 'varDecl', components, initializer, loc: this.loc(startTok),
          names: components.filter(Boolean).map((c) => c.name),
        };
      }
      this.pos = save;
    }

    // Simple declaration: TypeName name [loc] (= expr)?
    const save = this.pos;
    let typeNode;
    try {
      typeNode = this.parseTypeName();
    } catch (e) {
      this.pos = save;
      return null;
    }
    if (this.pos === save) return null;
    while (this.cur().type === 'keyword' && LOCATION_KEYWORDS.has(this.cur().value)) this.pos++;
    if (this.cur().type !== 'ident') { this.pos = save; return null; }
    const nameTok = this.cur();
    const cont = this.peek(1);
    const isCont = cont && (IS(cont, ';') || IS(cont, '=') || IS(cont, ',') ||
      (cont.type === 'keyword' && (LOCATION_KEYWORDS.has(cont.value) || cont.value === 'constant')));
    if (!isCont) { this.pos = save; return null; }
    this.pos++;
    const kws = [];
    while (this.cur().type === 'keyword' &&
           (LOCATION_KEYWORDS.has(this.cur().value) || this.cur().value === 'constant')) {
      kws.push(this.cur().value); this.pos++;
    }
    let initializer = null;
    if (this.accept('=')) initializer = this.parseExpression();
    if (!noSemicolon) this.eat(';');
    const comp = {
      name: nameTok.value, typeNode,
      dataLocation: kws.includes('storage') ? 'storage'
        : kws.includes('memory') ? 'memory'
        : kws.includes('calldata') ? 'calldata' : null,
    };
    return {
      kind: 'varDecl', components: [comp], initializer, loc: this.loc(startTok),
      names: [nameTok.value],
    };
  }

  // ---- Expressions ------------------------------------------------------

  parseExpression() {
    return this.parseAssignment();
  }

  parseAssignment() {
    const left = this.parseTernary();
    const t = this.cur();
    if (t.type === 'punct' && ['=', '+=', '-=', '*=', '/=', '%=', '|=', '&=', '^=', '<<=', '>>='].includes(t.value)) {
      const op = t.value;
      this.pos++;
      const value = this.parseAssignment();
      return {
        kind: 'assign', op, target: left, value,
        loc: {
          startOffset: left.loc.startOffset, startLine: left.loc.startLine,
          startColumn: left.loc.startColumn,
          endOffset: value.loc.endOffset, endLine: value.loc.endLine,
          endColumn: value.loc.endColumn,
        },
      };
    }
    return left;
  }

  parseTernary() {
    const test = this.parseBinary(0);
    if (this.accept('?')) {
      const cons = this.parseAssignment();
      this.eat(':');
      const alt = this.parseTernary();
      return { kind: 'conditional', test, cons, alt, loc: { ...test.loc, endOffset: alt.loc.endOffset, endLine: alt.loc.endLine, endColumn: alt.loc.endColumn } };
    }
    return test;
  }

  // precedence: higher binds tighter
  static BINARY_PRECEDENCE = {
    '||': 1, '&&': 2,
    '|': 3, '^': 4, '&': 5,
    '==': 6, '!=': 6,
    '<': 7, '>': 7, '<=': 7, '>=': 7,
    '<<': 8, '>>': 8,
    '+': 9, '-': 9,
    '*': 10, '/': 10, '%': 10,
    '**': 11,
  };

  parseBinary(minPrec) {
    let left = this.parseUnary();
    for (;;) {
      const t = this.cur();
      const prec = t.type === 'punct' ? Parser.BINARY_PRECEDENCE[t.value] : undefined;
      if (prec === undefined || prec < minPrec) break;
      this.pos++;
      const right = this.parseBinary(prec === 11 ? prec : prec + 1);
      left = {
        kind: 'binary', op: t.value, left, right,
        loc: {
          startOffset: left.loc.startOffset, startLine: left.loc.startLine,
          startColumn: left.loc.startColumn,
          endOffset: right.loc.endOffset, endLine: right.loc.endLine,
          endColumn: right.loc.endColumn,
        },
      };
    }
    return left;
  }

  parseUnary() {
    const t = this.cur();
    if (t.type === 'punct' && ['!', '~', '-', '+', '++', '--'].includes(t.value)) {
      this.pos++;
      const operand = this.parseUnary();
      return { kind: 'unary', op: t.value, prefix: true, operand, loc: this.loc(t) };
    }
    if (KW(t, 'after') || KW(t, 'delete')) {
      this.pos++;
      const operand = this.parseUnary();
      return { kind: 'unary', op: KW(t, 'after') ? 'after' : 'delete', prefix: true, operand, loc: this.loc(t) };
    }
    return this.parsePostfix();
  }

  parsePostfix() {
    let node = this.parsePrimary();
    for (;;) {
      if (this.accept('.')) {
        const propTok = this.cur();
        const property = this.expectIdent();
        node = {
          kind: 'member', object: node, property,
          propertyLoc: this.loc(propTok), loc: this.loc(this.firstTok(node)),
        };
        continue;
      }
      if (this.is('[')) {
        const startTok = this.firstTok(node);
        this.pos++;
        let index = null;
        if (!this.is(']')) index = this.parseExpression();
        this.eat(']');
        node = { kind: 'index', object: node, index, loc: this.loc(startTok) };
        continue;
      }
      if (this.is('(')) {
        const startTok = this.firstTok(node);
        const args = this.parseCallArguments();
        node = { kind: 'call', callee: node, args, options: null, loc: this.loc(startTok) };
        continue;
      }
      // call options: callee {value: x, gas: y} ( args )
      if (this.is('{') && this.callOptionsAhead()) {
        const startTok = this.firstTok(node);
        const options = this.parseCallOptions();
        const args = this.parseCallArguments();
        node = { kind: 'call', callee: node, args, options, loc: this.loc(startTok) };
        continue;
      }
      if (this.isPunct('++') || this.isPunct('--')) {
        const op = this.cur().value;
        const startTok = this.firstTok(node);
        this.pos++;
        node = { kind: 'unary', op, prefix: false, operand: node, loc: this.loc(startTok) };
        continue;
      }
      break;
    }
    return node;
  }

  isPunct(v) { return this.is(v); }

  firstTok(node) {
    for (const tk of this.tokens) if (tk.start === node.loc.startOffset) return tk;
    return this.cur();
  }

  callOptionsAhead() {
    // { ... } must be immediately followed by '(' to count as options.
    let i = this.pos;
    if (!IS(this.tokens[i], '{')) return false;
    let depth = 0;
    for (; i < this.tokens.length; i++) {
      const t = this.tokens[i];
      if (IS(t, '{') || IS(t, '(') || IS(t, '[')) depth++;
      else if (IS(t, '}') || IS(t, ')') || IS(t, ']')) {
        depth--;
        if (depth === 0) { i++; break; }
      } else if (IS(t, ';') && depth === 0) return false;
    }
    return i < this.tokens.length && IS(this.tokens[i], '(');
  }

  parseCallOptions() {
    this.eat('{');
    const options = [];
    while (!this.is('}') && !this.atEnd()) {
      const name = this.expectIdent();
      this.eat(':');
      const value = this.parseExpression();
      options.push({ name, value });
      if (!this.accept(',')) break;
    }
    this.eat('}');
    return options;
  }

  parseCallArguments() {
    this.eat('(');
    const args = [];
    while (!this.is(')') && !this.atEnd()) {
      if (this.is('{')) {
        // struct literal argument: { name: expr, ... }
        args.push(this.parseStructLiteral());
      } else {
        // named call arguments: {name: expr} are normally brace-led;
        // here handle plain expressions
        args.push(this.parseExpression());
      }
      if (!this.accept(',')) break;
    }
    this.eat(')');
    return args;
  }

  parseStructLiteral() {
    const startTok = this.cur();
    this.eat('{');
    const fields = [];
    while (!this.is('}') && !this.atEnd()) {
      const name = this.expectIdent();
      this.eat(':');
      const value = this.parseExpression();
      fields.push({ name, value });
      if (!this.accept(',')) break;
    }
    this.eat('}');
    return { kind: 'structLiteral', fields, loc: this.loc(startTok) };
  }

  parsePrimary() {
    const t = this.cur();
    if (t.type === 'number' || t.type === 'string') {
      this.pos++;
      return { kind: 'literal', literalType: t.type, value: t.value, loc: this.loc(t) };
    }
    if (KW(t, 'new')) {
      this.pos++;
      const typeNode = this.parseTypeName();
      return { kind: 'newExpr', typeNode, loc: this.loc(t) };
    }
    if (t.type === 'ident' || t.type === 'keyword') {
      // keywords usable as values (true/false are idents; address casts etc.)
      this.pos++;
      return { kind: 'ident', name: t.value, loc: this.loc(t) };
    }
    if (IS(t, '(')) {
      this.pos++;
      const items = [];
      while (!this.is(')') && !this.atEnd()) {
        if (this.is(',')) { items.push(null); this.pos++; continue; }
        items.push(this.parseAssignment());
        if (this.is(')')) break;
        if (!this.accept(',')) break;
      }
      this.eat(')');
      if (items.length === 1) return items[0];
      return { kind: 'tuple', items, isArray: false, loc: this.loc(t) };
    }
    if (IS(t, '[')) {
      this.pos++;
      const items = [];
      while (!this.is(']') && !this.atEnd()) {
        if (this.is(',')) { items.push(null); this.pos++; continue; }
        items.push(this.parseAssignment());
        if (this.is(']')) break;
        if (!this.accept(',')) break;
      }
      this.eat(']');
      return { kind: 'tuple', items, isArray: true, loc: this.loc(t) };
    }
    throw new ParseError(`Unexpected token '${t.value || t.type}' in expression`, t);
  }
}
