'use strict';

// Recursive-descent parser for a practical subset of Solidity. Produces an AST
// where every node carries a 1-based loc: {startLine, startColumn, endLine, endColumn}.
// Throws ParseError {startLine, startColumn} on unparseable input.

class ParseError extends Error {
  constructor(message, line, column) {
    super(message);
    this.name = 'ParseError';
    this.startLine = line;
    this.startColumn = column;
  }
}

const VISIBILITY = new Set(['public', 'private', 'internal', 'external']);
const MUTABILITY = new Set(['pure', 'view', 'payable']);
const ASSIGN_OPS = new Set(['=', '+=', '-=', '*=', '/=', '%=', '|=', '&=', '^=', '<<=', '>>=']);

class Parser {
  constructor(tokens) {
    this.toks = tokens;
    this.i = 0;
  }

  peek(k = 0) {
    return this.toks[Math.min(this.i + k, this.toks.length - 1)];
  }
  at(value) {
    const t = this.peek();
    return (t.type === 'punct' || t.type === 'id') && t.value === value;
  }
  atAny(values) {
    return values.some((v) => this.at(v));
  }
  atType(type) {
    return this.peek().type === type;
  }
  next() {
    return this.toks[this.i++];
  }
  err(message, tok) {
    const t = tok || this.peek();
    throw new ParseError(message, t.line, t.col);
  }
  expect(value) {
    const t = this.peek();
    if (t.value !== value) this.err(`expected '${value}' but found '${t.value}'`, t);
    this.i += 1;
    return t;
  }
  expectId() {
    const t = this.peek();
    if (t.type !== 'id') this.err(`expected identifier but found '${t.value}'`, t);
    this.i += 1;
    return t;
  }
  node(type, startTok, props, endTok) {
    const end = endTok || this.toks[this.i - 1] || startTok;
    return Object.assign({
      type,
      loc: {
        startLine: startTok.line,
        startColumn: startTok.col,
        endLine: end.endLine,
        endColumn: end.endCol,
      },
    }, props);
  }

  // ---- source unit ----

  parseSourceUnit() {
    const start = this.peek();
    const contracts = [];
    const freeFunctions = [];
    while (!this.atType('eof')) {
      if (this.at('pragma') || this.at('import')) {
        this.skipToSemicolon();
      } else if (this.at('abstract')) {
        this.next();
        contracts.push(this.parseContract(true));
      } else if (this.atAny(['contract', 'library', 'interface'])) {
        contracts.push(this.parseContract(false));
      } else if (this.at('struct')) {
        this.parseStruct();
      } else if (this.at('enum')) {
        this.parseEnum();
      } else if (this.at('using') || this.at('error') || this.at('type')) {
        this.skipToSemicolon();
      } else if (this.at('function')) {
        freeFunctions.push(this.parseFunction(null));
      } else {
        // top-level constant / variable declaration; parse and discard
        const saved = this.i;
        try {
          this.parseType();
          while (this.atAny(['public', 'private', 'internal', 'constant', 'immutable', 'override'])) this.next();
          this.expectId();
          if (this.at('=')) { this.next(); this.parseExpression(); }
          this.expect(';');
        } catch (e) {
          this.i = saved;
          this.err(`unexpected token '${this.peek().value}' at top level`);
        }
      }
    }
    return this.node('SourceUnit', start, { contracts, freeFunctions }, this.peek());
  }

  skipToSemicolon() {
    while (!this.at(';') && !this.atType('eof')) this.next();
    this.expect(';');
  }

  skipBalanced(open, close) {
    this.expect(open);
    let depth = 1;
    while (depth > 0) {
      if (this.atType('eof')) this.err(`unterminated '${open}'`);
      const t = this.next();
      if (t.value === open) depth += 1;
      else if (t.value === close) depth -= 1;
    }
  }

  parseStruct() {
    this.expect('struct');
    this.expectId();
    this.expect('{');
    while (!this.at('}')) {
      this.parseType();
      this.expectId();
      this.expect(';');
    }
    this.expect('}');
  }

  parseEnum() {
    this.expect('enum');
    this.expectId();
    this.expect('{');
    while (!this.at('}')) {
      this.expectId();
      if (this.at(',')) this.next(); else break;
    }
    this.expect('}');
  }

  // ---- contracts ----

  parseContract(isAbstract) {
    const start = this.next(); // contract | library | interface
    const kind = start.value;
    const nameTok = this.expectId();
    const bases = [];
    if (this.at('is')) {
      this.next();
      do {
        const parts = [this.expectId().value];
        while (this.at('.')) { this.next(); parts.push(this.expectId().value); }
        if (this.at('(')) {
          let depth = 0;
          do {
            const t = this.next();
            if (t.value === '(') depth += 1;
            else if (t.value === ')') depth -= 1;
          } while (depth > 0 && !this.atType('eof'));
        }
        bases.push(parts.join('.'));
        if (this.at(',')) this.next(); else break;
      } while (true);
    }
    this.expect('{');
    const stateVars = [];
    const functions = [];
    const modifiers = [];
    while (!this.at('}')) {
      if (this.atType('eof')) this.err('unterminated contract body');
      if (this.at('function')) {
        functions.push(this.parseFunction(nameTok.value));
      } else if (this.at('constructor')) {
        functions.push(this.parseConstructor());
      } else if (this.at('receive') || this.at('fallback')) {
        functions.push(this.parseFallbackReceive());
      } else if (this.at('modifier')) {
        modifiers.push(this.parseModifier());
      } else if (this.at('event') || this.at('error') || this.at('using') || this.at('type')) {
        this.skipToSemicolon();
      } else if (this.at('struct')) {
        this.parseStruct();
      } else if (this.at('enum')) {
        this.parseEnum();
      } else {
        stateVars.push(this.parseStateVar());
      }
    }
    const closeBrace = this.expect('}');
    return this.node('Contract', start, {
      kind,
      isAbstract,
      name: nameTok.value,
      bases,
      stateVars,
      functions,
      modifiers,
    }, closeBrace);
  }

  parseStateVar() {
    const start = this.peek();
    const varType = this.parseType();
    let visibility = 'internal';
    let isConstant = false;
    let isImmutable = false;
    while (true) {
      if (this.at('public') || this.at('private') || this.at('internal') || this.at('external')) {
        visibility = this.next().value;
      } else if (this.at('constant')) {
        isConstant = true; this.next();
      } else if (this.at('immutable')) {
        isImmutable = true; this.next();
      } else if (this.at('override')) {
        this.next();
        if (this.at('(')) this.skipBalanced('(', ')');
      } else break;
    }
    const nameTok = this.expectId();
    let init = null;
    if (this.at('=')) { this.next(); init = this.parseExpression(); }
    const semi = this.expect(';');
    return this.node('StateVar', start, {
      name: nameTok.value, varType, visibility, isConstant, isImmutable, init,
    }, semi);
  }

  parseModifier() {
    const start = this.expect('modifier');
    const nameTok = this.expectId();
    let params = [];
    if (this.at('(')) params = this.parseParams();
    while (this.at('virtual')) this.next();
    if (this.at('override')) {
      this.next();
      if (this.at('(')) this.skipBalanced('(', ')');
    }
    let body = null;
    if (this.at(';')) this.next();
    else body = this.parseBlock();
    return this.node('Modifier', start, { name: nameTok.value, params, body });
  }

  parseConstructor() {
    const start = this.expect('constructor');
    const params = this.parseParams();
    const mods = this.parseFunctionModifiers();
    const body = this.at(';') ? (this.next(), null) : this.parseBlock();
    return this.node('Function', start, {
      name: 'constructor',
      kind: 'constructor',
      params,
      returns: [],
      visibility: mods.visibility || 'public',
      mutability: mods.mutability,
      modifierInvocations: mods.invocations,
      body,
    });
  }

  parseFallbackReceive() {
    const start = this.next();
    const kind = start.value; // receive | fallback
    let params = [];
    let returns = [];
    if (this.at('(')) params = this.parseParams();
    const mods = this.parseFunctionModifiers();
    if (this.at('returns')) { this.next(); returns = this.parseParams(); }
    const body = this.at(';') ? (this.next(), null) : this.parseBlock();
    return this.node('Function', start, {
      name: kind,
      kind,
      params,
      returns,
      visibility: mods.visibility || 'external',
      mutability: mods.mutability,
      modifierInvocations: mods.invocations,
      body,
    });
  }

  parseFunction(contractName) {
    const start = this.expect('function');
    let name = null;
    if (this.atType('id') && !this.at('(')) name = this.next().value;
    const params = this.parseParams();
    const mods = this.parseFunctionModifiers();
    let returns = [];
    if (this.at('returns')) { this.next(); returns = this.parseParams(); }
    const body = this.at(';') ? (this.next(), null) : this.parseBlock();
    const isLegacyConstructor = contractName !== null && name === contractName;
    return this.node('Function', start, {
      name: isLegacyConstructor ? 'constructor' : (name || 'fallback'),
      kind: isLegacyConstructor ? 'constructor' : 'function',
      params,
      returns,
      visibility: mods.visibility || 'public',
      mutability: mods.mutability,
      modifierInvocations: mods.invocations,
      body,
    });
  }

  parseFunctionModifiers() {
    const mods = { visibility: null, mutability: null, invocations: [] };
    while (true) {
      const t = this.peek();
      if (t.type === 'id' && VISIBILITY.has(t.value)) {
        mods.visibility = this.next().value;
      } else if (t.type === 'id' && MUTABILITY.has(t.value)) {
        mods.mutability = this.next().value;
      } else if (this.at('virtual')) {
        this.next();
      } else if (this.at('override')) {
        this.next();
        if (this.at('(')) this.skipBalanced('(', ')');
      } else if (this.at('returns') || this.at('{') || this.at(';')) {
        break;
      } else if (t.type === 'id') {
        const nameTok = this.next();
        const args = [];
        if (this.at('(')) {
          this.expect('(');
          while (!this.at(')')) {
            args.push(this.parseExpression());
            if (this.at(',')) this.next(); else break;
          }
          this.expect(')');
        }
        mods.invocations.push(this.node('ModifierInvocation', nameTok, { name: nameTok.value, args }));
      } else {
        break;
      }
    }
    return mods;
  }

  // ---- types ----

  parseType() {
    const start = this.peek();
    let desc;
    if (this.at('mapping')) {
      this.next();
      this.expect('(');
      const key = this.parseType();
      this.expect('=>');
      const value = this.parseType();
      this.expect(')');
      desc = 'mapping';
    } else if (this.at('function')) {
      this.next();
      this.parseParams();
      while (this.atAny(['external', 'internal', 'public', 'private', 'pure', 'view', 'payable'])) this.next();
      if (this.at('returns')) { this.next(); this.parseParams(); }
      desc = 'function';
    } else {
      const parts = [this.expectId().value];
      while (this.at('.')) { this.next(); parts.push(this.expectId().value); }
      if (parts[0] === 'address' && this.at('payable')) { this.next(); parts.push('payable'); }
      desc = parts.join('.');
    }
    while (this.at('[')) {
      this.next();
      if (!this.at(']')) this.parseExpression();
      this.expect(']');
      desc += '[]';
    }
    return this.node('TypeName', start, { name: desc });
  }

  parseParams() {
    this.expect('(');
    const params = [];
    while (!this.at(')')) {
      const start = this.peek();
      const paramType = this.parseType();
      let location = null;
      while (this.atAny(['memory', 'storage', 'calldata', 'payable'])) location = this.next().value;
      let name = null;
      if (this.atType('id') && !this.at(')') && !this.at(',')) name = this.next().value;
      params.push(this.node('Param', start, { name, paramType, location }));
      if (this.at(',')) this.next(); else break;
    }
    this.expect(')');
    return params;
  }

  // ---- statements ----

  parseBlock() {
    const start = this.expect('{');
    const statements = [];
    while (!this.at('}')) {
      if (this.atType('eof')) this.err('unterminated block');
      statements.push(this.parseStatement());
    }
    const close = this.expect('}');
    return this.node('Block', start, { statements }, close);
  }

  parseStatement() {
    const t = this.peek();
    if (this.at('{')) return this.parseBlock();
    if (this.at('if')) return this.parseIf();
    if (this.at('for')) return this.parseFor();
    if (this.at('while')) return this.parseWhile();
    if (this.at('do')) return this.parseDoWhile();
    if (this.at('return')) {
      this.next();
      let value = null;
      if (!this.at(';')) value = this.parseExpression();
      const semi = this.expect(';');
      return this.node('Return', t, { value }, semi);
    }
    if (this.at('emit')) {
      this.next();
      const value = this.parseExpression();
      const semi = this.expect(';');
      return this.node('Emit', t, { value }, semi);
    }
    if (this.at('revert')) {
      this.next();
      let value = null;
      if (!this.at(';')) value = this.parseExpression();
      const semi = this.expect(';');
      return this.node('Revert', t, { value }, semi);
    }
    if (this.at('break') || this.at('continue')) {
      this.next();
      const semi = this.expect(';');
      return this.node(t.value === 'break' ? 'Break' : 'Continue', t, {}, semi);
    }
    if (this.at('unchecked')) {
      this.next();
      const body = this.parseBlock();
      return this.node('Unchecked', t, { body });
    }
    if (this.at('assembly')) {
      this.next();
      if (this.atType('str') || (this.atType('id') && !this.at('{'))) this.next();
      this.skipBalanced('{', '}');
      return this.node('Assembly', t, {});
    }
    if (this.at('try')) return this.parseTry();
    if (this.at('(')) {
      const tuple = this.tryParseTupleAssign();
      if (tuple) return tuple;
    }
    const decl = this.tryParseVarDecl(true);
    if (decl) return decl;
    const value = this.parseExpression();
    const semi = this.expect(';');
    return this.node('ExpressionStatement', t, { value }, semi);
  }

  parseIf() {
    const start = this.expect('if');
    this.expect('(');
    const condition = this.parseExpression();
    this.expect(')');
    const consequent = this.parseStatement();
    let alternate = null;
    if (this.at('else')) { this.next(); alternate = this.parseStatement(); }
    return this.node('If', start, { condition, consequent, alternate });
  }

  parseFor() {
    const start = this.expect('for');
    this.expect('(');
    let init = null;
    if (!this.at(';')) {
      init = this.tryParseVarDecl(false) || this.parseExpression();
    }
    this.expect(';');
    let condition = null;
    if (!this.at(';')) condition = this.parseExpression();
    this.expect(';');
    let update = null;
    if (!this.at(')')) update = this.parseExpression();
    this.expect(')');
    const body = this.parseStatement();
    return this.node('For', start, { init, condition, update, body });
  }

  parseWhile() {
    const start = this.expect('while');
    this.expect('(');
    const condition = this.parseExpression();
    this.expect(')');
    const body = this.parseStatement();
    return this.node('While', start, { condition, body });
  }

  parseDoWhile() {
    const start = this.expect('do');
    const body = this.parseStatement();
    this.expect('while');
    this.expect('(');
    const condition = this.parseExpression();
    this.expect(')');
    const semi = this.expect(';');
    return this.node('DoWhile', start, { body, condition }, semi);
  }

  parseTry() {
    const start = this.expect('try');
    const call = this.parseExpression();
    let returns = [];
    if (this.at('returns')) { this.next(); returns = this.parseParams(); }
    const body = this.parseBlock();
    const catches = [];
    while (this.at('catch')) {
      const cstart = this.next();
      let name = null;
      let params = [];
      if (this.atType('id') && !this.at('{')) name = this.next().value;
      if (this.at('(')) params = this.parseParams();
      const cbody = this.parseBlock();
      catches.push(this.node('Catch', cstart, { name, params, body: cbody }));
    }
    return this.node('Try', start, { call, returns, body, catches });
  }

  // Statement-level variable declaration, e.g. `uint256 x = 1;` or `Token t;`.
  // Returns null (and rewinds) when the tokens do not form a declaration.
  tryParseVarDecl(withSemicolon) {
    const saved = this.i;
    try {
      const start = this.peek();
      const varType = this.parseType();
      let location = null;
      while (this.atAny(['memory', 'storage', 'calldata'])) location = this.next().value;
      if (!this.atType('id')) { this.i = saved; return null; }
      const nameTok = this.next();
      let init = null;
      if (this.at('=')) { this.next(); init = this.parseExpression(); }
      let semi = null;
      if (withSemicolon) semi = this.expect(';');
      return this.node('VarDecl', start, {
        name: nameTok.value, varType, location, init,
      }, semi || undefined);
    } catch (e) {
      this.i = saved;
      return null;
    }
  }

  // Tuple assignment / declaration, e.g. `(bool ok, ) = addr.call("");`
  tryParseTupleAssign() {
    const saved = this.i;
    try {
      const start = this.expect('(');
      const items = [];
      while (!this.at(')')) {
        if (this.at(',')) { items.push(null); this.next(); continue; }
        const innerSaved = this.i;
        let item = null;
        try {
          const istart = this.peek();
          const varType = this.parseType();
          while (this.atAny(['memory', 'storage', 'calldata'])) this.next();
          if (this.atType('id') && (this.peek(1).value === ',' || this.peek(1).value === ')')) {
            const nameTok = this.next();
            item = this.node('VarDecl', istart, { name: nameTok.value, varType, location: null, init: null });
          } else {
            this.i = innerSaved;
          }
        } catch (e) {
          this.i = innerSaved;
        }
        if (!item) item = this.parseExpression();
        items.push(item);
        if (this.at(',')) this.next(); else break;
      }
      this.expect(')');
      if (!this.at('=')) { this.i = saved; return null; }
      this.next();
      const value = this.parseExpression();
      const semi = this.expect(';');
      return this.node('TupleAssign', start, { items, value }, semi);
    } catch (e) {
      this.i = saved;
      return null;
    }
  }

  // ---- expressions ----

  parseExpression() {
    return this.parseAssignment();
  }

  parseAssignment() {
    const left = this.parseTernary();
    const t = this.peek();
    if (t.type === 'punct' && ASSIGN_OPS.has(t.value)) {
      this.next();
      const right = this.parseAssignment();
      return this.node('Assignment', left.loc ? this.tokenAt(left.loc) : t, {
        operator: t.value, left, right,
      }, this.toks[this.i - 1]);
    }
    return left;
  }

  tokenAt(loc) {
    // Reconstruct a token-like object from a loc for node building.
    return { line: loc.startLine, col: loc.startColumn };
  }

  parseTernary() {
    const cond = this.parseBinary(0);
    if (this.at('?')) {
      const start = this.peek();
      this.next();
      const consequent = this.parseExpression();
      this.expect(':');
      const alternate = this.parseTernary();
      return this.node('Conditional', this.tokenAt(cond.loc), { condition: cond, consequent, alternate }, this.toks[this.i - 1]);
    }
    return cond;
  }

  parseBinary(level) {
    const LEVELS = [
      ['||'],
      ['&&'],
      ['==', '!='],
      ['<', '<=', '>', '>='],
      ['|'],
      ['^'],
      ['&'],
      ['<<', '>>'],
      ['+', '-'],
      ['*', '/', '%'],
    ];
    if (level >= LEVELS.length) return this.parseUnary();
    let left = this.parseBinary(level + 1);
    while (this.peek().type === 'punct' && LEVELS[level].includes(this.peek().value)) {
      const op = this.next();
      const right = this.parseBinary(level + 1);
      left = this.node('Binary', this.tokenAt(left.loc), { operator: op.value, left, right }, this.toks[this.i - 1]);
    }
    return left;
  }

  parseUnary() {
    const t = this.peek();
    if (t.type === 'punct' && ['!', '-', '+', '~', '++', '--'].includes(t.value)) {
      this.next();
      const argument = this.parseUnary();
      return this.node('Unary', t, { operator: t.value, prefix: true, argument });
    }
    if (this.at('delete')) {
      this.next();
      const argument = this.parseUnary();
      return this.node('Unary', t, { operator: 'delete', prefix: true, argument });
    }
    // exponentiation is right-associative and binds tighter than unary minus
    const base = this.parsePostfix();
    if (this.at('**')) {
      this.next();
      const exponent = this.parseUnary();
      return this.node('Binary', this.tokenAt(base.loc), { operator: '**', left: base, right: exponent }, this.toks[this.i - 1]);
    }
    return base;
  }

  parsePostfix() {
    let expr = this.parsePrimary();
    while (true) {
      const t = this.peek();
      if (this.at('.')) {
        this.next();
        const prop = this.expectId();
        expr = this.node('Member', this.tokenAt(expr.loc), { object: expr, property: prop.value }, prop);
      } else if (this.at('[')) {
        this.next();
        let index = null;
        if (!this.at(']')) {
          // tolerate array slices a[1:2] by parsing both sides
          index = this.parseExpression();
          if (this.at(':')) {
            this.next();
            const end = this.parseExpression();
            index = this.node('Binary', this.tokenAt(index.loc), { operator: ':', left: index, right: end }, this.toks[this.i - 1]);
          }
        }
        const close = this.expect(']');
        expr = this.node('Index', this.tokenAt(expr.loc), { object: expr, index }, close);
      } else if (this.at('{')) {
        // call options: addr.call{value: 1, gas: 1000}(...)
        this.next();
        const options = [];
        while (!this.at('}')) {
          const nameTok = this.expectId();
          this.expect(':');
          const value = this.parseExpression();
          options.push(this.node('CallOption', nameTok, { name: nameTok.value, value }));
          if (this.at(',')) this.next(); else break;
        }
        const close = this.expect('}');
        expr = this.node('CallOptions', this.tokenAt(expr.loc), { expression: expr, options }, close);
      } else if (this.at('(')) {
        this.next();
        const args = [];
        while (!this.at(')')) {
          args.push(this.parseExpression());
          if (this.at(',')) this.next(); else break;
        }
        const close = this.expect(')');
        expr = this.node('Call', this.tokenAt(expr.loc), { callee: expr, args }, close);
      } else if (this.at('++') || this.at('--')) {
        this.next();
        expr = this.node('Unary', this.tokenAt(expr.loc), { operator: t.value, prefix: false, argument: expr }, this.toks[this.i - 1]);
      } else {
        break;
      }
    }
    return expr;
  }

  parsePrimary() {
    const t = this.peek();
    if (t.type === 'num') {
      this.next();
      // unit suffixes: 1 ether, 2 days, ...
      if (this.atAny(['wei', 'gwei', 'ether', 'seconds', 'minutes', 'hours', 'days', 'weeks'])) this.next();
      return this.node('Literal', t, { value: t.value }, this.toks[this.i - 1]);
    }
    if (t.type === 'str') {
      this.next();
      return this.node('Literal', t, { value: t.value });
    }
    if (this.at('true') || this.at('false')) {
      this.next();
      return this.node('Literal', t, { value: t.value });
    }
    if (this.at('(')) {
      this.next();
      const elements = [];
      while (!this.at(')')) {
        if (this.at(',')) { elements.push(null); this.next(); continue; }
        elements.push(this.parseExpression());
        if (this.at(',')) this.next(); else break;
      }
      const close = this.expect(')');
      if (elements.length === 1 && elements[0]) return elements[0];
      return this.node('Tuple', t, { elements }, close);
    }
    if (this.at('[')) {
      this.next();
      const elements = [];
      while (!this.at(']')) {
        elements.push(this.parseExpression());
        if (this.at(',')) this.next(); else break;
      }
      const close = this.expect(']');
      return this.node('ArrayLiteral', t, { elements }, close);
    }
    if (this.at('new')) {
      this.next();
      const typeName = this.parseType();
      return this.node('New', t, { typeName });
    }
    if (t.type === 'id') {
      this.next();
      return this.node('Identifier', t, { name: t.value });
    }
    this.err(`unexpected token '${t.value}' in expression`, t);
    return null;
  }
}

function parse(tokens) {
  return new Parser(tokens).parseSourceUnit();
}

module.exports = { parse, ParseError };
