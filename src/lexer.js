// Lexer for the subset of Solidity needed by the analyzer.
// Produces tokens with absolute offsets and 1-based line/column spans.

export class LexError extends Error {
  constructor(message, offset, line, column) {
    super(message);
    this.name = 'LexError';
    this.offset = offset;
    this.line = line;
    this.startLine = line;
    this.startColumn = column;
  }
}

const KEYWORDS = new Set([
  'pragma', 'solidity', 'import', 'contract', 'interface', 'library',
  'abstract', 'is', 'function', 'modifier', 'event', 'enum', 'struct',
  'mapping', 'constructor', 'fallback', 'receive', 'using', 'for',
  'public', 'private', 'external', 'internal', 'pure', 'view', 'payable',
  'virtual', 'override', 'constant', 'immutable', 'memory', 'storage',
  'calldata', 'returns', 'return', 'revert', 'if', 'else', 'while', 'do', 'break',
  'continue', 'throw', 'emit', 'try', 'catch', 'new', 'delete', 'unchecked',
  'assembly', 'address', 'payable', 'indexed', 'anonymous', 'tuple',
  'type', 'typeof', 'error',
]);

// Multi-character operators, longest first.
const OPERATORS = [
  '>>=', '<<=', '...', '**=', '==', '!=', '>=', '<=', '&&', '||',
  '+=', '-=', '*=', '/=', '%=', '|=', '&=', '^=', '++', '--', '=>',
  '->', '<<', '>>', '::',
  '(', ')', '[', ']', '{', '}', ';', ',', '.', '!', '~', '*', '/',
  '%', '+', '-', '<', '>', '&', '|', '^', '?', ':', '=',
];

const isIdStart = (c) => /[A-Za-z_$]/.test(c);
const isIdPart = (c) => /[A-Za-z0-9_$]/.test(c);
const isDigit = (c) => c >= '0' && c <= '9';
const isHexDigit = (c) => /[0-9a-fA-F_]/.test(c);

export function lex(source) {
  const tokens = [];
  const n = source.length;
  let i = 0;
  let line = 1;
  let col = 1;

  function advance() {
    const c = source[i++];
    if (c === '\n') {
      line += 1;
      col = 1;
    } else {
      col += 1;
    }
    return c;
  }

  function make(type, value, start, sl, sc) {
    tokens.push({ type, value, start, end: i, startLine: sl, startColumn: sc, endLine: line, endColumn: col });
  }

  while (i < n) {
    const c = source[i];

    // Whitespace
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') {
      advance();
      continue;
    }

    const sl = line;
    const sc = col;
    const start = i;

    // Line comment
    if (c === '/' && source[i + 1] === '/') {
      while (i < n && source[i] !== '\n') advance();
      continue;
    }
    // Block comment (supports nested comments the way Solidity does)
    if (c === '/' && source[i + 1] === '*') {
      advance(); advance();
      let depth = 1;
      while (i < n && depth > 0) {
        if (source[i] === '/' && source[i + 1] === '*') {
          advance(); advance();
          depth += 1;
        } else if (source[i] === '*' && source[i + 1] === '/') {
          advance(); advance();
          depth -= 1;
        } else {
          advance();
        }
      }
      if (depth > 0) throw new LexError('Unterminated block comment', start, sl, sc);
      continue;
    }

    // Strings: single/double quoted with escapes.
    if (c === '"' || c === "'") {
      const quote = advance();
      while (i < n && source[i] !== quote) {
        if (source[i] === '\\') {
          advance();
          if (i < n) advance();
        } else if (source[i] === '\n') {
          throw new LexError('Unterminated string literal', start, sl, sc);
        } else {
          advance();
        }
      }
      if (i >= n) throw new LexError('Unterminated string literal', start, sl, sc);
      advance(); // closing quote
      make('string', source.slice(start, i), start, sl, sc);
      continue;
    }

    // Hex / unicode strings: hex"..." / hex'...' / unicode"..."
    {
      const m = /^(?:hex|unicode)\s*["']/i.exec(source.slice(i));
      if (m) {
        const prefixEnd = i + m[0].length;
        const quote = source[prefixEnd - 1];
        while (i < prefixEnd) advance();
        while (i < n && source[i] !== quote) {
          if (source[i] === '\\') {
            advance();
            if (i < n) advance();
          } else if (source[i] === '\n') {
            throw new LexError('Unterminated string literal', start, sl, sc);
          } else {
            advance();
          }
        }
        if (i >= n) throw new LexError('Unterminated string literal', start, sl, sc);
        advance();
        make('string', source.slice(start, i), start, sl, sc);
        continue;
      }
    }

    // Numbers
    if (isDigit(c) || (c === '.' && isDigit(source[i + 1]))) {
      if (source[i] === '0' && (source[i + 1] === 'x' || source[i + 1] === 'X')) {
        advance(); advance();
        if (i >= n || !isHexDigit(source[i])) {
          throw new LexError('Malformed hexadecimal number', start, sl, sc);
        }
        while (i < n && isHexDigit(source[i])) advance();
      } else {
        while (i < n && /[0-9_]/.test(source[i])) advance();
        if (source[i] === '.') {
          advance();
          while (i < n && /[0-9_]/.test(source[i])) advance();
        }
      }
      // exponent
      if (source[i] === 'e' || source[i] === 'E') {
        advance();
        if (source[i] === '+' || source[i] === '-') advance();
        while (i < n && /[0-9_]/.test(source[i])) advance();
      }
      // units / denominations
      while (i < n && isIdPart(source[i])) advance();
      make('number', source.slice(start, i), start, sl, sc);
      continue;
    }

    // Identifier / keyword
    if (isIdStart(c)) {
      while (i < n && isIdPart(source[i])) advance();
      const word = source.slice(start, i);
      make(KEYWORDS.has(word) ? 'keyword' : 'ident', word, start, sl, sc);
      continue;
    }

    // Operators / punctuation
    let matched = null;
    for (const op of OPERATORS) {
      if (source.startsWith(op, i)) {
        matched = op;
        break;
      }
    }
    if (matched !== null) {
      for (let k = 0; k < matched.length; k++) advance();
      make('punct', matched, start, sl, sc);
      continue;
    }

    throw new LexError(`Unexpected character ${JSON.stringify(c)}`, start, sl, sc);
  }

  make('eof', '', i, line, col);
  return tokens;
}
