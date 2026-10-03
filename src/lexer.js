'use strict';

// Tokenizer for a practical subset of Solidity. Every token carries 1-based
// line/column information so parse errors and findings can be located.

class LexError extends Error {
  constructor(message, line, column) {
    super(message);
    this.name = 'LexError';
    this.startLine = line;
    this.startColumn = column;
  }
}

const MULTI_PUNCTS = [
  '<<=', '>>=', '...',
  '=>', '==', '!=', '<=', '>=', '&&', '||', '++', '--',
  '+=', '-=', '*=', '/=', '%=', '|=', '&=', '^=',
  '<<', '>>', '**', '..',
];
const SINGLE_PUNCTS = new Set('{}()[];,.?:~!+-*/%<>=^&|'.split(''));

function isIdStart(c) { return /[A-Za-z_$]/.test(c); }
function isIdChar(c) { return /[A-Za-z0-9_$]/.test(c); }
function isDigit(c) { return /[0-9]/.test(c); }
function isHex(c) { return /[0-9a-fA-F_]/.test(c); }

function tokenize(source) {
  const tokens = [];
  let i = 0;
  let line = 1;
  let col = 1;
  const n = source.length;

  function advance(k) {
    while (k-- > 0) {
      if (source[i] === '\n') { line += 1; col = 1; } else { col += 1; }
      i += 1;
    }
  }
  function push(type, value, sl, sc) {
    tokens.push({ type, value, line: sl, col: sc, endLine: line, endCol: col });
  }

  while (i < n) {
    const c = source[i];
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') { advance(1); continue; }
    if (c === '/' && source[i + 1] === '/') {
      while (i < n && source[i] !== '\n') advance(1);
      continue;
    }
    if (c === '/' && source[i + 1] === '*') {
      const sl = line; const sc = col;
      advance(2);
      while (i < n && !(source[i] === '*' && source[i + 1] === '/')) advance(1);
      if (i >= n) throw new LexError('unterminated block comment', sl, sc);
      advance(2);
      continue;
    }
    if (c === '"' || c === "'") {
      const sl = line; const sc = col;
      const quote = c;
      advance(1);
      let s = '';
      while (i < n && source[i] !== quote) {
        if (source[i] === '\\') {
          s += source[i]; advance(1);
          if (i < n) { s += source[i]; advance(1); }
        } else {
          s += source[i]; advance(1);
        }
      }
      if (i >= n) throw new LexError('unterminated string literal', sl, sc);
      advance(1);
      push('str', s, sl, sc);
      continue;
    }
    if (isDigit(c)) {
      const sl = line; const sc = col;
      let s = '';
      if (c === '0' && (source[i + 1] === 'x' || source[i + 1] === 'X')) {
        s += source[i] + source[i + 1]; advance(2);
        while (i < n && isHex(source[i])) { s += source[i]; advance(1); }
      } else {
        while (i < n && (isDigit(source[i]) || source[i] === '_')) { s += source[i]; advance(1); }
        if (source[i] === '.' && isDigit(source[i + 1] || '')) {
          s += '.'; advance(1);
          while (i < n && (isDigit(source[i]) || source[i] === '_')) { s += source[i]; advance(1); }
        }
        if (source[i] === 'e' || source[i] === 'E') {
          s += source[i]; advance(1);
          if (source[i] === '+' || source[i] === '-') { s += source[i]; advance(1); }
          while (i < n && isDigit(source[i])) { s += source[i]; advance(1); }
        }
      }
      push('num', s, sl, sc);
      continue;
    }
    if (isIdStart(c)) {
      const sl = line; const sc = col;
      let s = '';
      while (i < n && isIdChar(source[i])) { s += source[i]; advance(1); }
      push('id', s, sl, sc);
      continue;
    }
    let matched = null;
    for (const p of MULTI_PUNCTS) {
      if (source.startsWith(p, i)) { matched = p; break; }
    }
    if (matched) {
      const sl = line; const sc = col;
      advance(matched.length);
      push('punct', matched, sl, sc);
      continue;
    }
    if (SINGLE_PUNCTS.has(c)) {
      const sl = line; const sc = col;
      advance(1);
      push('punct', c, sl, sc);
      continue;
    }
    throw new LexError(`unexpected character ${JSON.stringify(c)}`, line, col);
  }
  tokens.push({ type: 'eof', value: '<eof>', line, col, endLine: line, endCol: col });
  return tokens;
}

module.exports = { tokenize, LexError };
