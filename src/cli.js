// CLI entry: `contract-sentry audit <path>`.
// All public results are a single JSON object on stdout with stable order.

import fs from 'node:fs';
import path from 'node:path';
import { parse, ParseError } from './parser.js';
import { LexError } from './lexer.js';
import { analyze } from './analyzer.js';

const RULE_ORDER = [
  'DELEGATECALL_UNTRUSTED_TARGET',
  'UNCHECKED_EXTERNAL_CALL',
  'STATE_UPDATE_AFTER_CALL',
  'SELFDESTRUCT_UNTRUSTED_BENEFICIARY',
];

function emit(obj) {
  process.stdout.write(`${JSON.stringify(obj, null, 2)}\n`);
}

export class CliError extends Error {
  constructor(code, payload, exitCode) {
    super(code);
    this.code = code;
    this.payload = payload;
    this.exitCode = exitCode;
  }
}

// Recursively collect .sol files. Returns POSIX-style relative display
// paths: relative to cwd for a single file argument, `<dir>/...` for a
// directory argument.
export function collectSolFiles(inputPath) {
  let stat;
  try {
    stat = fs.statSync(inputPath);
  } catch (e) {
    throw new CliError('INPUT_READ_ERROR', {
      error: 'INPUT_READ_ERROR',
      file: inputPath,
      message: e.message,
    }, 2);
  }

  if (stat.isFile()) {
    if (!inputPath.endsWith('.sol')) return [];
    const abs = path.resolve(inputPath);
    const rel = path.relative(process.cwd(), abs).split(path.sep).join('/');
    return [{ abs, rel }];
  }

  if (stat.isDirectory()) {
    const dirAbs = path.resolve(inputPath);
    const dirName = path.basename(dirAbs);
    const found = [];
    const walk = (dir) => {
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch (e) {
        throw new CliError('INPUT_READ_ERROR', {
          error: 'INPUT_READ_ERROR',
          file: dir,
          message: e.message,
        }, 2);
      }
      for (const ent of entries) {
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) walk(full);
        else if (ent.isFile() && ent.name.endsWith('.sol')) {
          const inner = path.relative(dirAbs, full).split(path.sep).join('/');
          found.push({ abs: full, rel: `${dirName}/${inner}` });
        }
      }
    };
    walk(dirAbs);
    found.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
    return found;
  }

  throw new CliError('INPUT_READ_ERROR', {
    error: 'INPUT_READ_ERROR',
    file: inputPath,
    message: 'not a regular file or directory',
  }, 2);
}

function readSolFile(file) {
  let buffer;
  try {
    buffer = fs.readFileSync(file.abs);
  } catch (e) {
    throw new CliError('INPUT_READ_ERROR', {
      error: 'INPUT_READ_ERROR',
      file: file.rel,
      message: e.message,
    }, 2);
  }
  // Explicit fatal UTF-8 check: reading as 'utf8' would silently insert
  // replacement characters instead of failing.
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch (e) {
    throw new CliError('INPUT_READ_ERROR', {
      error: 'INPUT_READ_ERROR',
      file: file.rel,
      message: 'invalid UTF-8 encoding',
    }, 2);
  }
}

export function audit(inputPath) {
  const files = collectSolFiles(inputPath);
  if (files.length === 0) {
    throw new CliError('NO_INPUT_FILES', { error: 'NO_INPUT_FILES' }, 4);
  }

  const parsedFiles = [];
  for (const file of files) {
    const source = readSolFile(file);
    let ast;
    try {
      ast = parse(source);
    } catch (e) {
      if (e instanceof ParseError || e instanceof LexError) {
        throw new CliError('SOLIDITY_PARSE_ERROR', {
          error: 'SOLIDITY_PARSE_ERROR',
          file: file.rel,
          startLine: e.startLine,
          startColumn: e.startColumn,
          message: e.message,
        }, 3);
      }
      throw e;
    }
    parsedFiles.push({ file: file.rel, ast });
  }

  const findings = analyze(parsedFiles);
  findings.sort((a, b) => {
    if (a.location.file !== b.location.file) {
      return a.location.file < b.location.file ? -1 : 1;
    }
    if (a.location.startLine !== b.location.startLine) {
      return a.location.startLine - b.location.startLine;
    }
    if (a.location.startColumn !== b.location.startColumn) {
      return a.location.startColumn - b.location.startColumn;
    }
    return RULE_ORDER.indexOf(a.ruleId) - RULE_ORDER.indexOf(b.ruleId);
  });

  return {
    files: files.map((f) => f.rel),
    findings,
  };
}

export function run(argv) {
  const [cmd, target] = argv;
  if (cmd !== 'audit' || !target) {
    process.stderr.write('Usage: contract-sentry audit <path-to-sol-file-or-directory>\n');
    return 1;
  }
  try {
    const result = audit(target);
    emit(result);
    return 0;
  } catch (e) {
    if (e instanceof CliError) {
      emit(e.payload);
      return e.exitCode;
    }
    emit({ error: 'INTERNAL_ERROR', message: String(e && e.message || e) });
    return 1;
  }
}
