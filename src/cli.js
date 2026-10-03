'use strict';

const fs = require('fs');
const path = require('path');
const { tokenize } = require('./lexer');
const { parse } = require('./parser');
const { Model } = require('./model');
const { analyze } = require('./rules');

function emitError(code, extra, exitCode) {
  const error = Object.assign({ code }, extra);
  process.stdout.write(JSON.stringify({ error }, null, 2) + '\n');
  process.exit(exitCode);
}

function toPosix(p) {
  return p.split(path.sep).join('/');
}

function collectSolFiles(target) {
  let stat;
  try {
    stat = fs.statSync(target);
  } catch (e) {
    emitError('INPUT_READ_ERROR', {
      message: `cannot read input path: ${target}`,
      file: toPosix(target),
    }, 2);
  }
  if (stat.isDirectory()) {
    const found = [];
    const walk = (dir) => {
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch (e) {
        emitError('INPUT_READ_ERROR', {
          message: `cannot read directory: ${dir}`,
          file: toPosix(path.relative(target, dir) || '.'),
        }, 2);
      }
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.isFile() && entry.name.endsWith('.sol')) found.push(full);
      }
    };
    walk(target);
    found.sort((a, b) => {
      const ra = toPosix(path.relative(target, a));
      const rb = toPosix(path.relative(target, b));
      return ra < rb ? -1 : ra > rb ? 1 : 0;
    });
    return found.map((full) => ({
      abs: full,
      rel: toPosix(path.relative(target, full)),
    }));
  }
  if (stat.isFile()) {
    if (!target.endsWith('.sol')) return [];
    return [{ abs: target, rel: toPosix(target) }];
  }
  return [];
}

function readSource(file) {
  let buffer;
  try {
    buffer = fs.readFileSync(file.abs);
  } catch (e) {
    emitError('INPUT_READ_ERROR', {
      message: `cannot read file: ${file.rel}`,
      file: file.rel,
    }, 2);
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch (e) {
    emitError('INPUT_READ_ERROR', {
      message: `file is not valid UTF-8: ${file.rel}`,
      file: file.rel,
    }, 2);
  }
  return null;
}

function main(argv) {
  if (argv[0] !== 'audit' || !argv[1]) {
    process.stderr.write('usage: contract-sentry audit <path-to-.sol-file-or-directory>\n');
    process.exit(1);
  }
  const target = argv[1];
  const files = collectSolFiles(target);
  if (files.length === 0) {
    emitError('NO_INPUT_FILES', {
      message: `no .sol files found under: ${toPosix(target)}`,
    }, 4);
  }

  const parsedFiles = [];
  for (const file of files) {
    const source = readSource(file);
    let ast;
    try {
      ast = parse(tokenize(source));
    } catch (e) {
      if (e && typeof e.startLine === 'number' && typeof e.startColumn === 'number') {
        emitError('SOLIDITY_PARSE_ERROR', {
          message: e.message,
          file: file.rel,
          startLine: e.startLine,
          startColumn: e.startColumn,
        }, 3);
      }
      throw e;
    }
    parsedFiles.push({ path: file.rel, ast });
  }

  const model = new Model(parsedFiles);
  const findings = analyze(model);

  const fileOrder = new Map(files.map((f, idx) => [f.rel, idx]));
  findings.sort((a, b) => {
    const fa = fileOrder.has(a.location.file) ? fileOrder.get(a.location.file) : files.length;
    const fb = fileOrder.has(b.location.file) ? fileOrder.get(b.location.file) : files.length;
    if (fa !== fb) return fa - fb;
    if (a.location.startLine !== b.location.startLine) return a.location.startLine - b.location.startLine;
    if (a.location.startColumn !== b.location.startColumn) return a.location.startColumn - b.location.startColumn;
    return a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0;
  });

  const report = {
    files: files.map((f) => f.rel),
    findings,
  };
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  process.exit(0);
}

module.exports = { main };
