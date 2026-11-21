import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  type DiscoveryResult,
  type LoadedDocument,
  makeFinding,
} from './discovery.js';
import { normalizePathReference, type SafeFsContext } from './fs-safe.js';
import { anyFileMatchesGlobs, splitGlobList } from './glob.js';
import {
  type AgentContextReport,
  type AgentName,
  createNullRecord,
  type Finding,
  hasOwn,
  SEVERITY_ORDER,
  type Severity,
} from './types.js';

export const SAFE_DOTENV_FILENAMES: ReadonlySet<string> = new Set([
  '.env.example',
  '.env.sample',
  '.env.template',
  '.env.schema',
  '.env.schema.json',
]);

const STANDARD_REPO_DIR_PREFIXES: ReadonlySet<string> = new Set([
  'src',
  'lib',
  'app',
  'apps',
  'packages',
  'scripts',
  'bin',
  'test',
  'tests',
  'docs',
  'config',
  'tools',
  'cmd',
  'internal',
  'pkg',
  '.github',
  '.claude',
  '.cursor',
  '.gemini',
  '.agents',
]);

const IGNORED_PATH_PREFIXES: ReadonlySet<string> = new Set([
  'dist',
  'dist-test',
  'dist-tests',
  'build',
  'out',
  'node_modules',
  'coverage',
  '.git',
  'path',
  'your',
  'example',
]);

const SHELL_FENCE_LANGS: ReadonlySet<string> = new Set([
  '',
  'sh',
  'bash',
  'zsh',
  'shell',
  'console',
  'powershell',
  'pwsh',
  'ps1',
  'cmd',
  'bat',
]);

const NPM_BUILTINS: ReadonlySet<string> = new Set([
  'install',
  'i',
  'ci',
  'add',
  'uninstall',
  'remove',
  'rm',
  'r',
  'un',
  'update',
  'up',
  'upgrade',
  'init',
  'create',
  'publish',
  'pack',
  'link',
  'unlink',
  'audit',
  'fund',
  'outdated',
  'ls',
  'list',
  'll',
  'la',
  'dedupe',
  'prune',
  'rebuild',
  'rb',
  'cache',
  'config',
  'c',
  'set',
  'get',
  'pkg',
  'version',
  'view',
  'v',
  'info',
  'show',
  'search',
  's',
  'se',
  'login',
  'adduser',
  'logout',
  'whoami',
  'owner',
  'team',
  'access',
  'dist-tag',
  'deprecate',
  'unpublish',
  'exec',
  'x',
  'explore',
  'docs',
  'repo',
  'bugs',
  'home',
  'help',
  'help-search',
  'doctor',
  'ping',
  'prefix',
  'root',
  'bin',
  'explain',
  'why',
  'query',
  'sbom',
  ' signatures',
  'stop',
  'restart',
]);

const PNPM_BUILTINS: ReadonlySet<string> = new Set([
  'install',
  'i',
  'ci',
  'add',
  'remove',
  'rm',
  'uninstall',
  'un',
  'update',
  'up',
  'upgrade',
  'dlx',
  'exec',
  'create',
  'init',
  'publish',
  'pack',
  'link',
  'ln',
  'unlink',
  'import',
  'audit',
  'licenses',
  'outdated',
  'why',
  'list',
  'ls',
  'll',
  'la',
  'prune',
  'rebuild',
  'rb',
  'store',
  'config',
  'c',
  'env',
  'setup',
  'server',
  'patch',
  'patch-commit',
  'patch-remove',
  'dedupe',
  'fetch',
  'deploy',
  'doctor',
  'cat-file',
  'cat-index',
  'find-hash',
  'root',
  'bin',
  'help',
  'start',
]);

const YARN_BUILTINS: ReadonlySet<string> = new Set([
  'install',
  'add',
  'remove',
  'up',
  'upgrade',
  'upgrade-interactive',
  'dlx',
  'exec',
  'create',
  'init',
  'publish',
  'pack',
  'link',
  'unlink',
  'audit',
  'npm',
  'workspaces',
  'workspace',
  'config',
  'cache',
  'set',
  'policies',
  'plugin',
  'constraints',
  'stage',
  'why',
  'info',
  'list',
  'licenses',
  'outdated',
  'global',
  'bin',
  'node',
  'version',
  'versions',
  'login',
  'logout',
  'owner',
  'tag',
  'team',
  'autoclean',
  'check',
  'import',
  'dedupe',
  'explain',
  'rebuild',
  'unplug',
  'help',
]);

type PackageManagerName = 'npm' | 'pnpm' | 'yarn' | 'bun';

interface BuildConfigSnapshot {
  hasPackageJson: boolean;
  scripts: Set<string>;
  bins: Set<string>;
  hasServerJs: boolean;
  hasMakefile: boolean;
  makeTargets: Set<string>;
  hasJustfile: boolean;
  justRecipes: Set<string>;
}

/**
 * Redacts a detected secret in `ab...***REDACTED***` form, never exposing the raw token.
 */
export function redactSecret(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length <= 4) {
    return '***REDACTED***';
  }
  return `${trimmed.slice(0, 2)}...***REDACTED***`;
}

function hashShort(raw: string): string {
  return crypto.createHash('sha256').update(raw, 'utf8').digest('hex').slice(0, 12);
}

function isAsciiAlnumDashUnderscore(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a) ||
    code === 0x5f || // _
    code === 0x2d // -
  );
}

function isWordPrefixBeforeDotenv(code: number): boolean {
  // Exclude identifier/property prefixes such as `process.env`, `meta.env`, `$foo.env`, `my-app.env`, `..env`
  return (
    isAsciiAlnumDashUnderscore(code) ||
    code === 0x24 || // $
    code === 0x2e // .
  );
}

/**
 * Linear O(N) scanner extracting every `.env*` filename token on a line.
 * Matches `.env` after start-of-line, whitespace, quotes, `/`, `\`, `(`, `=`, `:`, `[`, `<`, `{`, `,`, `;`, `|`
 * and before end-of-line, whitespace, quotes, `)`, `]`, `>`, `}`, `,`, `;`, `:`, `|`, or sentence-final `.`,
 * while excluding word characters before `.env` so `process.env.KEY` and `import.meta.env` stay clean.
 */
export function extractDotenvTokens(
  text: string,
): Array<{ token: string; column: number }> {
  const results: Array<{ token: string; column: number }> = [];
  const lower = text.toLowerCase();
  let i = 0;

  while (i <= lower.length - 4) {
    const idx = lower.indexOf('.env', i);
    if (idx === -1) break;

    if (idx > 0 && isWordPrefixBeforeDotenv(text.charCodeAt(idx - 1))) {
      i = idx + 4;
      continue;
    }

    let end = idx + 4;
    // Reject `.environ`, `.envrc`, `.env_foo` where word char follows `.env` directly without `.`
    if (end < text.length && isAsciiAlnumDashUnderscore(text.charCodeAt(end))) {
      i = end + 1;
      continue;
    }

    // Consume zero or more `.<segment>` suffixes (stopping before trailing sentence period `.`!)
    while (
      end + 1 < text.length &&
      text.charCodeAt(end) === 0x2e &&
      isAsciiAlnumDashUnderscore(text.charCodeAt(end + 1))
    ) {
      end += 1;
      while (end < text.length && isAsciiAlnumDashUnderscore(text.charCodeAt(end))) {
        end += 1;
      }
    }

    // Ensure token is not immediately followed by word characters
    if (end < text.length && isAsciiAlnumDashUnderscore(text.charCodeAt(end))) {
      i = end + 1;
      continue;
    }

    results.push({
      token: text.slice(idx, end),
      column: idx + 1,
    });
    i = end;
  }

  return results;
}

function loadBuildConfigForDir(fsCtx: SafeFsContext, dirAbs: string): BuildConfigSnapshot {
  const scripts = new Set<string>();
  const bins = new Set<string>();
  let hasPackageJson = false;
  let hasServerJs = false;
  let hasMakefile = false;
  const makeTargets = new Set<string>();
  let hasJustfile = false;
  const justRecipes = new Set<string>();

  const pkgCheck = fsCtx.checkCaseExactPath(dirAbs, 'package.json');
  if (pkgCheck.status === 'ok' && !pkgCheck.isDirectory) {
    try {
      const raw = JSON.parse(fs.readFileSync(pkgCheck.realPath, 'utf8')) as unknown;
      if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
        hasPackageJson = true;
        const rec = raw as Record<string, unknown>;
        if (rec['scripts'] && typeof rec['scripts'] === 'object' && !Array.isArray(rec['scripts'])) {
          for (const k of Object.keys(rec['scripts'] as Record<string, unknown>)) {
            scripts.add(k);
          }
        }
        if (typeof rec['bin'] === 'string' && typeof rec['name'] === 'string') {
          const shortName = rec['name'].includes('/')
            ? rec['name'].slice(rec['name'].lastIndexOf('/') + 1)
            : rec['name'];
          bins.add(shortName);
        } else if (rec['bin'] && typeof rec['bin'] === 'object' && !Array.isArray(rec['bin'])) {
          for (const k of Object.keys(rec['bin'] as Record<string, unknown>)) {
            bins.add(k);
          }
        }
      }
    } catch {
      // Malformed package.json ignored here
    }
  }

  const serverCheck = fsCtx.checkCaseExactPath(dirAbs, 'server.js');
  if (serverCheck.status === 'ok' && !serverCheck.isDirectory) {
    hasServerJs = true;
  }

  const listing = fsCtx.getDirEntries(dirAbs);
  if (listing) {
    for (const mkName of ['Makefile', 'makefile', 'GNUmakefile']) {
      if (listing.exact.has(mkName)) {
        const mkCheck = fsCtx.checkCaseExactPath(dirAbs, mkName);
        if (mkCheck.status === 'ok' && !mkCheck.isDirectory) {
          hasMakefile = true;
          try {
            const text = fs.readFileSync(mkCheck.realPath, 'utf8');
            for (const rawLine of text.split(/\r?\n/)) {
              if (rawLine.startsWith('\t') || rawLine.trim().startsWith('#')) continue;
              const colonIdx = rawLine.indexOf(':');
              if (colonIdx <= 0) continue;
              // Skip `:=` and `?=` variable assignments
              if (rawLine[colonIdx + 1] === '=' || rawLine[colonIdx - 1] === '?') continue;
              const lhs = rawLine.slice(0, colonIdx).trim();
              if (!lhs || lhs.startsWith('.') || lhs.includes('%') || lhs.includes('$')) continue;
              for (const target of lhs.split(/\s+/)) {
                if (/^[A-Za-z0-9_./-]+$/.test(target)) {
                  makeTargets.add(target);
                }
              }
            }
          } catch {
            // Ignore read failure
          }
        }
      }
    }

    for (const jfName of ['justfile', 'Justfile', '.justfile']) {
      if (listing.exact.has(jfName)) {
        const jfCheck = fsCtx.checkCaseExactPath(dirAbs, jfName);
        if (jfCheck.status === 'ok' && !jfCheck.isDirectory) {
          hasJustfile = true;
          try {
            const text = fs.readFileSync(jfCheck.realPath, 'utf8');
            for (const rawLine of text.split(/\r?\n/)) {
              if (rawLine.startsWith(' ') || rawLine.startsWith('\t') || rawLine.trim().startsWith('#')) {
                continue;
              }
              const colonIdx = rawLine.indexOf(':');
              if (colonIdx <= 0) continue;
              if (rawLine[colonIdx + 1] === '=') continue;
              let lhs = rawLine.slice(0, colonIdx).trim();
              if (lhs.startsWith('@')) lhs = lhs.slice(1).trim();
              const recipe = lhs.split(/\s+/)[0] ?? '';
              if (/^[A-Za-z_][A-Za-z0-9_-]*$/.test(recipe)) {
                justRecipes.add(recipe);
              }
            }
          } catch {
            // Ignore read failure
          }
        }
      }
    }
  }

  return {
    hasPackageJson,
    scripts,
    bins,
    hasServerJs,
    hasMakefile,
    makeTargets,
    hasJustfile,
    justRecipes,
  };
}

function mergeBuildConfigs(primary: BuildConfigSnapshot, fallback: BuildConfigSnapshot): BuildConfigSnapshot {
  return {
    hasPackageJson: primary.hasPackageJson || fallback.hasPackageJson,
    scripts: new Set([...primary.scripts, ...fallback.scripts]),
    bins: new Set([...primary.bins, ...fallback.bins]),
    hasServerJs: primary.hasServerJs || fallback.hasServerJs,
    hasMakefile: primary.hasMakefile || fallback.hasMakefile,
    makeTargets: new Set([...primary.makeTargets, ...fallback.makeTargets]),
    hasJustfile: primary.hasJustfile || fallback.hasJustfile,
    justRecipes: new Set([...primary.justRecipes, ...fallback.justRecipes]),
  };
}

function isExternalOrAnchorHref(target: string): boolean {
  const trimmed = target.trim();
  if (trimmed.length === 0 || trimmed.startsWith('#')) return true;
  const lower = trimmed.toLowerCase();
  return (
    lower.startsWith('http://') ||
    lower.startsWith('https://') ||
    lower.startsWith('mailto:') ||
    lower.startsWith('tel:') ||
    lower.startsWith('data:') ||
    lower.startsWith('mdc:') ||
    lower.startsWith('vscode:') ||
    lower.startsWith('javascript:')
  );
}

function isWildcardOrTemplatePath(raw: string): boolean {
  return (
    raw.includes('*') ||
    raw.includes('?') ||
    raw.includes('{') ||
    raw.includes('}') ||
    raw.includes('<') ||
    raw.includes('>') ||
    raw.includes('$') ||
    raw.includes('%') ||
    raw.includes('|') ||
    raw.includes('...')
  );
}

function hasFileExtension(seg: string): boolean {
  const dot = seg.lastIndexOf('.');
  if (dot <= 0 || dot === seg.length - 1) return false;
  const ext = seg.slice(dot + 1);
  return /^[A-Za-z0-9]{1,12}$/.test(ext);
}

function checkRepoCandidatePath(
  fsCtx: SafeFsContext,
  primaryDirAbs: string,
  rootDirAbs: string,
  rawToken: string,
): { kind: 'ok' | 'missing' | 'case-mismatch' | 'escaped-root'; expectedSeg?: string; actualSeg?: string } {
  const primary = fsCtx.checkCaseExactPath(primaryDirAbs, rawToken);
  if (primary.status === 'ok') return { kind: 'ok' };
  if (primary.status === 'escaped-root') return { kind: 'escaped-root' };

  const normalized = rawToken.replace(/\\/g, '/');
  const isExplicitRelative = normalized.startsWith('./') || normalized.startsWith('../');

  if (!isExplicitRelative && primaryDirAbs !== rootDirAbs) {
    const rootRes = fsCtx.checkCaseExactPath(rootDirAbs, rawToken);
    if (rootRes.status === 'ok') return { kind: 'ok' };
    if (rootRes.status === 'escaped-root') return { kind: 'escaped-root' };
    if (rootRes.status === 'case-mismatch') {
      return {
        kind: 'case-mismatch',
        expectedSeg: rootRes.expectedSegment,
        actualSeg: rootRes.actualSegment,
      };
    }
  }

  if (primary.status === 'case-mismatch') {
    return {
      kind: 'case-mismatch',
      expectedSeg: primary.expectedSegment,
      actualSeg: primary.actualSegment,
    };
  }
  return { kind: 'missing' };
}

function analyzePathsAndLinksForDoc(
  doc: LoadedDocument,
  fsCtx: SafeFsContext,
  topLevelDirs: ReadonlySet<string>,
  findings: Finding[],
): void {
  const docDirAbs = path.dirname(doc.meta.absPath);
  const scopeDirAbs = doc.meta.scopeDir
    ? path.join(fsCtx.rootDirReal, doc.meta.scopeDir)
    : fsCtx.rootDirReal;
  const seenRefs = new Set<string>();

  // 1. Markdown links & images `[label](target)`
  for (const link of doc.parsed.links) {
    if (isExternalOrAnchorHref(link.target)) continue;
    const cleaned = normalizePathReference(link.target);
    if (cleaned.length === 0 || isWildcardOrTemplatePath(cleaned)) continue;

    const firstSeg = cleaned.split('/')[0] ?? '';
    if (IGNORED_PATH_PREFIXES.has(firstSeg)) continue;

    const dedupKey = `link:${link.line}:${cleaned}`;
    if (seenRefs.has(dedupKey)) continue;
    seenRefs.add(dedupKey);

    const res = checkRepoCandidatePath(fsCtx, docDirAbs, fsCtx.rootDirReal, cleaned);
    if (res.kind === 'escaped-root') {
      findings.push(
        makeFinding({
          ruleId: 'AGL012',
          message: `Markdown link "${link.target}" escapes the scan root; blocked.`,
          file: doc.meta.displayPath,
          line: link.line,
          column: link.column,
          evidence: link.target,
          fingerprintSubject: `link-escape:${cleaned}`,
        }),
      );
    } else if (res.kind === 'case-mismatch') {
      findings.push(
        makeFinding({
          ruleId: 'AGL010',
          message: `Broken Markdown link "${link.target}": segment "${res.expectedSeg}" does not match on-disk casing "${res.actualSeg}".`,
          file: doc.meta.displayPath,
          line: link.line,
          column: link.column,
          evidence: link.target,
          fingerprintSubject: `link-case:${cleaned}`,
        }),
      );
    } else if (res.kind === 'missing') {
      findings.push(
        makeFinding({
          ruleId: 'AGL010',
          message: `Broken Markdown link "${link.target}": target file does not exist.`,
          file: doc.meta.displayPath,
          line: link.line,
          column: link.column,
          evidence: link.target,
          fingerprintSubject: `link-missing:${cleaned}`,
        }),
      );
    }
  }

  // 2. Inline code spans & prose repo path tokens (`src/foo.ts`, `scripts/x.sh`, `src\foo.ts`, `readme.md`)
  function inspectPathCandidate(rawCandidate: string, lineNo: number, columnNo: number): void {
    let trimmed = rawCandidate.trim();
    // Strip wrapping quotes
    if (
      (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'"))
    ) {
      trimmed = trimmed.slice(1, -1).trim();
    }
    if (trimmed.length === 0 || trimmed.includes(' ') || trimmed.includes('\t')) return;
    if (trimmed.includes('://') || trimmed.startsWith('-') || trimmed.startsWith('#')) return;
    if (trimmed.startsWith('@')) return; // Handled by @import logic or npm scoped package
    if (isWildcardOrTemplatePath(trimmed)) return;

    const cleaned = normalizePathReference(trimmed);
    if (cleaned.length === 0 || isWildcardOrTemplatePath(cleaned)) return;

    const hasSlash = cleaned.includes('/');
    if (!hasSlash) {
      // Single-segment filename in inline code (e.g. `readme.md`): flag case mismatch against existing file!
      if (cleaned.startsWith('.env') || !hasFileExtension(cleaned)) return;
      const singleRes = checkRepoCandidatePath(fsCtx, scopeDirAbs, fsCtx.rootDirReal, cleaned);
      if (singleRes.kind === 'case-mismatch') {
        const dedupKey = `path:${lineNo}:${cleaned}`;
        if (seenRefs.has(dedupKey)) return;
        seenRefs.add(dedupKey);
        findings.push(
          makeFinding({
            ruleId: 'AGL010',
            message: `Referenced filename "${trimmed}" does not match on-disk casing "${singleRes.actualSeg}".`,
            file: doc.meta.displayPath,
            line: lineNo,
            column: columnNo,
            evidence: trimmed,
            fingerprintSubject: `file-case:${cleaned}`,
          }),
        );
      }
      return;
    }

    // Multi-segment path (`src/foo.ts`, `./readme.md`, `scripts\x.sh`)
    if (cleaned.startsWith('/')) return; // Absolute POSIX route/system path such as `/api/users`
    const segs = cleaned.split('/').filter((s) => s.length > 0);
    if (segs.length === 0) return;

    const rawFirst = cleaned.startsWith('./')
      ? '.'
      : cleaned.startsWith('../')
        ? '..'
        : segs[0]!;

    if (IGNORED_PATH_PREFIXES.has(rawFirst)) return;

    const lastSeg = segs[segs.length - 1]!;
    const isExplicitRel = rawFirst === '.' || rawFirst === '..';
    const isKnownDirPrefix =
      STANDARD_REPO_DIR_PREFIXES.has(rawFirst) || topLevelDirs.has(rawFirst);

    if (!isExplicitRel && !isKnownDirPrefix) {
      return;
    }
    if (!isExplicitRel && !hasFileExtension(lastSeg) && lastSeg !== 'Makefile' && lastSeg !== 'justfile' && lastSeg !== 'Dockerfile') {
      return;
    }

    const dedupKey = `path:${lineNo}:${cleaned}`;
    if (seenRefs.has(dedupKey)) return;
    seenRefs.add(dedupKey);

    const checkBase = isExplicitRel ? docDirAbs : scopeDirAbs;
    const res = checkRepoCandidatePath(fsCtx, checkBase, fsCtx.rootDirReal, cleaned);
    if (res.kind === 'escaped-root') {
      findings.push(
        makeFinding({
          ruleId: 'AGL012',
          message: `Referenced path "${trimmed}" escapes the scan root; blocked.`,
          file: doc.meta.displayPath,
          line: lineNo,
          column: columnNo,
          evidence: trimmed,
          fingerprintSubject: `path-escape:${cleaned}`,
        }),
      );
    } else if (res.kind === 'case-mismatch') {
      findings.push(
        makeFinding({
          ruleId: 'AGL010',
          message: `Referenced path "${trimmed}": segment "${res.expectedSeg}" does not match on-disk casing "${res.actualSeg}".`,
          file: doc.meta.displayPath,
          line: lineNo,
          column: columnNo,
          evidence: trimmed,
          fingerprintSubject: `path-case:${cleaned}`,
        }),
      );
    } else if (res.kind === 'missing') {
      findings.push(
        makeFinding({
          ruleId: 'AGL010',
          message: `Referenced path "${trimmed}" does not exist in the repository.`,
          file: doc.meta.displayPath,
          line: lineNo,
          column: columnNo,
          evidence: trimmed,
          fingerprintSubject: `path-missing:${cleaned}`,
        }),
      );
    }
  }

  const linksByLine = new Map<number, Array<{ startIdx: number; endIdx: number }>>();
  for (const link of doc.parsed.links) {
    const arr = linksByLine.get(link.line);
    const span = { startIdx: Math.max(0, link.column - 1), endIdx: link.endColumn };
    if (arr) arr.push(span);
    else linksByLine.set(link.line, [span]);
  }

  for (const pl of doc.parsed.proseLines) {
    for (const span of pl.inlineSpans) {
      const codeTrimmed = span.code.trim();
      if (!codeTrimmed.includes(' ')) {
        inspectPathCandidate(codeTrimmed, span.line, span.column);
      } else {
        // Also check runner invocations such as `bash scripts/x.sh`, `sh ./scripts/deploy.sh`, `node scripts/gen.mjs`
        const parts = codeTrimmed.split(/\s+/);
        if (
          parts.length >= 2 &&
          ['sh', 'bash', 'zsh', 'pwsh', 'powershell', 'node', 'python', 'python3', 'tsx', 'ts-node'].includes(
            parts[0]!.toLowerCase(),
          )
        ) {
          const arg = parts.find((p, idx) => idx > 0 && !p.startsWith('-'));
          if (arg) {
            inspectPathCandidate(arg, span.line, span.column);
          }
        }
      }
    }

    // Mask out Markdown `[label](target)` spans already validated above before bare-prose token scanning
    let bareLine = pl.maskedText;
    const lineLinks = linksByLine.get(pl.line);
    if (lineLinks && lineLinks.length > 0) {
      const chars = bareLine.split('');
      for (const sp of lineLinks) {
        for (let k = sp.startIdx; k < Math.min(chars.length, sp.endIdx); k += 1) {
          chars[k] = ' ';
        }
      }
      bareLine = chars.join('');
    }

    // Scan unquoted prose tokens with `/` or `\` for bare references like `See src/foo.ts or src\bar.ts.`
    const tokens = bareLine.split(/\s+/);
    let searchPos = 0;
    for (const rawTok of tokens) {
      if (rawTok.length === 0) continue;
      const colIdx = bareLine.indexOf(rawTok, searchPos);
      if (colIdx !== -1) {
        searchPos = colIdx + rawTok.length;
      }
      if (!rawTok.includes('/') && !rawTok.includes('\\')) continue;
      let tok = rawTok;
      while (tok.length > 0 && '([{"\''.includes(tok[0]!)) {
        tok = tok.slice(1);
      }
      while (tok.length > 0 && '.,;:!?)]}"\''.includes(tok[tok.length - 1]!)) {
        tok = tok.slice(0, -1);
      }
      if (tok.includes('/') || tok.includes('\\')) {
        inspectPathCandidate(tok, pl.line, (colIdx !== -1 ? colIdx : 0) + 1);
      }
    }
  }
}

function splitShellStatements(rawLine: string): string[] {
  let s = rawLine.trim();
  if (s.length === 0 || s.startsWith('#')) return [];
  if (s.startsWith('$ ')) s = s.slice(2).trim();
  else if (s.startsWith('PS> ')) s = s.slice(4).trim();
  else if (s.startsWith('> ')) s = s.slice(2).trim();

  const statements: string[] = [];
  let quote: '"' | "'" | null = null;
  let start = 0;
  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i]!;
    if (quote) {
      if (ch === quote && s[i - 1] !== '\\') {
        quote = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === ';') {
      const part = s.slice(start, i).trim();
      if (part) statements.push(part);
      start = i + 1;
    } else if ((ch === '&' && s[i + 1] === '&') || (ch === '|' && s[i + 1] === '|')) {
      const part = s.slice(start, i).trim();
      if (part) statements.push(part);
      start = i + 2;
      i += 1;
    }
  }
  const tail = s.slice(start).trim();
  if (tail) statements.push(tail);
  return statements;
}

function tokenizeCommandWords(stmt: string): string[] {
  const words: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;

  for (let i = 0; i < stmt.length; i += 1) {
    const ch = stmt[i]!;
    if (quote) {
      if (ch === quote && stmt[i - 1] !== '\\') {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === ' ' || ch === '\t') {
      if (current.length > 0) {
        words.push(current);
        current = '';
      }
      continue;
    }
    if (ch === '|') {
      break;
    }
    current += ch;
  }
  if (current.length > 0) {
    words.push(current);
  }

  // Strip leading `KEY=VALUE` environment variable assignments
  let idx = 0;
  while (idx < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[idx]!)) {
    idx += 1;
  }
  return words.slice(idx);
}

function analyzeCommandsForDoc(
  doc: LoadedDocument,
  fsCtx: SafeFsContext,
  configCache: Map<string, BuildConfigSnapshot>,
  findings: Finding[],
): void {
  // Only check against repo build configs for repo files (home files apply globally across many repos)
  if (doc.meta.sourceRoot !== 'repo') return;

  function getConfig(dirAbs: string): BuildConfigSnapshot {
    let cached = configCache.get(dirAbs);
    if (!cached) {
      cached = loadBuildConfigForDir(fsCtx, dirAbs);
      configCache.set(dirAbs, cached);
    }
    return cached;
  }

  const scopeDirAbs = doc.meta.scopeDir
    ? path.join(fsCtx.rootDirReal, doc.meta.scopeDir)
    : fsCtx.rootDirReal;
  const baseConfig =
    scopeDirAbs === fsCtx.rootDirReal
      ? getConfig(fsCtx.rootDirReal)
      : mergeBuildConfigs(getConfig(scopeDirAbs), getConfig(fsCtx.rootDirReal));

  const seenCmds = new Set<string>();

  function inspectStatement(stmt: string, lineNo: number, columnNo: number): void {
    const words = tokenizeCommandWords(stmt);
    if (words.length === 0) return;

    const rawCmd = words[0]!.toLowerCase();
    const cmd = rawCmd.endsWith('.cmd') ? rawCmd.slice(0, -4) : rawCmd;

    if (cmd === 'npm' || cmd === 'pnpm' || cmd === 'yarn') {
      let targetConfig = baseConfig;
      let ifPresent = false;
      const positional: string[] = [];

      for (let i = 1; i < words.length; i += 1) {
        const w = words[i]!;
        if (w === '--') break;
        if (w === '--if-present') {
          ifPresent = true;
          continue;
        }
        if ((w === '--prefix' || w === '-C' || w === '--dir') && i + 1 < words.length) {
          const sub = path.resolve(scopeDirAbs, words[i + 1]!);
          if (sub.startsWith(fsCtx.rootDirReal)) {
            targetConfig = mergeBuildConfigs(getConfig(sub), baseConfig);
          }
          i += 1;
          continue;
        }
        if (w === '--filter' || w === '-F' || w === '--workspace' || w === '-w') {
          // Workspace filter: skip the filter argument
          if (i + 1 < words.length && !words[i + 1]!.startsWith('-')) {
            i += 1;
          }
          continue;
        }
        if (w.startsWith('-')) continue;
        positional.push(w);
      }

      if (ifPresent || positional.length === 0) return;

      const first = positional[0]!;
      let scriptName: string | null = null;

      if (first === 'run' || first === 'run-script') {
        scriptName = positional[1] ?? null;
      } else if (first === 'test' || first === 't' || first === 'tst') {
        scriptName = 'test';
      } else if (cmd === 'npm' && first === 'start') {
        if (!targetConfig.hasServerJs) {
          scriptName = 'start';
        }
      } else if (cmd === 'pnpm') {
        if (!PNPM_BUILTINS.has(first) && !targetConfig.bins.has(first)) {
          scriptName = first;
        }
      } else if (cmd === 'yarn') {
        if (!YARN_BUILTINS.has(first) && !targetConfig.bins.has(first)) {
          scriptName = first;
        }
      } else if (cmd === 'npm') {
        if (!NPM_BUILTINS.has(first)) {
          // Unknown npm subcommand (for example `npm lint` instead of `npm run lint`)
          scriptName = first;
        }
      }

      if (!scriptName || isWildcardOrTemplatePath(scriptName)) return;

      if (!targetConfig.hasPackageJson || !targetConfig.scripts.has(scriptName)) {
        const dedupKey = `${lineNo}:${cmd}:${scriptName}`;
        if (seenCmds.has(dedupKey)) return;
        seenCmds.add(dedupKey);
        findings.push(
          makeFinding({
            ruleId: 'AGL011',
            message: targetConfig.hasPackageJson
              ? `Command "${stmt}" references script "${scriptName}", which is missing from package.json scripts.`
              : `Command "${stmt}" references script "${scriptName}", but no package.json was found.`,
            file: doc.meta.displayPath,
            line: lineNo,
            column: columnNo,
            evidence: stmt,
            fingerprintSubject: `script:${cmd}:${scriptName}`,
          }),
        );
      }
      return;
    }

    if (cmd === 'make') {
      let targetConfig = baseConfig;
      const targets: string[] = [];
      for (let i = 1; i < words.length; i += 1) {
        const w = words[i]!;
        if ((w === '-C' || w === '--directory') && i + 1 < words.length) {
          const sub = path.resolve(scopeDirAbs, words[i + 1]!);
          if (sub.startsWith(fsCtx.rootDirReal)) {
            targetConfig = getConfig(sub);
          }
          i += 1;
          continue;
        }
        if ((w === '-f' || w === '--file' || w === '--makefile' || w === '-j') && i + 1 < words.length) {
          i += 1;
          continue;
        }
        if (w.startsWith('-') || w.includes('=')) continue;
        targets.push(w);
      }

      if (!targetConfig.hasMakefile) {
        const key = `${lineNo}:make:no-makefile`;
        if (!seenCmds.has(key)) {
          seenCmds.add(key);
          findings.push(
            makeFinding({
              ruleId: 'AGL011',
              message: `Command "${stmt}" invokes make, but no Makefile exists in the repository.`,
              file: doc.meta.displayPath,
              line: lineNo,
              column: columnNo,
              evidence: stmt,
              fingerprintSubject: `make:missing-makefile:${targets[0] ?? 'default'}`,
            }),
          );
        }
        return;
      }

      for (const t of targets) {
        if (isWildcardOrTemplatePath(t)) continue;
        if (!targetConfig.makeTargets.has(t)) {
          const key = `${lineNo}:make:${t}`;
          if (seenCmds.has(key)) continue;
          seenCmds.add(key);
          findings.push(
            makeFinding({
              ruleId: 'AGL011',
              message: `Command "${stmt}" references Makefile target "${t}", which is not defined in Makefile.`,
              file: doc.meta.displayPath,
              line: lineNo,
              column: columnNo,
              evidence: stmt,
              fingerprintSubject: `make:${t}`,
            }),
          );
        }
      }
      return;
    }

    if (cmd === 'just') {
      const recipes: string[] = [];
      for (let i = 1; i < words.length; i += 1) {
        const w = words[i]!;
        if ((w === '--justfile' || w === '-f' || w === '--working-directory' || w === '-d') && i + 1 < words.length) {
          i += 1;
          continue;
        }
        if (w.startsWith('-') || w.includes('=')) continue;
        recipes.push(w);
        break; // In `just <recipe> <args...>`, subsequent words are recipe arguments
      }

      if (!baseConfig.hasJustfile) {
        const key = `${lineNo}:just:no-justfile`;
        if (!seenCmds.has(key)) {
          seenCmds.add(key);
          findings.push(
            makeFinding({
              ruleId: 'AGL011',
              message: `Command "${stmt}" invokes just, but no justfile exists in the repository.`,
              file: doc.meta.displayPath,
              line: lineNo,
              column: columnNo,
              evidence: stmt,
              fingerprintSubject: `just:missing-justfile:${recipes[0] ?? 'default'}`,
            }),
          );
        }
        return;
      }

      for (const r of recipes) {
        if (isWildcardOrTemplatePath(r)) continue;
        if (!baseConfig.justRecipes.has(r)) {
          const key = `${lineNo}:just:${r}`;
          if (seenCmds.has(key)) continue;
          seenCmds.add(key);
          findings.push(
            makeFinding({
              ruleId: 'AGL011',
              message: `Command "${stmt}" references just recipe "${r}", which is not defined in justfile.`,
              file: doc.meta.displayPath,
              line: lineNo,
              column: columnNo,
              evidence: stmt,
              fingerprintSubject: `just:${r}`,
            }),
          );
        }
      }
    }
  }

  for (const block of doc.parsed.fencedBlocks) {
    if (!SHELL_FENCE_LANGS.has(block.lang)) continue;
    for (const ln of block.lines) {
      for (const stmt of splitShellStatements(ln.text)) {
        inspectStatement(stmt, ln.line, 1);
      }
    }
  }

  for (const pl of doc.parsed.proseLines) {
    for (const span of pl.inlineSpans) {
      for (const stmt of splitShellStatements(span.code)) {
        inspectStatement(stmt, span.line, span.column);
      }
    }
  }
}

function detectRepoPackageManagers(fsCtx: SafeFsContext): Set<PackageManagerName> {
  const detected = new Set<PackageManagerName>();
  const listing = fsCtx.getDirEntries(fsCtx.rootDirReal);
  if (!listing) return detected;

  if (listing.exact.has('package-lock.json') || listing.exact.has('npm-shrinkwrap.json')) {
    detected.add('npm');
  }
  if (listing.exact.has('pnpm-lock.yaml')) {
    detected.add('pnpm');
  }
  if (listing.exact.has('yarn.lock')) {
    detected.add('yarn');
  }
  if (listing.exact.has('bun.lockb') || listing.exact.has('bun.lock')) {
    detected.add('bun');
  }

  const pkgCheck = fsCtx.checkCaseExactPath(fsCtx.rootDirReal, 'package.json');
  if (pkgCheck.status === 'ok' && !pkgCheck.isDirectory) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgCheck.realPath, 'utf8')) as Record<string, unknown>;
      const pmField = pkg['packageManager'];
      if (typeof pmField === 'string') {
        const name = pmField.split('@')[0]?.trim().toLowerCase();
        if (name === 'npm' || name === 'pnpm' || name === 'yarn' || name === 'bun') {
          detected.add(name);
        }
      }
    } catch {
      // Ignore malformed JSON
    }
  }

  return detected;
}

function extractDocMandatedPackageManagers(
  doc: LoadedDocument,
): Array<{ pm: PackageManagerName; line: number; evidence: string }> {
  const found = new Map<PackageManagerName, { line: number; evidence: string }>();

  function recordPm(pm: PackageManagerName, line: number, evidence: string): void {
    if (!found.has(pm)) {
      found.set(pm, { line, evidence: evidence.trim().slice(0, 100) });
    }
  }

  const MANDATE_PATTERNS: Array<{ pm: PackageManagerName; regex: RegExp }> = [
    { pm: 'pnpm', regex: /\b(?:always\s+use|must\s+use|use|prefer|package\s+manager\s*(?:is|:))\s+`?pnpm`?\b/i },
    { pm: 'npm', regex: /\b(?:always\s+use|must\s+use|use|prefer|package\s+manager\s*(?:is|:))\s+`?npm(?:\.cmd)?`?\b/i },
    { pm: 'yarn', regex: /\b(?:always\s+use|must\s+use|use|prefer|package\s+manager\s*(?:is|:))\s+`?yarn`?\b/i },
    { pm: 'bun', regex: /\b(?:always\s+use|must\s+use|use|prefer|package\s+manager\s*(?:is|:))\s+`?bun`?\b/i },
    { pm: 'pnpm', regex: /\b`?pnpm`?\s+only\b/i },
    { pm: 'npm', regex: /\b`?npm`?\s+only\b/i },
    { pm: 'yarn', regex: /\b`?yarn`?\s+only\b/i },
    { pm: 'bun', regex: /\b`?bun`?\s+only\b/i },
  ];

  for (let idx = 0; idx < doc.parsed.lines.length; idx += 1) {
    const lineNo = idx + 1;
    const line = doc.parsed.lines[idx]!;
    for (const pat of MANDATE_PATTERNS) {
      const m = pat.regex.exec(line);
      if (!m) continue;
      // Exclude negated clauses right before the match (`do not use pnpm`, `never use yarn`, `don't use npm`, `not use yarn`)
      const prefix = line.slice(Math.max(0, m.index - 24), m.index).toLowerCase();
      if (
        prefix.includes('not ') ||
        prefix.includes("don't ") ||
        prefix.includes('dont ') ||
        prefix.includes('never ') ||
        prefix.includes('avoid ') ||
        prefix.includes('instead of ')
      ) {
        continue;
      }
      recordPm(pat.pm, lineNo, m[0]);
    }
  }

  // Also check explicit install/run commands in shell blocks and inline code if not preceded by negation on that line
  function checkCmdForPm(stmt: string, fullLine: string, lineNo: number): void {
    const lowerLine = fullLine.toLowerCase();
    if (
      lowerLine.includes('do not ') ||
      lowerLine.includes("don't ") ||
      lowerLine.includes('never ') ||
      lowerLine.includes('avoid ') ||
      lowerLine.includes('instead of ')
    ) {
      return;
    }
    const words = tokenizeCommandWords(stmt);
    if (words.length < 2) return;
    const rawCmd = words[0]!.toLowerCase();
    const cmd = rawCmd.endsWith('.cmd') ? rawCmd.slice(0, -4) : rawCmd;
    if (cmd === 'npm' || cmd === 'pnpm' || cmd === 'yarn' || cmd === 'bun') {
      const sub = words[1]!.toLowerCase();
      if (sub === 'install' || sub === 'i' || sub === 'ci' || sub === 'run' || sub === 'test') {
        recordPm(cmd, lineNo, stmt);
      }
    }
  }

  for (const block of doc.parsed.fencedBlocks) {
    if (!SHELL_FENCE_LANGS.has(block.lang)) continue;
    for (const ln of block.lines) {
      for (const stmt of splitShellStatements(ln.text)) {
        checkCmdForPm(stmt, ln.text, ln.line);
      }
    }
  }

  for (const pl of doc.parsed.proseLines) {
    for (const span of pl.inlineSpans) {
      for (const stmt of splitShellStatements(span.code)) {
        checkCmdForPm(stmt, pl.rawText, span.line);
      }
    }
  }

  return [...found.entries()].map(([pm, info]) => ({ pm, line: info.line, evidence: info.evidence }));
}

function analyzePackageManagerConsistency(
  discovery: DiscoveryResult,
  findings: Finding[],
): void {
  const diskPms = detectRepoPackageManagers(discovery.repoFs);
  const singleDiskPm: PackageManagerName | null =
    diskPms.size === 1 ? ([...diskPms][0] ?? null) : null;

  const docMandates: Array<{
    doc: LoadedDocument;
    pm: PackageManagerName;
    line: number;
    evidence: string;
  }> = [];

  for (const doc of discovery.documents) {
    if (doc.meta.sourceRoot !== 'repo') continue;
    const pms = extractDocMandatedPackageManagers(doc);
    for (const item of pms) {
      docMandates.push({ doc, ...item });
      if (singleDiskPm && item.pm !== singleDiskPm) {
        findings.push(
          makeFinding({
            ruleId: 'AGL020',
            message: `Instruction file "${doc.meta.displayPath}" prescribes "${item.pm}", contradicting repository lockfile/config ("${singleDiskPm}").`,
            file: doc.meta.displayPath,
            line: item.line,
            column: 1,
            evidence: item.evidence,
            fingerprintSubject: `pm-disk:${item.pm}-vs-${singleDiskPm}`,
          }),
        );
      }
    }
  }

  // Cross-file contradiction when no single lockfile already flagged it (or across two instruction files)
  if (!singleDiskPm && docMandates.length >= 2) {
    const first = docMandates[0]!;
    for (let i = 1; i < docMandates.length; i += 1) {
      const other = docMandates[i]!;
      if (other.pm !== first.pm && other.doc.meta.displayPath !== first.doc.meta.displayPath) {
        findings.push(
          makeFinding({
            ruleId: 'AGL020',
            message: `Package-manager contradiction: "${other.doc.meta.displayPath}" prescribes "${other.pm}" while "${first.doc.meta.displayPath}" prescribes "${first.pm}".`,
            file: other.doc.meta.displayPath,
            line: other.line,
            column: 1,
            evidence: other.evidence,
            fingerprintSubject: `pm-cross:${other.pm}-vs-${first.pm}`,
          }),
        );
      }
    }
  }
}

function isHiddenUnicodeCodePoint(cp: number): boolean {
  return (
    (cp >= 0x200b && cp <= 0x200f) || // Zero-width & LRM/RLM
    (cp >= 0x202a && cp <= 0x202e) || // Trojan Source BiDi LRE/RLE/PDF/LRO/RLO
    (cp >= 0x2060 && cp <= 0x206f) || // Word Joiner & BiDi isolates LRI/RLI/FSI/PDI
    cp === 0xfeff || // Mid-file ZWNBSP (file-start BOM already stripped cleanly)
    (cp >= 0xe0000 && cp <= 0xe007f) // Unicode Tag characters
  );
}

function isBenignLinterPragmaComment(rawComment: string): boolean {
  const inner = rawComment
    .slice(4, rawComment.endsWith('-->') ? -3 : undefined)
    .trim()
    .toLowerCase();
  return (
    inner.startsWith('markdownlint-') ||
    inner.startsWith('prettier-ignore') ||
    inner.startsWith('eslint-') ||
    inner.startsWith('cspell:') ||
    inner.startsWith('vale ')
  );
}

function isBase64Char(code: number): boolean {
  return (
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a) ||
    (code >= 0x30 && code <= 0x39) ||
    code === 0x2b || // +
    code === 0x2f || // /
    code === 0x3d // =
  );
}

function findLongBase64PayloadOnLine(line: string): { snippet: string; column: number } | null {
  let i = 0;
  while (i < line.length) {
    if (!isBase64Char(line.charCodeAt(i))) {
      i += 1;
      continue;
    }
    const start = i;
    let hasUpper = false;
    let hasLower = false;
    let hasDigit = false;
    let slashCount = 0;
    while (i < line.length && isBase64Char(line.charCodeAt(i))) {
      const c = line.charCodeAt(i);
      if (c >= 0x41 && c <= 0x5a) hasUpper = true;
      else if (c >= 0x61 && c <= 0x7a) hasLower = true;
      else if (c >= 0x30 && c <= 0x39) hasDigit = true;
      else if (c === 0x2f) slashCount += 1;
      i += 1;
    }
    const len = i - start;
    if (len >= 128 && hasUpper && hasLower && hasDigit) {
      const token = line.slice(start, i);
      // Avoid mistaking normal deeply-nested URL paths for base64
      const prevSlice = line.slice(Math.max(0, start - 8), start).toLowerCase();
      if (prevSlice.endsWith('http://') || prevSlice.endsWith('https://')) {
        continue;
      }
      if (slashCount > len / 6) {
        continue;
      }
      return {
        snippet: `${token.slice(0, 24)}... (${len} base64 chars)`,
        column: start + 1,
      };
    }
  }
  return null;
}

function analyzeHiddenContentForDoc(doc: LoadedDocument, findings: Finding[]): void {
  // 1. Hidden Unicode code points across ALL lines (frontmatter, prose, AND fenced code blocks)
  for (let idx = 0; idx < doc.parsed.lines.length; idx += 1) {
    const lineNo = idx + 1;
    const line = doc.parsed.lines[idx]!;
    const pointsOnLine: string[] = [];
    let firstCol = 1;
    let charCol = 1;

    for (const ch of line) {
      const cp = ch.codePointAt(0);
      if (cp !== undefined && isHiddenUnicodeCodePoint(cp)) {
        const label = `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
        if (pointsOnLine.length === 0) {
          firstCol = charCol;
        }
        if (!pointsOnLine.includes(label)) {
          pointsOnLine.push(label);
        }
      }
      charCol += ch.length;
    }

    if (pointsOnLine.length > 0) {
      findings.push(
        makeFinding({
          ruleId: 'AGL030',
          message: `Detected hidden or bidirectional Unicode control character(s) (${pointsOnLine.join(', ')}).`,
          file: doc.meta.displayPath,
          line: lineNo,
          column: firstCol,
          evidence: pointsOnLine.join(', '),
          fingerprintSubject: `unicode:L${lineNo}:${pointsOnLine.join(',')}`,
        }),
      );
    }

    // 2. `data:` URIs on line
    const lower = line.toLowerCase();
    const dataIdx = lower.indexOf('data:');
    if (dataIdx !== -1) {
      const after = lower.slice(dataIdx + 5, dataIdx + 80);
      if (/^[a-z0-9.+-]+\/[a-z0-9.+;=_-]+,/.test(after) || after.startsWith(';base64,')) {
        findings.push(
          makeFinding({
            ruleId: 'AGL030',
            message: 'Detected embedded data: URI payload in instruction file.',
            file: doc.meta.displayPath,
            line: lineNo,
            column: dataIdx + 1,
            evidence: line.slice(dataIdx, Math.min(line.length, dataIdx + 48)),
            fingerprintSubject: `data-uri:L${lineNo}`,
          }),
        );
        continue;
      }
    }

    // 3. Long base64 payloads (>= 128 chars)
    const b64 = findLongBase64PayloadOnLine(line);
    if (b64) {
      findings.push(
        makeFinding({
          ruleId: 'AGL030',
          message: 'Detected concealed or high-length base64 payload (>= 128 chars).',
          file: doc.meta.displayPath,
          line: lineNo,
          column: b64.column,
          evidence: b64.snippet,
          fingerprintSubject: `base64:L${lineNo}`,
        }),
      );
    }
  }

  // 4. HTML `<!-- ... -->` comments outside fenced code blocks
  for (const comment of doc.parsed.htmlComments) {
    if (isBenignLinterPragmaComment(comment.raw)) continue;
    const preview = comment.raw.replace(/\s+/g, ' ').slice(0, 80);
    findings.push(
      makeFinding({
        ruleId: 'AGL030',
        message: 'Detected concealed HTML comment outside fenced code block.',
        file: doc.meta.displayPath,
        line: comment.line,
        column: comment.column,
        evidence: preview,
        fingerprintSubject: `html-comment:L${comment.line}`,
      }),
    );
  }
}

interface DangerousPattern {
  id: string;
  label: string;
  testLine: (line: string) => { matched: boolean; column: number; snippet: string };
}

function regexLineMatcher(regex: RegExp): (line: string) => { matched: boolean; column: number; snippet: string } {
  return (line: string) => {
    const m = regex.exec(line);
    if (!m) return { matched: false, column: 1, snippet: '' };
    return { matched: true, column: m.index + 1, snippet: m[0].slice(0, 80) };
  };
}

function pipeToShellMatcher(line: string): { matched: boolean; column: number; snippet: string } {
  const pipeIdx = line.indexOf('|');
  if (pipeIdx === -1) return { matched: false, column: 1, snippet: '' };
  const lhs = line.slice(0, pipeIdx);
  const rhs = line.slice(pipeIdx + 1).trim();
  const hasFetcher = /\b(?:curl|wget|irm|invoke-restmethod|iwr|invoke-webrequest)\b/i.test(lhs);
  if (!hasFetcher) return { matched: false, column: 1, snippet: '' };
  const hasShell = /^(?:sudo\s+)?(?:\/(?:usr\/)?bin\/)?(?:sh|bash|zsh|dash|ksh|pwsh|powershell|iex|invoke-expression|python3?|node)\b/i.test(
    rhs,
  );
  if (!hasShell) return { matched: false, column: 1, snippet: '' };
  return {
    matched: true,
    column: 1,
    snippet: line.trim().slice(0, 80),
  };
}

const DANGEROUS_DIRECTIVE_DETECTORS: readonly DangerousPattern[] = [
  {
    id: 'pipe-shell',
    label: 'remote pipe-to-shell execution (curl/wget/irm | sh/iex)',
    testLine: pipeToShellMatcher,
  },
  {
    id: 'powershell-iex',
    label: 'PowerShell Invoke-Expression / iex dynamic execution',
    testLine: regexLineMatcher(/\b(?:Invoke-Expression|iex\s+[\($'"A-Za-z])/i),
  },
  {
    id: 'no-verify',
    label: 'git verification / safety hook bypass (--no-verify / HUSKY=0 / skip hooks)',
    testLine: regexLineMatcher(
      /(?:--no-verify\b|--no-gpg-sign\b|\b(?:HUSKY|LEFTHOOK)=0\b|\b(?:skip|bypass|disable)\s+(?:git\s+|pre-commit\s+|verification\s+)?hooks?\b)/i,
    ),
  },
  {
    id: 'conceal-user',
    label: 'user concealment directive ("do not tell the user")',
    testLine: regexLineMatcher(
      /\b(?:do\s+not|don't|never|without)\s+(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|reveal(?:ing)?|alert(?:ing)?)\s+(?:this\s+to\s+)?(?:the\s+)?user\b/i,
    ),
  },
  {
    id: 'prompt-override',
    label: 'prompt-injection override directive ("ignore previous instructions")',
    testLine: regexLineMatcher(
      /\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions?|prompts?|rules?)\b/i,
    ),
  },
  {
    id: 'ssh-creds',
    label: 'sensitive credential store access (~/.ssh, ~/.aws, /etc/shadow, id_rsa)',
    testLine: regexLineMatcher(
      /(?:(?:~|\$HOME|%USERPROFILE%)[/\\]\.(?:ssh|aws|gnupg|npmrc|netrc)\b|\.kube[/\\]config\b|\b(?:id_rsa|id_ed25519|id_ecdsa)\b|\/etc\/(?:shadow|passwd)\b)/i,
    ),
  },
];

function analyzeDangerousDirectivesForDoc(doc: LoadedDocument, findings: Finding[]): void {
  const sensitiveDotenvTokens: Array<{ token: string; line: number; column: number }> = [];
  const safeDotenvTokens: Array<{ token: string; line: number; column: number }> = [];

  for (let idx = 0; idx < doc.parsed.lines.length; idx += 1) {
    const lineNo = idx + 1;
    const line = doc.parsed.lines[idx]!;

    for (const detector of DANGEROUS_DIRECTIVE_DETECTORS) {
      const hit = detector.testLine(line);
      if (hit.matched) {
        findings.push(
          makeFinding({
            ruleId: 'AGL031',
            severity: 'high',
            message: `Detected dangerous directive: ${detector.label}.`,
            file: doc.meta.displayPath,
            line: lineNo,
            column: hit.column,
            evidence: hit.snippet,
            fingerprintSubject: `directive:${detector.id}:L${lineNo}`,
          }),
        );
      }
    }

    const dotenvHits = extractDotenvTokens(line);
    for (const dh of dotenvHits) {
      if (SAFE_DOTENV_FILENAMES.has(dh.token.toLowerCase())) {
        safeDotenvTokens.push({ token: dh.token, line: lineNo, column: dh.column });
      } else {
        sensitiveDotenvTokens.push({ token: dh.token, line: lineNo, column: dh.column });
      }
    }
  }

  if (sensitiveDotenvTokens.length > 0) {
    const first = sensitiveDotenvTokens[0]!;
    const uniqueSensitive = [...new Set(sensitiveDotenvTokens.map((x) => x.token))];
    findings.push(
      makeFinding({
        ruleId: 'AGL031',
        severity: 'high',
        message: `Detected live dotenv credential file reference(s): ${uniqueSensitive.join(', ')}.`,
        file: doc.meta.displayPath,
        line: first.line,
        column: first.column,
        evidence: first.token,
        fingerprintSubject: `dotenv-sensitive:${uniqueSensitive.join(',')}`,
      }),
    );
  } else if (safeDotenvTokens.length > 0) {
    const first = safeDotenvTokens[0]!;
    const uniqueSafe = [...new Set(safeDotenvTokens.map((x) => x.token))];
    findings.push(
      makeFinding({
        ruleId: 'AGL031',
        severity: 'info',
        message: `Detected benign dotenv template/schema reference(s): ${uniqueSafe.join(', ')}.`,
        file: doc.meta.displayPath,
        line: first.line,
        column: first.column,
        evidence: first.token,
        remediation:
          'Benign dotenv template or schema filename reference; ensure live .env secret values are never read or committed.',
        fingerprintSubject: `dotenv-safe:${uniqueSafe.join(',')}`,
      }),
    );
  }
}

interface SecretPatternRule {
  provider: string;
  regex: RegExp;
  groupIndex?: number;
}

const SECRET_PATTERN_RULES: readonly SecretPatternRule[] = [
  { provider: 'AWS Access Key ID', regex: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g },
  { provider: 'Anthropic API Key', regex: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/g },
  { provider: 'OpenAI API Key', regex: /\b(sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})\b/g },
  {
    provider: 'GitHub Token',
    regex: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})\b/g,
  },
  { provider: 'Stripe API Key', regex: /\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b/g },
  { provider: 'Slack Token', regex: /\b(xox[baprs]-[0-9A-Za-z-]{16,})\b/g },
  { provider: 'Google API Key', regex: /\b(AIza[0-9A-Za-z_-]{35})\b/g },
  { provider: 'Apify API Token', regex: /\b(apify_api_[A-Za-z0-9]{20,})\b/g },
  { provider: 'NPM Access Token', regex: /\b(npm_[A-Za-z0-9]{30,})\b/g },
  { provider: 'HuggingFace Token', regex: /\b(hf_[A-Za-z0-9]{30,})\b/g },
  {
    provider: 'PEM Private Key',
    regex: /(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)/g,
  },
  {
    provider: 'Credentialed Connection URI',
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^:\s/'"]+:([^@\s/'"]{6,})@/gi,
    groupIndex: 1,
  },
];

function computeShannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = createNullRecord<number>();
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i]!;
    counts[ch] = (hasOwn(counts, ch) ? counts[ch]! : 0) + 1;
  }
  let entropy = 0;
  for (const k of Object.keys(counts)) {
    const p = counts[k]! / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function extractSecretKeyAssignment(
  line: string,
): { keyName: string; rawVal: string; column: number } | null {
  let sepIdx = -1;
  for (let i = 1; i < line.length - 20; i += 1) {
    const ch = line[i];
    if (ch === '=' || ch === ':') {
      // Skip `://` URL schemes
      if (ch === ':' && line[i + 1] === '/' && line[i + 2] === '/') continue;
      sepIdx = i;
      break;
    }
  }
  if (sepIdx === -1) return null;

  // Walk left across whitespace and quotes to extract identifier key
  let keyEnd = sepIdx;
  while (keyEnd > 0 && (line[keyEnd - 1] === ' ' || line[keyEnd - 1] === '\t' || line[keyEnd - 1] === '"' || line[keyEnd - 1] === "'")) {
    keyEnd -= 1;
  }
  let keyStart = keyEnd;
  while (keyStart > 0 && isAsciiAlnumDashUnderscore(line.charCodeAt(keyStart - 1))) {
    keyStart -= 1;
  }
  const keyName = line.slice(keyStart, keyEnd);
  if (keyName.length < 4) return null;

  const upperKey = keyName.toUpperCase().replace(/-/g, '_');
  const isSensitiveKey =
    upperKey.includes('API_KEY') ||
    upperKey.includes('APIKEY') ||
    upperKey.includes('SECRET_KEY') ||
    upperKey.includes('CLIENT_SECRET') ||
    upperKey.includes('PRIVATE_KEY') ||
    upperKey.includes('ACCESS_TOKEN') ||
    upperKey.includes('AUTH_TOKEN') ||
    upperKey.endsWith('_SECRET') ||
    upperKey === 'SECRET' ||
    upperKey.endsWith('_PASSWORD') ||
    upperKey === 'PASSWORD';
  if (!isSensitiveKey) return null;

  let valStart = sepIdx + 1;
  while (valStart < line.length && (line[valStart] === ' ' || line[valStart] === '\t')) {
    valStart += 1;
  }
  if (valStart < line.length && (line[valStart] === '"' || line[valStart] === "'" || line[valStart] === '`')) {
    valStart += 1;
  }
  let valEnd = valStart;
  while (valEnd < line.length) {
    const c = line.charCodeAt(valEnd);
    const ok =
      (c >= 0x30 && c <= 0x39) ||
      (c >= 0x41 && c <= 0x5a) ||
      (c >= 0x61 && c <= 0x7a) ||
      c === 0x2b ||
      c === 0x2f ||
      c === 0x3d ||
      c === 0x5f ||
      c === 0x2d;
    if (!ok) break;
    valEnd += 1;
  }
  const rawVal = line.slice(valStart, valEnd);
  if (rawVal.length < 20) return null;
  return { keyName, rawVal, column: keyStart + 1 };
}

function isObviousPlaceholderSecret(val: string): boolean {
  const trimmed = val.trim();
  if (trimmed.length === 0) return true;
  if (
    trimmed.startsWith('${') ||
    trimmed.startsWith('$') ||
    trimmed.startsWith('<') ||
    trimmed.startsWith('{{') ||
    trimmed.startsWith('%')
  ) {
    return true;
  }
  const lower = trimmed.toLowerCase();
  if (
    lower === 'example' ||
    lower === 'placeholder' ||
    lower === 'dummy' ||
    lower === 'changeme' ||
    lower === 'change_me' ||
    lower === 'change-me' ||
    lower === 'replace_me' ||
    lower === 'replace-me' ||
    lower === 'replaceme' ||
    lower === 'password' ||
    lower === 'secret' ||
    lower === 'todo' ||
    lower === 'none' ||
    lower === 'null' ||
    lower === 'undefined' ||
    lower.startsWith('your_') ||
    lower.startsWith('your-') ||
    lower.startsWith('replace_') ||
    lower.startsWith('replace-') ||
    lower.startsWith('insert_') ||
    lower.startsWith('insert-') ||
    lower.startsWith('example_') ||
    lower.startsWith('example-') ||
    lower.startsWith('placeholder_') ||
    lower.startsWith('dummy_') ||
    lower.endsWith('_here') ||
    lower.endsWith('-here')
  ) {
    return true;
  }
  // Repeated characters such as `xxxxxxxxxxxxxxxxxxxxxxxx`
  let allSame = true;
  for (let i = 1; i < lower.length; i += 1) {
    if (lower[i] !== lower[0]) {
      allSame = false;
      break;
    }
  }
  return allSame;
}

function analyzeSecretsForDoc(doc: LoadedDocument, findings: Finding[]): void {
  const seenPerLine = new Set<string>();

  for (let idx = 0; idx < doc.parsed.lines.length; idx += 1) {
    const lineNo = idx + 1;
    const line = doc.parsed.lines[idx]!;
    if (line.length === 0) continue;

    let matchedKnownOnLine = false;
    for (const rule of SECRET_PATTERN_RULES) {
      for (const m of line.matchAll(rule.regex)) {
        const rawSecret = m[rule.groupIndex ?? 1] ?? m[0];
        if (!isObviousPlaceholderSecret(rawSecret)) {
          const redacted =
            rule.provider === 'PEM Private Key'
              ? '-----BEGIN...***REDACTED***'
              : redactSecret(rawSecret);
          const key = `${lineNo}:${rule.provider}:${hashShort(rawSecret)}`;
          if (!seenPerLine.has(key)) {
            seenPerLine.add(key);
            matchedKnownOnLine = true;
            findings.push(
              makeFinding({
                ruleId: 'AGL032',
                message: `Detected pasted ${rule.provider} in instruction file (${redacted}).`,
                file: doc.meta.displayPath,
                line: lineNo,
                column: (m.index ?? 0) + 1,
                evidence: redacted,
                fingerprintSubject: `secret:${rule.provider}:L${lineNo}:${hashShort(rawSecret)}`,
              }),
            );
          }
        }
      }
    }

    if (matchedKnownOnLine) continue;

    // Check high-entropy assignment to secret-named key (`API_KEY=...`, `CLIENT_SECRET: "..."`)
    const kvMatch = extractSecretKeyAssignment(line);
    if (kvMatch) {
      const { keyName, rawVal } = kvMatch;
      if (!isObviousPlaceholderSecret(rawVal)) {
        let classes = 0;
        if (/[a-z]/.test(rawVal)) classes += 1;
        if (/[A-Z]/.test(rawVal)) classes += 1;
        if (/[0-9]/.test(rawVal)) classes += 1;
        if (/[^A-Za-z0-9]/.test(rawVal)) classes += 1;
        if (classes >= 2 && computeShannonEntropy(rawVal) >= 3.75) {
          const redacted = redactSecret(rawVal);
          findings.push(
            makeFinding({
              ruleId: 'AGL032',
              message: `Detected high-entropy secret value assigned to "${keyName}" (${redacted}).`,
              file: doc.meta.displayPath,
              line: lineNo,
              column: kvMatch.column,
              evidence: `${keyName}=${redacted}`,
              fingerprintSubject: `secret-kv:${keyName}:L${lineNo}:${hashShort(rawVal)}`,
            }),
          );
        }
      }
    }
  }
}

function analyzeSkillsAndFrontmatter(discovery: DiscoveryResult, findings: Finding[]): void {
  const skillsByName = new Map<string, LoadedDocument[]>();

  for (const doc of discovery.documents) {
    const fm = doc.parsed.frontmatter;

    // Prototype pollution & YAML alias checks apply to ANY frontmatter-bearing file
    if (fm.present && fm.dangerousKeys.length > 0) {
      findings.push(
        makeFinding({
          ruleId: 'AGL040',
          message: `YAML frontmatter contains unsafe prototype-pollution key(s): ${fm.dangerousKeys.join(', ')}.`,
          file: doc.meta.displayPath,
          line: fm.startLine,
          column: 1,
          evidence: fm.dangerousKeys.join(', '),
          fingerprintSubject: `yaml-proto:${fm.dangerousKeys.join(',')}`,
        }),
      );
    }

    if (fm.present && fm.aliasLimitExceeded) {
      findings.push(
        makeFinding({
          ruleId: 'AGL040',
          message: 'YAML frontmatter exceeded maximum alias expansion count (maxAliasCount guard).',
          file: doc.meta.displayPath,
          line: fm.startLine,
          column: 1,
          fingerprintSubject: 'yaml-alias-cap',
        }),
      );
    }

    if (doc.meta.kind !== 'skill-md') {
      continue;
    }

    if (!fm.present) {
      findings.push(
        makeFinding({
          ruleId: 'AGL040',
          message: 'SKILL.md is missing required YAML frontmatter (`--- ... ---`).',
          file: doc.meta.displayPath,
          line: 1,
          column: 1,
          fingerprintSubject: 'skill-missing-fm',
        }),
      );
      continue;
    }

    if (fm.empty) {
      findings.push(
        makeFinding({
          ruleId: 'AGL040',
          message: 'SKILL.md has empty YAML frontmatter; `name` and `description` are required.',
          file: doc.meta.displayPath,
          line: 1,
          column: 1,
          fingerprintSubject: 'skill-empty-fm',
        }),
      );
      continue;
    }

    if (fm.yamlError && !fm.aliasLimitExceeded) {
      findings.push(
        makeFinding({
          ruleId: 'AGL040',
          message: `SKILL.md frontmatter YAML parse error: ${fm.yamlError}`,
          file: doc.meta.displayPath,
          line: 1,
          column: 1,
          fingerprintSubject: 'skill-yaml-err',
        }),
      );
      continue;
    }

    const rawName = fm.data['name'];
    const rawDesc = fm.data['description'];

    if (typeof rawName !== 'string' || rawName.trim().length === 0) {
      findings.push(
        makeFinding({
          ruleId: 'AGL040',
          message: 'SKILL.md frontmatter is missing a non-empty string `name`.',
          file: doc.meta.displayPath,
          line: 1,
          column: 1,
          fingerprintSubject: 'skill-missing-name',
        }),
      );
    } else {
      const skillName = rawName.trim();
      if (skillName.length > 64) {
        findings.push(
          makeFinding({
            ruleId: 'AGL040',
            message: `SKILL.md \`name\` exceeds 64 characters (${skillName.length} chars).`,
            file: doc.meta.displayPath,
            line: 1,
            column: 1,
            evidence: skillName.slice(0, 40),
            fingerprintSubject: 'skill-name-len',
          }),
        );
      }

      const parentDirName = path.basename(path.dirname(doc.meta.absPath));
      if (skillName !== parentDirName) {
        findings.push(
          makeFinding({
            ruleId: 'AGL040',
            message: `SKILL.md frontmatter \`name\` ("${skillName}") does not match parent directory name ("${parentDirName}").`,
            file: doc.meta.displayPath,
            line: 1,
            column: 1,
            evidence: `name: ${skillName}`,
            fingerprintSubject: `skill-dir-mismatch:${skillName}-vs-${parentDirName}`,
          }),
        );
      }

      const group = skillsByName.get(skillName);
      if (group) {
        group.push(doc);
      } else {
        skillsByName.set(skillName, [doc]);
      }
    }

    if (typeof rawDesc !== 'string' || rawDesc.trim().length === 0) {
      findings.push(
        makeFinding({
          ruleId: 'AGL040',
          message: 'SKILL.md frontmatter is missing a non-empty string `description`.',
          file: doc.meta.displayPath,
          line: 1,
          column: 1,
          fingerprintSubject: 'skill-missing-desc',
        }),
      );
    } else if (rawDesc.trim().length > 1024) {
      findings.push(
        makeFinding({
          ruleId: 'AGL040',
          message: `SKILL.md \`description\` exceeds 1,024 characters (${rawDesc.trim().length} chars).`,
          file: doc.meta.displayPath,
          line: 1,
          column: 1,
          fingerprintSubject: 'skill-desc-len',
        }),
      );
    }
  }

  // Check duplicate skill names across skill roots
  for (const [skillName, docs] of skillsByName.entries()) {
    if (docs.length < 2) continue;
    const locations = docs.map((d) => d.meta.displayPath).join(', ');
    for (let i = 1; i < docs.length; i += 1) {
      const dupDoc = docs[i]!;
      findings.push(
        makeFinding({
          ruleId: 'AGL040',
          message: `Duplicate skill name "${skillName}" defined across multiple skill roots (${locations}).`,
          file: dupDoc.meta.displayPath,
          line: 1,
          column: 1,
          evidence: `name: ${skillName}`,
          fingerprintSubject: `skill-dup:${skillName}`,
        }),
      );
    }
  }
}

function analyzeRuleGlobs(discovery: DiscoveryResult, findings: Finding[]): void {
  for (const doc of discovery.documents) {
    if (doc.meta.sourceRoot !== 'repo') continue;
    const fm = doc.parsed.frontmatter;

    if (doc.meta.kind === 'cursor-mdc') {
      if (!fm.present || fm.yamlError) {
        findings.push(
          makeFinding({
            ruleId: 'AGL041',
            message: fm.yamlError
              ? `Cursor rule "${doc.meta.displayPath}" has invalid frontmatter: ${fm.yamlError}`
              : `Cursor rule "${doc.meta.displayPath}" is missing YAML frontmatter.`,
            file: doc.meta.displayPath,
            line: 1,
            column: 1,
            agent: 'cursor',
            fingerprintSubject: 'mdc-invalid-fm',
          }),
        );
        continue;
      }

      const alwaysApply = fm.data['alwaysApply'] === true;
      const globs = splitGlobList(fm.data['globs']);
      const description = typeof fm.data['description'] === 'string' ? fm.data['description'].trim() : '';

      if (alwaysApply && globs.length > 0) {
        findings.push(
          makeFinding({
            ruleId: 'AGL041',
            message: `Cursor rule "${doc.meta.displayPath}" sets both \`alwaysApply: true\` and \`globs\` (${globs.join(', ')}); \`globs\` are ignored when \`alwaysApply\` is true.`,
            file: doc.meta.displayPath,
            line: 1,
            column: 1,
            agent: 'cursor',
            evidence: `alwaysApply: true, globs: ${globs.join(', ')}`,
            fingerprintSubject: 'mdc-always-and-globs',
          }),
        );
      } else if (!alwaysApply && globs.length > 0) {
        if (!anyFileMatchesGlobs(globs, discovery.repoFilesPosix)) {
          findings.push(
            makeFinding({
              ruleId: 'AGL041',
              message: `Cursor rule "${doc.meta.displayPath}" \`globs\` (${globs.join(', ')}) matched zero files in the repository.`,
              file: doc.meta.displayPath,
              line: 1,
              column: 1,
              agent: 'cursor',
              evidence: globs.join(', '),
              fingerprintSubject: `mdc-zero-match:${globs.join(',')}`,
            }),
          );
        }
      } else if (!alwaysApply && globs.length === 0 && description.length === 0) {
        findings.push(
          makeFinding({
            ruleId: 'AGL041',
            message: `Cursor rule "${doc.meta.displayPath}" has \`alwaysApply !== true\`, empty \`globs\`, and empty \`description\`, so it will never auto-attach.`,
            file: doc.meta.displayPath,
            line: 1,
            column: 1,
            agent: 'cursor',
            fingerprintSubject: 'mdc-unreachable',
          }),
        );
      }
    } else if (doc.meta.kind === 'copilot-scoped-instructions') {
      if (!fm.present || fm.yamlError) {
        findings.push(
          makeFinding({
            ruleId: 'AGL041',
            message: fm.yamlError
              ? `Copilot instructions "${doc.meta.displayPath}" has invalid frontmatter: ${fm.yamlError}`
              : `Copilot instructions "${doc.meta.displayPath}" is missing YAML frontmatter with \`applyTo\`.`,
            file: doc.meta.displayPath,
            line: 1,
            column: 1,
            agent: 'copilot',
            fingerprintSubject: 'copilot-missing-fm',
          }),
        );
        continue;
      }

      const applyTo = splitGlobList(fm.data['applyTo']);
      if (applyTo.length === 0) {
        findings.push(
          makeFinding({
            ruleId: 'AGL041',
            message: `Copilot instructions "${doc.meta.displayPath}" is missing a non-empty \`applyTo\` glob pattern.`,
            file: doc.meta.displayPath,
            line: 1,
            column: 1,
            agent: 'copilot',
            fingerprintSubject: 'copilot-empty-applyto',
          }),
        );
      } else if (!anyFileMatchesGlobs(applyTo, discovery.repoFilesPosix)) {
        findings.push(
          makeFinding({
            ruleId: 'AGL041',
            message: `Copilot instructions "${doc.meta.displayPath}" \`applyTo\` pattern (${applyTo.join(', ')}) matched zero files in the repository.`,
            file: doc.meta.displayPath,
            line: 1,
            column: 1,
            agent: 'copilot',
            evidence: applyTo.join(', '),
            fingerprintSubject: `copilot-zero-match:${applyTo.join(',')}`,
          }),
        );
      }
    }
  }
}

function analyzeTokenBudgets(
  agentContexts: Partial<Record<AgentName, AgentContextReport>>,
  agents: readonly AgentName[],
  budgetTokens: number,
  findings: Finding[],
): void {
  const seenSingleFileShare = new Set<string>();

  for (const agent of agents) {
    const ctx = agentContexts[agent];
    if (!ctx) continue;

    if (ctx.totalAlwaysLoadedTokens > budgetTokens) {
      const highThreshold = Math.floor(budgetTokens * 1.5);
      const severity: Severity = ctx.totalAlwaysLoadedTokens > highThreshold ? 'high' : 'medium';
      const primaryFile = ctx.alwaysLoadedFiles[0]?.file ?? '.';
      findings.push(
        makeFinding({
          ruleId: 'AGL001',
          severity,
          message: `Always-loaded instruction context for "${agent}" is ~${ctx.totalAlwaysLoadedTokens} estimated tokens (chars/4), exceeding budget of ${budgetTokens} tokens.`,
          file: primaryFile,
          line: 1,
          column: 1,
          agent,
          evidence: `~${ctx.totalAlwaysLoadedTokens} / ${budgetTokens} tokens (${ctx.alwaysLoadedFiles.length} file(s))`,
          fingerprintSubject: `budget:${agent}`,
        }),
      );
    }

    const singleFileLimit = budgetTokens * 0.4;
    for (const entry of ctx.alwaysLoadedFiles) {
      if (entry.estimatedTokens > singleFileLimit && !seenSingleFileShare.has(entry.file)) {
        seenSingleFileShare.add(entry.file);
        findings.push(
          makeFinding({
            ruleId: 'AGL002',
            severity: 'low',
            message: `Single always-loaded file "${entry.file}" consumes ~${entry.estimatedTokens} estimated tokens (${entry.budgetSharePct}% of ${budgetTokens}-token budget, > 40% threshold).`,
            file: entry.file,
            line: 1,
            column: 1,
            agent,
            evidence: `~${entry.estimatedTokens} tokens (${entry.budgetSharePct}%)`,
            fingerprintSubject: `share:${entry.file}`,
          }),
        );
      }
    }
  }
}

export function runAllAnalyzers(params: {
  discovery: DiscoveryResult;
  agentContexts: Partial<Record<AgentName, AgentContextReport>>;
  agents: readonly AgentName[];
  budgetTokens: number;
}): Finding[] {
  const findings: Finding[] = [...params.discovery.discoveryFindings];
  const configCache = new Map<string, BuildConfigSnapshot>();

  analyzeTokenBudgets(params.agentContexts, params.agents, params.budgetTokens, findings);

  for (const doc of params.discovery.documents) {
    const fsCtx =
      doc.meta.sourceRoot === 'home' && params.discovery.homeFs
        ? params.discovery.homeFs
        : params.discovery.repoFs;
    const topDirs =
      doc.meta.sourceRoot === 'repo' ? params.discovery.repoTopLevelDirs : new Set<string>();

    analyzePathsAndLinksForDoc(doc, fsCtx, topDirs, findings);
    analyzeCommandsForDoc(doc, fsCtx, configCache, findings);
    analyzeHiddenContentForDoc(doc, findings);
    analyzeDangerousDirectivesForDoc(doc, findings);
    analyzeSecretsForDoc(doc, findings);
  }

  analyzePackageManagerConsistency(params.discovery, findings);
  analyzeSkillsAndFrontmatter(params.discovery, findings);
  analyzeRuleGlobs(params.discovery, findings);

  // Sort deterministically: severity DESC -> file ASC -> line ASC -> ruleId ASC
  findings.sort((a, b) => {
    const sevDiff = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (sevDiff !== 0) return sevDiff;
    const fileCmp = a.file.localeCompare(b.file);
    if (fileCmp !== 0) return fileCmp;
    if (a.line !== b.line) return a.line - b.line;
    return a.ruleId.localeCompare(b.ruleId);
  });

  return findings;
}

export function loadBaselineFingerprints(baselinePath: string): Set<string> {
  const rawText = fs.readFileSync(baselinePath, 'utf8');
  const parsed = JSON.parse(rawText) as unknown;
  const fingerprints = new Set<string>();

  if (Array.isArray(parsed)) {
    for (const item of parsed) {
      if (typeof item === 'string' && item.trim().length > 0) {
        fingerprints.add(item.trim());
      } else if (item && typeof item === 'object' && 'fingerprint' in item) {
        const fp = (item as Record<string, unknown>)['fingerprint'];
        if (typeof fp === 'string' && fp.trim().length > 0) {
          fingerprints.add(fp.trim());
        }
      }
    }
    return fingerprints;
  }

  if (parsed && typeof parsed === 'object') {
    const obj = parsed as Record<string, unknown>;
    if (Array.isArray(obj['fingerprints'])) {
      for (const fp of obj['fingerprints']) {
        if (typeof fp === 'string' && fp.trim().length > 0) {
          fingerprints.add(fp.trim());
        }
      }
    }
    if (Array.isArray(obj['findings'])) {
      for (const f of obj['findings']) {
        if (f && typeof f === 'object') {
          const fp = (f as Record<string, unknown>)['fingerprint'];
          if (typeof fp === 'string' && fp.trim().length > 0) {
            fingerprints.add(fp.trim());
          }
        }
      }
    }
    // Also support SARIF 2.1.0 baseline files (`runs[].results[].partialFingerprints.primaryLocationLineHash`)
    if (Array.isArray(obj['runs'])) {
      for (const run of obj['runs']) {
        if (!run || typeof run !== 'object') continue;
        const results = (run as Record<string, unknown>)['results'];
        if (!Array.isArray(results)) continue;
        for (const res of results) {
          if (!res || typeof res !== 'object') continue;
          const pf = (res as Record<string, unknown>)['partialFingerprints'];
          if (pf && typeof pf === 'object') {
            for (const val of Object.values(pf as Record<string, unknown>)) {
              if (typeof val === 'string' && val.trim().length > 0) {
                fingerprints.add(val.trim());
              }
            }
          }
        }
      }
    }
    return fingerprints;
  }

  throw new Error('Unsupported baseline JSON structure.');
}
