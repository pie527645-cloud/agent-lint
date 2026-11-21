import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { SafeFsContext, toPosixPath } from './fs-safe.js';
import { isUniversalGlob, splitGlobList } from './glob.js';
import { type ParsedMarkdown, parseMarkdownDocument } from './markdown.js';
import { RULES } from './rules-catalog.js';
import {
  type AgentContextReport,
  type AgentName,
  ALL_AGENTS,
  type ContextFileEntry,
  DEFAULT_BUDGET_TOKENS,
  DEFAULT_MAX_FILE_BYTES,
  DEFAULT_MAX_SCANNED_FILES,
  type DiscoveredFile,
  estimateTokens,
  type Finding,
  type InstructionKind,
  MAX_IMPORT_DEPTH,
  type RuleId,
  type ScopedContextEntry,
  type Severity,
  type SkillContextEntry,
  TOKEN_ESTIMATION_LABEL,
} from './types.js';

export interface LoadedDocument {
  meta: DiscoveredFile;
  parsed: ParsedMarkdown;
  /** Ordered transitive `@path` imports resolved from this file (for Claude configs). */
  resolvedImports: LoadedDocument[];
}

export interface DiscoveryResult {
  repoFs: SafeFsContext;
  homeFs: SafeFsContext | null;
  repoFilesPosix: string[];
  repoTopLevelDirs: Set<string>;
  documents: LoadedDocument[];
  /** Findings emitted during discovery (AGL010 broken @import, AGL012 escape, AGL900 cap skip). */
  discoveryFindings: Finding[];
}

export function computeFindingFingerprint(
  ruleId: RuleId,
  file: string,
  subject: string,
): string {
  const normalizedFile = file.replace(/\\/g, '/');
  const payload = `${ruleId}|${normalizedFile}|${subject}`;
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex').slice(0, 32);
}

export function makeFinding(params: {
  ruleId: RuleId;
  severity?: Severity;
  message: string;
  file: string;
  line?: number;
  column?: number;
  agent?: AgentName;
  evidence?: string;
  remediation?: string;
  fingerprintSubject: string;
}): Finding {
  const rule = RULES[params.ruleId];
  const line = params.line ?? 1;
  const column = params.column ?? 1;
  return {
    ruleId: params.ruleId,
    severity: params.severity ?? rule.defaultSeverity,
    category: rule.category,
    message: params.message,
    file: params.file.replace(/\\/g, '/'),
    line,
    column,
    ...(params.agent !== undefined ? { agent: params.agent } : {}),
    ...(params.evidence !== undefined ? { evidence: params.evidence } : {}),
    remediation: params.remediation ?? rule.remediation,
    fingerprint: computeFindingFingerprint(params.ruleId, params.file, params.fingerprintSubject),
  };
}

function computeScopeDir(relPosix: string, kind: InstructionKind): string {
  if (
    kind === 'copilot-instructions' ||
    kind === 'copilot-scoped-instructions' ||
    kind === 'cursor-mdc' ||
    kind === 'cursorrules' ||
    kind === 'skill-md'
  ) {
    return '';
  }
  if (relPosix === '.claude/CLAUDE.md' || relPosix === '.gemini/GEMINI.md' || relPosix === '.agents/AGENTS.md') {
    return '';
  }
  const slashIdx = relPosix.lastIndexOf('/');
  if (slashIdx === -1) return '';
  const dir = relPosix.slice(0, slashIdx);
  // `<subdir>/.claude/CLAUDE.md` -> `<subdir>`
  if (dir.endsWith('/.claude')) return dir.slice(0, -'/.claude'.length);
  if (dir.endsWith('/.gemini')) return dir.slice(0, -'/.gemini'.length);
  return dir;
}

export function classifyInstructionPath(
  relPosix: string,
  sourceRoot: 'repo' | 'home',
): InstructionKind | null {
  const base = relPosix.slice(relPosix.lastIndexOf('/') + 1);

  if (base === 'AGENTS.md') {
    return 'agents-md';
  }
  if (base === 'CLAUDE.md') {
    return 'claude-md';
  }
  if (base === 'CLAUDE.local.md') {
    return 'claude-local-md';
  }
  if (base === 'GEMINI.md') {
    return 'gemini-md';
  }
  if (relPosix === '.github/copilot-instructions.md') {
    return 'copilot-instructions';
  }
  if (relPosix.startsWith('.github/instructions/') && relPosix.endsWith('.instructions.md')) {
    return 'copilot-scoped-instructions';
  }
  if (relPosix.startsWith('.cursor/rules/') && relPosix.endsWith('.mdc')) {
    return 'cursor-mdc';
  }
  if (relPosix === '.cursorrules') {
    return 'cursorrules';
  }
  if (base === 'SKILL.md') {
    if (
      relPosix.startsWith('.claude/skills/') ||
      relPosix.startsWith('.agents/skills/') ||
      relPosix.startsWith('.gemini/skills/') ||
      (sourceRoot === 'home' && relPosix.startsWith('skills/'))
    ) {
      return 'skill-md';
    }
  }
  return null;
}

function agentsForFile(
  kind: InstructionKind,
  relPosix: string,
  parsed: ParsedMarkdown,
): { agents: AgentName[]; alwaysLoadedFor: AgentName[] } {
  const scopeDir = computeScopeDir(relPosix, kind);
  const isRootScope = scopeDir === '';

  switch (kind) {
    case 'agents-md':
      return {
        agents: ['gemini', 'cursor', 'copilot'],
        alwaysLoadedFor: isRootScope ? ['gemini', 'cursor', 'copilot'] : [],
      };
    case 'claude-md':
    case 'claude-local-md':
    case 'claude-import':
      return {
        agents: ['claude'],
        alwaysLoadedFor: isRootScope ? ['claude'] : [],
      };
    case 'gemini-md':
      return {
        agents: ['gemini'],
        alwaysLoadedFor: isRootScope ? ['gemini'] : [],
      };
    case 'copilot-instructions':
      return {
        agents: ['copilot'],
        alwaysLoadedFor: ['copilot'],
      };
    case 'copilot-scoped-instructions': {
      const applyTo = splitGlobList(parsed.frontmatter.data['applyTo']);
      const always = isUniversalGlob(applyTo);
      return {
        agents: ['copilot'],
        alwaysLoadedFor: always ? ['copilot'] : [],
      };
    }
    case 'cursorrules':
      return {
        agents: ['cursor'],
        alwaysLoadedFor: ['cursor'],
      };
    case 'cursor-mdc': {
      const always = parsed.frontmatter.data['alwaysApply'] === true;
      return {
        agents: ['cursor'],
        alwaysLoadedFor: always ? ['cursor'] : [],
      };
    }
    case 'skill-md': {
      if (relPosix.startsWith('.claude/skills/')) {
        return { agents: ['claude'], alwaysLoadedFor: [] };
      }
      if (relPosix.startsWith('.gemini/skills/')) {
        return { agents: ['gemini'], alwaysLoadedFor: [] };
      }
      // `.agents/skills/` is cross-agent
      return { agents: ['claude', 'gemini', 'cursor', 'copilot'], alwaysLoadedFor: [] };
    }
  }
}

function isAgentRelevantEscapedPath(relPosix: string): boolean {
  const base = relPosix.slice(relPosix.lastIndexOf('/') + 1);
  if (
    relPosix.startsWith('.claude') ||
    relPosix.startsWith('.gemini') ||
    relPosix.startsWith('.cursor') ||
    relPosix.startsWith('.agents') ||
    relPosix.startsWith('.github/instructions') ||
    relPosix === '.github/copilot-instructions.md' ||
    relPosix === '.cursorrules'
  ) {
    return true;
  }
  return (
    base === 'AGENTS.md' ||
    base === 'CLAUDE.md' ||
    base === 'CLAUDE.local.md' ||
    base === 'GEMINI.md' ||
    base === 'SKILL.md' ||
    base.endsWith('.mdc') ||
    base.endsWith('.instructions.md')
  );
}

export function discoverWorkspace(options: {
  repoDir: string;
  homeDir?: string | null;
  maxFileBytes?: number;
  maxScannedFiles?: number;
}): DiscoveryResult {
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const maxScannedFiles = options.maxScannedFiles ?? DEFAULT_MAX_SCANNED_FILES;

  const repoFs = new SafeFsContext(options.repoDir, { maxFileBytes, maxScannedFiles });
  const homeFs =
    options.homeDir !== undefined && options.homeDir !== null
      ? new SafeFsContext(options.homeDir, { maxFileBytes, maxScannedFiles })
      : null;

  const discoveryFindings: Finding[] = [];
  const documents: LoadedDocument[] = [];
  const loadedByRealPath = new Map<string, LoadedDocument>();
  const importsExpandedRealPaths = new Set<string>();

  const repoInventory = repoFs.collectRepoInventory();

  for (const escaped of repoInventory.escapedPaths) {
    if (isAgentRelevantEscapedPath(escaped.relPath)) {
      discoveryFindings.push(
        makeFinding({
          ruleId: 'AGL012',
          message: `Symlink or junction "${escaped.relPath}" resolves outside the scan root; blocked.`,
          file: escaped.relPath,
          line: 1,
          column: 1,
          fingerprintSubject: `symlink:${escaped.relPath}`,
        }),
      );
    }
  }

  if (repoInventory.truncatedByCap) {
    discoveryFindings.push(
      makeFinding({
        ruleId: 'AGL900',
        message: `Repository file walk reached the ${maxScannedFiles}-file scan limit; remaining files were skipped.`,
        file: '.',
        line: 1,
        column: 1,
        fingerprintSubject: `file-cap:${maxScannedFiles}`,
      }),
    );
  }

  function loadSingleFile(params: {
    fsCtx: SafeFsContext;
    sourceRoot: 'repo' | 'home';
    absPath: string;
    realPath: string;
    relPosix: string;
    kind: InstructionKind;
    importedBy?: string;
    importDepth?: number;
  }): LoadedDocument | null {
    const displayPath =
      params.sourceRoot === 'home' ? `home:${params.relPosix}` : params.relPosix;

    const existing = loadedByRealPath.get(params.realPath);
    if (existing) {
      return existing;
    }

    let stat: fs.Stats;
    try {
      stat = fs.statSync(params.realPath);
    } catch {
      return null;
    }

    if (stat.size > maxFileBytes) {
      discoveryFindings.push(
        makeFinding({
          ruleId: 'AGL900',
          message: `Skipped "${displayPath}" (${stat.size} bytes exceeds the ${maxFileBytes}-byte per-file size cap).`,
          file: displayPath,
          line: 1,
          column: 1,
          fingerprintSubject: `size-cap:${displayPath}`,
        }),
      );
      return null;
    }

    let rawContent: string;
    try {
      rawContent = fs.readFileSync(params.realPath, 'utf8');
    } catch {
      return null;
    }

    const parsed = parseMarkdownDocument(rawContent);
    const scopeDir = computeScopeDir(params.relPosix, params.kind);
    const { agents, alwaysLoadedFor } = agentsForFile(params.kind, params.relPosix, parsed);
    const chars = parsed.cleanContent.length;

    const meta: DiscoveredFile = {
      absPath: params.absPath,
      realPath: params.realPath,
      displayPath,
      relToSourceRoot: params.relPosix,
      sourceRoot: params.sourceRoot,
      rootDirReal: params.fsCtx.rootDirReal,
      kind: params.kind,
      scopeDir,
      agents,
      alwaysLoadedFor,
      bytes: stat.size,
      chars,
      estimatedTokens: estimateTokens(chars),
      hasBom: parsed.hasBom,
      content: parsed.cleanContent,
      frontmatter: parsed.frontmatter,
      ...(params.importedBy !== undefined ? { importedBy: params.importedBy } : {}),
      ...(params.importDepth !== undefined ? { importDepth: params.importDepth } : {}),
    };

    const doc: LoadedDocument = {
      meta,
      parsed,
      resolvedImports: [],
    };

    loadedByRealPath.set(params.realPath, doc);
    documents.push(doc);
    return doc;
  }

  function expandClaudeImports(
    doc: LoadedDocument,
    fsCtx: SafeFsContext,
    activeAncestors: Set<string>,
    depth: number,
  ): void {
    if (importsExpandedRealPaths.has(doc.meta.realPath)) {
      return;
    }
    importsExpandedRealPaths.add(doc.meta.realPath);

    if (doc.parsed.claudeImports.length === 0) {
      return;
    }

    const parentDirAbs = path.dirname(doc.meta.absPath);
    for (const imp of doc.parsed.claudeImports) {
      const check = fsCtx.checkCaseExactPath(parentDirAbs, imp.targetPath);
      if (check.status === 'escaped-root') {
        discoveryFindings.push(
          makeFinding({
            ruleId: 'AGL012',
            message: `@import "${imp.rawToken}" escapes the scan root; blocked without reading target.`,
            file: doc.meta.displayPath,
            line: imp.line,
            column: imp.column,
            agent: 'claude',
            evidence: imp.rawToken,
            fingerprintSubject: `escape:${imp.rawToken}`,
          }),
        );
        continue;
      }

      if (check.status === 'case-mismatch') {
        discoveryFindings.push(
          makeFinding({
            ruleId: 'AGL010',
            message: `Broken @import "${imp.rawToken}": path segment "${check.expectedSegment}" does not match on-disk casing "${check.actualSegment}".`,
            file: doc.meta.displayPath,
            line: imp.line,
            column: imp.column,
            agent: 'claude',
            evidence: imp.rawToken,
            fingerprintSubject: `import-case:${imp.rawToken}`,
          }),
        );
        continue;
      }

      if (check.status === 'missing') {
        discoveryFindings.push(
          makeFinding({
            ruleId: 'AGL010',
            message: `Broken @import "${imp.rawToken}": referenced file does not exist.`,
            file: doc.meta.displayPath,
            line: imp.line,
            column: imp.column,
            agent: 'claude',
            evidence: imp.rawToken,
            fingerprintSubject: `import-missing:${imp.rawToken}`,
          }),
        );
        continue;
      }

      if (check.isDirectory) {
        discoveryFindings.push(
          makeFinding({
            ruleId: 'AGL010',
            message: `Broken @import "${imp.rawToken}": target resolves to a directory rather than a file.`,
            file: doc.meta.displayPath,
            line: imp.line,
            column: imp.column,
            agent: 'claude',
            evidence: imp.rawToken,
            fingerprintSubject: `import-dir:${imp.rawToken}`,
          }),
        );
        continue;
      }

      // Cycle guard: A -> B -> A
      if (activeAncestors.has(check.realPath)) {
        continue;
      }

      // Max hop depth guard (max depth 5)
      if (depth >= MAX_IMPORT_DEPTH) {
        continue;
      }

      const relPosix = toPosixPath(path.relative(fsCtx.rootDirReal, check.resolvedAbs));
      const naturalKind = classifyInstructionPath(relPosix, doc.meta.sourceRoot);
      const childDoc = loadSingleFile({
        fsCtx,
        sourceRoot: doc.meta.sourceRoot,
        absPath: check.resolvedAbs,
        realPath: check.realPath,
        relPosix,
        kind: naturalKind ?? 'claude-import',
        importedBy: doc.meta.displayPath,
        importDepth: depth + 1,
      });

      if (!childDoc) {
        continue;
      }

      // Ensure Claude is registered on imported files (e.g. if CLAUDE.md imports @AGENTS.md or @docs/style.md)
      if (!childDoc.meta.agents.includes('claude')) {
        childDoc.meta.agents.push('claude');
      }
      if (doc.meta.alwaysLoadedFor.includes('claude') && !childDoc.meta.alwaysLoadedFor.includes('claude')) {
        childDoc.meta.alwaysLoadedFor.push('claude');
      }

      doc.resolvedImports.push(childDoc);

      const nextAncestors = new Set(activeAncestors);
      nextAncestors.add(check.realPath);
      expandClaudeImports(childDoc, fsCtx, nextAncestors, depth + 1);
    }
  }

  function scanSourceRoot(
    fsCtx: SafeFsContext,
    sourceRoot: 'repo' | 'home',
    filesPosix: readonly string[],
  ): LoadedDocument[] {
    const created: LoadedDocument[] = [];
    for (const relPosix of filesPosix) {
      const kind = classifyInstructionPath(relPosix, sourceRoot);
      if (!kind) continue;

      const check = fsCtx.checkCaseExactPath(fsCtx.rootDirReal, relPosix);
      if (check.status === 'escaped-root') {
        const display = sourceRoot === 'home' ? `home:${relPosix}` : relPosix;
        discoveryFindings.push(
          makeFinding({
            ruleId: 'AGL012',
            message: `Instruction file "${display}" resolves outside its root via symlink or junction; blocked.`,
            file: display,
            line: 1,
            column: 1,
            fingerprintSubject: `file-escape:${display}`,
          }),
        );
        continue;
      }
      if (check.status !== 'ok' || check.isDirectory) {
        continue;
      }

      const doc = loadSingleFile({
        fsCtx,
        sourceRoot,
        absPath: check.resolvedAbs,
        realPath: check.realPath,
        relPosix,
        kind,
      });
      if (doc) {
        created.push(doc);
      }
    }
    return created;
  }

  // 1. Optional explicit --home discovery first (so home files precede repo files in load order)
  if (homeFs) {
    const homeInventory = homeFs.collectRepoInventory();
    for (const escaped of homeInventory.escapedPaths) {
      if (isAgentRelevantEscapedPath(escaped.relPath)) {
        discoveryFindings.push(
          makeFinding({
            ruleId: 'AGL012',
            message: `Home config symlink or junction "home:${escaped.relPath}" escapes the --home root; blocked.`,
            file: `home:${escaped.relPath}`,
            line: 1,
            column: 1,
            fingerprintSubject: `home-symlink:${escaped.relPath}`,
          }),
        );
      }
    }
    const homeDocs = scanSourceRoot(homeFs, 'home', homeInventory.filesPosix);
    for (const doc of homeDocs) {
      if (doc.meta.kind === 'claude-md' || doc.meta.kind === 'claude-local-md') {
        expandClaudeImports(doc, homeFs, new Set([doc.meta.realPath]), 0);
      }
    }
  }

  // 2. Repository discovery
  const repoDocs = scanSourceRoot(repoFs, 'repo', repoInventory.filesPosix);
  for (const doc of repoDocs) {
    if (doc.meta.kind === 'claude-md' || doc.meta.kind === 'claude-local-md') {
      expandClaudeImports(doc, repoFs, new Set([doc.meta.realPath]), 0);
    }
  }

  return {
    repoFs,
    homeFs,
    repoFilesPosix: repoInventory.filesPosix,
    repoTopLevelDirs: repoInventory.topLevelDirs,
    documents,
    discoveryFindings,
  };
}

function isScopeOnAncestorChain(fileScope: string, targetScope: string): boolean {
  if (fileScope === '') return true;
  if (targetScope === '') return false;
  return targetScope === fileScope || targetScope.startsWith(`${fileScope}/`);
}

function scopeDepth(scope: string): number {
  if (scope === '') return 0;
  return scope.split('/').length;
}

/**
 * Computes the effective ordered context set, scoped instructions, and skills for one agent.
 * Supports optional `scopeDir` (e.g. `packages/web`) to evaluate monorepo nested precedence.
 */
export function buildAgentContext(
  discovery: DiscoveryResult,
  agent: AgentName,
  options?: { budgetTokens?: number; scopeDir?: string },
): AgentContextReport {
  const budgetTokens = options?.budgetTokens ?? DEFAULT_BUDGET_TOKENS;
  let scopeDir = (options?.scopeDir ?? '').replace(/\\/g, '/').trim();
  while (scopeDir.startsWith('./')) scopeDir = scopeDir.slice(2);
  while (scopeDir.startsWith('/')) scopeDir = scopeDir.slice(1);
  while (scopeDir.endsWith('/')) scopeDir = scopeDir.slice(0, -1);
  if (scopeDir === '.') scopeDir = '';

  const alwaysLoadedDocs: Array<{ doc: LoadedDocument; importedBy?: string; importDepth?: number }> = [];
  const seenRealPaths = new Set<string>();
  const scopedFiles: ScopedContextEntry[] = [];
  const skillFiles: SkillContextEntry[] = [];

  function pushAlways(doc: LoadedDocument, importedBy?: string, importDepth?: number): void {
    if (seenRealPaths.has(doc.meta.realPath)) return;
    seenRealPaths.add(doc.meta.realPath);
    alwaysLoadedDocs.push({
      doc,
      ...(importedBy !== undefined
        ? { importedBy }
        : doc.meta.importedBy !== undefined
          ? { importedBy: doc.meta.importedBy }
          : {}),
      ...(importDepth !== undefined
        ? { importDepth }
        : doc.meta.importDepth !== undefined
          ? { importDepth: doc.meta.importDepth }
          : {}),
    });
  }

  function pushClaudeWithImports(rootDoc: LoadedDocument): void {
    const visitedInWalk = new Set<string>([rootDoc.meta.realPath]);
    pushAlways(rootDoc);
    function visitImports(parent: LoadedDocument, depth: number): void {
      if (depth > MAX_IMPORT_DEPTH) return;
      for (const child of parent.resolvedImports) {
        pushAlways(child, parent.meta.displayPath, depth);
        if (visitedInWalk.has(child.meta.realPath)) {
          continue;
        }
        visitedInWalk.add(child.meta.realPath);
        visitImports(child, depth + 1);
      }
    }
    visitImports(rootDoc, 1);
  }

  const homeDocs = discovery.documents.filter((d) => d.meta.sourceRoot === 'home');
  const repoDocs = discovery.documents.filter((d) => d.meta.sourceRoot === 'repo');

  if (agent === 'claude') {
    // 1. Home CLAUDE.md + imports
    for (const d of homeDocs) {
      if ((d.meta.kind === 'claude-md' || d.meta.kind === 'claude-local-md') && d.meta.scopeDir === '') {
        pushClaudeWithImports(d);
      }
    }
    // 2. Repo hierarchical CLAUDE.md + CLAUDE.local.md along ancestor chain `"" -> ... -> scopeDir`
    const repoClaudeRoots = repoDocs
      .filter((d) => d.meta.kind === 'claude-md' || d.meta.kind === 'claude-local-md')
      .sort((a, b) => {
        const da = scopeDepth(a.meta.scopeDir);
        const db = scopeDepth(b.meta.scopeDir);
        if (da !== db) return da - db;
        // At same scope depth: CLAUDE.md before .claude/CLAUDE.md before CLAUDE.local.md
        const rank = (doc: LoadedDocument): number => {
          if (doc.meta.kind === 'claude-local-md') return 2;
          if (doc.meta.relToSourceRoot.includes('.claude/')) return 1;
          return 0;
        };
        const ra = rank(a);
        const rb = rank(b);
        if (ra !== rb) return ra - rb;
        return a.meta.relToSourceRoot.localeCompare(b.meta.relToSourceRoot);
      });

    for (const d of repoClaudeRoots) {
      if (isScopeOnAncestorChain(d.meta.scopeDir, scopeDir)) {
        pushClaudeWithImports(d);
      } else {
        scopedFiles.push({
          file: d.meta.displayPath,
          kind: d.meta.kind,
          sourceRoot: d.meta.sourceRoot,
          scope: d.meta.scopeDir || '.',
          chars: d.meta.chars,
          estimatedTokens: d.meta.estimatedTokens,
        });
      }
    }
  } else if (agent === 'gemini') {
    // 1. Home AGENTS.md then GEMINI.md
    const homeGemini = homeDocs
      .filter((d) => (d.meta.kind === 'agents-md' || d.meta.kind === 'gemini-md') && d.meta.scopeDir === '')
      .sort((a, b) => (a.meta.kind === b.meta.kind ? 0 : a.meta.kind === 'agents-md' ? -1 : 1));
    for (const d of homeGemini) {
      pushAlways(d);
    }
    // 2. Hierarchical AGENTS.md and GEMINI.md shallowest-to-deepest (nearest subdir wins last)
    const candidates = repoDocs
      .filter((d) => d.meta.kind === 'agents-md' || d.meta.kind === 'gemini-md')
      .sort((a, b) => {
        const da = scopeDepth(a.meta.scopeDir);
        const db = scopeDepth(b.meta.scopeDir);
        if (da !== db) return da - db;
        // At same directory level: AGENTS.md first, then GEMINI.md
        if (a.meta.kind !== b.meta.kind) {
          return a.meta.kind === 'agents-md' ? -1 : 1;
        }
        return a.meta.relToSourceRoot.localeCompare(b.meta.relToSourceRoot);
      });

    for (const d of candidates) {
      if (isScopeOnAncestorChain(d.meta.scopeDir, scopeDir)) {
        pushAlways(d);
      } else {
        scopedFiles.push({
          file: d.meta.displayPath,
          kind: d.meta.kind,
          sourceRoot: d.meta.sourceRoot,
          scope: d.meta.scopeDir || '.',
          chars: d.meta.chars,
          estimatedTokens: d.meta.estimatedTokens,
        });
      }
    }
  } else if (agent === 'cursor') {
    const homeCursor = homeDocs
      .filter(
        (d) =>
          (d.meta.kind === 'agents-md' && d.meta.scopeDir === '') ||
          d.meta.kind === 'cursorrules' ||
          (d.meta.kind === 'cursor-mdc' && d.parsed.frontmatter.data['alwaysApply'] === true),
      )
      .sort((a, b) => {
        const rank = (k: InstructionKind): number =>
          k === 'agents-md' ? 0 : k === 'cursorrules' ? 1 : 2;
        return rank(a.meta.kind) - rank(b.meta.kind);
      });
    for (const d of homeCursor) {
      pushAlways(d);
    }
    // Hierarchical AGENTS.md along scopeDir
    const agentsDocs = repoDocs
      .filter((d) => d.meta.kind === 'agents-md')
      .sort((a, b) => scopeDepth(a.meta.scopeDir) - scopeDepth(b.meta.scopeDir));
    for (const d of agentsDocs) {
      if (isScopeOnAncestorChain(d.meta.scopeDir, scopeDir)) {
        pushAlways(d);
      } else {
        scopedFiles.push({
          file: d.meta.displayPath,
          kind: d.meta.kind,
          sourceRoot: d.meta.sourceRoot,
          scope: d.meta.scopeDir || '.',
          chars: d.meta.chars,
          estimatedTokens: d.meta.estimatedTokens,
        });
      }
    }
    // Legacy .cursorrules
    for (const d of repoDocs) {
      if (d.meta.kind === 'cursorrules') {
        pushAlways(d);
      }
    }
    // .cursor/rules/*.mdc
    const mdcDocs = repoDocs
      .filter((d) => d.meta.kind === 'cursor-mdc')
      .sort((a, b) => a.meta.relToSourceRoot.localeCompare(b.meta.relToSourceRoot));
    for (const d of mdcDocs) {
      if (d.parsed.frontmatter.data['alwaysApply'] === true) {
        pushAlways(d);
      } else {
        const globs = splitGlobList(d.parsed.frontmatter.data['globs']);
        scopedFiles.push({
          file: d.meta.displayPath,
          kind: d.meta.kind,
          sourceRoot: d.meta.sourceRoot,
          scope: globs.length > 0 ? globs.join(', ') : 'agent-requested',
          chars: d.meta.chars,
          estimatedTokens: d.meta.estimatedTokens,
        });
      }
    }
  } else if (agent === 'copilot') {
    const homeCopilot = homeDocs
      .filter(
        (d) =>
          (d.meta.kind === 'agents-md' && d.meta.scopeDir === '') ||
          d.meta.kind === 'copilot-instructions',
      )
      .sort((a, b) => (a.meta.kind === b.meta.kind ? 0 : a.meta.kind === 'agents-md' ? -1 : 1));
    for (const d of homeCopilot) {
      pushAlways(d);
    }
    const agentsDocs = repoDocs
      .filter((d) => d.meta.kind === 'agents-md')
      .sort((a, b) => scopeDepth(a.meta.scopeDir) - scopeDepth(b.meta.scopeDir));
    for (const d of agentsDocs) {
      if (isScopeOnAncestorChain(d.meta.scopeDir, scopeDir)) {
        pushAlways(d);
      } else {
        scopedFiles.push({
          file: d.meta.displayPath,
          kind: d.meta.kind,
          sourceRoot: d.meta.sourceRoot,
          scope: d.meta.scopeDir || '.',
          chars: d.meta.chars,
          estimatedTokens: d.meta.estimatedTokens,
        });
      }
    }
    for (const d of repoDocs) {
      if (d.meta.kind === 'copilot-instructions') {
        pushAlways(d);
      }
    }
    const instrDocs = repoDocs
      .filter((d) => d.meta.kind === 'copilot-scoped-instructions')
      .sort((a, b) => a.meta.relToSourceRoot.localeCompare(b.meta.relToSourceRoot));
    for (const d of instrDocs) {
      const applyTo = splitGlobList(d.parsed.frontmatter.data['applyTo']);
      if (isUniversalGlob(applyTo)) {
        pushAlways(d);
      } else {
        scopedFiles.push({
          file: d.meta.displayPath,
          kind: d.meta.kind,
          sourceRoot: d.meta.sourceRoot,
          scope: applyTo.length > 0 ? applyTo.join(', ') : 'unscoped',
          chars: d.meta.chars,
          estimatedTokens: d.meta.estimatedTokens,
        });
      }
    }
  }

  // Skills for this agent (on-demand)
  for (const d of discovery.documents) {
    if (d.meta.kind === 'skill-md' && d.meta.agents.includes(agent)) {
      const rawName = d.parsed.frontmatter.data['name'];
      skillFiles.push({
        file: d.meta.displayPath,
        sourceRoot: d.meta.sourceRoot,
        ...(typeof rawName === 'string' && rawName.trim().length > 0
          ? { skillName: rawName.trim() }
          : {}),
        chars: d.meta.chars,
        estimatedTokens: d.meta.estimatedTokens,
      });
    }
  }

  let totalAlwaysLoadedChars = 0;
  let totalAlwaysLoadedTokens = 0;
  const alwaysLoadedFiles: ContextFileEntry[] = alwaysLoadedDocs.map((item) => {
    totalAlwaysLoadedChars += item.doc.meta.chars;
    totalAlwaysLoadedTokens += item.doc.meta.estimatedTokens;
    const share =
      budgetTokens > 0
        ? Math.round((item.doc.meta.estimatedTokens / budgetTokens) * 1000) / 10
        : 0;
    return {
      file: item.doc.meta.displayPath,
      kind: item.doc.meta.kind,
      sourceRoot: item.doc.meta.sourceRoot,
      scopeDir: item.doc.meta.scopeDir,
      chars: item.doc.meta.chars,
      estimatedTokens: item.doc.meta.estimatedTokens,
      budgetSharePct: share,
      ...(item.importedBy !== undefined ? { importedBy: item.importedBy } : {}),
      ...(item.importDepth !== undefined ? { importDepth: item.importDepth } : {}),
    };
  });

  return {
    agent,
    scopeDir: scopeDir || '.',
    budgetTokens,
    tokenEstimationMethod: TOKEN_ESTIMATION_LABEL,
    alwaysLoadedFiles,
    scopedFiles,
    skillFiles,
    totalAlwaysLoadedChars,
    totalAlwaysLoadedTokens,
  };
}

export function parseAgentList(raw: string): AgentName[] {
  const parts = raw
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);
  if (parts.length === 0) {
    return [...ALL_AGENTS];
  }
  const validSet = new Set<string>(ALL_AGENTS);
  const out: AgentName[] = [];
  for (const p of parts) {
    if (!validSet.has(p)) {
      throw new Error(
        `Unsupported agent "${p}". Supported v1 agents: ${ALL_AGENTS.join(', ')}.`,
      );
    }
    const typed = p as AgentName;
    if (!out.includes(typed)) {
      out.push(typed);
    }
  }
  return out;
}
