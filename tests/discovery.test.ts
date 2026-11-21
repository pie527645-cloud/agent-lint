import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  inspectAgentContext,
  lintWorkspace,
} from '../src/index.js';

function withTempWorkspace(fn: (dir: string) => void): void {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-lint-disc-'));
  try {
    fn(tmpDir);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function writeFile(root: string, rel: string, content: string): void {
  const full = path.join(root, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, 'utf8');
}

describe('Discovery, @import cycles/depth, monorepo precedence, and README table parity', () => {
  it('handles @import cycles A -> B -> A without infinite recursion and deduplicates tokens', () => {
    withTempWorkspace((dir) => {
      writeFile(dir, 'CLAUDE.md', '# Root\nSee @docs/a.md for details.\n');
      writeFile(dir, 'docs/a.md', '# Doc A\nImports @./b.md next.\n');
      writeFile(dir, 'docs/b.md', '# Doc B\nCycles back to @./a.md and @../CLAUDE.md.\n');

      const ctx = inspectAgentContext({ dir, agent: 'claude', homeDir: null });
      assert.deepEqual(
        ctx.alwaysLoadedFiles.map((f) => f.file),
        ['CLAUDE.md', 'docs/a.md', 'docs/b.md'],
      );
      assert.ok(ctx.totalAlwaysLoadedTokens > 0);

      const report = lintWorkspace({ dir, agents: ['claude'], homeDir: null });
      const errors = report.findings.filter((f) => f.ruleId === 'AGL010' || f.ruleId === 'AGL012');
      assert.equal(errors.length, 0);
    });
  });

  it('enforces max @import hop depth of 5 and stops expanding deeper hops', () => {
    withTempWorkspace((dir) => {
      writeFile(dir, 'CLAUDE.md', '# Root\n@h1.md\n');
      writeFile(dir, 'h1.md', '@h2.md\n');
      writeFile(dir, 'h2.md', '@h3.md\n');
      writeFile(dir, 'h3.md', '@h4.md\n');
      writeFile(dir, 'h4.md', '@h5.md\n');
      writeFile(dir, 'h5.md', '@h6.md\n');
      writeFile(dir, 'h6.md', '# Hop 6 should not be loaded\n');

      const ctx = inspectAgentContext({ dir, agent: 'claude', homeDir: null });
      const loaded = ctx.alwaysLoadedFiles.map((f) => f.file);
      assert.deepEqual(loaded, ['CLAUDE.md', 'h1.md', 'h2.md', 'h3.md', 'h4.md', 'h5.md']);
      assert.ok(!loaded.includes('h6.md'));
    });
  });

  it('ignores @import tokens inside fenced code blocks and inline code spans, as well as @scope/pkg names', () => {
    withTempWorkspace((dir) => {
      writeFile(
        dir,
        'CLAUDE.md',
        [
          '# Guide for @pie527645-cloud/agent-lint',
          '',
          'Inline syntax example: `@nonexistent-inline.md` is ignored.',
          '',
          '```markdown',
          '@nonexistent-fenced.md',
          '```',
          '',
          '~~~md',
          '@also-ignored-tilde.md',
          '~~~',
        ].join('\n'),
      );

      const report = lintWorkspace({ dir, agents: ['claude'], homeDir: null });
      assert.equal(report.findings.length, 0);
    });
  });

  it('resolves monorepo nested AGENTS.md and GEMINI.md precedence in hierarchical load order', () => {
    withTempWorkspace((dir) => {
      writeFile(dir, 'AGENTS.md', '# Root Agents\nShared repository instructions.\n');
      writeFile(dir, 'GEMINI.md', '# Root Gemini\nRoot Gemini rules.\n');
      writeFile(dir, 'packages/web/AGENTS.md', '# Web Agents\nFrontend workspace rules.\n');
      writeFile(dir, 'packages/web/GEMINI.md', '# Web Gemini\nFrontend Gemini rules.\n');
      writeFile(dir, 'packages/api/AGENTS.md', '# API Agents\nBackend workspace rules.\n');

      // Root context: only root files are always-loaded; nested packages are listed as scoped
      const rootCtx = inspectAgentContext({ dir, agent: 'gemini', homeDir: null });
      assert.deepEqual(
        rootCtx.alwaysLoadedFiles.map((f) => f.file),
        ['AGENTS.md', 'GEMINI.md'],
      );
      assert.deepEqual(
        rootCtx.scopedFiles.map((f) => f.file).sort(),
        ['packages/api/AGENTS.md', 'packages/web/AGENTS.md', 'packages/web/GEMINI.md'],
      );

      // Scoped to `packages/web`: ancestor chain loads shallowest-to-deepest so nearest nested wins
      const webCtx = inspectAgentContext({
        dir,
        agent: 'gemini',
        scopeDir: 'packages/web',
        homeDir: null,
      });
      assert.deepEqual(
        webCtx.alwaysLoadedFiles.map((f) => f.file),
        ['AGENTS.md', 'GEMINI.md', 'packages/web/AGENTS.md', 'packages/web/GEMINI.md'],
      );
      assert.deepEqual(
        webCtx.scopedFiles.map((f) => f.file),
        ['packages/api/AGENTS.md'],
      );
    });
  });

  it('supports synthetic fixture --home directory while keeping --no-home isolated by default', () => {
    withTempWorkspace((base) => {
      const repoDir = path.join(base, 'repo');
      const syntheticHome = path.join(base, 'synthetic-home');
      fs.mkdirSync(repoDir, { recursive: true });
      fs.mkdirSync(syntheticHome, { recursive: true });

      writeFile(syntheticHome, '.claude/CLAUDE.md', '# Global Synthetic Claude\nKeep diffs minimal.\n');
      writeFile(syntheticHome, '.gemini/GEMINI.md', '# Global Synthetic Gemini\nPrefer strict types.\n');
      writeFile(
        syntheticHome,
        '.claude/skills/review-helper/SKILL.md',
        '---\nname: review-helper\ndescription: Synthetic global skill.\n---\n# Review Helper\n',
      );

      writeFile(repoDir, 'CLAUDE.md', '# Repo Claude\nRun tests before commit.\n');
      writeFile(repoDir, 'GEMINI.md', '# Repo Gemini\nRepo instructions.\n');

      // Default (homeDir: null / --no-home) never touches syntheticHome
      const noHomeCtx = inspectAgentContext({ dir: repoDir, agent: 'claude', homeDir: null });
      assert.deepEqual(
        noHomeCtx.alwaysLoadedFiles.map((f) => f.file),
        ['CLAUDE.md'],
      );
      assert.equal(noHomeCtx.skillFiles.length, 0);

      // Explicit synthetic --home prepends home config before repo config
      const withHomeCtx = inspectAgentContext({
        dir: repoDir,
        agent: 'claude',
        homeDir: syntheticHome,
      });
      assert.deepEqual(
        withHomeCtx.alwaysLoadedFiles.map((f) => f.file),
        ['home:.claude/CLAUDE.md', 'CLAUDE.md'],
      );
      assert.deepEqual(
        withHomeCtx.skillFiles.map((s) => s.file),
        ['home:.claude/skills/review-helper/SKILL.md'],
      );
    });
  });

  it('skips files larger than the 2 MB size cap with an AGL900 info finding', () => {
    withTempWorkspace((dir) => {
      const overTwoMb = '# Oversized\n' + 'a'.repeat(2 * 1024 * 1024 + 512);
      writeFile(dir, 'GEMINI.md', overTwoMb);
      writeFile(dir, 'AGENTS.md', '# Normal\nSmall file.\n');

      const report = lintWorkspace({ dir, homeDir: null });
      const capFindings = report.findings.filter((f) => f.ruleId === 'AGL900');
      assert.equal(capFindings.length, 1);
      assert.equal(capFindings[0]!.severity, 'info');
      assert.equal(capFindings[0]!.file, 'GEMINI.md');
    });
  });

  it('matches the documented README.md discovery table across all four v1 agents', () => {
    const readmePath = path.resolve(process.cwd(), 'README.md');
    const readme = fs.readFileSync(readmePath, 'utf8');
    const startMarker = '<!-- DISCOVERY_TABLE_START -->';
    const endMarker = '<!-- DISCOVERY_TABLE_END -->';
    const startIdx = readme.indexOf(startMarker);
    const endIdx = readme.indexOf(endMarker);
    assert.ok(startIdx !== -1 && endIdx > startIdx, 'README.md must contain discovery table markers');

    const tableText = readme.slice(startIdx, endIdx);
    for (const agent of ['claude', 'gemini', 'cursor', 'copilot'] as const) {
      assert.ok(tableText.includes(`| \`${agent}\` |`), `README table missing row for ${agent}`);
    }

    withTempWorkspace((base) => {
      const repo = path.join(base, 'repo');
      const home = path.join(base, 'home');
      fs.mkdirSync(repo, { recursive: true });
      fs.mkdirSync(home, { recursive: true });

      writeFile(home, '.claude/CLAUDE.md', '# Home Claude\n');
      writeFile(home, 'AGENTS.md', '# Home Agents\n');
      writeFile(home, '.gemini/GEMINI.md', '# Home Gemini\n');
      writeFile(home, '.cursorrules', '# Home Cursor\n');
      writeFile(home, '.github/copilot-instructions.md', '# Home Copilot\n');

      writeFile(repo, 'AGENTS.md', '# Repo Agents\n');
      writeFile(repo, 'CLAUDE.md', '# Repo Claude\n@docs/imported.md\n');
      writeFile(repo, 'docs/imported.md', '# Imported\n');
      writeFile(repo, 'CLAUDE.local.md', '# Local Claude\n');
      writeFile(repo, 'GEMINI.md', '# Repo Gemini\n');
      writeFile(repo, '.cursorrules', '# Repo Cursorrules\n');
      writeFile(
        repo,
        '.cursor/rules/global.mdc',
        '---\ndescription: Global rule\nalwaysApply: true\n---\n# Global MDC\n',
      );
      writeFile(
        repo,
        '.cursor/rules/scoped.mdc',
        '---\ndescription: Scoped rule\nalwaysApply: false\nglobs: ["docs/*.md"]\n---\n# Scoped MDC\n',
      );
      writeFile(repo, '.github/copilot-instructions.md', '# Copilot Root\n');
      writeFile(
        repo,
        '.github/instructions/all.instructions.md',
        '---\napplyTo: "**/*"\n---\n# Universal Copilot\n',
      );
      writeFile(
        repo,
        '.github/instructions/docs.instructions.md',
        '---\napplyTo: "docs/*.md"\n---\n# Docs Copilot\n',
      );
      writeFile(
        repo,
        '.agents/skills/shared-skill/SKILL.md',
        '---\nname: shared-skill\ndescription: Cross-agent skill.\n---\n# Skill\n',
      );

      const claudeCtx = inspectAgentContext({ dir: repo, agent: 'claude', homeDir: home });
      assert.deepEqual(
        claudeCtx.alwaysLoadedFiles.map((f) => f.file),
        ['home:.claude/CLAUDE.md', 'CLAUDE.md', 'docs/imported.md', 'CLAUDE.local.md'],
      );

      const geminiCtx = inspectAgentContext({ dir: repo, agent: 'gemini', homeDir: home });
      assert.deepEqual(
        geminiCtx.alwaysLoadedFiles.map((f) => f.file),
        ['home:AGENTS.md', 'home:.gemini/GEMINI.md', 'AGENTS.md', 'GEMINI.md'],
      );

      const cursorCtx = inspectAgentContext({ dir: repo, agent: 'cursor', homeDir: home });
      assert.deepEqual(
        cursorCtx.alwaysLoadedFiles.map((f) => f.file),
        ['home:AGENTS.md', 'home:.cursorrules', 'AGENTS.md', '.cursorrules', '.cursor/rules/global.mdc'],
      );
      assert.deepEqual(
        cursorCtx.scopedFiles.map((f) => f.file),
        ['.cursor/rules/scoped.mdc'],
      );

      const copilotCtx = inspectAgentContext({ dir: repo, agent: 'copilot', homeDir: home });
      assert.deepEqual(
        copilotCtx.alwaysLoadedFiles.map((f) => f.file),
        [
          'home:AGENTS.md',
          'home:.github/copilot-instructions.md',
          'AGENTS.md',
          '.github/copilot-instructions.md',
          '.github/instructions/all.instructions.md',
        ],
      );
      assert.deepEqual(
        copilotCtx.scopedFiles.map((f) => f.file),
        ['.github/instructions/docs.instructions.md'],
      );
    });
  });

  it('never imports or calls os.homedir anywhere in src/', () => {
    const srcDir = path.resolve(process.cwd(), 'src');
    const srcFiles = fs.readdirSync(srcDir).filter((f) => f.endsWith('.ts'));
    assert.ok(srcFiles.length >= 8);
    for (const f of srcFiles) {
      const content = fs.readFileSync(path.join(srcDir, f), 'utf8');
      assert.ok(!content.includes('homedir'), `Found forbidden homedir reference in src/${f}`);
    }
  });
});
