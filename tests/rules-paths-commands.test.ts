import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { lintWorkspace } from '../src/index.js';

function withTempWorkspace(fn: (dir: string) => void): void {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-lint-paths-'));
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

describe('AGL001/002 budgets, AGL010 case-exact paths, AGL011 static commands, AGL012 escapes, AGL020 PMs', () => {
  it('flags AGL010 on case-mismatched paths (readme.md vs README.md) even on case-insensitive OSes', () => {
    withTempWorkspace((dir) => {
      writeFile(dir, 'README.md', '# Project\n');
      writeFile(dir, 'src/index.ts', 'export const ok = true;\n');
      writeFile(
        dir,
        'AGENTS.md',
        [
          '# Instructions',
          'Read [Project Docs](readme.md) before editing.',
          'Also check `src/Index.ts` and `scripts/missing.sh`.',
        ].join('\n'),
      );

      const report = lintWorkspace({ dir, homeDir: null });
      const agl010 = report.findings.filter((f) => f.ruleId === 'AGL010');
      assert.equal(agl010.length, 3);
      assert.ok(agl010.some((f) => f.message.includes('README.md')));
      assert.ok(agl010.some((f) => f.message.includes('index.ts')));
      assert.ok(agl010.some((f) => f.message.includes('scripts/missing.sh')));
    });
  });

  it('handles UTF-8 BOM + CRLF files and Windows backslash paths cleanly', () => {
    withTempWorkspace((dir) => {
      writeFile(dir, 'src/utils/helper.ts', 'export const x = 1;\n');
      writeFile(
        dir,
        '.claude/skills/win-skill/SKILL.md',
        '\uFEFF---\r\nname: win-skill\r\ndescription: Handles Windows CRLF + BOM cleanly.\r\n---\r\n# Win Skill\r\nInspect `src\\utils\\helper.ts` and `src\\utils\\missing.ts`.\r\n',
      );

      const report = lintWorkspace({ dir, homeDir: null });
      // Valid BOM at index 0 should NOT trigger AGL030, and valid frontmatter should NOT trigger AGL040
      assert.equal(report.findings.filter((f) => f.ruleId === 'AGL030').length, 0);
      assert.equal(report.findings.filter((f) => f.ruleId === 'AGL040').length, 0);

      // `src\utils\helper.ts` passes, while `src\utils\missing.ts` triggers AGL010 at exact CRLF line 6
      const agl010 = report.findings.filter((f) => f.ruleId === 'AGL010');
      assert.equal(agl010.length, 1);
      assert.equal(agl010[0]!.line, 6);
      assert.ok(agl010[0]!.message.includes('src\\utils\\missing.ts'));
    });
  });

  it('blocks @import lexical traversals and symlink/junction escapes with AGL012 without reading outside files', () => {
    withTempWorkspace((base) => {
      const repoDir = path.join(base, 'repo');
      const outsideDir = path.join(base, 'outside');
      fs.mkdirSync(repoDir, { recursive: true });
      fs.mkdirSync(outsideDir, { recursive: true });

      writeFile(
        outsideDir,
        'SKILL.md',
        '---\nname: outside\ndescription: Secret outside file.\n---\n# Outside\n',
      );
      writeFile(outsideDir, 'secret.md', '# Secret Outside\n');

      writeFile(repoDir, 'CLAUDE.md', '# Claude\n@../outside/secret.md\n');

      // Create directory junction (works without admin rights on Windows) or dir symlink on POSIX
      const skillsParent = path.join(repoDir, '.claude', 'skills');
      fs.mkdirSync(skillsParent, { recursive: true });
      const junctionPath = path.join(skillsParent, 'escaped-skill');
      fs.symlinkSync(
        outsideDir,
        junctionPath,
        process.platform === 'win32' ? 'junction' : 'dir',
      );

      const report = lintWorkspace({ dir: repoDir, homeDir: null });
      const agl012 = report.findings.filter((f) => f.ruleId === 'AGL012');
      assert.ok(agl012.length >= 2, `Expected >= 2 AGL012 findings, got ${agl012.length}`);
      assert.ok(agl012.some((f) => f.message.includes('@../outside/secret.md')));
      assert.ok(agl012.some((f) => f.file.includes('.claude/skills/escaped-skill')));
      // Ensure outside SKILL.md was never loaded into discoveredFiles
      assert.ok(!report.discoveredFiles.some((d) => d.file.includes('escaped-skill')));
    });
  });

  it('statically checks npm, pnpm, yarn, make, and just commands against package.json, Makefile, and justfile (AGL011)', () => {
    withTempWorkspace((dir) => {
      writeFile(
        dir,
        'package.json',
        JSON.stringify(
          {
            name: 'fixture-pkg',
            scripts: {
              build: 'tsc',
              test: 'node --test',
            },
          },
          null,
          2,
        ),
      );
      writeFile(dir, 'Makefile', '.PHONY: build clean\nbuild:\n\techo ok\nclean:\n\trm -rf dist\n');
      writeFile(dir, 'justfile', 'check:\n  echo ok\n');

      writeFile(
        dir,
        'AGENTS.md',
        [
          '# Commands',
          '',
          '```bash',
          'npm ci',
          'npm run build',
          'npm test',
          'npm run missing-script',
          'pnpm ghost-task',
          'yarn absent-script',
          'make build',
          'make deploy-prod',
          'just check',
          'just ship-it',
          '```',
        ].join('\n'),
      );

      const report = lintWorkspace({ dir, homeDir: null });
      const agl011 = report.findings.filter((f) => f.ruleId === 'AGL011');
      assert.equal(agl011.length, 5);
      const msgs = agl011.map((f) => f.message).join('\n');
      assert.ok(msgs.includes('missing-script'));
      assert.ok(msgs.includes('ghost-task'));
      assert.ok(msgs.includes('absent-script'));
      assert.ok(msgs.includes('deploy-prod'));
      assert.ok(msgs.includes('ship-it'));
    });
  });

  it('flags package manager contradictions (AGL020) while honoring negated prose like "never use yarn"', () => {
    withTempWorkspace((dir) => {
      writeFile(dir, 'package-lock.json', '{"name":"demo","lockfileVersion":3,"packages":{}}\n');
      writeFile(
        dir,
        'package.json',
        JSON.stringify({ name: 'demo', scripts: { test: 'node --test' } }),
      );
      // Clean file with negated warning ("Never use yarn; always use npm")
      writeFile(dir, 'CLAUDE.md', '# Claude\nNever use yarn; always use npm.\nRun `npm test`.\n');

      const cleanReport = lintWorkspace({ dir, homeDir: null });
      assert.equal(cleanReport.findings.filter((f) => f.ruleId === 'AGL020').length, 0);

      // Add contradicting AGENTS.md mandating pnpm
      writeFile(dir, 'AGENTS.md', '# Agents\nAlways use pnpm for dependency management.\n');
      const dirtyReport = lintWorkspace({ dir, homeDir: null });
      const agl020 = dirtyReport.findings.filter((f) => f.ruleId === 'AGL020');
      assert.equal(agl020.length, 1);
      assert.equal(agl020[0]!.file, 'AGENTS.md');
      assert.equal(agl020[0]!.severity, 'medium');
    });
  });

  it('flags AGL001 (medium > 1x, high > 1.5x) and AGL002 (low > 40% share) on tight budgets', () => {
    withTempWorkspace((dir) => {
      // 480 chars => 120 estimated tokens
      writeFile(dir, 'GEMINI.md', '# Gemini\n' + 'x'.repeat(470));

      // Budget 100 -> 120 > 100 (<= 150) => AGL001 medium + AGL002 low (120 > 40)
      const medReport = lintWorkspace({ dir, agents: ['gemini'], budgetTokens: 100, homeDir: null });
      const med001 = medReport.findings.find((f) => f.ruleId === 'AGL001');
      const low002 = medReport.findings.find((f) => f.ruleId === 'AGL002');
      assert.ok(med001);
      assert.equal(med001.severity, 'medium');
      assert.ok(low002);
      assert.equal(low002.severity, 'low');

      // Budget 60 -> 120 > 90 (1.5x) => AGL001 high
      const highReport = lintWorkspace({ dir, agents: ['gemini'], budgetTokens: 60, homeDir: null });
      const high001 = highReport.findings.find((f) => f.ruleId === 'AGL001');
      assert.ok(high001);
      assert.equal(high001.severity, 'high');
    });
  });
});
