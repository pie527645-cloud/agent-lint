import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

const CLI_DIST = path.resolve(process.cwd(), 'dist', 'cli.js');

function runCliSubprocess(args: readonly string[], cliEntrypoint = CLI_DIST): {
  status: number | null;
  stdout: string;
  stderr: string;
} {
  const res = spawnSync(process.execPath, [cliEntrypoint, ...args], {
    encoding: 'utf8',
    shell: false,
  });
  return {
    status: res.status,
    stdout: res.stdout ?? '',
    stderr: res.stderr ?? '',
  };
}

function withTempWorkspace(fn: (dir: string) => void): void {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-lint-cli-'));
  try {
    fn(tmpDir);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

describe('CLI commands, exit codes (0/1/2), --home privacy validation, and symlinked entrypoint', () => {
  it('returns exit code 0 on clean repo, 1 when findings >= --fail-on, and respects --fail-on threshold', () => {
    withTempWorkspace((dir) => {
      fs.writeFileSync(path.join(dir, 'AGENTS.md'), '# Clean Repo\nReference `.env.example`.\n', 'utf8');

      // Only `info` finding from `.env.example` -> default `--fail-on high` exits 0
      const cleanRes = runCliSubprocess(['check', dir, '--no-home', '--format', 'json']);
      assert.equal(cleanRes.status, 0);
      const parsed = JSON.parse(cleanRes.stdout) as { summary: { info: number; high: number } };
      assert.equal(parsed.summary.info, 1);
      assert.equal(parsed.summary.high, 0);

      // `--fail-on info` exits 1 on that `info` finding
      const infoFailRes = runCliSubprocess(['check', dir, '--no-home', '--fail-on', 'info']);
      assert.equal(infoFailRes.status, 1);

      // High finding (`src/does-not-exist.ts`) exits 1 under default `--fail-on high`
      fs.writeFileSync(path.join(dir, 'AGENTS.md'), '# Broken\nCheck `src/does-not-exist.ts`.\n', 'utf8');
      const highFailRes = runCliSubprocess(['check', dir, '--no-home']);
      assert.equal(highFailRes.status, 1);
    });
  });

  it('returns exit code 2 on bare --home without directory, missing directory, or unknown rule/flags', () => {
    withTempWorkspace((dir) => {
      // Bare `--home` without explicit directory must fail with exit code 2 (never fallback to os.homedir)
      const bareHome = runCliSubprocess(['check', dir, '--home']);
      assert.equal(bareHome.status, 2);
      assert.ok(bareHome.stderr.includes('--home'));

      const bareHomeFlagNext = runCliSubprocess(['check', dir, '--home', '--format', 'json']);
      assert.equal(bareHomeFlagNext.status, 2);

      const missingDir = runCliSubprocess(['check', path.join(dir, 'nonexistent-folder')]);
      assert.equal(missingDir.status, 2);

      const missingAgent = runCliSubprocess(['context', dir]);
      assert.equal(missingAgent.status, 2);

      const badRule = runCliSubprocess(['explain', 'AGL999']);
      assert.equal(badRule.status, 2);
    });
  });

  it('runs context and explain subcommands cleanly', () => {
    withTempWorkspace((dir) => {
      fs.writeFileSync(path.join(dir, 'CLAUDE.md'), '# Claude Instructions\nKeep functions pure.\n', 'utf8');

      const ctxRes = runCliSubprocess(['context', dir, '--agent', 'claude', '--no-home', '--format', 'json']);
      assert.equal(ctxRes.status, 0);
      const ctx = JSON.parse(ctxRes.stdout) as { agent: string; totalAlwaysLoadedTokens: number };
      assert.equal(ctx.agent, 'claude');
      assert.ok(ctx.totalAlwaysLoadedTokens > 0);

      const explainRes = runCliSubprocess(['explain', 'AGL010']);
      assert.equal(explainRes.status, 0);
      assert.ok(explainRes.stdout.includes('AGL010'));
      assert.ok(explainRes.stdout.includes('BrokenPathOrImport'));
    });
  });

  it('executes properly when invoked through a symlinked / junctioned CLI path', () => {
    withTempWorkspace((tmp) => {
      const repoDir = path.join(tmp, 'sample');
      fs.mkdirSync(repoDir, { recursive: true });
      fs.writeFileSync(path.join(repoDir, 'GEMINI.md'), '# Gemini\nClean file.\n', 'utf8');

      // 1. Directory junction / symlink to `dist/` so `argv[1]` differs lexically from real `dist/cli.js`
      const distRealDir = path.dirname(CLI_DIST);
      const linkedDistDir = path.join(tmp, 'linked-bin-dir');
      fs.symlinkSync(
        distRealDir,
        linkedDistDir,
        process.platform === 'win32' ? 'junction' : 'dir',
      );
      const junctionCli = path.join(linkedDistDir, 'cli.js');
      const junctionRun = runCliSubprocess(['check', repoDir, '--no-home', '--format', 'json'], junctionCli);
      assert.equal(junctionRun.status, 0);
      assert.equal(JSON.parse(junctionRun.stdout).tool, 'agent-lint');

      // 2. Direct file symlink when permitted by OS privileges
      const fileSymlinkCli = path.join(tmp, 'agent-lint-symlink.mjs');
      let createdFileSymlink = false;
      try {
        fs.symlinkSync(CLI_DIST, fileSymlinkCli, 'file');
        createdFileSymlink = true;
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code !== 'EPERM') {
          throw err;
        }
      }

      if (createdFileSymlink) {
        const symRun = runCliSubprocess(['check', repoDir, '--no-home', '--format', 'json'], fileSymlinkCli);
        assert.equal(symRun.status, 0);
        assert.equal(JSON.parse(symRun.stdout).tool, 'agent-lint');
      }
    });
  });

  it('dogfoods cleanly on the agent-lint repository itself with zero findings across all severities', () => {
    const selfRes = runCliSubprocess([
      'check',
      process.cwd(),
      '--no-home',
      '--fail-on',
      'info',
      '--format',
      'json',
    ]);
    assert.equal(selfRes.status, 0, `Unexpected findings on self: ${selfRes.stdout}`);
    const parsed = JSON.parse(selfRes.stdout) as {
      discoveredFiles: Array<{ file: string }>;
      summary: { total: number };
    };
    assert.equal(parsed.summary.total, 0);
    assert.ok(parsed.discoveredFiles.some((f) => f.file === 'AGENTS.md'));
  });
});
