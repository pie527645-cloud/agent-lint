#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseAgentList } from './discovery.js';
import {
  formatContextReport,
  formatLintReport,
  formatRuleExplanation,
} from './formatters.js';
import {
  hasFailingFindings,
  inspectAgentContext,
  lintWorkspace,
} from './index.js';
import { getRuleDefinition, ORDERED_RULE_IDS } from './rules-catalog.js';
import {
  type AgentName,
  ALL_AGENTS,
  DEFAULT_BUDGET_TOKENS,
  type OutputFormat,
  PACKAGE_VERSION,
  type Severity,
  UsageError,
} from './types.js';

const VALID_FORMATS: ReadonlySet<string> = new Set(['pretty', 'json', 'markdown', 'sarif']);
const VALID_SEVERITIES: ReadonlySet<string> = new Set(['info', 'low', 'medium', 'high']);

function printHelp(stream: NodeJS.WriteStream): void {
  const text = `agent-lint v${PACKAGE_VERSION} — AI instruction-file & skill linter

Usage:
  agent-lint check [dir] [options]
  agent-lint context [dir] --agent <claude|gemini|cursor|copilot> [options]
  agent-lint explain <ruleId> [--format pretty|json|markdown]

Options for "check":
  --agents <list>        Comma-separated agents (default: claude,gemini,cursor,copilot)
  --budget <tokens>      Per-agent always-loaded token budget (default: ${DEFAULT_BUDGET_TOKENS})
  --no-home              Scan repository only without any home directory (default)
  --home <dir>           Explicit global config directory to include read-only
  --format <fmt>         Output format: pretty | json | markdown | sarif (default: pretty)
  --fail-on <severity>   Exit 1 threshold: info | low | medium | high (default: high)
  --baseline <file>      JSON or SARIF baseline file to suppress known fingerprints

Options for "context":
  --agent <name>         Target agent: claude | gemini | cursor | copilot (required)
  --scope <subpath>      Optional monorepo subdirectory scope (default: .)
  --budget <tokens>      Token budget for share calculation (default: ${DEFAULT_BUDGET_TOKENS})
  --no-home              Scan repository only (default)
  --home <dir>           Explicit global config directory to include read-only
  --format <fmt>         Output format: pretty | json | markdown (default: pretty)

Rules:
  ${ORDERED_RULE_IDS.join(', ')}

Exit codes:
  0  Clean (no findings at or above --fail-on)
  1  Findings detected at or above --fail-on
  2  CLI usage, I/O, or configuration error
`;
  stream.write(text);
}

function readFlagValue(argv: readonly string[], idx: number, flagName: string): { value: string; nextIdx: number } {
  const token = argv[idx]!;
  const eqIdx = token.indexOf('=');
  if (eqIdx !== -1) {
    const val = token.slice(eqIdx + 1).trim();
    if (val.length === 0) {
      throw new UsageError(`Option "${flagName}" requires a non-empty value.`);
    }
    return { value: val, nextIdx: idx };
  }
  const next = argv[idx + 1];
  if (next === undefined || next.startsWith('-')) {
    throw new UsageError(`Option "${flagName}" requires an explicit value.`);
  }
  return { value: next, nextIdx: idx + 1 };
}

function parseBudget(raw: string): number {
  if (!/^\d+$/.test(raw.trim())) {
    throw new UsageError(`Invalid --budget "${raw}": expected a positive integer.`);
  }
  const num = Number.parseInt(raw.trim(), 10);
  if (!Number.isSafeInteger(num) || num <= 0) {
    throw new UsageError(`Invalid --budget "${raw}": expected a positive integer.`);
  }
  return num;
}

export function runCli(
  argv: readonly string[],
  io: { stdout: NodeJS.WriteStream; stderr: NodeJS.WriteStream } = {
    stdout: process.stdout,
    stderr: process.stderr,
  },
): number {
  try {
    if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h' || argv[0] === 'help') {
      printHelp(io.stdout);
      return 0;
    }

    if (argv[0] === '--version' || argv[0] === '-v') {
      io.stdout.write(`${PACKAGE_VERSION}\n`);
      return 0;
    }

    const command = argv[0];

    if (command === 'check') {
      let targetDir: string | undefined;
      let agents: AgentName[] = [...ALL_AGENTS];
      let budgetTokens = DEFAULT_BUDGET_TOKENS;
      let homeDir: string | null = null;
      let format: OutputFormat = 'pretty';
      let failOn: Severity = 'high';
      let baselinePath: string | undefined;

      for (let i = 1; i < argv.length; i += 1) {
        const arg = argv[i]!;
        if (arg === '--help' || arg === '-h') {
          printHelp(io.stdout);
          return 0;
        }
        if (arg === '--no-home') {
          homeDir = null;
          continue;
        }
        if (arg === '--home' || arg.startsWith('--home=')) {
          const parsed = readFlagValue(argv, i, '--home');
          homeDir = parsed.value;
          i = parsed.nextIdx;
          continue;
        }
        if (arg === '--agents' || arg.startsWith('--agents=')) {
          const parsed = readFlagValue(argv, i, '--agents');
          try {
            agents = parseAgentList(parsed.value);
          } catch (err) {
            throw new UsageError(err instanceof Error ? err.message : String(err));
          }
          i = parsed.nextIdx;
          continue;
        }
        if (arg === '--budget' || arg.startsWith('--budget=')) {
          const parsed = readFlagValue(argv, i, '--budget');
          budgetTokens = parseBudget(parsed.value);
          i = parsed.nextIdx;
          continue;
        }
        if (arg === '--format' || arg.startsWith('--format=')) {
          const parsed = readFlagValue(argv, i, '--format');
          const fmt = parsed.value.toLowerCase();
          if (!VALID_FORMATS.has(fmt)) {
            throw new UsageError(
              `Invalid --format "${parsed.value}". Expected pretty, json, markdown, or sarif.`,
            );
          }
          format = fmt as OutputFormat;
          i = parsed.nextIdx;
          continue;
        }
        if (arg === '--fail-on' || arg.startsWith('--fail-on=')) {
          const parsed = readFlagValue(argv, i, '--fail-on');
          const sev = parsed.value.toLowerCase();
          if (!VALID_SEVERITIES.has(sev)) {
            throw new UsageError(
              `Invalid --fail-on "${parsed.value}". Expected info, low, medium, or high.`,
            );
          }
          failOn = sev as Severity;
          i = parsed.nextIdx;
          continue;
        }
        if (arg === '--baseline' || arg.startsWith('--baseline=')) {
          const parsed = readFlagValue(argv, i, '--baseline');
          baselinePath = parsed.value;
          i = parsed.nextIdx;
          continue;
        }
        if (arg.startsWith('-')) {
          throw new UsageError(`Unknown option for "check": "${arg}".`);
        }
        if (targetDir !== undefined) {
          throw new UsageError(`Unexpected positional argument "${arg}" (directory already set to "${targetDir}").`);
        }
        targetDir = arg;
      }

      const report = lintWorkspace({
        dir: targetDir ?? process.cwd(),
        agents,
        budgetTokens,
        homeDir,
        ...(baselinePath !== undefined ? { baselinePath } : {}),
      });

      io.stdout.write(formatLintReport(report, format));
      return hasFailingFindings(report.findings, failOn) ? 1 : 0;
    }

    if (command === 'context') {
      let targetDir: string | undefined;
      let agent: AgentName | undefined;
      let scopeDir: string | undefined;
      let budgetTokens = DEFAULT_BUDGET_TOKENS;
      let homeDir: string | null = null;
      let format: 'pretty' | 'json' | 'markdown' = 'pretty';

      for (let i = 1; i < argv.length; i += 1) {
        const arg = argv[i]!;
        if (arg === '--help' || arg === '-h') {
          printHelp(io.stdout);
          return 0;
        }
        if (arg === '--no-home') {
          homeDir = null;
          continue;
        }
        if (arg === '--home' || arg.startsWith('--home=')) {
          const parsed = readFlagValue(argv, i, '--home');
          homeDir = parsed.value;
          i = parsed.nextIdx;
          continue;
        }
        if (arg === '--agent' || arg.startsWith('--agent=')) {
          const parsed = readFlagValue(argv, i, '--agent');
          const list = (() => {
            try {
              return parseAgentList(parsed.value);
            } catch (err) {
              throw new UsageError(err instanceof Error ? err.message : String(err));
            }
          })();
          if (list.length !== 1) {
            throw new UsageError(`--agent requires a single agent name (${ALL_AGENTS.join(', ')}).`);
          }
          agent = list[0];
          i = parsed.nextIdx;
          continue;
        }
        if (arg === '--scope' || arg.startsWith('--scope=')) {
          const parsed = readFlagValue(argv, i, '--scope');
          scopeDir = parsed.value;
          i = parsed.nextIdx;
          continue;
        }
        if (arg === '--budget' || arg.startsWith('--budget=')) {
          const parsed = readFlagValue(argv, i, '--budget');
          budgetTokens = parseBudget(parsed.value);
          i = parsed.nextIdx;
          continue;
        }
        if (arg === '--format' || arg.startsWith('--format=')) {
          const parsed = readFlagValue(argv, i, '--format');
          const fmt = parsed.value.toLowerCase();
          if (fmt !== 'pretty' && fmt !== 'json' && fmt !== 'markdown') {
            throw new UsageError(`Invalid --format "${parsed.value}" for "context". Expected pretty, json, or markdown.`);
          }
          format = fmt;
          i = parsed.nextIdx;
          continue;
        }
        if (arg.startsWith('-')) {
          throw new UsageError(`Unknown option for "context": "${arg}".`);
        }
        if (targetDir !== undefined) {
          throw new UsageError(`Unexpected positional argument "${arg}".`);
        }
        targetDir = arg;
      }

      if (!agent) {
        throw new UsageError(`"context" requires --agent <${ALL_AGENTS.join('|')}>.`);
      }

      const ctx = inspectAgentContext({
        dir: targetDir ?? process.cwd(),
        agent,
        budgetTokens,
        homeDir,
        ...(scopeDir !== undefined ? { scopeDir } : {}),
      });

      io.stdout.write(formatContextReport(ctx, format));
      return 0;
    }

    if (command === 'explain') {
      let ruleIdArg: string | undefined;
      let format: 'pretty' | 'json' | 'markdown' = 'pretty';

      for (let i = 1; i < argv.length; i += 1) {
        const arg = argv[i]!;
        if (arg === '--help' || arg === '-h') {
          printHelp(io.stdout);
          return 0;
        }
        if (arg === '--format' || arg.startsWith('--format=')) {
          const parsed = readFlagValue(argv, i, '--format');
          const fmt = parsed.value.toLowerCase();
          if (fmt !== 'pretty' && fmt !== 'json' && fmt !== 'markdown') {
            throw new UsageError(`Invalid --format "${parsed.value}" for "explain". Expected pretty, json, or markdown.`);
          }
          format = fmt;
          i = parsed.nextIdx;
          continue;
        }
        if (arg.startsWith('-')) {
          throw new UsageError(`Unknown option for "explain": "${arg}".`);
        }
        if (ruleIdArg !== undefined) {
          throw new UsageError(`Unexpected argument "${arg}".`);
        }
        ruleIdArg = arg;
      }

      if (!ruleIdArg) {
        throw new UsageError(`"explain" requires a rule ID (for example: agent-lint explain AGL031).`);
      }

      const rule = getRuleDefinition(ruleIdArg);
      if (!rule) {
        throw new UsageError(
          `Unknown rule ID "${ruleIdArg}". Known rules: ${ORDERED_RULE_IDS.join(', ')}.`,
        );
      }

      io.stdout.write(formatRuleExplanation(rule, format));
      return 0;
    }

    throw new UsageError(
      `Unknown command "${command}". Expected "check", "context", or "explain" (run --help for usage).`,
    );
  } catch (err) {
    if (err instanceof UsageError) {
      io.stderr.write(`Error: ${err.message}\n`);
      return 2;
    }
    const msg = err instanceof Error ? err.message : String(err);
    io.stderr.write(`Error: ${msg}\n`);
    return 2;
  }
}

function isExecutedDirectly(): boolean {
  const entryArg = process.argv[1];
  if (!entryArg) return false;
  const modulePath = fileURLToPath(import.meta.url);
  try {
    return fs.realpathSync(modulePath) === fs.realpathSync(path.resolve(entryArg));
  } catch {
    return path.resolve(modulePath) === path.resolve(entryArg);
  }
}

if (isExecutedDirectly()) {
  process.exitCode = runCli(process.argv.slice(2));
}
