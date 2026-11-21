import fs from 'node:fs';
import {
  extractDotenvTokens,
  loadBaselineFingerprints,
  redactSecret,
  runAllAnalyzers,
  SAFE_DOTENV_FILENAMES,
} from './analyzers.js';
import { buildAgentContext, discoverWorkspace, parseAgentList } from './discovery.js';
import {
  buildSarifObject,
  formatContextReport,
  formatLintReport,
  formatRuleExplanation,
} from './formatters.js';
import { getRuleDefinition, ORDERED_RULE_IDS, type RuleDefinition, RULES } from './rules-catalog.js';
import {
  type AgentContextReport,
  type AgentName,
  ALL_AGENTS,
  DEFAULT_BUDGET_TOKENS,
  type DiscoveredFileSummary,
  type Finding,
  type LintOptions,
  type LintReport,
  PACKAGE_NAME,
  PACKAGE_VERSION,
  SEVERITY_ORDER,
  type Severity,
  type SeveritySummary,
  TOKEN_ESTIMATION_LABEL,
  UsageError,
} from './types.js';

function validateDirectoryExists(dirPath: string, label: string): void {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(dirPath);
  } catch {
    throw new UsageError(`${label} does not exist: "${dirPath}"`);
  }
  if (!stat.isDirectory()) {
    throw new UsageError(`${label} is not a directory: "${dirPath}"`);
  }
}

function summarizeFindings(findings: readonly Finding[]): SeveritySummary {
  const summary: SeveritySummary = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    total: findings.length,
  };
  for (const f of findings) {
    summary[f.severity] += 1;
  }
  return summary;
}

export function lintWorkspace(options: LintOptions): LintReport {
  validateDirectoryExists(options.dir, 'Target directory');

  const homeEnabled = options.homeDir !== undefined && options.homeDir !== null;
  if (homeEnabled) {
    validateDirectoryExists(options.homeDir!, '--home directory');
  }

  const agents = options.agents && options.agents.length > 0 ? [...options.agents] : [...ALL_AGENTS];
  const budgetTokens = options.budgetTokens ?? DEFAULT_BUDGET_TOKENS;
  if (!Number.isFinite(budgetTokens) || budgetTokens <= 0) {
    throw new UsageError(`--budget must be a positive integer (received ${String(options.budgetTokens)}).`);
  }

  let baselineFingerprints: Set<string> | null = null;
  if (options.baselinePath) {
    try {
      baselineFingerprints = loadBaselineFingerprints(options.baselinePath);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new UsageError(`Failed to read --baseline "${options.baselinePath}": ${msg}`);
    }
  }

  const discovery = discoverWorkspace({
    repoDir: options.dir,
    homeDir: homeEnabled ? options.homeDir! : null,
    ...(options.maxFileBytes !== undefined ? { maxFileBytes: options.maxFileBytes } : {}),
    ...(options.maxScannedFiles !== undefined ? { maxScannedFiles: options.maxScannedFiles } : {}),
  });

  const agentContexts: Partial<Record<AgentName, AgentContextReport>> = {};
  for (const agent of agents) {
    agentContexts[agent] = buildAgentContext(discovery, agent, { budgetTokens });
  }

  const rawFindings = runAllAnalyzers({
    discovery,
    agentContexts,
    agents,
    budgetTokens,
  });

  // Filter agent-specific findings if `--agents` restricted the agent set
  const selectedAgentSet = new Set<AgentName>(agents);
  const agentFilteredFindings = rawFindings.filter((f) => {
    if (!f.agent) return true;
    return selectedAgentSet.has(f.agent);
  });

  let suppressedCount = 0;
  const activeFindings: Finding[] = [];
  for (const f of agentFilteredFindings) {
    if (baselineFingerprints && baselineFingerprints.has(f.fingerprint)) {
      suppressedCount += 1;
    } else {
      activeFindings.push(f);
    }
  }

  const discoveredFiles: DiscoveredFileSummary[] = discovery.documents.map((d) => ({
    file: d.meta.displayPath,
    kind: d.meta.kind,
    sourceRoot: d.meta.sourceRoot,
    agents: d.meta.agents,
    alwaysLoadedFor: d.meta.alwaysLoadedFor,
    bytes: d.meta.bytes,
    chars: d.meta.chars,
    estimatedTokens: d.meta.estimatedTokens,
  }));

  return {
    tool: 'agent-lint',
    version: PACKAGE_VERSION,
    budgetTokens,
    agents,
    homeEnabled,
    tokenEstimationMethod: TOKEN_ESTIMATION_LABEL,
    discoveredFiles,
    agentContexts,
    suppressedCount,
    findings: activeFindings,
    summary: summarizeFindings(activeFindings),
  };
}

export function inspectAgentContext(options: {
  dir: string;
  agent: AgentName;
  scopeDir?: string;
  budgetTokens?: number;
  homeDir?: string | null;
  maxFileBytes?: number;
  maxScannedFiles?: number;
}): AgentContextReport {
  validateDirectoryExists(options.dir, 'Target directory');
  const homeEnabled = options.homeDir !== undefined && options.homeDir !== null;
  if (homeEnabled) {
    validateDirectoryExists(options.homeDir!, '--home directory');
  }
  const budgetTokens = options.budgetTokens ?? DEFAULT_BUDGET_TOKENS;
  if (!Number.isFinite(budgetTokens) || budgetTokens <= 0) {
    throw new UsageError(`--budget must be a positive integer (received ${String(options.budgetTokens)}).`);
  }

  const discovery = discoverWorkspace({
    repoDir: options.dir,
    homeDir: homeEnabled ? options.homeDir! : null,
    ...(options.maxFileBytes !== undefined ? { maxFileBytes: options.maxFileBytes } : {}),
    ...(options.maxScannedFiles !== undefined ? { maxScannedFiles: options.maxScannedFiles } : {}),
  });

  return buildAgentContext(discovery, options.agent, {
    budgetTokens,
    ...(options.scopeDir !== undefined ? { scopeDir: options.scopeDir } : {}),
  });
}

export function hasFailingFindings(findings: readonly Finding[], failOn: Severity): boolean {
  const threshold = SEVERITY_ORDER[failOn];
  return findings.some((f) => SEVERITY_ORDER[f.severity] >= threshold);
}

export {
  ALL_AGENTS,
  buildAgentContext,
  buildSarifObject,
  DEFAULT_BUDGET_TOKENS,
  discoverWorkspace,
  extractDotenvTokens,
  formatContextReport,
  formatLintReport,
  formatRuleExplanation,
  getRuleDefinition,
  ORDERED_RULE_IDS,
  PACKAGE_NAME,
  PACKAGE_VERSION,
  parseAgentList,
  redactSecret,
  type RuleDefinition,
  RULES,
  SAFE_DOTENV_FILENAMES,
  SEVERITY_ORDER,
  UsageError,
};

export type * from './types.js';
