export const PACKAGE_NAME = '@pie527645-cloud/agent-lint';
export const PACKAGE_VERSION = '1.0.0';
export const INFORMATION_URI = 'https://github.com/pie527645-cloud/agent-lint';
export const TOKEN_ESTIMATION_LABEL = 'Math.ceil(chars / 4) (estimate)';

export const DEFAULT_BUDGET_TOKENS = 4000;
export const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024; // 2 MB
export const DEFAULT_MAX_SCANNED_FILES = 2000;
export const MAX_IMPORT_DEPTH = 5;
export const MAX_YAML_ALIAS_COUNT = 50;

export type AgentName = 'claude' | 'gemini' | 'cursor' | 'copilot';

export const ALL_AGENTS: readonly AgentName[] = ['claude', 'gemini', 'cursor', 'copilot'];

export type Severity = 'info' | 'low' | 'medium' | 'high';

export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
};

export type OutputFormat = 'pretty' | 'json' | 'markdown' | 'sarif';

export type RuleId =
  | 'AGL001'
  | 'AGL002'
  | 'AGL010'
  | 'AGL011'
  | 'AGL012'
  | 'AGL020'
  | 'AGL030'
  | 'AGL031'
  | 'AGL032'
  | 'AGL040'
  | 'AGL041'
  | 'AGL900';

export type RuleCategory =
  | 'budget'
  | 'integrity'
  | 'consistency'
  | 'security'
  | 'skills'
  | 'rules-config'
  | 'limits';

export type InstructionKind =
  | 'agents-md'
  | 'claude-md'
  | 'claude-local-md'
  | 'claude-import'
  | 'gemini-md'
  | 'copilot-instructions'
  | 'copilot-scoped-instructions'
  | 'cursor-mdc'
  | 'cursorrules'
  | 'skill-md';

export interface FrontmatterParseResult {
  present: boolean;
  empty: boolean;
  rawYaml: string;
  startLine: number;
  endLine: number;
  bodyStartLine: number;
  data: Record<string, unknown>;
  yamlError?: string;
  aliasLimitExceeded: boolean;
  dangerousKeys: string[];
}

export interface DiscoveredFile {
  absPath: string;
  realPath: string;
  /** POSIX-normalized display path (`home:...` when sourced from explicit `--home`). */
  displayPath: string;
  /** POSIX-normalized path relative to its own source root (`repo` or `home`). */
  relToSourceRoot: string;
  sourceRoot: 'repo' | 'home';
  rootDirReal: string;
  kind: InstructionKind;
  /** Directory relative to sourceRoot (`""` for root). */
  scopeDir: string;
  agents: AgentName[];
  alwaysLoadedFor: AgentName[];
  bytes: number;
  chars: number;
  estimatedTokens: number;
  hasBom: boolean;
  content: string;
  frontmatter?: FrontmatterParseResult;
  importedBy?: string;
  importDepth?: number;
}

export interface Finding {
  ruleId: RuleId;
  severity: Severity;
  category: RuleCategory;
  message: string;
  file: string;
  line: number;
  column: number;
  agent?: AgentName;
  evidence?: string;
  remediation: string;
  fingerprint: string;
}

export interface ContextFileEntry {
  file: string;
  kind: InstructionKind;
  sourceRoot: 'repo' | 'home';
  scopeDir: string;
  chars: number;
  estimatedTokens: number;
  budgetSharePct: number;
  importedBy?: string;
  importDepth?: number;
}

export interface ScopedContextEntry {
  file: string;
  kind: InstructionKind;
  sourceRoot: 'repo' | 'home';
  scope: string;
  chars: number;
  estimatedTokens: number;
}

export interface SkillContextEntry {
  file: string;
  sourceRoot: 'repo' | 'home';
  skillName?: string;
  chars: number;
  estimatedTokens: number;
}

export interface AgentContextReport {
  agent: AgentName;
  scopeDir: string;
  budgetTokens: number;
  tokenEstimationMethod: string;
  alwaysLoadedFiles: ContextFileEntry[];
  scopedFiles: ScopedContextEntry[];
  skillFiles: SkillContextEntry[];
  totalAlwaysLoadedChars: number;
  totalAlwaysLoadedTokens: number;
}

export interface DiscoveredFileSummary {
  file: string;
  kind: InstructionKind;
  sourceRoot: 'repo' | 'home';
  agents: AgentName[];
  alwaysLoadedFor: AgentName[];
  bytes: number;
  chars: number;
  estimatedTokens: number;
}

export interface SeveritySummary {
  info: number;
  low: number;
  medium: number;
  high: number;
  total: number;
}

export interface LintOptions {
  dir: string;
  agents?: AgentName[];
  budgetTokens?: number;
  homeDir?: string | null;
  baselinePath?: string;
  maxFileBytes?: number;
  maxScannedFiles?: number;
}

export interface LintReport {
  tool: 'agent-lint';
  version: string;
  budgetTokens: number;
  agents: AgentName[];
  homeEnabled: boolean;
  tokenEstimationMethod: string;
  discoveredFiles: DiscoveredFileSummary[];
  agentContexts: Partial<Record<AgentName, AgentContextReport>>;
  suppressedCount: number;
  findings: Finding[];
  summary: SeveritySummary;
}

export class UsageError extends Error {
  public readonly exitCode = 2;
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export function estimateTokens(chars: number): number {
  if (chars <= 0) return 0;
  return Math.ceil(chars / 4);
}

export function createNullRecord<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}

export function hasOwn(obj: object, key: string): boolean {
  return Object.hasOwn(obj, key);
}
