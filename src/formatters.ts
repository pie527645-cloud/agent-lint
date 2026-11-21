import { ORDERED_RULE_IDS, type RuleDefinition, RULES } from './rules-catalog.js';
import {
  type AgentContextReport,
  INFORMATION_URI,
  type LintReport,
  type OutputFormat,
  PACKAGE_NAME,
  PACKAGE_VERSION,
  type Severity,
} from './types.js';

export type SarifLevel = 'error' | 'warning' | 'note';

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: Array<{
    tool: {
      driver: {
        name: string;
        fullName: string;
        version: string;
        informationUri: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: { text: string };
          fullDescription: { text: string };
          help: { text: string; markdown: string };
          defaultConfiguration: { level: SarifLevel };
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      ruleIndex: number;
      level: SarifLevel;
      message: { text: string };
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string };
          region: { startLine: number; startColumn: number };
        };
      }>;
      partialFingerprints: {
        primaryLocationLineHash: string;
      };
    }>;
  }>;
}

function severityToSarifLevel(severity: Severity): SarifLevel {
  switch (severity) {
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
  }
}

function toSarifUri(file: string): string {
  if (!file || file === '.') {
    return 'AGENTS.md';
  }
  const normalized = file.replace(/\\/g, '/');
  if (normalized.startsWith('home:')) {
    return `home/${normalized.slice(5)}`;
  }
  return normalized;
}

function escapeMdCell(text: string): string {
  return text.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

export function buildSarifObject(report: LintReport): SarifLog {
  const ruleIndexMap = new Map<string, number>();
  const driverRules = ORDERED_RULE_IDS.map((id, idx) => {
    ruleIndexMap.set(id, idx);
    const def = RULES[id];
    return {
      id: def.id,
      name: def.name,
      shortDescription: { text: def.shortDescription },
      fullDescription: { text: def.fullDescription },
      help: {
        text: def.remediation,
        markdown: `**Remediation:** ${def.remediation}`,
      },
      defaultConfiguration: {
        level: severityToSarifLevel(def.defaultSeverity),
      },
    };
  });

  const results = report.findings.map((f) => ({
    ruleId: f.ruleId,
    ruleIndex: ruleIndexMap.get(f.ruleId) ?? 0,
    level: severityToSarifLevel(f.severity),
    message: {
      text: f.evidence ? `${f.message} (Evidence: ${f.evidence})` : f.message,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: toSarifUri(f.file) },
          region: {
            startLine: Math.max(1, f.line),
            startColumn: Math.max(1, f.column),
          },
        },
      },
    ],
    partialFingerprints: {
      primaryLocationLineHash: f.fingerprint,
    },
  }));

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'agent-lint',
            fullName: PACKAGE_NAME,
            version: PACKAGE_VERSION,
            informationUri: INFORMATION_URI,
            rules: driverRules,
          },
        },
        results,
      },
    ],
  };
}

export function formatLintPretty(report: LintReport): string {
  const lines: string[] = [];
  lines.push(`agent-lint v${report.version} — AI Instruction & Skill Audit`);
  lines.push('='.repeat(68));
  lines.push(
    `Discovered Files : ${report.discoveredFiles.length} (${report.homeEnabled ? 'repo + explicit --home' : '--no-home'})`,
  );
  lines.push(`Token Estimator  : ${report.tokenEstimationMethod}`);
  lines.push(`Per-Agent Budget : ${report.budgetTokens} tokens`);

  lines.push('');
  lines.push('Always-Loaded Context Estimate:');
  for (const agent of report.agents) {
    const ctx = report.agentContexts[agent];
    if (!ctx) continue;
    lines.push(
      `  - ${agent.padEnd(8, ' ')}: ~${String(ctx.totalAlwaysLoadedTokens).padStart(5, ' ')} / ${report.budgetTokens} est. tokens (${ctx.alwaysLoadedFiles.length} file(s))`,
    );
  }

  if (report.suppressedCount > 0) {
    lines.push('');
    lines.push(`Baseline Suppressed: ${report.suppressedCount} finding(s)`);
  }

  lines.push('');
  lines.push(
    `Summary: ${report.summary.high} high, ${report.summary.medium} medium, ${report.summary.low} low, ${report.summary.info} info (${report.summary.total} total)`,
  );

  if (report.findings.length === 0) {
    lines.push('No findings.');
    return `${lines.join('\n')}\n`;
  }

  lines.push('');
  for (const f of report.findings) {
    const badge = `[${f.severity.toUpperCase()}]`.padEnd(8, ' ');
    lines.push(`${badge} ${f.ruleId} ${f.file}:${f.line}:${f.column}`);
    lines.push(`         ${f.message}`);
    if (f.evidence) {
      lines.push(`         Evidence: ${f.evidence}`);
    }
  }

  return `${lines.join('\n')}\n`;
}

export function formatLintMarkdown(report: LintReport): string {
  const lines: string[] = [];
  lines.push('## agent-lint Audit Report');
  lines.push('');
  lines.push(`- **Discovered Files:** ${report.discoveredFiles.length}`);
  lines.push(`- **Token Estimation:** \`${report.tokenEstimationMethod}\``);
  lines.push(`- **Budget:** ${report.budgetTokens} tokens`);
  if (report.suppressedCount > 0) {
    lines.push(`- **Suppressed via Baseline:** ${report.suppressedCount}`);
  }
  lines.push(
    `- **Summary:** **${report.summary.high}** high, **${report.summary.medium}** medium, **${report.summary.low}** low, **${report.summary.info}** info (${report.summary.total} total)`,
  );
  lines.push('');
  lines.push('### Always-Loaded Context by Agent');
  lines.push('');
  lines.push('| Agent | Always-Loaded Files | Est. Tokens (chars/4) | Budget |');
  lines.push('| --- | ---: | ---: | ---: |');
  for (const agent of report.agents) {
    const ctx = report.agentContexts[agent];
    if (!ctx) continue;
    lines.push(
      `| \`${agent}\` | ${ctx.alwaysLoadedFiles.length} | ~${ctx.totalAlwaysLoadedTokens} | ${report.budgetTokens} |`,
    );
  }
  lines.push('');

  if (report.findings.length === 0) {
    lines.push('No findings detected.');
    return `${lines.join('\n')}\n`;
  }

  lines.push('### Findings');
  lines.push('');
  lines.push('| Severity | Rule | Location | Message |');
  lines.push('| --- | --- | --- | --- |');
  for (const f of report.findings) {
    lines.push(
      `| \`${f.severity}\` | \`${f.ruleId}\` | \`${escapeMdCell(`${f.file}:${f.line}:${f.column}`)}\` | ${escapeMdCell(f.message)} |`,
    );
  }

  return `${lines.join('\n')}\n`;
}

export function formatLintReport(report: LintReport, format: OutputFormat): string {
  switch (format) {
    case 'pretty':
      return formatLintPretty(report);
    case 'json':
      return `${JSON.stringify(report, null, 2)}\n`;
    case 'markdown':
      return formatLintMarkdown(report);
    case 'sarif':
      return `${JSON.stringify(buildSarifObject(report), null, 2)}\n`;
  }
}

export function formatContextReport(
  ctx: AgentContextReport,
  format: 'pretty' | 'json' | 'markdown',
): string {
  if (format === 'json') {
    return `${JSON.stringify(ctx, null, 2)}\n`;
  }

  if (format === 'markdown') {
    const lines: string[] = [];
    lines.push(`## Effective Context — \`${ctx.agent}\` (scope: \`${ctx.scopeDir}\`)`);
    lines.push('');
    lines.push(`- **Token Estimator:** \`${ctx.tokenEstimationMethod}\``);
    lines.push(
      `- **Total Always-Loaded:** ~${ctx.totalAlwaysLoadedTokens} est. tokens (${ctx.totalAlwaysLoadedChars} chars, budget ${ctx.budgetTokens})`,
    );
    lines.push('');
    lines.push('| Order | File | Kind | Chars | Est. Tokens (chars/4) | Budget % |');
    lines.push('| ---: | --- | --- | ---: | ---: | ---: |');
    ctx.alwaysLoadedFiles.forEach((f, idx) => {
      lines.push(
        `| ${idx + 1} | \`${escapeMdCell(f.file)}\` | \`${f.kind}\` | ${f.chars} | ~${f.estimatedTokens} | ${f.budgetSharePct}% |`,
      );
    });
    if (ctx.alwaysLoadedFiles.length === 0) {
      lines.push('| - | *(none)* | - | 0 | 0 | 0% |');
    }
    return `${lines.join('\n')}\n`;
  }

  const lines: string[] = [];
  lines.push(`Effective Context for agent "${ctx.agent}" (scope: ${ctx.scopeDir})`);
  lines.push('='.repeat(68));
  lines.push(`Token Estimator : ${ctx.tokenEstimationMethod}`);
  lines.push(`Budget          : ${ctx.budgetTokens} tokens`);
  lines.push('');
  lines.push(`Always-Loaded Files in Load Order (${ctx.alwaysLoadedFiles.length}):`);
  if (ctx.alwaysLoadedFiles.length === 0) {
    lines.push('  (none)');
  } else {
    ctx.alwaysLoadedFiles.forEach((f, idx) => {
      const via = f.importedBy ? ` [imported by ${f.importedBy}]` : '';
      lines.push(
        `  ${idx + 1}. ${f.file} (~${f.estimatedTokens} est. tokens, ${f.chars} chars, ${f.budgetSharePct}% of budget)${via}`,
      );
    });
  }
  lines.push('');
  lines.push(
    `Total Always-Loaded: ~${ctx.totalAlwaysLoadedTokens} estimated tokens (${ctx.totalAlwaysLoadedChars} chars)`,
  );

  if (ctx.scopedFiles.length > 0) {
    lines.push('');
    lines.push(`Scoped / Conditional Instructions (${ctx.scopedFiles.length}):`);
    for (const sf of ctx.scopedFiles) {
      lines.push(`  - ${sf.file} [scope: ${sf.scope}] (~${sf.estimatedTokens} est. tokens)`);
    }
  }

  if (ctx.skillFiles.length > 0) {
    lines.push('');
    lines.push(`On-Demand Skills (${ctx.skillFiles.length}):`);
    for (const sk of ctx.skillFiles) {
      const label = sk.skillName ? `${sk.skillName} (${sk.file})` : sk.file;
      lines.push(`  - ${label} (~${sk.estimatedTokens} est. tokens when invoked)`);
    }
  }

  return `${lines.join('\n')}\n`;
}

export function formatRuleExplanation(
  rule: RuleDefinition,
  format: 'pretty' | 'json' | 'markdown',
): string {
  if (format === 'json') {
    return `${JSON.stringify(rule, null, 2)}\n`;
  }
  if (format === 'markdown') {
    return [
      `## ${rule.id} — ${rule.name}`,
      '',
      `- **Category:** \`${rule.category}\``,
      `- **Default Severity:** \`${rule.defaultSeverity}\``,
      '',
      rule.fullDescription,
      '',
      `### Remediation`,
      rule.remediation,
      '',
      `### Examples`,
      `- **Problematic:** ${rule.examples.bad}`,
      `- **Recommended:** ${rule.examples.good}`,
      '',
    ].join('\n');
  }

  return [
    `${rule.id} — ${rule.name} [${rule.defaultSeverity.toUpperCase()} | ${rule.category}]`,
    '='.repeat(68),
    `Summary    : ${rule.shortDescription}`,
    '',
    `Details    : ${rule.fullDescription}`,
    '',
    `Remediation: ${rule.remediation}`,
    '',
    `Examples:`,
    `  Bad : ${rule.examples.bad}`,
    `  Good: ${rule.examples.good}`,
    '',
  ].join('\n');
}
