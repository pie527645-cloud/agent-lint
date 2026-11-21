# @pie527645-cloud/agent-lint

Static security, path/command drift, frontmatter, and context-token-budget linter for AI coding agent instruction files and skills (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, GitHub Copilot instructions, Cursor `.mdc` rules, and `SKILL.md`).

Modern repositories carry multiple overlapping AI instruction files that silently drift from the codebase: referencing deleted or miscased file paths, prescribing missing `package.json` / `Makefile` / `justfile` commands, contradicting repository lockfiles, inflating every conversation turn's token budget, or concealing prompt-injection directives. `agent-lint` audits these files deterministically offline without ever executing repository code or touching the user's real home directory by default.

## Key Capabilities

- **Multi-agent context modeling (`claude`, `gemini`, `cursor`, `copilot`):** Computes ordered always-loaded instruction sets, hierarchical monorepo precedence, scoped glob rules, and on-demand skills with deterministic `Math.ceil(chars / 4)` token estimates.
- **Case-exact path & `@import` verification (`AGL010`, `AGL012`):** Verifies `@path` imports (up to 5 hops with cycle detection, ignoring fenced code blocks), Markdown links, and referenced repository paths against exact directory entry casing on Windows, macOS, and Linux, while blocking `realpathSync` symlink/junction escapes.
- **Static command drift checks (`AGL011`, `AGL020`):** Statically validates `npm`, `pnpm`, `yarn`, `make`, and `just` invocations in code blocks against `package.json`, `Makefile`, and `justfile` (never executed) and flags package-manager lockfile contradictions.
- **Prompt-injection & secret hygiene (`AGL030`, `AGL031`, `AGL032`):** Detects Trojan Source bidirectional/zero-width Unicode, hidden HTML comments, `data:`/base64 payloads, `curl | sh`, `--no-verify`, user-concealment directives, live `.env` / `~/.ssh` references (with benign `.env.{example,sample,template,schema,schema.json}` downgraded to `info`), and pasted API keys redacted as `ab...***REDACTED***`.
- **Skill & rule frontmatter safety (`AGL040`, `AGL041`):** Validates `SKILL.md`, `.cursor/rules/*.mdc`, and `.github/instructions/*.instructions.md` frontmatter with YAML `maxAliasCount` bounds and prototype-pollution (`__proto__`) guards.
- **CI & Code Scanning ready:** Supports `pretty`, `json`, `markdown`, and **SARIF 2.1.0** output plus fingerprint-based `--baseline` suppression.

## Installation & Build from Source

Requires **Node.js `>=20.18.1`**.

```bash
git clone https://github.com/pie527645-cloud/agent-lint.git
cd agent-lint
npm install
npm run build
npm test
```

Run the compiled CLI directly with `node`:

```bash
node /abs/path/to/agent-lint/dist/cli.js check /path/to/target-repo --no-home
```

## CLI Usage

### 1. Audit a repository (`check`)

```bash
node /abs/path/to/agent-lint/dist/cli.js check [dir] \
  [--agents claude,gemini,cursor,copilot] \
  [--budget 4000] \
  [--no-home | --home <synthetic-or-config-dir>] \
  [--format pretty|json|markdown|sarif] \
  [--fail-on info|low|medium|high] \
  [--baseline <baseline.json>]
```

- Defaults: `[dir] = .`, `--agents claude,gemini,cursor,copilot`, `--budget 4000`, `--no-home`, `--format pretty`, `--fail-on high`.
- **Privacy invariant:** `--no-home` is always the default. Global configs are read only when an explicit `--home <dir>` path is supplied.

### 2. Inspect effective agent load order & token tax (`context`)

```bash
node /abs/path/to/agent-lint/dist/cli.js context [dir] \
  --agent <claude|gemini|cursor|copilot> \
  [--scope <subpath>] \
  [--budget 4000] \
  [--no-home | --home <dir>] \
  [--format pretty|json|markdown]
```

Use `--scope packages/web` in a monorepo to inspect hierarchical ancestor-to-leaf load order (`AGENTS.md` -> `packages/web/AGENTS.md`).

### 3. Explain a rule (`explain`)

```bash
node /abs/path/to/agent-lint/dist/cli.js explain AGL031
```

### Exit Codes

| Exit Code | Meaning |
| --- | --- |
| `0` | Clean — zero unsuppressed findings at or above `--fail-on` |
| `1` | Lint failure — one or more findings at or above `--fail-on` |
| `2` | Usage, configuration, or I/O error |

## v1 Discovery & Per-Agent Load Rules

Token counts are computed via `Math.ceil(chars / 4)` and labelled explicitly as estimates (no heavy tokenizer dependency).

<!-- DISCOVERY_TABLE_START -->
| Agent | Always-Loaded Files (Load Order) | Scoped / Conditional Instructions | On-Demand Skills |
| --- | --- | --- | --- |
| `claude` | `home:.claude/CLAUDE.md` (+ `@path` imports), root `CLAUDE.md` / `.claude/CLAUDE.md` (+ `@path` imports, max depth 5), `CLAUDE.local.md` (+ `@path` imports) | Nested `<subdir>/CLAUDE.md`, `<subdir>/CLAUDE.local.md` | `.claude/skills/**/SKILL.md`, `.agents/skills/**/SKILL.md`, `home:.claude/skills/**/SKILL.md` |
| `gemini` | `home:AGENTS.md`, `home:.gemini/GEMINI.md`, root `AGENTS.md`, root `GEMINI.md` / `.gemini/GEMINI.md` | Hierarchical `<subdir>/AGENTS.md`, `<subdir>/GEMINI.md` | `.gemini/skills/**/SKILL.md`, `.agents/skills/**/SKILL.md`, `home:.gemini/skills/**/SKILL.md` |
| `cursor` | `home:AGENTS.md`, `home:.cursorrules`, root `AGENTS.md`, `.cursorrules`, `.cursor/rules/**/*.mdc` (`alwaysApply: true`) | `.cursor/rules/**/*.mdc` (`alwaysApply !== true` / `globs`), nested `<subdir>/AGENTS.md` | `.agents/skills/**/SKILL.md` |
| `copilot` | `home:AGENTS.md`, `home:.github/copilot-instructions.md`, root `AGENTS.md`, `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md` (`applyTo: "**"` / `"**/*"`) | `.github/instructions/*.instructions.md` (narrow `applyTo` globs), nested `<subdir>/AGENTS.md` | `.agents/skills/**/SKILL.md` |
<!-- DISCOVERY_TABLE_END -->

*(Note: Windsurf `.windsurfrules`, Cline `.clinerules`, Codex-specific discovery, `AGL021`, and `AGL022` are deferred to v1.1.)*

## Rule Reference (v1)

| Rule ID | Default Severity | Category | Summary |
| --- | --- | --- | --- |
| `AGL001` | `medium` / `high` | `budget` | Per-agent always-loaded token estimate exceeds `--budget` (`medium` > 1.0x, `high` > 1.5x). |
| `AGL002` | `low` | `budget` | Single always-loaded file consumes `> 40%` of `--budget`. |
| `AGL010` | `high` | `integrity` | Broken `@import`, local Markdown link, or referenced repo file path (case-exact across all OSes). |
| `AGL011` | `high` | `integrity` | Command in code block/span (`npm`, `pnpm`, `yarn`, `make`, `just`) references a missing script/target. |
| `AGL012` | `high` | `security` | `@import` traversal or symlink/junction target escapes the scan root (`realpathSync` check). |
| `AGL020` | `medium` | `consistency` | Package-manager mandate contradicts repository lockfile or sibling instruction file. |
| `AGL030` | `high` | `security` | Hidden zero-width/BiDi Trojan Source Unicode, concealed HTML comment, `data:` URI, or `>= 128`-char base64 blob. |
| `AGL031` | `high` / `info` | `security` | Dangerous directive (`curl \| sh`, `iex`, `--no-verify`, `"do not tell the user"`, `~/.ssh`, live `.env`). Benign `.env.{example,sample,template,schema,schema.json}` alone emits `info`; mixed `.env.example and .env` stays `high`. |
| `AGL032` | `medium` | `security` | Pasted secret / API token / private key / credentialed URI (redacted as `ab...***REDACTED***`). |
| `AGL040` | `medium` | `skills` | `SKILL.md` frontmatter missing/empty, invalid YAML, `maxAliasCount` exceeded, `__proto__` key, `name !== dir`, or duplicate skill name. |
| `AGL041` | `low` | `rules-config` | Cursor `.mdc` sets both `alwaysApply: true` and `globs`, or `.mdc` / `.instructions.md` globs match zero repo files. |
| `AGL900` | `info` | `limits` | File skipped safely after exceeding the `2 MB` per-file size cap or `2,000`-file scan limit. |

## Combined Context Budget Workflow (`mcp-doctor` + `agent-lint`)

On a synthetic fixture repository (`fixtures/sample-service` with `--no-home`), you can combine MCP tool-schema token tax from `@pie527645-cloud/mcp-doctor` with instruction-file token estimates from `agent-lint` to measure total baseline context overhead before the first user prompt:

```text
Synthetic Fixture: fixtures/sample-service (--no-home)
--------------------------------------------------------------------
1. mcp-doctor inspect (3 stdio MCP tools)     : ~  640 tokens/turn
2. agent-lint context --agent claude          : ~  820 est. tokens (chars/4)
   - CLAUDE.md                                : ~  510 est. tokens (12.8% of 4000)
   - docs/architecture.md [imported]          : ~  310 est. tokens ( 7.8% of 4000)
--------------------------------------------------------------------
Combined pre-turn context footprint           : ~1,460 est. tokens/turn
```

## Baseline Suppression & GitHub Code Scanning (SARIF 2.1.0)

Generate a baseline file from existing findings so CI blocks only newly introduced issues:

```bash
node /abs/path/to/agent-lint/dist/cli.js check . --no-home --format json > .agent-lint-baseline.json
node /abs/path/to/agent-lint/dist/cli.js check . --no-home --baseline .agent-lint-baseline.json --fail-on medium
```

Export SARIF 2.1.0 with stable `partialFingerprints.primaryLocationLineHash` hashes:

```bash
node /abs/path/to/agent-lint/dist/cli.js check . --no-home --format sarif > agent-lint.sarif
```

## Programmatic API

```ts
import { lintWorkspace, inspectAgentContext } from '@pie527645-cloud/agent-lint';

const report = lintWorkspace({
  dir: './fixtures/sample-repo',
  agents: ['claude', 'gemini', 'cursor', 'copilot'],
  budgetTokens: 4000,
  homeDir: null,
});

const claudeCtx = inspectAgentContext({
  dir: './fixtures/sample-repo',
  agent: 'claude',
  homeDir: null,
});
```

## License

MIT
