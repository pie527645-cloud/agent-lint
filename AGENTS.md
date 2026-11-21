# Repository Instructions (`@pie527645-cloud/agent-lint`)

## Build & Verification Commands

Always use `npm` matching `package-lock.json`:

```bash
npm ci
npm run lint
npm run build
npm test
```

## Architecture & Key Paths

- Public API entrypoint: [src/index.ts](src/index.ts)
- CLI entrypoint: [src/cli.ts](src/cli.ts)
- File discovery & `@path` import resolver: [src/discovery.ts](src/discovery.ts)
- Static rule analyzers (`AGL001`-`AGL041`, `AGL900`): [src/analyzers.ts](src/analyzers.ts)
- Safe case-exact filesystem containment: [src/fs-safe.ts](src/fs-safe.ts)
- Documentation & discovery matrix: [README.md](README.md)

## Security & Privacy Rules

- Never import or invoke home-directory auto-detection; `--no-home` is the strict default.
- Never execute commands parsed from scanned Markdown or YAML files.
- Keep all path checks confined inside `realpathSync` root boundaries.
