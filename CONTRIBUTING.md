# Contributing

Thanks for looking. This is a small, security-sensitive library, so the bar for
changes is deliberately high.

## Ground rules

- The crypto surface is intentionally minimal. New primitives or protocol
  changes need a written rationale in the PR, not just code.
- Every change ships with a test. Bug fixes ship with a test that fails before
  the fix and passes after.
- Wire format is versioned (`OCX1`). Any change to bytes on the wire is a new
  version, never a silent edit to the current one.
- No new runtime dependencies without a strong reason. Today the only runtime
  deps are the four `@noble` packages.

## Local setup

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # 20 adversarial tests
npm run build       # tsup -> ESM + CJS + d.ts
node examples/demo.mjs
```

All four must be green before you open a PR. CI runs the same on Node 18, 20,
and 22.

## Reporting a vulnerability

Do not open a public issue for security problems. See [SECURITY.md](./SECURITY.md).
