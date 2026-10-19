# supa-scan

A **pre-deploy, CI-friendly static security scanner for Supabase projects**. It
parses a project's SQL migrations with the real PostgreSQL parser (libpg-query,
compiled to WebAssembly), replays those migrations **in order** to build the
final schema state, then runs a fixed allowlist of security rules over that state
and emits **structured findings**.

The point is **timing and surface**. Supabase already ships a database
**Security Advisor** that flags several of these issues on a *live* database.
supa-scan instead runs **before deploy, in CI, against source and migrations** —
and will also catch things a live-DB linter cannot see, such as a `service_role`
key baked into a client bundle or a secret committed to the repo.

## Status

The scanner **engine** is implemented and tested: an ordered schema-state builder
from a real AST, plus the five v1 SQL rules below. The **CLI** (JSON + SARIF
output, exit codes, and project file collection) is the next milestone, followed
by the key/secret rules and a client-side demo UI. Usage examples are added once
the CLI lands.

## What it checks (v1)

| Rule | Severity | Detects |
| --- | --- | --- |
| `RLS_DISABLED` | high | A `public` (or unqualified) table with no `ENABLE ROW LEVEL SECURITY`. |
| `POLICY_PERMISSIVE` | high / medium | A **write** policy whose `USING`/`WITH CHECK` is the constant `true`. High when granted to `anon`/`PUBLIC`, medium when authenticated-only. A `true` predicate on a *read-only* policy is treated as legitimate public reference data and is **not** flagged. |
| `POLICY_ANON_WRITE` | high | A write policy (`INSERT`/`UPDATE`/`DELETE`/`ALL`) reachable by `anon` or `PUBLIC`. |
| `VIEW_NO_SECURITY_INVOKER` | medium | A view created without `security_invoker` (runs as its owner, bypassing the base table's RLS). |
| `SECDEF_NO_SEARCH_PATH` | high | A `SECURITY DEFINER` function without a fixed `search_path` (hijackable via a shadowing object). |

Planned next: `KEY_SERVICE_ROLE_CLIENT` (incl. a JWT-payload check) and
`SECRET_COMMITTED` (masked evidence). Deferred as needing data-flow analysis.

Rules are a fixed allowlist of pure functions. There is no `eval`, no dynamic
dispatch of scanned content, and no network access at scan time.

## Supply chain

- **Exact pins.** Direct dependencies are pinned to exact versions (no ranges).
- **Committed lockfile.** `pnpm-lock.yaml` is checked in; CI installs with
  `pnpm install --frozen-lockfile`.
- **No dependency build scripts.** `pnpm-workspace.yaml` sets `allowBuilds` to
  `false` for the only packages that would run install-time scripts (`sharp`,
  `unrs-resolver`), and installs are run with `--ignore-scripts`.
- **Vetted additions.** New packages are checked (publisher, release history,
  install scripts, download count) before they are added. `libpg-query` was
  chosen because it is Postgres' own parser compiled to WASM with no install-time
  build step.
- **Audit status.** `pnpm audit --prod` is **clean** — the shipped/runtime
  dependency graph has no known vulnerabilities. The one advisory in the full
  tree is `braces <=3.0.3` (a stack-exhaustion DoS) reached only through
  `eslint-config-next → … → micromatch → braces`, a **dev-only linting**
  dependency that is not on the scanner's runtime or scan path. There is **no
  patched release** of `braces` (3.0.3 is the latest), so no override is
  possible; it is tracked here and re-audited on each dependency bump.
- **Release age gate (off).** A `minimumReleaseAge` delay was evaluated as a
  first-moment supply-chain guard. pnpm's `minimumReleaseAgeExclude` works
  (including `@next/*` scoping), but on a freshly adopted Next.js 16.4.2 the
  14-day window also falls over the whole build toolchain (`@babel/*`,
  `@rolldown/*`, `@oxc-project/*`, `@typescript-eslint/*`, and more), so passing
  it would mean exempting the bulk of the tree — which defeats the gate. The age
  policy is therefore **left off** rather than ship a config that breaks
  `pnpm install` on a clean checkout, and is to be revisited once the pinned
  Next.js release ages past the target window.

## Limitations

- **Static analysis only.** supa-scan reads source; it never connects to or
  inspects a database, executes code, or runs queries. It flags risky *patterns*,
  not confirmed runtime exploits.
- **What counts as schema state.** Findings are derived from migration and
  declarative-schema SQL (Supabase's `supabase/migrations/*.sql`, applied in
  path/timestamp order). **Seed files (`supabase/seed.sql`) are excluded** — they
  carry data, not schema.
- **Dashboard and out-of-band changes are invisible.** Any change made in the
  Supabase dashboard, applied directly to a live database, or kept outside the
  migration paths above is not seen by a static scan. A clean result means "the
  scanned files look correct," not "the deployed database is safe."
- **Unparseable files are never silently skipped.** A file the parser cannot read
  (e.g. a newer grammar than libpg-query supports) is reported as a
  `PARSE_FAILED` entry and the scan is marked **incomplete** — the scanner will
  not certify input it could not analyze.
- **Not a replacement for RLS itself or the Security Advisor.** Enabling RLS on a
  table with no policies denies access by default (safe but possibly broken);
  correct policies still need authoring. Use supa-scan in CI **alongside** the
  live Security Advisor.

## Development

Requires Node.js 20+.

```bash
pnpm install --frozen-lockfile   # install from the committed lockfile
pnpm test                        # run the engine test suite
pnpm typecheck                   # tsc --noEmit
pnpm lint                        # eslint
pnpm build                       # next build
```

## License

MIT
