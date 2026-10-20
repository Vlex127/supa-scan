# supa-scan

A **pre-deploy, CI-friendly static security scanner for Supabase projects**. It
parses a project's SQL migrations with the real PostgreSQL parser (libpg-query,
compiled to WebAssembly), replays those migrations **in order** to build the
final schema state, then runs a fixed allowlist of security rules over that state
and emits **structured findings**.

The point is **timing and surface**. Supabase already ships a database
**Security Advisor** that flags several of these issues on a *live* database.
supa-scan instead runs **before deploy, in CI, against source and migrations** —
and catches things a live-DB linter cannot see, such as a `service_role` key baked
into a client bundle or a Supabase secret committed to the repo.

## Status

The scanner **engine** and **CLI** are implemented and tested: an ordered
schema-state builder from a real AST, seven rules (five SQL, two source/env),
JSON and SARIF output, deterministic and hostile-input-safe file collection, and
CI exit codes. A client-side demo UI is the next milestone.

## What it checks (v1)

| Rule | Severity | Detects |
| --- | --- | --- |
| `RLS_DISABLED` | high | A `public` (or unqualified) table with no `ENABLE ROW LEVEL SECURITY`. |
| `POLICY_PERMISSIVE` | high / medium | A **write** policy whose `USING`/`WITH CHECK` is the constant `true`. High when granted to `anon`/`PUBLIC`, medium when authenticated-only. A `true` predicate on a *read-only* policy is treated as legitimate public reference data and is **not** flagged. |
| `POLICY_ANON_WRITE` | high | A write policy (`INSERT`/`UPDATE`/`DELETE`/`ALL`) reachable by `anon` or `PUBLIC`. |
| `VIEW_NO_SECURITY_INVOKER` | medium | A view created without `security_invoker` (runs as its owner, bypassing the base table's RLS). |
| `SECDEF_NO_SEARCH_PATH` | high | A `SECURITY DEFINER` function without a fixed `search_path` (hijackable via a shadowing object). |
| `KEY_SERVICE_ROLE_CLIENT` | **critical** / high | A `service_role` credential in client-reachable code: a `NEXT_PUBLIC_*` name mentioning `SERVICE_ROLE`/`SECRET` (high), a service-role reference inside a `"use client"` module (high), or a JWT literal whose **decoded payload** asserts `role: service_role` (critical). |
| `SECRET_COMMITTED` | high | Supabase-specific committed secrets: an `sb_secret_*`/`sbp_*` key, a PEM private-key block, or a service-role JWT in a `.env` file **or `.env` template**; plus a key-like assignment in a **real** `.env` (templates skip that generic check so placeholders stay quiet). Evidence is **masked** — never the secret. |

The `critical` tier is reserved for a confirmed `service_role` credential in client
code (a full RLS bypass). Severity order is `critical > high > medium > low > info`.

The five SQL rules run on the parsed, ordered schema state. The two source rules
run on raw **text** (`.ts`/`.tsx`/`.js`/`.jsx`/`.mjs`/`.cjs`/`.json` and `.env*`)
and scope themselves; they decode JWT payloads with the standard `atob` +
`TextDecoder` globals (present in Node 20+ and the browser) and **never** verify
signatures (a leaked key is dangerous whatever its signature). Long lines are
scanned in **overlapping chunks** rather than skipped, so a credential can't hide
past an arbitrary cut. The `anon` key is the public, logged-out role and is never
flagged — `sb_publishable_*` and a `role: anon` payload are expected.

Rules are a fixed allowlist of pure functions. There is no `eval`, no dynamic
dispatch of scanned content, and no network access at scan time.

## Usage

Build the CLI once, then run it against a project directory:

```bash
pnpm build:cli
node dist/cli/bin.js [scan] [options] [root]

node dist/cli/bin.js                      # scan the current dir, JSON to stdout
node dist/cli/bin.js --format sarif .     # SARIF 2.1.0 for GitHub code scanning
node dist/cli/bin.js --fail-on high .     # exit 1 only on high-or-worse findings
node dist/cli/bin.js --help               # full help
```

Exit codes: **0** clean (no finding at or above `--fail-on`), **1** one or more
findings at or above the gate, **2** usage error, tool error, **or an incomplete
scan**. Incomplete outranks findings: if a scannable file was skipped (oversized,
over count, a symlink we don't follow, or unreadable) or a file failed to parse,
the scan is `complete: false`, surfaces in SARIF via
`invocations[].toolExecutionNotifications` with `executionSuccessful: false`, and
exits 2 rather than reporting a false-clean pass.

## Scope, secrets, and what "committed" means

The scanner reports on **the files it is given**. It reads only the working
directory you point it at — it runs no git, opens no database, and reaches no
network. In CI, where a checkout contains only tracked files, "the files it is
given" equals "the committed files." To restrict a local run to tracked files,
pass them explicitly (e.g. via `git ls-files -z`) rather than scanning a dirty
tree that still holds an ignored `.env`.

`SECRET_COMMITTED` targets **Supabase-specific credential formats** (service-role
JWTs, `sb_secret_*`/`sbp_*` keys, `.env` assignments) because a Supabase scanner
should catch the keys that bypass its RLS. It is **not** a general secret scanner —
for the broad case (AWS keys, GitHub tokens, arbitrary passwords) run **gitleaks**
or rely on GitHub's push protection alongside supa-scan.

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
- **Release age gate (off, revisit 2026-10-29).** `minimumReleaseAge` was evaluated
  as a first-moment supply-chain guard and **tested against a clean checkout**:
  with `minimumReleaseAge: 20160` (14 days) and `minimumReleaseAgeExclude` for
  `next`, `@next/*`, and `electron-to-chromium`, `pnpm install` still fails with
  `ERR_PNPM_MINIMUM_RELEASE_AGE_VIOLATION` on **42 lockfile entries** — not the
  excluded ones but the transitive build toolchain Next pulls in: `@babel/*`,
  `@rolldown/*` (1.2.14, published 2026-10-14), `@oxc-project/*`, and
  `@typescript-eslint/*` (8.71.2). Exempting those is the bulk of the dev tree,
  which defeats the gate, so the policy is **left off** rather than ship a config
  that breaks `pnpm install` from a clean checkout. **Reminder:** re-enable it on or
  after **2026-10-29**, once these pins age past the 14-day window; until then the
  exact-pins + committed-lockfile + `--ignore-scripts` posture above is the guard.

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
  (e.g. a newer grammar than libpg-query supports) is reported as a `PARSE_FAILED`
  entry — its file, the line at the parser's cursor, and a **fixed category**
  (`syntax_error`, `unterminated_string`, …) — and the scan is marked **incomplete**;
  the scanner will not certify input it could not analyze. The parser's own message
  is never carried: Postgres interpolates the offending token (an unterminated string
  echoes its contents), so a raw message could surface attacker text or a credential
  sitting in broken SQL.
- **Not a replacement for RLS itself or the Security Advisor.** Enabling RLS on a
  table with no policies denies access by default (safe but possibly broken);
  correct policies still need authoring. Use supa-scan in CI **alongside** the
  live Security Advisor.
- **Only scannable files are read.** The collector reads `.sql`, source
  (`.ts`/`.tsx`/`.js`/`.jsx`/`.mjs`/`.cjs`), `.json` config, and `.env*` **including
  `.env.example`-style templates** (a template can still hold a real credential), and
  it **excludes vendored and generated files** — `node_modules`/`vendor` dirs,
  lockfiles, `*.min.js`, and source maps — which never count toward a scan. It sizes
  each read file (default 1 MiB) and caps the file count (default 5000); a skipped
  **scannable** file marks the scan incomplete rather than passing silently.
- **Secrets are masked, never echoed.** The source rules report the claim
  (`role: service_role`, the matched format, the variable name) and a **length**;
  the credential value is never placed in evidence, JSON, or SARIF. Control and
  bidirectional/zero-width characters in scanned text are neutralized on output so
  attacker-controlled strings cannot spoof a terminal or reorder displayed code.
- **Long lines are chunk-scanned, not skipped.** A source line longer than the chunk
  window (8192 chars) is scanned in overlapping windows (4096-char overlap), so no
  line is silently skipped and any credential no longer than the overlap is always
  covered whole in some window. Real Supabase secrets and JWTs are far shorter than
  that; only a >8 KB token could in principle straddle a window — not a credible
  credential.

## Development

Requires Node.js 20+.

```bash
pnpm install --frozen-lockfile   # install from the committed lockfile
pnpm test                        # run the engine + CLI test suite
pnpm typecheck                   # tsc --noEmit
pnpm lint                        # eslint
pnpm build:cli                   # compile the CLI to dist/ (CommonJS)
node dist/cli/bin.js fixtures/insecure   # scan a sample project (exit 1)
pnpm build                       # next build
```

## License

Released under the [MIT License](LICENSE). See [SECURITY.md](SECURITY.md) for the
authorized-use policy and how to report a vulnerability.

## About this build

This project was built with **AI-assisted development**: an AI pair-programmed
the modules, tests, and docs alongside me, and where AI assistance was used the
commit carries a `Co-Authored-By` trailer. The design decisions, security
posture, and trust boundaries are mine to explain and defend — the value here is
the architecture and the verification, not the keystrokes.
