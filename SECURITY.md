# Security & responsible use

supa-scan is a **defensive** tool: a static, pre-deploy security scanner for
Supabase projects. It reads files and reports risky patterns. It does not connect
to a database, execute scanned code, or make any network call at scan time.

## Authorized use

- Run supa-scan against projects you own or are explicitly permitted to review.
- It is read-only by design and changes nothing — the risk surface is what you
  feed it and how you handle its output, not any action it takes.
- In CI, point it at the checked-out (tracked) files. Locally, prefer passing the
  tracked set explicitly (e.g. via `git ls-files`) over scanning a dirty tree that
  may still hold an ignored `.env`.

## Handling findings

- Findings describe patterns, not confirmed exploits, and a Supabase project can
  contain real credentials in its history. Treat scan output as sensitive:
  supa-scan **masks** credential values (it reports the claim and a length, never
  the secret) and neutralizes control/bidi/zero-width characters on output, but
  you should still avoid pasting raw findings into public channels.
- A finding on a committed secret means the secret is already exposed in your
  repo's history — rotate it, don't just delete the line.

## Reporting a vulnerability

If you find a security issue in supa-scan itself, please report it privately
rather than in a public issue: open a GitHub **private security advisory** against
this repository (Security → Report a vulnerability). I aim to acknowledge within a
few days and will coordinate disclosure before publishing details.
