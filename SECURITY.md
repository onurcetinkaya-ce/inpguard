# Security Policy

## Scope

`inpguard` parses untrusted files. Its entire threat model is the `.inp` parser
and the rules in `inpguard/lint.py`. Anything that makes the tool do something
other than *report a finding and exit* is in scope.

In scope:

- **Parser crashes** on malformed input: `UnicodeDecodeError`, `IndexError`,
  `KeyError`, recursion or memory exhaustion, or any unhandled exception that
  escapes `lint_bytes()`.
- **Unbounded resource use**: inputs that make the tool allocate or run far
  beyond the ceilings declared in `inpguard/spec.py` (`LIMITS`).
- **Report forgery**: input that causes a clean file to be reported as clean
  when it is not, or an error to be silently swallowed. A linter that can be
  made to lie is a linter that fails open.
- **Any code execution path.** There should be none. There is no `eval`, no
  `exec`, no `pickle`, no `subprocess`, and no network access in the package.
  If you find one, that is the highest-severity report possible.
- **CI or supply-chain issues** in `.github/workflows/ci.yml`.

Out of scope:

- EPANET's own behaviour, and hydraulically invalid networks that are
  nonetheless syntactically well-formed. `inpguard` checks representation, not
  hydraulics.
- Findings that require the attacker to already control the invoking user's
  shell, environment, or installed dependencies.
- Denial of service from a file larger than the 64 MiB ceiling in `LIMITS` —
  that is rejected by design before parsing.

## Reporting

**Please do not open a public issue for a security report.**

Use GitHub's private vulnerability reporting:
<https://github.com/onurcetinkaya-ce/inpguard/security/advisories/new>

That channel is private between you and the maintainer until an advisory is
published. If it is unavailable, email the maintainer at the address on the
GitHub profile and say so explicitly in the subject line.

## What to expect

This is a single-maintainer project maintained alongside full-time study. Honest
timelines:

| Stage | Target |
| --- | --- |
| Acknowledgement of your report | 7 days |
| Triage and severity assessment | 14 days |
| Fix or documented mitigation | 90 days for high severity |
| Public advisory, with credit | On release of the fix |

If a fix will take longer than 90 days, you will be told why rather than left
waiting. If you do not receive an acknowledgement within 14 days, treat the
channel as failed and escalate publicly — that is a fair response to silence.

## Credit

Reporters are credited by name or handle in the published advisory and in
`CHANGELOG.md`, unless you ask to remain anonymous. Say which you prefer in
your first message.

## A note on the domain

`inpguard` exists because water utilities exchange `.inp` model files with
consultants, contractors, and between agencies, and those files are opened by
civil engineers — not by people trained to treat input as hostile. If you work
in water infrastructure and have a file that breaks the parser, that report is
valuable even if you would not call it a "security" finding. Send it.