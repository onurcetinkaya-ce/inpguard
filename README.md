# inpguard

Defensive linting for EPANET `.inp` water-network model files.

`inpguard` is a dependency-free Python library and CLI that inspects an EPANET
input file **before** it reaches a hydraulic solver. It reports malformed
structure, dangling cross-references, numeric values that overflow single
precision, embedded control bytes that desynchronise C string handling, and
other input hazards.

It is a *linter*, not a fuzzer and not an exploit. It never executes the file.

## Why this exists

Water utilities exchange `.inp` files constantly — with consultants, with
contractors, between distribution-system teams, and increasingly through
automated pipelines. The format is plain text, section-delimited, and widely
reimplemented in memory-unsafe languages. Most parsers assume the file is
benign because historically it always was.

That assumption is aging badly. Water systems are now an explicit target class,
and the people who steward these models — civil and environmental engineers —
are trained in hydraulics, not in adversarial input handling. The realistic
failure mode isn't a nation-state exploit; it's a subtle malformed file that
silently corrupts a hydraulic model, or a parser that crashes and takes a
modelling session with it.

`inpguard` gives the engineering side a two-second sanity check that speaks in
byte offsets and line numbers rather than stack traces.

## Install

```bash
pip install -e .
```

No runtime dependencies. Python 3.9+.

## Use

```bash
inpguard check network.inp
inpguard check models/*.inp --json
```

```
network.inp: 412 bytes, 34 lines, 6 sections
  ERROR INP032      line 14: link endpoint 'J9' is not a defined node
  WARN  INP022      line 12: value 1e39 in column 4 exceeds float32 range and will overflow to inf on a single-precision parser
  1 error(s), 1 warning(s)
```

Exit codes: `0` clean, `1` error findings, `2` I/O or usage failure.

As a library:

```python
from inpguard import lint_text

report = lint_text(open("network.inp").read())
for finding in report.sorted_findings():
    print(finding)
print(report.ok())
```

## Rule reference

| Code | Severity | Meaning |
|------|----------|---------|
| INP001 | ERROR | File exceeds the 64 MiB ceiling (checked before parsing) |
| INP002 | ERROR | Physical line exceeds 8 KiB |
| INP003 | ERROR | Forbidden control byte (NUL, vertical tab, form feed, etc.) |
| INP004 | ERROR | Line is not valid UTF-8 |
| INP005 | ERROR | Empty or malformed section header |
| INP006 | ERROR | Data before the first section header |
| INP007 | ERROR | Section exceeds its row ceiling |
| INP008 | ERROR | Too many sections |
| INP010 | WARN | Unknown section name |
| INP011 | WARN | Section appears more than once |
| INP012 | WARN | Token exceeds 256 bytes (fixed-buffer hazard) |
| INP013 | WARN | No `[END]` section |
| INP014 | WARN | Cross-reference limit reached; reference findings are a lower bound |
| INP020 | ERROR | Duplicate node/link identifier |
| INP021 | ERROR | Non-finite numeric literal (`nan`, `inf`) |
| INP022 | WARN | Value overflows IEEE-754 single precision |
| INP023 | WARN | Numeric literal uses digit separators (`1_000`) |
| INP030 | WARN | Reference to an undefined pattern |
| INP031 | WARN | Reference to an undefined curve |
| INP032 | ERROR | Link endpoint is not a defined node |

## Design notes

**Line splitting is deliberately narrow.** The file is split on LF and CRLF
only. It does *not* split on `\v`, `\f`, `\x1c`–`\x1e`, `\u2028`, or `\u0085`,
which `str.splitlines()` does honour. If the linter and the target parser
disagree about where a record ends, an attacker can craft a file that reads one
way to the linter and another way to the parser. The corpus contains an
explicit `unicode_line_sep` case asserting this.

**The UTF-8 BOM is stripped, not rejected.** Windows and spreadsheet tooling
emits BOMs routinely. A linter that rejects every such file gets switched off
in production within a week, and a linter that is switched off protects nobody.

**Limits are checked before the work they bound.** An oversized file is
reported and abandoned without walking its body.

**Findings carry byte offsets.** A finding you cannot locate is a finding
nobody acts on.

## Corpus

`inpguard/corpus.py` ships eleven cases: a clean model, a truncated transfer, a
Windows CRLF+BOM export, and adversarial inputs for dangling references,
duplicate identifiers, float32 overflow, NaN/Inf literals, embedded NULs,
Unicode line-separator smuggling, unknown sections, and oversized tokens.

These are not exploits. They are malformed or hostile *inputs* that a parser
should reject or survive. The corpus exists so that the check has something to
fail against, and so that a parser author can reproduce a report.

## Validation

Validated against 17 `.inp` files it did not author, ~37,400 lines in total,
from two independent publishing bodies.

**Nine benchmark distribution networks** — C-Town, d-town, Modena, Jilin, Zhi
Jiang, KL, ky1, ky8, RuralNetwork — sourced from the DiTEC-WDN corpus
(Truong et al., *Scientific Data* 2025): **zero errors, zero warnings**. Sizes
range from 234 to 7,731 lines.

**Eight files from the USEPA/WNTR reference suite**, including the 847 KB
`Net6_plus.inp` benchmark: five lint completely clean; the three that do not are
malformed on purpose and produce exactly one finding each, the one they were
built to contain.

The first run against those files produced 66 false positives and exposed three
real bugs (inline `;` comments, `[PUMPS]`/`[VALVES]` column indexing, repeated
sections). Each is fixed and carries a regression test. Adversarial self-testing
separately found and fixed a resource-amplification bug in this tool.

See `VALIDATION.md` for the full tables, method, and a candid statement of what
a clean result does and does not demonstrate.

## Status

`0.1.0` — alpha. The rule set is deliberately conservative: it flags only what
is unambiguous in the format specification. Rules that would warn on a
legitimate file exported from a common modelling tool are bugs, not features.

Output and memory are bounded: findings are capped per rule code (with the number
of elided occurrences reported, never silently dropped), and cross-reference
checking is capped with an explicit `INP014` rather than growing without limit.
A 3.2 MB adversarial file that once produced 400,002 findings and 287.9 MB peak
RSS now produces 106 findings and 38.7 MB. See `VALIDATION.md`.

## License

MIT.