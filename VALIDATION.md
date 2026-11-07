# Validation against real-world models

A linter is only worth its false-positive rate. This document records what
`inpguard` does on `.inp` files it did not author — and what running it against
those files found.

Two corpora were used, both downloaded unmodified:

1. **USEPA/WNTR test suite** (`wntr/tests/networks_for_testing/`) — the
   reference Python toolkit for EPANET, shipping models used in published
   water-security research. Small hand-built networks plus benchmarks.
2. **DiTEC-WDN** (Truong, Tello, Lazovik & Degeler, *Scientific Data* 12:1733,
   2025; doi:10.1038/s41597-025-06026-0) publishes the source `.inp` files it
   used for optimisation, at
   `DiTEC-project/DiTEC_WDN_dataset/ditec_wdn_dataset/inputs/public`. These are
   benchmark distribution networks drawn from the water-distribution research
   literature — C-Town, d-town, Modena, Jilin, Zhi Jiang, KL, two Kentucky
   systems and Marchi's rural network — of the size a utility actually operates.

   A precision note, because it bears on how much the numbers below are worth:
   DiTEC republishes the *source topology* `.inp` files, not utility export
   files. The project states that hydraulically sensitive values in its derived
   dataset were discarded and re-synthesised. The `.inp` files validated here
   are the originals used as optimisation input, and are the same networks
   circulated in the research literature. They are realistic and independently
   authored; they are not confidential utility exports, and this document does
   not claim they are.

Neither corpus is redistributed here. The root `.gitignore` excludes both —
`realworld/` is download-only, so a clone contains no third-party files.

```
# USEPA/WNTR
curl -sSLO https://raw.githubusercontent.com/USEPA/WNTR/main/wntr/tests/networks_for_testing/<file>

# DiTEC
curl -sSLO https://raw.githubusercontent.com/DiTEC-project/DiTEC_WDN_dataset/main/ditec_wdn_dataset/inputs/public/<file>

inpguard check realworld/**/*.inp
```

## Results — USEPA/WNTR suite

| File | Size | Lines | Errors | Warnings |
|------|------|-------|--------|----------|
| `Anytown.inp` | 12,867 B | 251 | 0 | 0 |
| `latin1.inp` | 6,070 B | 179 | 0 | 0 |
| `Net6_plus.inp` | 847,192 B | 11,226 | 0 | 0 |
| `simulator.inp` | 16,114 B | 462 | 0 | 0 |
| `bad_times.inp` | 15,659 B | 462 | 0 | 0 |
| `bad_syntax.inp` | 15,686 B | 463 | 0 | 1 |
| `io.inp` | 2,848 B | 134 | 0 | 1 |
| `bad_values.inp` | 15,648 B | 461 | 1 | 0 |

Five of the eight lint completely clean. The three that do not are each
malformed on purpose, and each produces exactly one finding — the one it was
built to contain. `Net6_plus.inp` is the largest published EPANET benchmark in
that suite and lints in well under a second.

## Results — DiTEC networks

| Network | Size | Lines | Sections | Errors | Warnings |
|---------|------|-------|----------|--------|----------|
| `CTOWN.INP` | 116,999 B | 1,650 | 29 | 0 | 0 |
| `modena.inp` | 70,837 B | 983 | 29 | 0 | 0 |
| `d-town.inp` | 125,797 B | 2,052 | 29 | 0 | 0 |
| `Jilin.inp` | 9,936 B | 234 | 29 | 0 | 0 |
| `ZJ.inp` | 37,530 B | 634 | 29 | 0 | 0 |
| `KL.inp` | 413,102 B | 6,256 | 29 | 0 | 0 |
| `ky1.inp` | 215,227 B | 2,829 | 29 | 0 | 0 |
| `ky8.inp` | 511,418 B | 7,731 | 29 | 0 | 0 |
| `RuralNetwork.inp` | 101,820 B | 1,395 | 29 | 0 | 0 |

**Zero errors and zero warnings across all nine.** Every one reports the same
single `INFO`: `[REACTIONS]` appears more than once, which EPANET accumulates
by design and which the linter therefore must not treat as a defect.

This is the result that matters. Nine independently authored networks, a 33×
spread in size (234 to 7,731 lines), and the linter is silent on all of them. A
linter that flagged any of these would be uninstalled before it was ever run in
CI. Total runtime for all nine is under a second.

The honest reading of a clean result is narrow: it bounds the false-positive
rate, it does not demonstrate detection power. Detection is covered by the
hand-built corpus in `inpguard/corpus.py` and by the three deliberately
malformed EPA files above.

## What this exercise found

### Three false positives in `inpguard`

The first run against the USEPA files produced **66 errors on `Net6_plus.inp`
alone**, all false positives. Three genuine bugs:

1. **Inline `;` comments were not stripped.** EPANET treats `;` as a comment
   introducer anywhere on a line, and real exports pad optional columns with a
   trailing `;`. The linter was reading that as an identifier, inventing a
   pattern literally named `;`. Fixed; regression test
   `test_inline_semicolon_comment_not_an_identifier`.

2. **`[PUMPS]` and `[VALVES]` columns were misindexed.** Both formats are
   `ID, Node1, Node2, parameters`. The linter read columns 2 and 3, so the
   parameter keywords `HEAD` and `POWER` were reported as undefined nodes.
   Fixed; regression tests `test_pump_parameters_not_read_as_nodes` and
   `test_valve_parameters_not_read_as_nodes`.

3. **Repeated sections were flagged as warnings.** EPANET *accumulates* a
   repeated section rather than rejecting it, and EPA's own networks repeat
   `[REACTIONS]`, `[DEMANDS]` and `[TAGS]`. Downgraded to `INFO`. Regression
   test `test_duplicate_section_is_info_only`.

Note what these three have in common: every one was the linter being stricter
than the format. That is the dominant failure mode for a checker like this, and
it is why the validation corpus exists.

### One denial of service in `inpguard` itself

`inpguard` exists to stop a malformed `.inp` from exhausting a parser. It was
doing that itself.

A 3.2 MB file — `[JUNCTIONS]` followed by 200,000 identical rows — produced:

| Metric | Before | After |
|--------|--------|-------|
| Peak RSS | 287.9 MB | 38.7 MB |
| RSS relative to input size | ~90× | ~12× |
| Output lines | 400,002 | 106 |

Two independent causes:

- **Unbounded findings.** Every duplicate identifier emitted a `Finding`. A file
  engineered to repeat one bad row produced 400k findings. Findings are now
  capped per-code (`LIMITS["findings_per_code"]`), and the count of elided
  occurrences is reported rather than silently dropped, so a reader can still
  tell "one bad row" from "two million bad rows". The cap is per-code so one
  noisy rule cannot crowd a different, more serious finding out of the report
  (`test_cap_does_not_hide_other_codes`).

- **Retained rows.** The parser buffered every tokenised row into
  `Section.data`, which nothing read. Removed; all checks run streaming off the
  token list. Pending cross-references are also capped in aggregate
  (`LIMITS["refs"]`), with an explicit `INP014` warning when reference checking
  is truncated — a lower bound is stated as a lower bound, never implied to be
  complete.

This bug was found by adversarial self-testing, not by the corpora. It is
recorded here because a security tool that cannot survive its own input domain
is not a security tool.

Six regression tests lock the behaviour in (`AmplificationTests`).

Scope of that claim, stated plainly: this was a resource-consumption bug in this
project's own code, found by its own author, and fixed before release. It is not
a vulnerability in EPANET, in WNTR, or in any third-party product, and no
disclosure process was involved.

## The two remaining warnings are correct

- `bad_syntax.inp` contains a `[FOO]` section — that is the defect the file
  exists to test.
- `io.inp` references `CURVE1` without defining it — likewise deliberate.

`bad_values.inp` produces one error: a link endpoint named `node1` that is
never defined. That is the file's purpose.

## Honest limits

This is a format-conformance and input-hygiene linter. It does **not**:

- prove a file is safe for any particular parser;
- detect memory-safety bugs in a parser (that needs a fuzzer and a sanitizer);
- model hydraulics, so it cannot tell you a network is *wrong*, only that it is
  malformed;
- cover the full EPANET grammar — `[RULES]`, `[CONTROLS]` and `[ENERGY]`
  semantics are parsed structurally but not validated.

The corpus in `inpguard/corpus.py` is hand-built and small. It is a starting
point for a parser author, not a conformance suite.

Coverage is 17 files from 2 independent publishing bodies, totalling ~2.5 MB and
~37,400 lines. That is a credible sample, not a census: a full utility dataset
would run to thousands of networks, and would very likely find rules that need
relaxing. Anyone deploying this on a large corpus should expect to tune it, and
should treat a first-run finding on an unfamiliar file as a question to ask of
the file, not a verdict.
