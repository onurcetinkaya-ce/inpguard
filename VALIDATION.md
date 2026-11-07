# Validation against real-world models

A linter is only worth its false-positive rate. This document records what
`inpguard` does on `.inp` files it did not author.

## Method

Files were downloaded unmodified from the USEPA/WNTR test suite
(`wntr/tests/networks_for_testing/`), which is the reference Python toolkit for
EPANET and ships models used in published water-security research. They are not
redistributed in this repository; `realworld/.gitignore` excludes them.

```
curl -sSLO https://raw.githubusercontent.com/USEPA/WNTR/main/wntr/tests/networks_for_testing/<file>
inpguard check realworld/*.inp
```

## Results

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

`Net6_plus.inp` is the largest published EPANET benchmark in the suite and
lints in well under a second.

## What this exercise found

The first run against these files produced **66 errors on `Net6_plus.inp`
alone**, all false positives. Three genuine bugs in `inpguard`:

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

The two remaining warnings are correct and intentional:

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
