"""End-to-end tests over the corpus, plus targeted unit tests for each rule.

These assertions are the contract. If a rule changes, a test changes first.
"""

from __future__ import annotations

import unittest

from inpguard import ERROR, WARN, lint_bytes, lint_text
from inpguard.corpus import CASES, CLEAN, get
from inpguard.lint import lint_bytes as _lint
from inpguard.spec import LIMITS


class CorpusTests(unittest.TestCase):
    def test_every_corpus_case(self) -> None:
        for case in CASES:
            with self.subTest(case=case.name):
                report = lint_text(case.data)
                codes = {f.code for f in report.findings}
                self.assertTrue(
                    case.expect_codes.issubset(codes),
                    f"{case.name}: expected {sorted(case.expect_codes)}, got {sorted(codes)}",
                )
                self.assertEqual(
                    report.ok(),
                    case.expect_ok,
                    f"{case.name}: expected ok={case.expect_ok}, "
                    f"errors={[str(e) for e in report.errors]}",
                )

    def test_clean_file_has_no_findings(self) -> None:
        report = lint_text(CLEAN)
        self.assertTrue(report.ok())
        self.assertEqual(report.findings, [], [str(f) for f in report.findings])


class LineSplittingTests(unittest.TestCase):
    def test_unicode_line_separator_is_not_a_line_break(self) -> None:
        """U+2028 must stay inside one line so linter and parser agree."""
        report = lint_text(get("unicode_line_sep").data)
        self.assertEqual(report.ok(), True)
        # J2 must not have been registered as a separate junction row.
        junction_rows = [s for s in report.sections if s.name == "JUNCTIONS"]
        self.assertEqual(len(junction_rows), 1)
        self.assertEqual(junction_rows[0].rows, 1)

    def test_crlf_and_bom_tolerated(self) -> None:
        report = lint_text(get("crlf_bom").data)
        self.assertTrue(report.ok(), [str(f) for f in report.findings])


class LimitTests(unittest.TestCase):
    def test_oversized_file_short_circuits(self) -> None:
        raw = b"[JUNCTIONS]\n" + b" " * (LIMITS["file_bytes"] + 1)
        report = lint_bytes(raw)
        self.assertFalse(report.ok())
        self.assertIn("INP001", {f.code for f in report.findings})
        # Must not have walked the body.
        self.assertEqual(report.sections, [])

    def test_oversized_line_reported(self) -> None:
        raw = b"[JUNCTIONS]\n" + b"A" * (LIMITS["line_bytes"] + 1) + b"\n[END]\n"
        report = lint_bytes(raw)
        self.assertIn("INP002", {f.code for f in report.findings})

    def test_oversized_token_reported_but_not_fatal(self) -> None:
        report = lint_text(get("long_token").data)
        self.assertIn("INP012", {f.code for f in report.findings})
        self.assertTrue(report.ok())


class ControlByteTests(unittest.TestCase):
    def test_nul_rejected(self) -> None:
        report = lint_bytes(b"[JUNCTIONS]\n J1\x0010.0 5.0\n[END]\n")
        self.assertIn("INP003", {f.code for f in report.findings})
        self.assertFalse(report.ok())

    def test_tab_and_newline_allowed(self) -> None:
        report = lint_bytes(b"[JUNCTIONS]\n\tJ1\t10.0\t5.0\n[END]\n")
        self.assertTrue(report.ok(), [str(f) for f in report.findings])

    def test_invalid_utf8_rejected(self) -> None:
        report = lint_bytes(b"[JUNCTIONS]\n \xff\xfe 10.0 5.0\n[END]\n")
        self.assertIn("INP004", {f.code for f in report.findings})


class NumericTests(unittest.TestCase):
    def test_nan_and_inf_rejected(self) -> None:
        report = lint_text("[JUNCTIONS]\n J1 nan 5.0\n[END]\n")
        self.assertIn("INP021", {f.code for f in report.findings})
        self.assertFalse(report.ok())

    def test_float32_overflow_warned(self) -> None:
        report = lint_text("[JUNCTIONS]\n J1 1e40 5.0\n[END]\n")
        self.assertIn("INP022", {f.code for f in report.findings})
        self.assertTrue(report.ok())

    def test_digit_separator_flagged(self) -> None:
        report = lint_text("[JUNCTIONS]\n J1 1_000.0 5.0\n[END]\n")
        self.assertIn("INP023", {f.code for f in report.findings})

    def test_float_ceiling_override(self) -> None:
        report = lint_bytes(b"[JUNCTIONS]\n J1 1e10 5.0\n[END]\n", float_ceiling=1e9)
        self.assertIn("INP022", {f.code for f in report.findings})


class StructureTests(unittest.TestCase):
    def test_data_before_section_rejected(self) -> None:
        report = lint_text(" J1 10.0 5.0\n[JUNCTIONS]\n[END]\n")
        self.assertIn("INP006", {f.code for f in report.findings})
        self.assertFalse(report.ok())

    def test_empty_section_header_rejected(self) -> None:
        report = lint_text("[]\n[JUNCTIONS]\n[END]\n")
        self.assertIn("INP005", {f.code for f in report.findings})

    def test_duplicate_section_is_info_only(self) -> None:
        """EPA's own test networks repeat [REACTIONS]; they must lint clean."""
        report = lint_text("[JUNCTIONS]\n J1 1.0 1.0\n[JUNCTIONS]\n J2 2.0 2.0\n[END]\n")
        self.assertIn("INP011", {f.code for f in report.findings})
        self.assertNotIn("INP011", {f.code for f in report.warnings})
        self.assertTrue(report.ok())

    def test_missing_end_warned(self) -> None:
        report = lint_text("[JUNCTIONS]\n J1 1.0 1.0\n")
        self.assertIn("INP013", {f.code for f in report.findings})
        self.assertTrue(report.ok())

    def test_unknown_section_warned_not_fatal(self) -> None:
        report = lint_text("[JUNCTIONS]\n J1 1.0 1.0\n[ZORP]\n a b\n[END]\n")
        self.assertIn("INP010", {f.code for f in report.findings})
        self.assertTrue(report.ok())


class ReferenceTests(unittest.TestCase):
    def test_undefined_pattern_warned(self) -> None:
        report = lint_text(
            "[JUNCTIONS]\n J1 10.0 5.0 P9\n[PATTERNS]\n P1 1.0\n[END]\n"
        )
        self.assertIn("INP030", {f.code for f in report.findings})

    def test_defined_pattern_no_warning(self) -> None:
        report = lint_text(
            "[JUNCTIONS]\n J1 10.0 5.0 P1\n[PATTERNS]\n P1 1.0\n[END]\n"
        )
        self.assertNotIn("INP030", {f.code for f in report.findings})

    def test_undefined_curve_warned(self) -> None:
        report = lint_text(
            "[RESERVOIRS]\n R1 55.0\n[JUNCTIONS]\n J1 10.0 1.0\n"
            "[PUMPS]\n PU1 R1 J1 HEAD C9\n[END]\n"
        )
        self.assertIn("INP031", {f.code for f in report.findings})

    def test_references_can_be_disabled(self) -> None:
        report = lint_bytes(
            b"[PIPES]\n P1 R1 J9 1.0 1.0 1.0 0 Open\n[END]\n",
            strict_references=False,
        )
        self.assertNotIn("INP032", {f.code for f in report.findings})


class RealWorldRegressionTests(unittest.TestCase):
    """Bugs found by linting USEPA/WNTR's own test networks.

    Each of these produced a false positive on a legitimate file. Kept as
    regression tests because a linter that cries wolf gets uninstalled.
    """

    def test_inline_semicolon_comment_not_an_identifier(self) -> None:
        # Anytown.inp and latin1.inp pad optional columns with a trailing ';'.
        # Treating it as an id invented a phantom pattern named ';'.
        report = lint_text(
            "[JUNCTIONS]\n J1 710 0 ;\n"
            "[PATTERNS]\n P1 1.0\n[END]\n"
        )
        self.assertNotIn("INP030", {f.code for f in report.findings})

    def test_pump_parameters_not_read_as_nodes(self) -> None:
        # PUMPS rows are ID, Node1, Node2, params. Reading columns 2 and 3
        # made 'HEAD' and 'POWER' look like undefined nodes.
        report = lint_text(
            "[RESERVOIRS]\n R1 55.0\n[JUNCTIONS]\n J1 10.0 1.0\n"
            "[PUMPS]\n PU1 R1 J1 HEAD C1\n"
            "[CURVES]\n C1 1.0 1.0\n[END]\n"
        )
        self.assertNotIn("INP032", {f.code for f in report.findings})

    def test_valve_parameters_not_read_as_nodes(self) -> None:
        report = lint_text(
            "[RESERVOIRS]\n R1 55.0\n[JUNCTIONS]\n J1 10.0 1.0\n"
            "[VALVES]\n V1 R1 J1 300 PRV 0 0\n[END]\n"
        )
        self.assertNotIn("INP032", {f.code for f in report.findings})

    def test_anytown_shaped_file_is_clean(self) -> None:
        """A condensed version of the real Anytown layout must produce zero findings."""
        report = lint_text(
            "[JUNCTIONS]\n 10 710 0 ;\n 11 710 150 ;\n"
            "[RESERVOIRS]\n 40 800\n"
            "[PUMPS]\n 78 40 10 HEAD 2 PATTERN 2 ;\n"
            "[PATTERNS]\n 2 1.0\n[REACTIONS]\n 10 1.0\n[REACTIONS]\n 11 1.0\n"
            "[END]\n"
        )
        self.assertTrue(report.ok(), [str(f) for f in report.findings])


class AmplificationTests(unittest.TestCase):
    """The linter must not be turned into the thing it defends against.

    Found by feeding inpguard a 3 MB file of repeated identical rows. It
    produced 400,002 findings and peaked at 288 MB RSS -- a denial of service
    in the tool whose entire purpose is preventing one. Both are capped now.
    """

    def test_findings_are_capped_per_code(self) -> None:
        raw = b"[JUNCTIONS]\n" + b"a b c d e f g h\n" * 5000 + b"[END]\n"
        report = lint_bytes(raw)
        cap = LIMITS["findings_per_code"]
        dupes = [f for f in report.findings if f.code == "INP020"]
        self.assertEqual(len(dupes), cap)
        # The elisions must be counted, not silently swallowed.
        self.assertIn("INP020", report.suppressed)
        self.assertEqual(report.suppressed["INP020"], 5000 - 1 - cap)

    def test_cap_does_not_hide_other_codes(self) -> None:
        """One noisy rule must not crowd a different finding out of the report."""
        raw = (
            b"[JUNCTIONS]\n"
            + b"a b c d e f g h\n" * 200
            + b"[PIPES]\n P1 NOPE1 NOPE2 1 1 1 1 Open\n"
            + b"[END]\n"
        )
        report = lint_bytes(raw)
        codes = {f.code for f in report.findings}
        self.assertIn("INP020", codes)
        self.assertIn("INP032", codes)

    def test_clean_file_not_truncated(self) -> None:
        report = lint_text(CLEAN)
        self.assertEqual(report.suppressed, {})

    def test_reference_buckets_bounded(self) -> None:
        """A file with more refs than the cap must warn, not grow unbounded."""
        rows = b"".join(
            b"P%d J%d J%d 1 1 1 1 Open\n" % (i, i, i + 1)
            for i in range(LIMITS["refs"] + 100)
        )
        raw = b"[JUNCTIONS]\n J0 1 1\n[PIPES]\n" + rows + b"[END]\n"
        report = lint_bytes(raw)
        self.assertIn("INP014", {f.code for f in report.findings})

    def test_suppressed_reported_in_json(self) -> None:
        from inpguard.cli import _render_json

        raw = b"[JUNCTIONS]\n" + b"a b c d\n" * 200 + b"[END]\n"
        report = lint_bytes(raw)
        payload = _render_json(report, "x.inp")
        self.assertIn('"suppressed"', payload)
        self.assertIn("INP020", payload)

    def test_text_output_is_bounded(self) -> None:
        """Output size must not scale with the number of bad rows."""
        from inpguard.cli import _render_text

        small = _render_text(lint_bytes(b"[JUNCTIONS]\n" + b"a b c d\n" * 10), "x")
        huge = _render_text(lint_bytes(b"[JUNCTIONS]\n" + b"a b c d\n" * 50_000), "x")
        self.assertLess(len(huge), len(small) * 10)


class DeterminismTests(unittest.TestCase):
    def test_findings_are_ordered(self) -> None:
        report = lint_text(get("dangling_node").data)
        ordered = report.sorted_findings()
        sev = [f.severity for f in ordered]
        self.assertEqual(sev, sorted(sev, key=lambda s: {ERROR: 0, WARN: 1}.get(s, 2)))

    def test_repeat_runs_identical(self) -> None:
        a = lint_text(CLEAN)
        b = lint_text(CLEAN)
        self.assertEqual([str(f) for f in a.findings], [str(f) for f in b.findings])

    def test_no_mutation_of_input(self) -> None:
        data = get("duplicate_id").data
        before = data
        lint_text(data)
        self.assertEqual(data, before)


if __name__ == "__main__":
    unittest.main(verbosity=2)