"""Core linter: parse an EPANET .inp file defensively and report hazards.

Design rules that matter more than the checks themselves:
  * Never trust length fields. Everything is bounded while reading.
  * Every finding carries a byte offset so it can be diffed and triaged.
  * Severity is about *consequence*, not aesthetics: ERROR blocks a file from
    entering an unsafe parser, WARN is a smell, INFO is context.
  * No third-party imports. This must run in a locked-down CI container.
  * The linter must survive the inputs it exists to flag. Bounded time, bounded
    memory, bounded output. A tool that can be made to exhaust memory by the
    file it is inspecting has reproduced the bug it was written to prevent.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Iterator

from .spec import (
    FORBIDDEN_CONTROL,
    KNOWN_SECTIONS,
    LIMITS,
    LINK_SECTIONS,
    NODE_SECTIONS,
)

ERROR = "ERROR"
WARN = "WARN"
INFO = "INFO"

_SEVERITY_ORDER = {ERROR: 0, WARN: 1, INFO: 2}


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    message: str
    offset: int
    line: int
    section: str = ""

    def __str__(self) -> str:
        where = f"line {self.line}"
        if self.section:
            where += f" [{self.section}]"
        return f"{self.severity:5s} {self.code:12s} {where}: {self.message}"


@dataclass
class Section:
    name: str
    offset: int
    line: int
    rows: int = 0


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    bytes_read: int = 0
    lines_read: int = 0
    # code -> number of findings dropped after the per-code cap was reached
    suppressed: dict[str, int] = field(default_factory=dict)
    # code -> number of findings actually kept; keeps Report.add O(1)
    _kept: dict[str, int] = field(default_factory=dict)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == WARN]

    def ok(self) -> bool:
        return not self.errors

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings, key=lambda f: (_SEVERITY_ORDER[f.severity], f.offset)
        )

    def add(self, finding: Finding) -> None:
        """Record a finding, enforcing the per-code output cap.

        Dropping is per-code and counted, never silent: the report states how
        many occurrences of each code were elided, so a reader can tell "one
        bad row" apart from "two million bad rows".
        """
        cap = LIMITS["findings_per_code"]
        seen = self._kept.get(finding.code, 0)
        if seen >= cap:
            self.suppressed[finding.code] = self.suppressed.get(finding.code, 0) + 1
            return
        self._kept[finding.code] = seen + 1
        self.findings.append(finding)


def _is_number(tok: str) -> bool:
    try:
        float(tok)
    except ValueError:
        return False
    return True


def _iter_lines(raw: bytes) -> Iterator[tuple[int, int, bytes]]:
    """Yield (offset, line_no, line) without splitting on exotic separators.

    Only LF and CRLF are treated as line breaks. Splitting on a wider set (the
    default str.splitlines behaviour, which also honours \\v, \\f, \\x1c-\\x1e,
    \\u2028) would let an attacker desynchronise the linter from the target
    parser: the two would disagree about where a record ends.
    """
    offset = 0
    line_no = 0
    for i, chunk in enumerate(raw.split(b"\n")):
        line_no += 1
        if i == 0 and chunk.startswith(b"\xef\xbb\xbf"):
            # Strip a UTF-8 BOM so the first section header is still recognised.
            # Spreadsheet and Windows tooling emit these routinely; treating the
            # BOM as data would reject every such file.
            stub = chunk[3:]
            yield offset + 3, line_no, stub
        else:
            yield offset, line_no, chunk
        offset += len(chunk) + 1


def lint_bytes(
    raw: bytes,
    *,
    strict_references: bool = True,
    float_ceiling: float | None = None,
) -> Report:
    """Lint raw .inp bytes. Pure function: no I/O, no globals mutated."""
    report = Report(bytes_read=len(raw))

    ceiling = LIMITS["float32_max"] if float_ceiling is None else float_ceiling

    if len(raw) > LIMITS["file_bytes"]:
        report.add(
            Finding(
                ERROR,
                "INP001",
                f"file is {len(raw)} bytes, exceeding the "
                f"{LIMITS['file_bytes']} byte ceiling",
                0,
                0,
            )
        )
        # Refuse to walk a file we have already declared oversized.
        return report

    current: Section | None = None
    section_names: set[str] = set()
    seen_sections = 0

    node_ids: dict[str, tuple[int, int]] = {}
    link_ids: dict[str, tuple[int, int]] = {}
    pattern_ids: set[str] = set()
    curve_ids: set[str] = set()
    pattern_refs: list[tuple[str, int, int]] = []
    curve_refs: list[tuple[str, int, int]] = []
    node_refs: list[tuple[str, int, int]] = []
    refs_truncated = False

    def _keep(bucket: list[tuple[str, int, int]], item: tuple[str, int, int]) -> None:
        """Append a pending reference, bounded in aggregate across all buckets."""
        nonlocal refs_truncated
        total = len(pattern_refs) + len(curve_refs) + len(node_refs)
        if total >= LIMITS["refs"]:
            refs_truncated = True
            return
        bucket.append(item)

    for offset, line_no, raw_line in _iter_lines(raw):
        report.lines_read = line_no

        if len(raw_line) > LIMITS["line_bytes"]:
            report.add(
                Finding(
                    ERROR,
                    "INP002",
                    f"line is {len(raw_line)} bytes, exceeding the "
                    f"{LIMITS['line_bytes']} byte ceiling",
                    offset,
                    line_no,
                    current.name if current else "",
                )
            )
            continue

        # Strip trailing CR only; other whitespace can be semantically loaded.
        line = raw_line.rstrip(b"\r")

        bad = [b for b in line if b in FORBIDDEN_CONTROL]
        if bad:
            report.add(
                Finding(
                    ERROR,
                    "INP003",
                    f"{len(bad)} forbidden control byte(s), first 0x{bad[0]:02x}; "
                    "these desynchronise C string handling",
                    offset,
                    line_no,
                    current.name if current else "",
                )
            )
            # Keep scanning: a control byte may be a deliberate payload marker
            # and the rest of the file is still worth reporting on.

        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError:
            report.add(
                Finding(
                    ERROR,
                    "INP004",
                    "line is not valid UTF-8",
                    offset,
                    line_no,
                    current.name if current else "",
                )
            )
            continue

        stripped = text.strip()
        if not stripped:
            continue

        if stripped.startswith(";"):
            continue

        # EPANET treats ';' as a comment introducer anywhere on a line, not just
        # at column 0. Real exports rely on this: a trailing ";" after a blank
        # optional column is how modellers pad a record. Failing to strip it
        # invents phantom identifiers (";") and produces false positives on
        # files straight out of EPANET's own test suite.
        comment = stripped.find(";")
        if comment > 0:
            stripped = stripped[:comment].strip()
            if not stripped:
                continue

        if stripped.startswith("[") and stripped.endswith("]"):
            name = stripped[1:-1].strip().upper()
            if not name:
                report.add(
                    Finding(ERROR, "INP005", "empty section header", offset, line_no)
                )
                continue
            seen_sections += 1
            if name not in KNOWN_SECTIONS:
                report.add(
                    Finding(
                        WARN,
                        "INP010",
                        f"unknown section [{name}]; the target parser may treat "
                        "this as data or reject the file",
                        offset,
                        line_no,
                        name,
                    )
                )
            if name in section_names:
                # EPANET accumulates a repeated section rather than rejecting
                # it, and real exports from EPA's own test suite do this for
                # [REACTIONS], [DEMANDS] and [TAGS]. Reporting it as a warning
                # would be wrong; it is noted as context for a reviewer.
                report.add(
                    Finding(
                        INFO,
                        "INP011",
                        f"section [{name}] appears more than once; EPANET "
                        "accumulates repeated sections",
                        offset,
                        line_no,
                        name,
                    )
                )
            section_names.add(name)
            current = Section(name=name, offset=offset, line=line_no)
            report.sections.append(current)
            continue

        if current is None:
            report.add(
                Finding(
                    ERROR,
                    "INP006",
                    "data appears before the first section header",
                    offset,
                    line_no,
                )
            )
            continue

        current.rows += 1
        if current.rows > LIMITS["rows_per_section"]:
            report.add(
                Finding(
                    ERROR,
                    "INP007",
                    f"section exceeds {LIMITS['rows_per_section']} rows",
                    offset,
                    line_no,
                    current.name,
                )
            )
            current.rows = LIMITS["rows_per_section"]  # stop re-reporting
            continue

        # Tokenise on ASCII whitespace, replicating strtok-family behaviour.
        tokens = stripped.split()
        for tok in tokens:
            if len(tok) > LIMITS["token_bytes"]:
                report.add(
                    Finding(
                        WARN,
                        "INP012",
                        f"token of {len(tok)} bytes exceeds {LIMITS['token_bytes']}; "
                        "parsers using fixed buffers may truncate or overflow",
                        offset,
                        line_no,
                        current.name,
                    )
                )
                break

        # Rows are deliberately NOT retained. Nothing downstream reads them,
        # and buffering every row of a 2M-row file cost ~90x the input size in
        # RSS. The checks below run streaming, off the token list only.

        _check_semantics(
            report,
            current,
            tokens,
            offset,
            line_no,
            ceiling,
            node_ids,
            link_ids,
            pattern_ids,
            curve_ids,
            pattern_refs,
            curve_refs,
            node_refs,
            _keep,
        )

    if seen_sections > LIMITS["sections"]:
        report.add(
            Finding(
                ERROR,
                "INP008",
                f"{seen_sections} sections exceeds the limit of {LIMITS['sections']}",
                0,
                0,
            )
        )

    if refs_truncated:
        report.add(
            Finding(
                WARN,
                "INP014",
                f"more than {LIMITS['refs']} cross-references; remaining "
                "reference checks were skipped — findings are a lower bound",
                0,
                report.lines_read,
            )
        )

    if strict_references:
        _check_references(
            report, pattern_ids, curve_ids, node_ids, link_ids,
            pattern_refs, curve_refs, node_refs,
        )

    if "END" not in section_names:
        report.add(
            Finding(
                WARN,
                "INP013",
                "no [END] section; some parsers read past end of input",
                0,
                report.lines_read,
            )
        )

    return report


def _check_semantics(
    report: Report,
    section: Section,
    tokens: list[str],
    offset: int,
    line_no: int,
    ceiling: float,
    node_ids: dict[str, tuple[int, int]],
    link_ids: dict[str, tuple[int, int]],
    pattern_ids: set[str],
    curve_ids: set[str],
    pattern_refs: list[tuple[str, int, int]],
    curve_refs: list[tuple[str, int, int]],
    node_refs: list[tuple[str, int, int]],
    keep,
) -> None:
    name = section.name

    if not tokens:
        return

    # --- identifier definitions -------------------------------------------
    if name in NODE_SECTIONS or name in LINK_SECTIONS:
        ident = tokens[0]
        table = node_ids if name in NODE_SECTIONS else link_ids
        if ident in table:
            report.add(
                Finding(
                    ERROR,
                    "INP020",
                    f"duplicate identifier '{ident}' in [{name}] "
                    f"(first defined at line {table[ident][1]})",
                    offset,
                    line_no,
                    name,
                )
            )
        else:
            table[ident] = (offset, line_no)
        # [JUNCTIONS] pattern is column 3 (id, elev, demand, pattern).
        # [PIPES] pattern is column 6. Off-by-one here means every clean file
        # warns, which is how a linter gets switched off in production.
        if name == "JUNCTIONS" and len(tokens) >= 4:
            if not _is_number(tokens[3]):
                keep(pattern_refs, (tokens[3], offset, line_no))
        elif name == "PIPES" and len(tokens) >= 6:
            if not _is_number(tokens[5]):
                keep(pattern_refs, (tokens[5], offset, line_no))
    elif name == "PATTERNS":
        pattern_ids.add(tokens[0])
    elif name == "CURVES":
        curve_ids.add(tokens[0])

    # --- numeric sanity across every row ----------------------------------
    for idx, tok in enumerate(tokens):
        if not _is_number(tok):
            continue
        val = float(tok)
        if math.isnan(val) or math.isinf(val):
            report.add(
                Finding(
                    ERROR,
                    "INP021",
                    f"non-finite numeric value '{tok}' in column {idx + 1}",
                    offset,
                    line_no,
                    name,
                )
            )
        elif abs(val) > ceiling:
            report.add(
                Finding(
                    WARN,
                    "INP022",
                    f"value {tok} in column {idx + 1} exceeds float32 range and "
                    "will overflow to inf on a single-precision parser",
                    offset,
                    line_no,
                    name,
                )
            )
        elif "_" in tok:
            report.add(
                Finding(
                    WARN,
                    "INP023",
                    f"numeric literal '{tok}' uses digit separators, which "
                    "C-family strtod does not accept",
                    offset,
                    line_no,
                    name,
                )
            )

    # --- section-specific reference and domain checks ---------------------
    if name == "PIPES" and len(tokens) >= 3:
        keep(node_refs, (tokens[1], offset, line_no))
        keep(node_refs, (tokens[2], offset, line_no))
    elif name in {"PUMPS", "VALVES"} and len(tokens) >= 3:
        # Both formats are: ID, Node1, Node2, then parameters. Using columns 2
        # and 3 here silently reads parameter keywords ("HEAD", "POWER") as node
        # identifiers, which is how a linter earns a reputation for noise.
        keep(node_refs, (tokens[1], offset, line_no))
        keep(node_refs, (tokens[2], offset, line_no))
    elif name == "DEMANDS":
        if len(tokens) >= 2 and not _is_number(tokens[1]):
            keep(pattern_refs, (tokens[1], offset, line_no))

    # Curves referenced by pumps/valves (HEAD / curve identifiers).
    if name == "PUMPS":
        text = " ".join(tokens[1:]).upper()
        marker = text.find("HEAD ")
        if marker >= 0:
            rest = text[marker + 5 :].split()
            if rest and not _is_number(rest[0]):
                keep(curve_refs, (rest[0], offset, line_no))


def _check_references(
    report: Report,
    pattern_ids: set[str],
    curve_ids: set[str],
    node_ids: dict[str, tuple[int, int]],
    link_ids: dict[str, tuple[int, int]],
    pattern_refs: list[tuple[str, int, int]],
    curve_refs: list[tuple[str, int, int]],
    node_refs: list[tuple[str, int, int]],
) -> None:
    for ref, offset, line_no in pattern_refs:
        if ref not in pattern_ids:
            report.add(
                Finding(
                    WARN,
                    "INP030",
                    f"reference to undefined pattern '{ref}'",
                    offset,
                    line_no,
                    "PATTERNS",
                )
            )
    for ref, offset, line_no in curve_refs:
        if ref not in curve_ids:
            report.add(
                Finding(
                    WARN,
                    "INP031",
                    f"reference to undefined curve '{ref}'",
                    offset,
                    line_no,
                    "CURVES",
                )
            )
    for ref, offset, line_no in node_refs:
        if ref not in node_ids:
            report.add(
                Finding(
                    ERROR,
                    "INP032",
                    f"link endpoint '{ref}' is not a defined node",
                    offset,
                    line_no,
                )
            )


_SAFE_IDENT = re.compile(r"^[A-Za-z0-9_.\-*]+$")


def lint_text(text: str, **kwargs) -> Report:
    return lint_bytes(text.encode("utf-8", errors="surrogateescape"), **kwargs)
