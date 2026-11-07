"""CORPUS — a regression corpus of hand-built EPANET .inp inputs.

Every case here is a file a real water utility could plausibly receive: a clean
export from a modelling tool, a truncated transfer, a legacy file with CRLF
endings, and a set of adversarial files exercising specific parser assumptions.

The adversarial cases are NOT exploits. They are malformed or hostile *inputs*
that a parser should reject or survive. Publishing them is the point: the
defender needs a test suite, and the vendor needs a reproducible report.
"""

from __future__ import annotations

from dataclasses import dataclass

CLEAN = """\
[TITLE]
METU campus distribution model - synthetic

[JUNCTIONS]
;ID       Elev    Dem     Pattern
 J1       10.0    5.0     P1
 J2       12.5    3.5     P1

[RESERVOIRS]
;ID       Head
 R1       55.0

[PIPES]
;ID   Node1  Node2  Length  Diam  Rough  Mloss  Status
 P1    R1     J1     120.0   300   130    0       Open
 P2    J1     J2     240.0   200   130    0       Open

[PATTERNS]
;ID   Factor
 P1   1.0
 P1   1.2

[OPTIONS]
 Units LPS
 Headloss H-W

[END]
"""

# Truncated download / interrupted transfer: valid prefix, no terminator.
TRUNCATED = CLEAN.split("[OPTIONS]")[0]

# Legacy export with CRLF and a BOM.
CRLF_BOM = "\ufeff" + CLEAN.replace("\n", "\r\n")

# Dangling reference: pipe names a node that does not exist.
DANGLING_NODE = """\
[JUNCTIONS]
 J1 10.0 5.0

[RESERVOIRS]
 R1 55.0

[PIPES]
 P1 R1 J9 120.0 300 130 0 Open

[END]
"""

# Duplicate identifiers: depends on whether the parser overwrites or appends.
DUPLICATE_ID = """\
[JUNCTIONS]
 J1 10.0 5.0
 J1 12.0 4.0

[END]
"""

# Numeric bombs: values that overflow single precision.
NUMERIC_BOMB = """\
[JUNCTIONS]
 J1 10.0 5.0

[PIPES]
 P1 J1 J1 1e39 300 130 0 Open

[END]
"""

# NaN/Inf literals: strtod accepts these; many downstream models do not.
NONFINITE = """\
[JUNCTIONS]
 J1 10.0 nan
 J2 inf 5.0

[END]
"""

# Embedded NUL: truncates C string handling, classic parser desync.
EMBEDDED_NUL = "[JUNCTIONS]\n J1\x0010.0 5.0\n\n[END]\n"

# Line-separator smuggling: the linter must NOT split these as newlines,
# otherwise an attacker can make the linter and the parser disagree.
UNICODE_LINE_SEP = "[JUNCTIONS]\n J1 10.0 5.0\u2028 J2 99.0 99.0\n\n[END]\n"

# Unknown section: an extension the parser may or may not understand.
UNKNOWN_SECTION = """\
[JUNCTIONS]
 J1 10.0 5.0

[MYSTERY_EXTENSION]
 whatever 1 2 3

[END]
"""

# Long token: fixed-buffer parsers may truncate or overflow.
LONG_TOKEN = "[JUNCTIONS]\n " + ("A" * 5000) + " 10.0 5.0\n\n[END]\n"


@dataclass(frozen=True)
class Case:
    name: str
    data: str
    expect_codes: frozenset[str]
    expect_ok: bool
    note: str


CASES: tuple[Case, ...] = (
    Case("clean", CLEAN, frozenset(), True, "well-formed file; must lint clean"),
    Case("truncated", TRUNCATED, frozenset({"INP013"}), True,
         "interrupted transfer; no [END]"),
    Case("crlf_bom", CRLF_BOM, frozenset(), True,
         "Windows export with BOM; must not false-positive"),
    Case("dangling_node", DANGLING_NODE, frozenset({"INP032"}), False,
         "referential integrity failure"),
    Case("duplicate_id", DUPLICATE_ID, frozenset({"INP020"}), False,
         "identifier collision"),
    Case("numeric_bomb", NUMERIC_BOMB, frozenset({"INP022"}), True,
         "float32 overflow"),
    Case("nonfinite", NONFINITE, frozenset({"INP021"}), False,
         "NaN/Inf literals"),
    Case("embedded_nul", EMBEDDED_NUL, frozenset({"INP003"}), False,
         "NUL truncates C strings"),
    Case("unicode_line_sep", UNICODE_LINE_SEP, frozenset(), True,
         "U+2028 must not split lines"),
    Case("unknown_section", UNKNOWN_SECTION, frozenset({"INP010"}), True,
         "undocumented extension"),
    Case("long_token", LONG_TOKEN, frozenset({"INP012"}), True,
         "fixed-buffer truncation hazard"),
)


def get(name: str) -> Case:
    for case in CASES:
        if case.name == name:
            return case
    raise KeyError(name)