"""EPANET .inp format reference data and hard limits.

The EPANET input file is a plain-text, section-delimited format consumed by
hydraulic modelling tools (EPANET, epanet-inp-parser, WNTR, EPANET-UI, and
commercial water-distribution packages). Many of these parsers are written in
memory-unsafe languages and treat the file as trusted input, which is a poor
assumption: .inp files are routinely downloaded, emailed, and shared between
utilities, consultants, and contractors.

This module is deliberately dependency-free so it can be embedded in CI.
"""

from __future__ import annotations

# Sections defined by the EPANET 2.2 input file specification (plus a few
# widely-implemented extensions). Anything outside this set is either an
# extension the linter cannot reason about, or an attacker-controlled string
# being fed to a parser that may not expect it.
KNOWN_SECTIONS: frozenset[str] = frozenset(
    {
        "TITLE",
        "JUNCTIONS",
        "RESERVOIRS",
        "TANKS",
        "PIPES",
        "PUMPS",
        "VALVES",
        "EMITTERS",
        "PATTERNS",
        "CURVES",
        "STATUS",
        "CONTROLS",
        "RULES",
        "DEMANDS",
        "QUALITY",
        "SOURCES",
        "REACTIONS",
        "MIXING",
        "ENERGY",
        "REPORT",
        "TIMES",
        "OPTIONS",
        "COORDINATES",
        "VERTICES",
        "LABELS",
        "BACKDROP",
        "TAGS",
        "END",
    }
)

# Sections in which the first token is a node or link identifier that later
# sections may reference. Used for referential-integrity checks.
NODE_SECTIONS: frozenset[str] = frozenset({"JUNCTIONS", "RESERVOIRS", "TANKS"})
LINK_SECTIONS: frozenset[str] = frozenset({"PIPES", "PUMPS", "VALVES"})

# Hard caps. These are not arbitrary: each one bounds a specific class of
# parser hazard (unbounded allocation, stack copy, integer width, pathological
# runtime). A conforming file is far below every one of them.
LIMITS = {
    "file_bytes": 64 * 1024 * 1024,      # 64 MiB
    "line_bytes": 8 * 1024,              # 8 KiB per physical line
    "token_bytes": 256,                  # 256 B per whitespace-delimited token
    "rows_per_section": 2_000_000,       # allocation / loop bound
    "sections": 4_096,                   # section-count bound
    "float32_max": 3.4028235e38,         # IEEE-754 binary32 ceiling
    "int32_max": 2_147_483_647,          # historically used as row/id type
    "pattern_period_hours": 24 * 365 * 10,  # 10 years
}

# Characters that must never appear raw in a well-formed .inp file. NUL
# truncates C string handling; the rest are terminal/parser escape hazards.
FORBIDDEN_CONTROL = frozenset(range(0x00, 0x09)) | frozenset({0x0B, 0x0C}) | frozenset(
    range(0x0E, 0x20)
) | frozenset({0x7F})

SECTION_RE = r"^\[[A-Za-z][A-Za-z0-9 _]*\]$"