"""CLI entry point: `inpguard check network.inp`.

Exit codes are the contract for CI:
  0  clean (no ERROR findings)
  1  at least one ERROR finding
  2  usage or I/O failure
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, lint_bytes
from .lint import Report


def _render_text(report: Report, path: str) -> str:
    lines = [f"{path}: {report.bytes_read} bytes, {report.lines_read} lines, "
             f"{len(report.sections)} sections"]
    findings = report.sorted_findings()
    if not findings:
        lines.append("  clean")
        return "\n".join(lines)
    for finding in findings:
        lines.append(f"  {finding}")
    for code, count in sorted(report.suppressed.items()):
        lines.append(
            f"  NOTE  {code:12s} {count} further finding(s) of this code suppressed"
        )
    errors = len(report.errors)
    warns = len(report.warnings)
    lines.append(f"  {errors} error(s), {warns} warning(s)")
    return "\n".join(lines)


def _render_json(report: Report, path: str) -> str:
    payload = {
        "path": path,
        "bytes": report.bytes_read,
        "lines": report.lines_read,
        "ok": report.ok(),
        "sections": [s.name for s in report.sections],
        "findings": [
            {
                "severity": f.severity,
                "code": f.code,
                "message": f.message,
                "offset": f.offset,
                "line": f.line,
                "section": f.section,
            }
            for f in report.sorted_findings()
        ],
        "suppressed": dict(sorted(report.suppressed.items())),
    }
    return json.dumps(payload, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inpguard",
        description="Defensive linting for EPANET .inp water-network model files.",
    )
    parser.add_argument("--version", action="version", version=f"inpguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="lint one or more .inp files")
    check.add_argument("files", nargs="+", type=Path)
    check.add_argument("--json", action="store_true", help="machine-readable output")
    check.add_argument(
        "--allow-references",
        action="store_true",
        help="skip cross-section reference checks (partial files)",
    )
    check.add_argument(
        "--max-float",
        type=float,
        default=None,
        help="override the single-precision ceiling",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    worst = 0
    for path in args.files:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            print(f"{path}: cannot read: {exc}", file=sys.stderr)
            worst = max(worst, 2)
            continue

        report = lint_bytes(
            raw,
            strict_references=not args.allow_references,
            float_ceiling=args.max_float,
        )
        out = _render_json(report, str(path)) if args.json else _render_text(report, str(path))
        print(out)
        if not report.ok():
            worst = max(worst, 1)

    return worst


if __name__ == "__main__":
    raise SystemExit(main())