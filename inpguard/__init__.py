"""inpguard — defensive linting for EPANET .inp water-network model files.

Water utilities exchange .inp files constantly: between utilities, with
consultants, with contractors, and increasingly through automated pipelines.
Most parsers handle that input with the assumption that it is benign. This
package makes the malicious and the merely-malformed cases visible *before* the
file reaches a parser.

    >>> from inpguard import lint_text
    >>> report = lint_text(open("network.inp").read())
    >>> print(report.ok())
"""

from .lint import ERROR, INFO, WARN, Finding, Report, lint_bytes, lint_text
from .spec import KNOWN_SECTIONS, LIMITS

__version__ = "0.1.0"

__all__ = [
    "ERROR",
    "INFO",
    "WARN",
    "Finding",
    "Report",
    "KNOWN_SECTIONS",
    "LIMITS",
    "lint_bytes",
    "lint_text",
    "__version__",
]