"""Spreadsheet formula neutralisation for CSV cells (CWE-1236).

A cell that starts with ``=``, ``+``, ``-``, ``@``, a tab or a carriage return
becomes a live formula when the file is opened in a spreadsheet. The
OWASP-recommended neutraliser is a leading single quote, which survives
round-tripping in Excel, LibreOffice and Google Sheets. The TPRM
concentration report used this rule since v0.7.9; the Tableau and Power BI
extracts share it since the v0.13.0 review.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

CSV_FORMULA_LEAD_CHARS: frozenset[str] = frozenset(["=", "+", "-", "@", "\t", "\r"])


def csv_safe(value: object) -> object:
    """Return ``value`` with a leading quote when a string would read as a formula.

    Non-string values pass through unchanged, so numeric and boolean cells
    keep their type for consumers that infer it.
    """
    if isinstance(value, str) and value and value[0] in CSV_FORMULA_LEAD_CHARS:
        return "'" + value
    return value


def csv_safe_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """Apply :func:`csv_safe` to every value of a row mapping."""
    return {key: csv_safe(value) for key, value in row.items()}
