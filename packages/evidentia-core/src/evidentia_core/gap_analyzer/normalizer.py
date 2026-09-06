"""Control ID normalization and fuzzy matching.

Handles the many ways people write control IDs:
- "AC-2" vs "AC2" vs "ac-2" vs "Access Control 2"
- "CC6.1" vs "CC 6.1" vs "cc6.1"
- "A.9.2.1" vs "A9.2.1" vs "ISO A.9.2.1"
"""

from __future__ import annotations

import re

from thefuzz import fuzz, process

from evidentia_core.models.catalog import ControlCatalog


def normalize_control_id(raw_id: str) -> str:
    """Normalize a control ID to a canonical form.

    Rules:
    1. Strip whitespace and convert to uppercase
    2. Remove common prefixes: "NIST ", "ISO ", "CIS ", "SOC2 "
    3. Ensure hyphen separators for NIST-style IDs: "AC2" → "AC-2"
    4. Preserve dot separators for ISO/SOC2 style: "CC6.1" stays "CC6.1"
    """
    result = raw_id.strip().upper()

    for prefix in ["NIST ", "ISO ", "CIS ", "SOC2 ", "SOC 2 ", "PCI ", "CMMC "]:
        if result.startswith(prefix):
            result = result[len(prefix) :]

    # Handle NIST-style IDs: ensure hyphen between family prefix and number
    nist_pattern = re.compile(r"^([A-Z]{2,3})(\d+)(.*)$")
    match = nist_pattern.match(result.replace("-", "").replace(" ", ""))
    if match and not re.search(r"\.", result):
        family = match.group(1)
        number = match.group(2)
        suffix = match.group(3)
        if suffix.startswith("("):
            result = f"{family}-{number}{suffix}"
        elif suffix:
            result = f"{family}-{number}-{suffix}" if suffix.isdigit() else f"{family}-{number}{suffix}"
        else:
            result = f"{family}-{number}"

    return result


def find_best_match(
    user_control_id: str,
    catalog: ControlCatalog,
    threshold: int = 75,
) -> str | None:
    """Find the best matching control ID in a catalog using fuzzy matching.

    Steps:
    1. Try exact match (after normalization)
    2. Try fuzzy matching on control IDs
    3. Try fuzzy matching on control titles (for natural language input)
    """
    normalized = normalize_control_id(user_control_id)

    # 1. Exact match
    exact = catalog.get_control(normalized)
    if exact:
        return exact.id

    # 2. Fuzzy match on control IDs
    all_ids: list[str] = [c.id for c in catalog.controls]
    for c in catalog.controls:
        all_ids.extend(e.id for e in c.enhancements)

    id_match = process.extractOne(normalized, all_ids, scorer=fuzz.ratio)
    if id_match and id_match[1] >= threshold:
        # thefuzz returns Any-typed tuples; the first element is always
        # the matched string from `all_ids` (list[str]).
        return str(id_match[0])

    # 3. Fuzzy match on titles (for inputs like "Account Management")
    title_map: dict[str, str] = {}
    for c in catalog.controls:
        if c.title:
            title_map[c.title] = c.id
        for e in c.enhancements:
            if e.title:
                title_map[e.title] = e.id

    if not title_map:
        return None

    title_match = process.extractOne(user_control_id, list(title_map.keys()), scorer=fuzz.ratio)
    if title_match and title_match[1] >= threshold:
        return title_map[title_match[0]]

    return None
