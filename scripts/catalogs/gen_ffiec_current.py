"""Generate current FFIEC booklet catalogs from reviewed public HTML headings.

The compact source preserves literal body headings and their source locators.
It omits introductions, appendices, examination procedures, and narrative text.
The TSP input uses public HTML only; its marked PDF is excluded.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from _generators import emit_control_catalog

SOURCE_PATH = Path(__file__).parent / "sources" / "ffiec-current-headings.json"


def build_catalogs() -> list[dict[str, Any]]:
    """Build six heading catalogs without writing or fetching source material."""
    source = json.loads(SOURCE_PATH.read_text(encoding="utf-8"))
    catalogs = []
    for booklet in source["booklets"]:
        controls = [
            {
                "id": id_,
                "title": title,
                "description": "",
                "family": family,
                "properties": {
                    "source_url": booklet["source_url"] + relative_path,
                    "id_origin": booklet["id_origin"],
                },
            }
            for id_, title, family, relative_path in booklet["rows"]
        ]
        notes = (
            "Public HTML body headings only. Introductions, appendices, examination procedures, "
            "and narrative statements are omitted. Heading coverage does not establish full assessment coverage. "
        )
        if booklet["id_origin"] == "local":
            notes += (
                "IDs beginning local. are stable Evidentia identifiers derived from source heading URL paths; "
                "they are not publisher control IDs. "
            )
        else:
            notes += "IDs are published document section locators, not official assessment control IDs. "
        notes += f"Edition source: {booklet['edition_source']}."
        if booklet["release_date"]:
            notes += f" Released {booklet['release_date']}: {booklet['release_source']}."
        if booklet["source_note"]:
            notes += " " + booklet["source_note"]
        catalogs.append(
            {
                "framework_id": booklet["id"],
                "framework_name": booklet["name"],
                "version": booklet["version"],
                "source": booklet["source_url"],
                "families": list(dict.fromkeys(c["family"] for c in controls)),
                "controls": controls,
                "tier": "A",
                "status": "current",
                "notes": notes,
                "verified_on": source["verified_on"],
            }
        )
    return catalogs


def main() -> None:
    """Emit the reviewed heading catalogs through the shared output helper."""
    for catalog in build_catalogs():
        emit_control_catalog(**catalog)


if __name__ == "__main__":
    main()
