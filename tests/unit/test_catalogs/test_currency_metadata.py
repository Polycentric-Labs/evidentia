"""Currency notices survive loading without becoming assessment requirements."""

from __future__ import annotations

import importlib.util
import json
from datetime import date
from pathlib import Path

import pytest
from evidentia_core.catalogs.loader import load_evidentia_catalog
from evidentia_core.catalogs.manifest import FrameworkManifestEntry
from evidentia_core.gap_analyzer import GapAnalyzer
from evidentia_core.models.catalog import ControlCatalog
from pydantic import ValidationError


def _data() -> dict:
    return {
        "framework_id": "demo",
        "framework_name": "Demo",
        "version": "1",
        "source": "https://example.org/policy",
        "tier": "A",
        "controls": [{"id": "AC-1", "title": "Policy", "description": "Set policy."}],
    }


def test_absent_currency_metadata_is_unknown() -> None:
    catalog = ControlCatalog.model_validate(_data())
    assert catalog.status is None
    assert catalog.verified_on is None
    assert catalog.audit_contexts == {}
    assert catalog.publication_notices == []
    assert catalog.controls[0].properties == {}


def test_native_loader_preserves_independent_properties_and_csa_context(tmp_path: Path) -> None:
    data = _data()
    data.update(
        {
            "status": "superseded",
            "notes": "Historical set; consult the successor.",
            "verified_on": "2026-09-09",
            "superseded_by": "demo-new",
            "family_hierarchy": {"Governance": ["Policy"]},
            "v0_9_3_note": "A retained source note.",
            "annex_iii_risk_categories": ["employment"],
            "audit_contexts": {
                "US-TX": {
                    "authority": "Texas DPS",
                    "version": "5.9.5",
                    "source_url": "https://example.org/texas",
                    "verified_on": "2026-09-09",
                    "valid_through": "2027-03-31",
                    "notes": "Only the named CSA is covered.",
                }
            },
        }
    )
    data["controls"][0].update({"priority": "P4", "properties": {"existing": "true", "audit_status": "Existing"}})
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    loaded = load_evidentia_catalog(path)
    assert loaded.status == "superseded"
    assert loaded.notes == data["notes"]
    assert loaded.verified_on == date(2026, 9, 9)
    assert loaded.superseded_by == "demo-new"
    assert loaded.audit_contexts["US-TX"].version == "5.9.5"
    assert loaded.audit_contexts["US-TX"].valid_through == date(2027, 3, 31)
    assert loaded.audit_contexts.get("US-CA") is None
    assert loaded.controls[0].priority == "P4"
    assert loaded.controls[0].properties == {"existing": "true", "audit_status": "Existing"}
    assert loaded.family_hierarchy == data["family_hierarchy"]
    assert loaded.v0_9_3_note == data["v0_9_3_note"]
    assert loaded.annex_iii_risk_categories == ["employment"]
    assert ControlCatalog.model_validate_json(loaded.model_dump_json()) == loaded


def test_publication_notices_never_enter_required_set_or_text_depth() -> None:
    data = _data()
    data["publication_notices"] = [
        {
            "id": "AC-2",
            "title": "Future control",
            "status": "approved-future",
            "source_url": "https://example.org/future",
            "approved_on": "2020-01-01",
            "published_on": "2020-02-01",
            "order_effective_on": "2020-03-01",
            "effective_on": "2020-04-01",
            "notes": "An elapsed date does not activate a publication notice.",
        }
    ]
    catalog = ControlCatalog.model_validate(data)
    assert catalog.control_count == 1
    assert catalog.get_control("AC-2") is None
    assert catalog.text_depth == "full"
    assert set(GapAnalyzer()._build_required_set({"demo": catalog})) == {"demo:AC-1"}
    notice = catalog.publication_notices[0]
    assert notice.approved_on == date(2020, 1, 1)
    assert notice.order_effective_on == date(2020, 3, 1)
    assert notice.effective_on == date(2020, 4, 1)


@pytest.mark.parametrize(
    "extra",
    [
        {"status": "assumed-current"},
        {"verified_on": "not-a-date"},
        {"audit_contexts": {"US-TX": {"version": "5.9.5"}}},
        {"publication_notices": [{"id": "AC-2", "status": "active"}]},
    ],
)
def test_native_loader_rejects_malformed_currency_metadata(tmp_path: Path, extra: dict) -> None:
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps({**_data(), **extra}), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_evidentia_catalog(path)


def test_manifest_generator_preserves_currency_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    script = Path(__file__).resolve().parents[3] / "scripts/catalogs/regenerate_manifest.py"
    spec = importlib.util.spec_from_file_location("currency_manifest_generator", script)
    assert spec and spec.loader
    monkeypatch.syspath_prepend(str(script.parent))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    directory = tmp_path / "us-federal"
    directory.mkdir()
    data = {
        **_data(),
        "status": "retired",
        "notes": "No longer maintained.",
        "verified_on": "2026-09-09",
        "superseded_by": "demo-next",
    }
    (directory / "demo.json").write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(module, "DATA_ROOT", tmp_path)
    row = module.scan_dir("us-federal")[0]
    assert row["status"] == "retired"
    assert row["notes"] == data["notes"]
    assert row["verified_on"] == "2026-09-09"
    assert row["superseded_by"] == "demo-next"
    manifest = FrameworkManifestEntry.model_validate(row)
    assert manifest.verified_on == date(2026, 9, 9)
