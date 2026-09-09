"""Date corrections retain the scope distinctions in the primary publications."""

import hashlib
import importlib.util
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest
from evidentia_core.catalogs.loader import load_catalog


def test_eu_dates_do_not_shift_all_obligations() -> None:
    catalog = load_catalog("eu-ai-act")
    assert catalog.verified_on == date(2026, 9, 9)
    assert catalog.control_count == 22
    for control_id in ("AIA.Art.9", "AIA.Art.26"):
        props = catalog.get_control(control_id).properties
        assert props["annex_iii_application_on"] == "2027-12-02"
        assert props["annex_i_application_on"] == "2028-08-02"
        assert "application_on" not in props
    assert catalog.get_control("AIA.Art.50").properties["application_on"] == "2026-08-02"
    assert catalog.get_control("AIA.Art.53").properties["application_on"] == "2025-08-02"
    assert catalog.get_control("AIA.Art.5").properties["application_on"] == "2025-02-02"
    assert catalog.get_control("AIA.Art.5").properties["new_prohibitions_application_on"] == "2026-12-02"
    assert "2026/1744" in catalog.source
    assert catalog.annex_iii_risk_categories and len(catalog.annex_iii_risk_categories) == 8
    assert catalog.get_control("AIA.Art.9").risk_tier == "high"


def test_nydfs_amendment_transition_is_not_every_future_scope_deadline() -> None:
    catalog = load_catalog("ny-dfs-500")
    assert catalog.verified_on == date(2026, 9, 9)
    props = catalog.get_control("500.22").properties
    assert props["last_amendment_transition_on"] == "2025-11-01"
    assert "500.19(h)" in catalog.notes
    assert "180" in catalog.notes
    assert catalog.get_control("500.21").properties["amendment_effective_on"] == "2023-11-01"


def test_fda_current_guidance_is_already_bundled() -> None:
    catalog = load_catalog("fda-524b-appendix1")
    assert "2026-02-03" in catalog.version
    assert catalog.control_count == 8


def test_eu_refresh_preserves_the_existing_article_summaries() -> None:
    root = Path(__file__).resolve().parents[3]
    path = root / "packages/evidentia-core/src/evidentia_core/catalogs/data/international/eu-ai-act.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    retained = {
        "controls": [{k: v for k, v in row.items() if k != "properties"} for row in data["controls"]],
        "annex_iii_risk_categories": data["annex_iii_risk_categories"],
        "v0_9_3_note": data["v0_9_3_note"],
    }
    # Pin the pre-refresh payload, independent of checkout line endings.
    encoded = json.dumps(retained, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == "f4febc43a4cde65dca3f1e997de015fcaccfc9fb438bb875eb89ab800287a718"


@pytest.mark.parametrize(
    ("generator", "legacy", "relative"),
    [
        ("gen_eu_ai_act.py", "gen_international.py", "international/eu-ai-act.json"),
        ("gen_nydfs_currency.py", "gen_us_regulatory.py", "us-federal/ny-dfs-500.json"),
    ],
)
def test_date_generators_and_legacy_entrypoints_retain_current_metadata(
    generator: str, legacy: str, relative: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[3]
    scripts = root / "scripts/catalogs"
    monkeypatch.syspath_prepend(str(scripts))
    import _generators

    monkeypatch.setattr(_generators, "DATA_ROOT", tmp_path / "direct")
    spec = importlib.util.spec_from_file_location("date_generator_under_test", scripts / generator)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main()
    expected = json.loads(
        (root / "packages/evidentia-core/src/evidentia_core/catalogs/data" / relative).read_text(encoding="utf-8")
    )
    direct = list((tmp_path / "direct").rglob("*.json"))
    assert len(direct) == 1
    assert json.loads(direct[0].read_text(encoding="utf-8")) == expected
    # Legacy scripts run as fresh processes in normal use. Avoid module-cache
    # substitutions from other generator tests affecting their helper bindings.
    command = (
        "import sys, runpy; from pathlib import Path; "
        "sys.path.insert(0, sys.argv[1]); import _generators; "
        "_generators.DATA_ROOT = Path(sys.argv[2]); "
        "runpy.run_path(sys.argv[3], run_name='__main__')"
    )
    result = subprocess.run(
        [sys.executable, "-B", "-c", command, str(scripts), str(tmp_path / "legacy"), str(scripts / legacy)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads((tmp_path / "legacy" / relative).read_text(encoding="utf-8")) == expected


def test_eu_fundamental_rights_assessment_is_scoped_to_annex_iii() -> None:
    props = load_catalog("eu-ai-act").get_control("AIA.Art.27").properties
    assert props["annex_iii_application_on"] == "2027-12-02"
    assert "annex_i_application_on" not in props
    assert "Article 6(2)" in props["scope_note"]
    assert "point 2" in props["scope_note"]
    assert "5(b)" in props["scope_note"] and "5(c)" in props["scope_note"]


def test_nydfs_corrected_section_headings_keep_reporting_subjects_distinct() -> None:
    catalog = load_catalog("ny-dfs-500")
    expected = {
        "500.4(c)": "CISO reporting of material cybersecurity issues",
        "500.4(d)": "Senior governing body oversight",
        "500.14(b)": "Class A endpoint detection and response and centralized logging",
        "500.16": "Incident response and business continuity management",
        "500.17(a)": "Notice of cybersecurity incident",
        "500.17(b)": "Notice of compliance",
        "500.17(c)": "Notice and explanation of extortion payment",
        "500.24": "Exemptions from electronic filing and submission requirements",
    }
    assert {key: catalog.get_control(key).title if catalog.get_control(key) else None for key in expected} == expected
    assert catalog.control_count == 29
    assert catalog.get_control("500.17(b)").family == "Governance"
    assert catalog.get_control("500.17(c)").family == "Incident Response"
    assert "prior evidence" in catalog.notes
