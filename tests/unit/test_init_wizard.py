"""Unit tests for ``evidentia_core.init_wizard``.

Covers YAML generators (structural correctness via yaml.safe_load) and
the framework-recommender decision tree.
"""

from __future__ import annotations

import pytest
import yaml
from evidentia_core.init_wizard import (
    generate_evidentia_yaml,
    generate_my_controls_yaml,
    generate_system_context_yaml,
    recommend_frameworks,
)

# ── evidentia.yaml ────────────────────────────────────────────────────


class TestGenerateEvidentiaYaml:
    def test_minimal(self) -> None:
        text = generate_evidentia_yaml(organization="Test Org", frameworks=["soc2-tsc"])
        data = yaml.safe_load(text)
        assert data["organization"] == "Test Org"
        assert data["frameworks"] == ["soc2-tsc"]
        assert data["llm"]["model"] == "gpt-4o"
        assert data["llm"]["temperature"] == 0.1

    def test_with_system_name(self) -> None:
        text = generate_evidentia_yaml(
            organization="Acme",
            frameworks=["nist-800-53-rev5-moderate"],
            system_name="Acme SaaS",
        )
        data = yaml.safe_load(text)
        assert data["system_name"] == "Acme SaaS"

    def test_without_system_name_leaves_commented_hint(self) -> None:
        text = generate_evidentia_yaml(organization="Acme", frameworks=["soc2-tsc"])
        # The commented-out hint should be present; un-commented key should not.
        assert "# system_name:" in text
        data = yaml.safe_load(text)
        assert "system_name" not in data

    def test_empty_frameworks_produces_commented_placeholder(self) -> None:
        text = generate_evidentia_yaml(organization="Acme", frameworks=[])
        assert "# Add at least one framework ID here." in text
        data = yaml.safe_load(text)
        # Empty list in YAML parses to None; both shapes are acceptable.
        assert not data.get("frameworks")

    def test_multiple_frameworks_ordered(self) -> None:
        text = generate_evidentia_yaml(
            organization="Acme",
            frameworks=["nist-800-53-rev5-moderate", "soc2-tsc", "hipaa-security"],
        )
        data = yaml.safe_load(text)
        assert data["frameworks"] == [
            "nist-800-53-rev5-moderate",
            "soc2-tsc",
            "hipaa-security",
        ]

    def test_llm_overrides_applied(self) -> None:
        text = generate_evidentia_yaml(
            organization="Acme",
            frameworks=["soc2-tsc"],
            llm_model="claude-sonnet-4-6",
            llm_temperature=0.3,
        )
        data = yaml.safe_load(text)
        assert data["llm"]["model"] == "claude-sonnet-4-6"
        assert data["llm"]["temperature"] == 0.3

    def test_roundtrip_through_evidentia_config_loader(self, tmp_path) -> None:
        """The generated YAML must load cleanly via the v0.2.1 config loader."""
        from evidentia_core.config import load_config

        target = tmp_path / "evidentia.yaml"
        target.write_text(
            generate_evidentia_yaml(
                organization="Smoke Test Org",
                frameworks=["nist-800-53-rev5-moderate"],
                system_name="Smoke Test System",
            ),
            encoding="utf-8",
        )
        cfg = load_config(target)
        assert cfg.organization == "Smoke Test Org"
        assert cfg.system_name == "Smoke Test System"
        assert cfg.frameworks == ["nist-800-53-rev5-moderate"]


# ── my-controls.yaml ──────────────────────────────────────────────────────


class TestGenerateMyControlsYaml:
    @pytest.mark.parametrize(
        "preset",
        [
            "soc2-starter",
            "nist-moderate-starter",
            "hipaa-starter",
            "cmmc-starter",
            "empty",
        ],
    )
    def test_preset_yaml_is_valid(self, preset: str) -> None:
        text = generate_my_controls_yaml(preset=preset, organization="Smoke")  # type: ignore[arg-type]
        data = yaml.safe_load(text)
        assert data is not None
        assert data["organization"] == "Smoke"
        # Empty preset produces a commented-out controls section with
        # no list entries; all others produce at least one entry.
        controls = data.get("controls")
        if preset == "empty":
            assert controls is None or controls == []
        else:
            assert isinstance(controls, list)
            assert len(controls) >= 3
            for control in controls:
                assert "id" in control
                assert "title" in control
                assert control["status"] in {
                    "implemented",
                    "partially_implemented",
                    "planned",
                    "not_implemented",
                    "not_applicable",
                }

    def test_rejects_unknown_preset(self) -> None:
        with pytest.raises(ValueError, match="Unknown preset"):
            generate_my_controls_yaml(preset="bogus")  # type: ignore[arg-type]

    def test_soc2_preset_uses_cc_ids(self) -> None:
        text = generate_my_controls_yaml(preset="soc2-starter", organization="X")
        data = yaml.safe_load(text)
        ids = {c["id"] for c in data["controls"]}
        assert any(cid.startswith("CC") for cid in ids)

    def test_hipaa_preset_uses_164_ids(self) -> None:
        text = generate_my_controls_yaml(preset="hipaa-starter", organization="X")
        data = yaml.safe_load(text)
        ids = {c["id"] for c in data["controls"]}
        assert any(cid.startswith("164.") for cid in ids)


# ── system-context.yaml ───────────────────────────────────────────────────


class TestGenerateSystemContextYaml:
    def test_minimal(self) -> None:
        text = generate_system_context_yaml(organization="Acme")
        data = yaml.safe_load(text)
        assert data["organization"] == "Acme"
        assert data["system_name"] == "Your System"
        assert "PII" in data["data_classification"]
        assert isinstance(data["threat_actors"], list)
        assert len(data["threat_actors"]) >= 1

    def test_custom_classification_and_regulatory(self) -> None:
        text = generate_system_context_yaml(
            organization="Acme",
            system_name="Acme Clinic",
            data_classification=["PHI", "PII"],
            regulatory_requirements=["HIPAA", "GDPR"],
        )
        data = yaml.safe_load(text)
        assert set(data["data_classification"]) == {"PHI", "PII"}
        assert set(data["regulatory_requirements"]) == {"HIPAA", "GDPR"}

    def test_multiline_description_indented_correctly(self) -> None:
        text = generate_system_context_yaml(
            organization="Acme",
            system_description="Line one\nLine two",
        )
        data = yaml.safe_load(text)
        assert "Line one" in data["system_description"]
        assert "Line two" in data["system_description"]


# ── recommend_frameworks ──────────────────────────────────────────────────


class TestRecommendFrameworks:
    def test_default_baseline_includes_nist_moderate(self) -> None:
        assert "nist-800-53-rev5-moderate" in recommend_frameworks()

    def test_saas_default_adds_soc2(self) -> None:
        rec = recommend_frameworks(industry="saas")
        assert "soc2-tsc" in rec
        assert "nist-800-53-rev5-moderate" in rec

    def test_fintech_pci_cde_recommends_pci(self) -> None:
        rec = recommend_frameworks(industry="fintech", data_classification=["PII", "PCI-CDE"])
        assert "pci-dss-v4" in rec

    def test_healthtech_recommends_hipaa(self) -> None:
        rec = recommend_frameworks(industry="healthtech")
        assert "hipaa-security" in rec
        assert "hipaa-privacy" in rec

    def test_phi_data_recommends_hipaa_regardless_of_industry(self) -> None:
        rec = recommend_frameworks(industry="saas", data_classification=["PHI"])
        assert "hipaa-security" in rec

    def test_govcon_recommends_cmmc_and_800_171(self) -> None:
        rec = recommend_frameworks(industry="govcon")
        assert "cmmc-l2" in rec
        assert "nist-800-171-rev2" in rec

    def test_cui_data_recommends_cmmc(self) -> None:
        rec = recommend_frameworks(industry="saas", data_classification=["CUI"])
        assert "cmmc-l2" in rec

    def test_gdpr_regulatory_recommends_eu_gdpr(self) -> None:
        rec = recommend_frameworks(regulatory_requirements=["GDPR"])
        assert "eu-gdpr" in rec

    def test_fedramp_regulatory_recommends_fedramp_moderate(self) -> None:
        rec = recommend_frameworks(regulatory_requirements=["FedRAMP-moderate"])
        assert "fedramp-rev5-moderate" in rec

    def test_deduplicates(self) -> None:
        # fintech + SOC 2 regulatory should not double up on soc2-tsc.
        rec = recommend_frameworks(
            industry="fintech",
            regulatory_requirements=["SOC 2", "GDPR"],
        )
        assert len(rec) == len(set(rec))

    def test_ordering_stable(self) -> None:
        rec_a = recommend_frameworks(industry="saas")
        rec_b = recommend_frameworks(industry="saas")
        assert rec_a == rec_b

    def test_case_insensitive_data_classification(self) -> None:
        rec_upper = recommend_frameworks(data_classification=["PHI"])
        rec_lower = recommend_frameworks(data_classification=["phi"])
        # Lowercase should still match since the function uppercases internally.
        assert "hipaa-security" in rec_upper
        assert "hipaa-security" in rec_lower
