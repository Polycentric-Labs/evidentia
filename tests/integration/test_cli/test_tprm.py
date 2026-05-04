"""Integration tests for `evidentia tprm vendor` subcommands (v0.7.9 P0.1.3).

Uses Typer's CliRunner against the real `evidentia.cli.main:app`.
Each test scopes the vendor store to ``tmp_path`` via the
``EVIDENTIA_VENDOR_STORE_DIR`` env var so no state leaks across
tests or into the real user profile.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia.cli.main import app
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _isolated_vendor_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point EVIDENTIA_VENDOR_STORE_DIR at an isolated tmp for each test."""
    store = tmp_path / "vendor-store"
    monkeypatch.setenv("EVIDENTIA_VENDOR_STORE_DIR", str(store))
    return store


# ── add ────────────────────────────────────────────────────────────


class TestVendorAdd:
    def test_atomic_happy_path(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "tprm", "vendor", "add",
                "--name", "Acme Cloud",
                "--type", "cloud_provider",
                "--criticality-tier", "critical",
                "--owner", "allen@allenfbyrd.com",
                "--contract-start-date", "2025-01-01",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Added vendor" in result.output
        assert "Acme Cloud" in result.output

    def test_missing_required_field_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "tprm", "vendor", "add",
                "--name", "X",
                # Missing --type / --criticality-tier / --owner / --contract-start-date
            ],
        )
        assert result.exit_code == 1
        assert "Missing required field" in result.output

    def test_invalid_date_format_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "tprm", "vendor", "add",
                "--name", "X",
                "--type", "saas",
                "--criticality-tier", "low",
                "--owner", "x@x.com",
                "--contract-start-date", "not-a-date",
            ],
        )
        assert result.exit_code == 1
        assert "ISO-8601" in result.output

    def test_invalid_enum_value_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "tprm", "vendor", "add",
                "--name", "X",
                "--type", "not-a-real-type",
                "--criticality-tier", "low",
                "--owner", "x@x.com",
                "--contract-start-date", "2025-01-01",
            ],
        )
        assert result.exit_code == 1

    def test_auto_computes_next_review_due_when_last_dd_provided(
        self, runner: CliRunner
    ) -> None:
        runner.invoke(
            app,
            [
                "tprm", "vendor", "add",
                "--name", "Test Vendor",
                "--type", "saas",
                "--criticality-tier", "high",
                "--owner", "x@x.com",
                "--contract-start-date", "2025-01-01",
                "--last-due-diligence-review", "2025-06-15",
            ],
        )
        # Now list with --json and verify next_review_due was set
        list_result = runner.invoke(
            app, ["tprm", "vendor", "list", "--json"]
        )
        assert list_result.exit_code == 0, list_result.output
        vendors = json.loads(list_result.output)
        assert len(vendors) == 1
        # high → annual cadence, so 2025-06-15 + 12 months
        assert vendors[0]["next_review_due"] == "2026-06-15"

    def test_from_yaml_with_complex_fields(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        yaml_path = tmp_path / "vendor.yaml"
        yaml_path.write_text(
            """
name: Complex Vendor
type: saas
criticality_tier: high
relationship_owner: x@x.com
contract_start_date: '2025-01-01'
fourth_parties:
  - name: AWS
    type: cloud_provider
    relationship: underlying IaaS
evidence_refs:
  - title: SOC 2 Type II
    artifact_id: abc-123
""",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            ["tprm", "vendor", "add", "--from-yaml", str(yaml_path)],
        )
        assert result.exit_code == 0, result.output
        # Verify the embedded sub-models survived
        list_result = runner.invoke(
            app, ["tprm", "vendor", "list", "--json"]
        )
        vendors = json.loads(list_result.output)
        assert len(vendors[0]["fourth_parties"]) == 1
        assert len(vendors[0]["evidence_refs"]) == 1

    def test_atomic_flags_override_yaml_when_both_supplied(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        yaml_path = tmp_path / "vendor.yaml"
        yaml_path.write_text(
            """
name: YAML Name
type: saas
criticality_tier: high
relationship_owner: yaml@x.com
contract_start_date: '2025-01-01'
""",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "tprm", "vendor", "add",
                "--from-yaml", str(yaml_path),
                "--name", "Flag Override Name",
            ],
        )
        assert result.exit_code == 0, result.output
        list_result = runner.invoke(
            app, ["tprm", "vendor", "list", "--json"]
        )
        vendors = json.loads(list_result.output)
        assert vendors[0]["name"] == "Flag Override Name"


# ── list ───────────────────────────────────────────────────────────


class TestVendorList:
    def _seed_vendors(self, runner: CliRunner) -> None:
        runner.invoke(
            app,
            [
                "tprm", "vendor", "add",
                "--name", "A Critical Cloud",
                "--type", "cloud_provider",
                "--criticality-tier", "critical",
                "--owner", "x@x.com",
                "--contract-start-date", "2025-01-01",
            ],
        )
        runner.invoke(
            app,
            [
                "tprm", "vendor", "add",
                "--name", "B High SaaS",
                "--type", "saas",
                "--criticality-tier", "high",
                "--owner", "x@x.com",
                "--contract-start-date", "2025-01-01",
            ],
        )
        runner.invoke(
            app,
            [
                "tprm", "vendor", "add",
                "--name", "C Low Contractor",
                "--type", "contractor",
                "--criticality-tier", "low",
                "--owner", "x@x.com",
                "--contract-start-date", "2025-01-01",
            ],
        )

    def test_empty_store_message(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["tprm", "vendor", "list"])
        assert result.exit_code == 0
        assert "No vendors" in result.output

    def test_table_output_default(self, runner: CliRunner) -> None:
        self._seed_vendors(runner)
        result = runner.invoke(app, ["tprm", "vendor", "list"])
        assert result.exit_code == 0
        assert "Vendor inventory" in result.output
        # Sort: critical → high → low. Rich Table can wrap long names
        # across visual lines but the leading-letter prefix survives,
        # so test ordering by 'A '/'B '/'C ' substring positions.
        a_idx = result.output.index("A ")
        b_idx = result.output.index("B ")
        c_idx = result.output.index("C ")
        assert a_idx < b_idx < c_idx

    def test_json_output(self, runner: CliRunner) -> None:
        self._seed_vendors(runner)
        result = runner.invoke(app, ["tprm", "vendor", "list", "--json"])
        assert result.exit_code == 0
        vendors = json.loads(result.output)
        assert len(vendors) == 3
        assert {v["name"] for v in vendors} == {
            "A Critical Cloud",
            "B High SaaS",
            "C Low Contractor",
        }

    def test_filter_by_criticality_tier(self, runner: CliRunner) -> None:
        self._seed_vendors(runner)
        result = runner.invoke(
            app,
            ["tprm", "vendor", "list", "--criticality-tier", "high", "--json"],
        )
        vendors = json.loads(result.output)
        assert len(vendors) == 1
        assert vendors[0]["name"] == "B High SaaS"

    def test_filter_by_type(self, runner: CliRunner) -> None:
        self._seed_vendors(runner)
        result = runner.invoke(
            app, ["tprm", "vendor", "list", "--type", "saas", "--json"]
        )
        vendors = json.loads(result.output)
        assert len(vendors) == 1
        assert vendors[0]["name"] == "B High SaaS"

    def test_unknown_criticality_tier_rejected(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            ["tprm", "vendor", "list", "--criticality-tier", "ultra-critical"],
        )
        assert result.exit_code == 1
        assert "Unknown criticality tier" in result.output


# ── show ───────────────────────────────────────────────────────────


class TestVendorShow:
    def _add_one(self, runner: CliRunner) -> str:
        runner.invoke(
            app,
            [
                "tprm", "vendor", "add",
                "--name", "Show Test",
                "--type", "saas",
                "--criticality-tier", "low",
                "--owner", "x@x.com",
                "--contract-start-date", "2025-01-01",
            ],
        )
        list_result = runner.invoke(
            app, ["tprm", "vendor", "list", "--json"]
        )
        vendors = json.loads(list_result.output)
        return str(vendors[0]["id"])

    def test_show_human_readable(self, runner: CliRunner) -> None:
        vid = self._add_one(runner)
        result = runner.invoke(app, ["tprm", "vendor", "show", vid])
        assert result.exit_code == 0
        assert "Show Test" in result.output
        assert "Criticality tier:" in result.output

    def test_show_json(self, runner: CliRunner) -> None:
        vid = self._add_one(runner)
        result = runner.invoke(app, ["tprm", "vendor", "show", vid, "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "Show Test"
        assert data["id"] == vid

    def test_show_unknown_id_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            ["tprm", "vendor", "show",
             "00000000-0000-0000-0000-000000000000"],
        )
        assert result.exit_code == 1
        # Rich console wraps lines; flatten + lowercase before substring
        # check so wrapped "not\nfound" still passes.
        flat = " ".join(result.output.lower().split())
        assert "no vendor" in flat and "found" in flat

    def test_show_malformed_id_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app, ["tprm", "vendor", "show", "../etc/passwd"]
        )
        assert result.exit_code == 1
        assert "Invalid vendor ID" in result.output


# ── edit ───────────────────────────────────────────────────────────


class TestVendorEdit:
    def _add_one(self, runner: CliRunner) -> str:
        runner.invoke(
            app,
            [
                "tprm", "vendor", "add",
                "--name", "Original",
                "--type", "saas",
                "--criticality-tier", "low",
                "--owner", "x@x.com",
                "--contract-start-date", "2025-01-01",
            ],
        )
        return str(
            json.loads(
                runner.invoke(app, ["tprm", "vendor", "list", "--json"]).output
            )[0]["id"]
        )

    def test_atomic_field_update(self, runner: CliRunner) -> None:
        vid = self._add_one(runner)
        result = runner.invoke(
            app,
            [
                "tprm", "vendor", "edit", vid,
                "--name", "Updated",
                "--residual-risk-score", "12",
            ],
        )
        assert result.exit_code == 0, result.output
        show_result = runner.invoke(
            app, ["tprm", "vendor", "show", vid, "--json"]
        )
        data = json.loads(show_result.output)
        assert data["name"] == "Updated"
        assert data["residual_risk_score"] == 12

    def test_no_input_errors(self, runner: CliRunner) -> None:
        vid = self._add_one(runner)
        result = runner.invoke(app, ["tprm", "vendor", "edit", vid])
        assert result.exit_code == 1
        assert "No edit input" in result.output

    def test_mixed_modes_error(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        vid = self._add_one(runner)
        yaml_path = tmp_path / "x.yaml"
        yaml_path.write_text(
            """
name: From YAML
type: saas
criticality_tier: low
relationship_owner: x@x.com
contract_start_date: '2025-01-01'
""",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "tprm", "vendor", "edit", vid,
                "--from-yaml", str(yaml_path),
                "--name", "Conflicting",
            ],
        )
        assert result.exit_code == 1
        assert "mutually exclusive" in result.output

    def test_from_yaml_preserves_id_and_created_at(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        vid = self._add_one(runner)
        # Capture original created_at
        orig_data = json.loads(
            runner.invoke(
                app, ["tprm", "vendor", "show", vid, "--json"]
            ).output
        )
        orig_created = orig_data["created_at"]

        yaml_path = tmp_path / "replace.yaml"
        yaml_path.write_text(
            """
name: Fully Replaced
type: cloud_provider
criticality_tier: critical
relationship_owner: new@x.com
contract_start_date: '2025-02-01'
""",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            ["tprm", "vendor", "edit", vid, "--from-yaml", str(yaml_path)],
        )
        assert result.exit_code == 0, result.output
        new_data = json.loads(
            runner.invoke(
                app, ["tprm", "vendor", "show", vid, "--json"]
            ).output
        )
        assert new_data["id"] == vid
        assert new_data["created_at"] == orig_created
        assert new_data["name"] == "Fully Replaced"


# ── delete ─────────────────────────────────────────────────────────


class TestVendorDelete:
    def _add_one(self, runner: CliRunner) -> str:
        runner.invoke(
            app,
            [
                "tprm", "vendor", "add",
                "--name", "Doomed",
                "--type", "saas",
                "--criticality-tier", "low",
                "--owner", "x@x.com",
                "--contract-start-date", "2025-01-01",
            ],
        )
        return str(
            json.loads(
                runner.invoke(app, ["tprm", "vendor", "list", "--json"]).output
            )[0]["id"]
        )

    def test_yes_flag_bypasses_prompt(self, runner: CliRunner) -> None:
        vid = self._add_one(runner)
        result = runner.invoke(
            app, ["tprm", "vendor", "delete", vid, "--yes"]
        )
        assert result.exit_code == 0, result.output
        assert "Deleted" in result.output
        # Verify gone
        list_result = runner.invoke(
            app, ["tprm", "vendor", "list", "--json"]
        )
        assert json.loads(list_result.output) == []

    def test_default_prompt_decline_aborts(self, runner: CliRunner) -> None:
        vid = self._add_one(runner)
        result = runner.invoke(
            app, ["tprm", "vendor", "delete", vid], input="n\n"
        )
        assert result.exit_code == 0
        assert "Aborted" in result.output
        # Vendor still present
        list_result = runner.invoke(
            app, ["tprm", "vendor", "list", "--json"]
        )
        assert len(json.loads(list_result.output)) == 1

    def test_default_prompt_accept_deletes(self, runner: CliRunner) -> None:
        vid = self._add_one(runner)
        result = runner.invoke(
            app, ["tprm", "vendor", "delete", vid], input="y\n"
        )
        assert result.exit_code == 0
        assert "Deleted" in result.output

    def test_unknown_id_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            ["tprm", "vendor", "delete",
             "00000000-0000-0000-0000-000000000000",
             "--yes"],
        )
        assert result.exit_code == 1


# ── concentration-report ───────────────────────────────────────────


class TestConcentrationReport:
    def _seed_vendors_with_regions(self, runner: CliRunner) -> None:
        """Seed 4 vendors: 2 in us-east-1, 1 in eu-west-1, 1 with no region."""
        for name, region in [
            ("US-A", "us-east-1"),
            ("US-B", "us-east-1"),
            ("EU-A", "eu-west-1"),
            ("Unknown", None),
        ]:
            cmd = [
                "tprm", "vendor", "add",
                "--name", name,
                "--type", "saas",
                "--criticality-tier", "high",
                "--owner", "x@x.com",
                "--contract-start-date", "2025-01-01",
            ]
            if region:
                # Region is only on the model, not on the CLI add flags
                # (the CLI doesn't expose --region in add yet — that's
                # a P0.3 follow-up). For now, set region via --from-yaml.
                pass
            runner.invoke(app, cmd)

    def _seed_via_yaml(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        """Seed vendors via --from-yaml so we can set the region field."""
        for name, region in [
            ("US-A", "us-east-1"),
            ("US-B", "us-east-1"),
            ("EU-A", "eu-west-1"),
            ("Unknown", None),
        ]:
            yaml_text = f"""
name: {name}
type: saas
criticality_tier: high
relationship_owner: x@x.com
contract_start_date: '2025-01-01'
"""
            if region:
                yaml_text += f"region: {region}\n"
            yaml_path = tmp_path / f"{name}.yaml"
            yaml_path.write_text(yaml_text, encoding="utf-8")
            runner.invoke(
                app,
                ["tprm", "vendor", "add", "--from-yaml", str(yaml_path)],
            )

    def test_json_output_default_dimensions(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        self._seed_via_yaml(runner, tmp_path)
        result = runner.invoke(
            app,
            ["tprm", "concentration-report", "--by", "region",
             "--format", "json"],
        )
        assert result.exit_code == 0, result.output
        # The output's stdout has the JSON dump
        data = json.loads(result.output)
        assert data["total_vendors"] == 4
        # 1 dimension requested
        assert len(data["dimensions"]) == 1
        assert data["dimensions"][0]["dimension"] == "region"

    def test_unsupported_dimension_errors(
        self, runner: CliRunner
    ) -> None:
        result = runner.invoke(
            app,
            ["tprm", "concentration-report", "--by", "not-a-dim",
             "--format", "json"],
        )
        assert result.exit_code == 1
        assert "Unsupported dimension" in result.output

    def test_invalid_format_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            ["tprm", "concentration-report", "--format", "xml"],
        )
        assert result.exit_code == 1
        assert "html/json/csv" in result.output

    def test_threshold_flag_applies(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        self._seed_via_yaml(runner, tmp_path)
        # 2 of 4 vendors in us-east-1 = 50% — threshold=50 should flag
        result = runner.invoke(
            app,
            [
                "tprm", "concentration-report",
                "--by", "region",
                "--threshold", "50",
                "--format", "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        flagged = [
            v for v in data["dimensions"][0]["distribution"]
            if v["exceeds_threshold"]
        ]
        assert len(flagged) == 1
        assert flagged[0]["value"] == "us-east-1"

    def test_html_output_to_file(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        self._seed_via_yaml(runner, tmp_path)
        out_path = tmp_path / "report.html"
        result = runner.invoke(
            app,
            [
                "tprm", "concentration-report",
                "--by", "region",
                "--format", "html",
                "--output", str(out_path),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Wrote HTML report" in result.output
        assert out_path.is_file()
        content = out_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "us-east-1" in content

    def test_csv_output_to_file(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        self._seed_via_yaml(runner, tmp_path)
        out_path = tmp_path / "report.csv"
        result = runner.invoke(
            app,
            [
                "tprm", "concentration-report",
                "--by", "region",
                "--format", "csv",
                "--output", str(out_path),
            ],
        )
        assert result.exit_code == 0, result.output
        content = out_path.read_text(encoding="utf-8")
        # Header
        assert content.startswith(
            "dimension,value,count,percentage,exceeds_threshold"
        )

    def test_multiple_dimensions(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        self._seed_via_yaml(runner, tmp_path)
        result = runner.invoke(
            app,
            [
                "tprm", "concentration-report",
                "--by", "region,service-category,criticality-tier",
                "--format", "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert [d["dimension"] for d in data["dimensions"]] == [
            "region",
            "service-category",
            "criticality-tier",
        ]


# ── dd-questionnaire generate ─────────────────────────────────────


class TestDDQuestionnaireGenerate:
    def _add_vendor(self, runner: CliRunner) -> str:
        runner.invoke(
            app,
            [
                "tprm", "vendor", "add",
                "--name", "Test Vendor",
                "--type", "saas",
                "--criticality-tier", "high",
                "--owner", "x@x.com",
                "--contract-start-date", "2025-01-01",
            ],
        )
        return str(
            json.loads(
                runner.invoke(
                    app, ["tprm", "vendor", "list", "--json"]
                ).output
            )[0]["id"]
        )

    def test_generic_json_to_stdout(self, runner: CliRunner) -> None:
        vid = self._add_vendor(runner)
        result = runner.invoke(
            app,
            [
                "tprm", "dd-questionnaire", "generate",
                "--vendor-id", vid,
                "--format", "evidentia-generic",
                "--output-format", "json",
            ],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["format"] == "evidentia-generic"
        assert data["vendor"]["vendor_name"] == "Test Vendor"
        assert len(data["questions"]) >= 15

    def test_caiq_lite_json_to_file(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        vid = self._add_vendor(runner)
        out_path = tmp_path / "q.json"
        result = runner.invoke(
            app,
            [
                "tprm", "dd-questionnaire", "generate",
                "--vendor-id", vid,
                "--format", "caiq-lite",
                "--output-format", "json",
                "--output", str(out_path),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Wrote JSON questionnaire" in result.output
        data = json.loads(out_path.read_text(encoding="utf-8"))
        assert data["format"] == "caiq-lite"
        assert data["licensing_attribution"]
        assert "CSA" in data["licensing_attribution"]

    def test_csv_output(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        vid = self._add_vendor(runner)
        out_path = tmp_path / "q.csv"
        result = runner.invoke(
            app,
            [
                "tprm", "dd-questionnaire", "generate",
                "--vendor-id", vid,
                "--format", "evidentia-generic",
                "--output-format", "csv",
                "--output", str(out_path),
            ],
        )
        assert result.exit_code == 0, result.output
        content = out_path.read_text(encoding="utf-8")
        assert "# Vendor DD Questionnaire" in content
        assert "# Vendor name,Test Vendor" in content
        assert "id,domain,question_text" in content

    def test_unknown_format_errors(self, runner: CliRunner) -> None:
        vid = self._add_vendor(runner)
        result = runner.invoke(
            app,
            [
                "tprm", "dd-questionnaire", "generate",
                "--vendor-id", vid,
                "--format", "not-a-format",
            ],
        )
        assert result.exit_code == 1
        assert "Unknown questionnaire format" in result.output

    def test_sig_format_errors_with_byo_template_message(
        self, runner: CliRunner
    ) -> None:
        vid = self._add_vendor(runner)
        result = runner.invoke(
            app,
            [
                "tprm", "dd-questionnaire", "generate",
                "--vendor-id", vid,
                "--format", "sig",
            ],
        )
        assert result.exit_code == 1
        # Message should clearly state SIG isn't shipped + reference BYO
        assert "Shared Assessments" in result.output

    def test_invalid_output_format_errors(
        self, runner: CliRunner
    ) -> None:
        """v0.7.9 P0.2 second slice: xlsx is now valid; an invalid
        format like 'pdf' should be rejected, AND xlsx-without-output
        should be rejected with the binary-output guard."""
        vid = self._add_vendor(runner)
        # Truly invalid format
        result = runner.invoke(
            app,
            [
                "tprm", "dd-questionnaire", "generate",
                "--vendor-id", vid,
                "--output-format", "pdf",
            ],
        )
        assert result.exit_code == 1
        assert "json/csv/xlsx" in result.output
        # xlsx without --output errors on the binary-output guard
        result_xlsx = runner.invoke(
            app,
            [
                "tprm", "dd-questionnaire", "generate",
                "--vendor-id", vid,
                "--output-format", "xlsx",
            ],
        )
        assert result_xlsx.exit_code == 1
        assert "binary output" in result_xlsx.output.lower()

    def test_unknown_vendor_id_errors(
        self, runner: CliRunner
    ) -> None:
        result = runner.invoke(
            app,
            [
                "tprm", "dd-questionnaire", "generate",
                "--vendor-id", "00000000-0000-0000-0000-000000000000",
                "--format", "evidentia-generic",
            ],
        )
        assert result.exit_code == 1
