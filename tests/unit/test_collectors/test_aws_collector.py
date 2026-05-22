"""AWS collector tests using ``moto`` for the AWS SDK backend.

Covers:
- test_connection (STS get-caller-identity)
- collect_config_findings (AWS Config evaluations)
- collect_security_hub_findings (Security Hub batch-import + get-findings)
- collect_all (orchestration)
- error handling when a sub-service fails

``moto`` mocks boto3 transport-level; the collector code paths run
unchanged against the mock. No real AWS network traffic.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from evidentia_collectors.aws import AwsCollector
from evidentia_core.models.common import Severity
from evidentia_core.models.finding import FindingStatus

# ── test_connection ──────────────────────────────────────────────────────


class TestTestConnection:
    def test_success_returns_caller_identity(self) -> None:
        from moto import mock_aws

        with mock_aws():
            import boto3

            session = boto3.Session(
                region_name="us-east-1",
                aws_access_key_id="AKIA-moto",
                aws_secret_access_key="secret",
            )
            collector = AwsCollector(
                region="us-east-1",
                _clients={"sts": session.client("sts")},
            )
            info = collector.test_connection()

        assert "account" in info
        assert info["region"] == "us-east-1"


# ── Config collector ─────────────────────────────────────────────────────


class TestConfigCollector:
    def test_noncompliant_rule_produces_findings(self) -> None:
        from unittest.mock import MagicMock

        # moto's AWS Config support is thin; use a MagicMock paginator
        # that mimics the paginator interface we rely on.
        mock_config = MagicMock()

        def _describe_paginator() -> Any:
            p = MagicMock()
            p.paginate.return_value = iter(
                [
                    {
                        "ComplianceByConfigRules": [
                            {
                                "ConfigRuleName": "s3-bucket-public-read-prohibited",
                                "Compliance": {
                                    "ComplianceType": "NON_COMPLIANT",
                                },
                            },
                            {
                                "ConfigRuleName": "iam-user-mfa-enabled",
                                "Compliance": {
                                    "ComplianceType": "COMPLIANT",
                                },
                            },
                        ]
                    }
                ]
            )
            return p

        def _details_paginator() -> Any:
            p = MagicMock()
            p.paginate.return_value = iter(
                [
                    {
                        "EvaluationResults": [
                            {
                                "EvaluationResultIdentifier": {
                                    "EvaluationResultQualifier": {
                                        "ResourceType": "AWS::S3::Bucket",
                                        "ResourceId": "bucket-one",
                                    }
                                },
                                "Annotation": "Bucket has public read ACL.",
                                "ResultRecordedTime": datetime(
                                    2026, 4, 15, 12, 0, 0, tzinfo=UTC
                                ),
                            },
                            {
                                "EvaluationResultIdentifier": {
                                    "EvaluationResultQualifier": {
                                        "ResourceType": "AWS::S3::Bucket",
                                        "ResourceId": "bucket-two",
                                    }
                                },
                                "Annotation": "Bucket has public read ACL.",
                                "ResultRecordedTime": datetime(
                                    2026, 4, 15, 12, 0, 0, tzinfo=UTC
                                ),
                            },
                        ]
                    }
                ]
            )
            return p

        def _get_paginator(name: str) -> Any:
            if name == "describe_compliance_by_config_rule":
                return _describe_paginator()
            if name == "get_compliance_details_by_config_rule":
                return _details_paginator()
            raise KeyError(name)

        mock_config.get_paginator.side_effect = _get_paginator

        collector = AwsCollector(region="us-east-1", _clients={"config": mock_config})
        findings = collector.collect_config_findings()

        assert len(findings) == 2
        for f in findings:
            assert f.source_system == "aws-config"
            assert f.control_ids == ["AC-3", "AC-6"]
            assert f.resource_type == "AWS::S3::Bucket"
            assert f.severity == Severity.MEDIUM
            assert f.status == FindingStatus.ACTIVE

    def test_compliant_rules_yield_no_findings(self) -> None:
        from unittest.mock import MagicMock

        mock_config = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = iter(
            [
                {
                    "ComplianceByConfigRules": [
                        {
                            "ConfigRuleName": "iam-user-mfa-enabled",
                            "Compliance": {"ComplianceType": "COMPLIANT"},
                        }
                    ]
                }
            ]
        )
        mock_config.get_paginator.return_value = paginator

        collector = AwsCollector(region="us-east-1", _clients={"config": mock_config})
        assert collector.collect_config_findings() == []


# ── Security Hub collector ───────────────────────────────────────────────


class TestSecurityHubCollector:
    def test_builds_finding_from_security_hub_response(self) -> None:
        from unittest.mock import MagicMock

        mock_sh = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = iter(
            [
                {
                    "Findings": [
                        {
                            "Id": "arn:aws:securityhub:us-east-1:111:finding/abc",
                            "Title": "S3 bucket public",
                            "Description": "A public S3 bucket exists.",
                            "Severity": {"Label": "HIGH"},
                            "Workflow": {"Status": "NEW"},
                            "AwsAccountId": "111222333444",
                            "CreatedAt": "2026-04-15T10:00:00.000Z",
                            "UpdatedAt": "2026-04-15T11:00:00.000Z",
                            "Compliance": {
                                "SecurityControlId": "S3.3",
                                "RelatedRequirements": [
                                    "NIST.800-53.r5 AC-3",
                                    "NIST.800-53.r5 AC-6",
                                ],
                            },
                            "Resources": [
                                {
                                    "Id": "arn:aws:s3:::my-bucket",
                                    "Type": "AwsS3Bucket",
                                    "Region": "us-east-1",
                                }
                            ],
                        }
                    ]
                }
            ]
        )
        mock_sh.get_paginator.return_value = paginator

        collector = AwsCollector(
            region="us-east-1", _clients={"securityhub": mock_sh}
        )
        findings = collector.collect_security_hub_findings()

        assert len(findings) == 1
        f = findings[0]
        assert f.title == "S3 bucket public"
        assert f.severity == Severity.HIGH
        assert f.source_system == "aws-security-hub"
        assert f.resource_type == "AwsS3Bucket"
        assert f.resource_account == "111222333444"
        # Control IDs should come from the RelatedRequirements (preferred).
        assert f.control_ids == ["AC-3", "AC-6"]

    def test_falls_back_to_mapping_table_when_related_requirements_absent(
        self,
    ) -> None:
        from unittest.mock import MagicMock

        mock_sh = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = iter(
            [
                {
                    "Findings": [
                        {
                            "Id": "f-2",
                            "Title": "IAM root access key",
                            "Description": "Root has access keys.",
                            "Severity": {"Label": "CRITICAL"},
                            "Workflow": {"Status": "NEW"},
                            "Compliance": {
                                "SecurityControlId": "IAM.1",
                                "RelatedRequirements": [],
                            },
                            "Resources": [
                                {"Id": "acct-1", "Type": "AwsAccount", "Region": "us-east-1"}
                            ],
                        }
                    ]
                }
            ]
        )
        mock_sh.get_paginator.return_value = paginator

        collector = AwsCollector(
            region="us-east-1", _clients={"securityhub": mock_sh}
        )
        findings = collector.collect_security_hub_findings()

        assert len(findings) == 1
        # IAM.1 -> fsbp.iam.1 -> [AC-6, IA-2]
        assert set(findings[0].control_ids) == {"AC-6", "IA-2"}
        assert findings[0].severity == Severity.CRITICAL

    def test_max_findings_cap_enforced(self) -> None:
        from unittest.mock import MagicMock

        mock_sh = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = iter(
            [
                {
                    "Findings": [
                        {
                            "Id": f"f-{i}",
                            "Title": f"Finding {i}",
                            "Description": "x",
                            "Severity": {"Label": "LOW"},
                            "Workflow": {"Status": "NEW"},
                            "Compliance": {"SecurityControlId": "1.4"},
                            "Resources": [
                                {"Id": "r", "Type": "x", "Region": "us-east-1"}
                            ],
                        }
                        for i in range(20)
                    ]
                }
            ]
        )
        mock_sh.get_paginator.return_value = paginator

        collector = AwsCollector(
            region="us-east-1", _clients={"securityhub": mock_sh}
        )
        findings = collector.collect_security_hub_findings(max_findings=5)
        assert len(findings) == 5


# ── collect_all orchestration ────────────────────────────────────────────


class TestCollectAll:
    def test_returns_union_of_sub_collectors(self) -> None:
        from unittest.mock import MagicMock

        config = MagicMock()
        config_paginator = MagicMock()
        config_paginator.paginate.return_value = iter(
            [
                {
                    "ComplianceByConfigRules": [
                        {
                            "ConfigRuleName": "cloudtrail-enabled",
                            "Compliance": {"ComplianceType": "NON_COMPLIANT"},
                        }
                    ]
                }
            ]
        )
        details = MagicMock()
        details.paginate.return_value = iter(
            [
                {
                    "EvaluationResults": [
                        {
                            "EvaluationResultIdentifier": {
                                "EvaluationResultQualifier": {
                                    "ResourceType": "AWS::CloudTrail::Trail",
                                    "ResourceId": "trail-1",
                                }
                            },
                            "Annotation": "No trail enabled.",
                        }
                    ]
                }
            ]
        )

        def _cfg_paginator(name: str) -> Any:
            if name == "describe_compliance_by_config_rule":
                return config_paginator
            if name == "get_compliance_details_by_config_rule":
                return details
            raise KeyError(name)

        config.get_paginator.side_effect = _cfg_paginator

        sh = MagicMock()
        sh_paginator = MagicMock()
        sh_paginator.paginate.return_value = iter(
            [
                {
                    "Findings": [
                        {
                            "Id": "sh-1",
                            "Title": "finding",
                            "Description": "x",
                            "Severity": {"Label": "MEDIUM"},
                            "Workflow": {"Status": "NEW"},
                            "Compliance": {"SecurityControlId": "S3.3"},
                            "Resources": [
                                {"Id": "r", "Type": "x", "Region": "us-east-1"}
                            ],
                        }
                    ]
                }
            ]
        )
        sh.get_paginator.return_value = sh_paginator

        collector = AwsCollector(
            region="us-east-1",
            _clients={"config": config, "securityhub": sh},
        )
        findings = collector.collect_all()
        assert len(findings) == 2
        sources = {f.source_system for f in findings}
        assert "aws-config" in sources
        assert "aws-security-hub" in sources

    def test_subcollector_failure_is_swallowed_and_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from unittest.mock import MagicMock

        config = MagicMock()
        config.get_paginator.side_effect = RuntimeError("region has no config")

        sh = MagicMock()
        sh_paginator = MagicMock()
        sh_paginator.paginate.return_value = iter(
            [
                {
                    "Findings": [
                        {
                            "Id": "sh-2",
                            "Title": "x",
                            "Description": "x",
                            "Severity": {"Label": "LOW"},
                            "Workflow": {"Status": "NEW"},
                            "Compliance": {"SecurityControlId": "1.4"},
                            "Resources": [
                                {"Id": "r", "Type": "x", "Region": "us-east-1"}
                            ],
                        }
                    ]
                }
            ]
        )
        sh.get_paginator.return_value = sh_paginator

        collector = AwsCollector(
            region="us-east-1",
            _clients={"config": config, "securityhub": sh},
        )
        # Should not raise; Security Hub findings still returned.
        findings = collector.collect_all()
        assert len(findings) == 1
        assert findings[0].source_system == "aws-security-hub"
        assert any(
            "AWS Config collector failed" in r.message for r in caplog.records
        )


# ── v0.10.0: compliance_status + remediation + OCSF round-trip ───────────


def _config_collector() -> AwsCollector:
    """An AwsCollector whose Config client yields one non-compliant rule."""
    from unittest.mock import MagicMock

    describe = MagicMock()
    describe.paginate.return_value = iter(
        [
            {
                "ComplianceByConfigRules": [
                    {
                        "ConfigRuleName": "s3-bucket-public-read-prohibited",
                        "Compliance": {"ComplianceType": "NON_COMPLIANT"},
                    }
                ]
            }
        ]
    )
    details = MagicMock()
    details.paginate.return_value = iter(
        [
            {
                "EvaluationResults": [
                    {
                        "EvaluationResultIdentifier": {
                            "EvaluationResultQualifier": {
                                "ResourceType": "AWS::S3::Bucket",
                                "ResourceId": "bucket-one",
                            }
                        },
                        "Annotation": "Public read ACL.",
                    }
                ]
            }
        ]
    )
    mock_config = MagicMock()
    mock_config.get_paginator.side_effect = lambda name: (
        describe
        if name == "describe_compliance_by_config_rule"
        else details
    )
    return AwsCollector(region="us-east-1", _clients={"config": mock_config})


def _sh_collector(raw_finding: dict[str, Any]) -> AwsCollector:
    """An AwsCollector whose Security Hub client yields one finding."""
    from unittest.mock import MagicMock

    paginator = MagicMock()
    paginator.paginate.return_value = iter([{"Findings": [raw_finding]}])
    mock_sh = MagicMock()
    mock_sh.get_paginator.return_value = paginator
    return AwsCollector(region="us-east-1", _clients={"securityhub": mock_sh})


def test_config_findings_have_fail_compliance_status() -> None:
    from evidentia_core.models.finding import ComplianceStatus

    findings = _config_collector().collect_config_findings()
    assert findings
    assert all(
        f.compliance_status == ComplianceStatus.FAIL for f in findings
    )


def test_security_hub_failed_status_maps_to_fail_with_remediation() -> None:
    from evidentia_core.models.finding import ComplianceStatus

    raw = {
        "Id": "f-fail",
        "Title": "S3 bucket public",
        "Description": "x",
        "Severity": {"Label": "HIGH"},
        "Workflow": {"Status": "NEW"},
        "Compliance": {"Status": "FAILED", "SecurityControlId": "S3.3"},
        "Remediation": {
            "Recommendation": {
                "Text": "Enable S3 Block Public Access.",
                "Url": "https://docs.aws.amazon.com/console/securityhub/S3.3",
            }
        },
        "Resources": [
            {"Id": "arn:aws:s3:::b", "Type": "AwsS3Bucket", "Region": "us-east-1"}
        ],
    }
    finding = _sh_collector(raw).collect_security_hub_findings()[0]
    assert finding.compliance_status == ComplianceStatus.FAIL
    assert finding.remediation == "Enable S3 Block Public Access."


def test_security_hub_passed_status_maps_to_pass() -> None:
    from evidentia_core.models.finding import ComplianceStatus

    raw = {
        "Id": "f-pass",
        "Title": "S3 bucket OK",
        "Description": "x",
        "Severity": {"Label": "INFORMATIONAL"},
        "Workflow": {"Status": "NEW"},
        "Compliance": {"Status": "PASSED", "SecurityControlId": "S3.3"},
        "Resources": [
            {"Id": "arn:aws:s3:::b", "Type": "AwsS3Bucket", "Region": "us-east-1"}
        ],
    }
    finding = _sh_collector(raw).collect_security_hub_findings()[0]
    assert finding.compliance_status == ComplianceStatus.PASS


def test_aws_finding_ocsf_round_trips() -> None:
    pytest.importorskip("py_ocsf_models")
    from evidentia_core.ocsf import finding_from_ocsf, finding_to_ocsf

    finding = _config_collector().collect_config_findings()[0]
    assert finding_from_ocsf(finding_to_ocsf(finding)) == finding
