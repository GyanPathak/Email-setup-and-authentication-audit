import pytest
from unittest.mock import Mock

from app.audit.domain_audit import run_domain_audit



def make_resolver():
    return Mock()


def test_invalid_domain_returns_invalid_input():
    result = run_domain_audit("not a domain", make_resolver())

    assert result["overall_status"] == "invalid_input"
    assert result["domain"] is None
    assert result["checks"] == {}


def test_dkim_is_not_checked_without_selectors(monkeypatch):
    import app.audit.domain_audit as audit

    monkeypatch.setattr(
        audit, "check_spf",
        lambda domain, resolver: {
            "domain": domain,
            "status": "pass",
            "record": "v=spf1 -all",
            "issues": [],
        },
    )
    monkeypatch.setattr(
        audit, "evaluate_spf",
        lambda domain, resolver: {
            "status": "success",
            "errors": [],
            "warnings": [],
            "limit_exceeded": False,
        },
    )
    monkeypatch.setattr(
        audit, "check_dmarc",
        lambda domain, resolver: {
            "domain": domain,
            "status": "success",
            "errors": [],
            "warnings": [],
        },
    )

    result = run_domain_audit("example.com", make_resolver())

    assert result["checks"]["dkim"]["status"] == "not_checked"
    assert result["overall_status"] == "partial"

    dkim_finding = next(
        (
            finding
            for finding in result["findings"]
            if finding["code"] == "dkim_not_checked"
        ),
        None,
    )

    assert dkim_finding is not None
    assert dkim_finding["severity"] == "info"


def test_valid_checks_return_pass(monkeypatch):
    import app.audit.domain_audit as audit

    monkeypatch.setattr(
        audit, "check_spf",
        lambda domain, resolver: {
            "domain": domain,
            "status": "pass",
            "record": "v=spf1 -all",
            "issues": [],
        },
    )
    monkeypatch.setattr(
        audit, "evaluate_spf",
        lambda domain, resolver: {
            "status": "success",
            "errors": [],
            "warnings": [],
            "limit_exceeded": False,
        },
    )
    monkeypatch.setattr(
        audit, "check_dkim",
        lambda domain, selectors, resolver: {
            "domain": domain,
            "status": "success",
            "selectors_checked": [
                {"selector": "google", "status": "valid"}
            ],
        },
    )
    monkeypatch.setattr(
        audit, "check_dmarc",
        lambda domain, resolver: {
            "domain": domain,
            "status": "success",
            "errors": [],
            "warnings": [],
        },
    )

    result = run_domain_audit(
        "example.com",
        make_resolver(),
        selectors=["google"],
    )

    assert result["overall_status"] == "pass"
    assert result["domain"] == "example.com"
    assert result["root_domain"] == "example.com"
    assert set(result["checks"]) == {"spf", "dkim", "dmarc"}


def test_dkim_dns_failure_is_partial(monkeypatch):
    import app.audit.domain_audit as audit

    monkeypatch.setattr(
        audit, "check_spf",
        lambda domain, resolver: {
            "status": "pass",
            "record": "v=spf1 -all",
            "issues": [],
        },
    )
    monkeypatch.setattr(
        audit, "evaluate_spf",
        lambda domain, resolver: {
            "status": "success",
            "errors": [],
            "warnings": [],
            "limit_exceeded": False,
        },
    )
    monkeypatch.setattr(
        audit, "check_dkim",
        lambda domain, selectors, resolver: {
            "status": "partial",
            "selectors_checked": [
                {
                    "selector": "google",
                    "status": "unverifiable",
                }
            ],
        },
    )
    monkeypatch.setattr(
        audit, "check_dmarc",
        lambda domain, resolver: {
            "status": "success",
            "errors": [],
            "warnings": [],
        },
    )

    result = run_domain_audit(
        "example.com",
        make_resolver(),
        selectors=["google"],
    )

    assert result["overall_status"] == "partial"
    assert any(
        finding["severity"] == "unverifiable"
        for finding in result["findings"]
    )


def test_missing_dmarc_is_failure(monkeypatch):
    import app.audit.domain_audit as audit

    monkeypatch.setattr(
        audit, "check_spf",
        lambda domain, resolver: {
            "status": "pass",
            "record": "v=spf1 -all",
            "issues": [],
        },
    )
    monkeypatch.setattr(
        audit, "evaluate_spf",
        lambda domain, resolver: {
            "status": "success",
            "errors": [],
            "warnings": [],
            "limit_exceeded": False,
        },
    )
    monkeypatch.setattr(
        audit, "check_dkim",
        lambda domain, selectors, resolver: {
            "status": "success",
            "selectors_checked": [
                {"selector": "google", "status": "valid"}
            ],
        },
    )
    monkeypatch.setattr(
        audit, "check_dmarc",
        lambda domain, resolver: {
            "status": "missing",
            "errors": [],
            "warnings": [],
        },
    )

    result = run_domain_audit(
        "example.com",
        make_resolver(),
        selectors=["google"],
    )

    assert result["overall_status"] == "fail"
    assert any(
        finding["code"] == "dmarc_missing"
        for finding in result["findings"]
    )

def test_checker_failure_without_findings_returns_fail():
    from app.audit.domain_audit import _get_overall_status

    checks = {
        "spf": {"status": "fail"},
        "dkim": {"status": "success"},
        "dmarc": {"status": "success"},
    }

    assert _get_overall_status([], checks) == "fail"


def test_unchecked_dkim_returns_partial():
    from app.audit.domain_audit import _get_overall_status

    checks = {
        "spf": {"status": "success"},
        "dkim": {"status": "not_checked"},
        "dmarc": {"status": "success"},
    }

    assert _get_overall_status([], checks) == "partial"


def test_warning_status_is_preserved():
    from app.audit.domain_audit import _get_overall_status

    checks = {
        "spf": {"status": "success"},
        "dkim": {"status": "success"},
        "dmarc": {"status": "warning"},
    }

    assert _get_overall_status([], checks) == "warning"


def test_nested_spf_failure_returns_fail():
    from app.audit.domain_audit import _get_overall_status

    checks = {
        "spf": {
            "configuration": {"status": "success"},
            "analysis": {"status": "fail"},
        },
        "dkim": {"status": "success"},
        "dmarc": {"status": "success"},
    }

    assert _get_overall_status([], checks) == "fail"


def test_recursive_spf_analysis_failure_affects_overall_status(monkeypatch):
    import app.audit.domain_audit as audit

    monkeypatch.setattr(
        audit,
        "check_spf",
        lambda domain, resolver: {
            "status": "pass",
            "record": "v=spf1 -all",
            "issues": [],
        },
    )

    monkeypatch.setattr(
        audit,
        "evaluate_spf",
        lambda domain, resolver: {
            "status": "fail",
            "errors": [],
            "warnings": [],
            "limit_exceeded": False,
        },
    )

    monkeypatch.setattr(
        audit,
        "check_dmarc",
        lambda domain, resolver: {
            "status": "success",
            "errors": [],
            "warnings": [],
        },
    )

    monkeypatch.setattr(
        audit,
        "check_dkim",
        lambda domain, selectors, resolver: {
            "status": "success",
            "selectors_checked": [
                {"selector": "google", "status": "valid"}
            ],
        },
    )

    result = audit.run_domain_audit(
        "example.com",
        make_resolver(),
        selectors=["google"],
    )

    assert result["checks"]["spf"]["configuration"]["status"] == "pass"
    assert result["checks"]["spf"]["analysis"]["status"] == "fail"
    assert result["overall_status"] == "fail"

def test_invalid_spf_syntax_causes_unified_audit_failure(monkeypatch):
    import app.audit.domain_audit as audit

    class FakeDNSResolver:
        def query(self, domain, record_type):
            if domain == "example.com":
                return {
                    "domain": domain,
                    "record_type": record_type,
                    "status": "success",
                    "records": ["v=spf1 unknownmechanism -all"],
                    "error": None,
                }

            return {
                "domain": domain,
                "record_type": record_type,
                "status": "not_found",
                "records": [],
                "error": None,
            }

    # Keep this test focused on SPF.
    monkeypatch.setattr(
        audit,
        "check_dkim",
        lambda domain, selectors, resolver: {
            "domain": domain,
            "status": "success",
            "selectors_checked": [
                {"selector": "google", "status": "valid"}
            ],
        },
    )

    monkeypatch.setattr(
        audit,
        "check_dmarc",
        lambda domain, resolver: {
            "domain": domain,
            "status": "success",
            "errors": [],
            "warnings": [],
        },
    )

    result = audit.run_domain_audit(
        "example.com",
        FakeDNSResolver(),
        selectors=["google"],
    )

    assert result["checks"]["spf"]["configuration"]["status"] == "fail"
    assert result["checks"]["spf"]["analysis"]["status"] == "error"
    assert result["overall_status"] == "fail"

def test_spf_softfail_is_info_when_dmarc_enforces_rejection(monkeypatch):
    import app.audit.domain_audit as audit

    monkeypatch.setattr(
        audit,
        "check_spf",
        lambda domain, resolver: {
            "domain": domain,
            "status": "warning",
            "record": "v=spf1 include:_spf.google.com ~all",
            "issues": [
                {
                    "code": "spf_softfail_all",
                    "severity": "warning",
                    "message": "The SPF record uses ~all.",
                    "recommendation": "Review whether -all is appropriate.",
                }
            ],
        },
    )

    monkeypatch.setattr(
        audit,
        "evaluate_spf",
        lambda domain, resolver: {
            "status": "success",
            "errors": [],
            "warnings": [],
            "limit_exceeded": False,
        },
    )

    monkeypatch.setattr(
        audit,
        "check_dkim",
        lambda domain, selectors, resolver: {
            "domain": domain,
            "status": "success",
            "selectors_checked": [
                {"selector": "google", "status": "valid"}
            ],
        },
    )

    monkeypatch.setattr(
        audit,
        "check_dmarc",
        lambda domain, resolver: {
            "domain": domain,
            "status": "success",
            "policy": "reject",
            "tags": {"p": "reject"},
            "errors": [],
            "warnings": [],
        },
    )

    result = audit.run_domain_audit(
        "example.com",
        make_resolver(),
        selectors=["google"],
    )

    finding = next(
        item for item in result["findings"]
        if item["code"] == "spf_softfail_all"
    )

    assert finding["severity"] == "info"
    assert result["checks"]["spf"]["configuration"]["status"] == "warning"
    assert result["overall_status"] == "pass"

@pytest.mark.parametrize(
    "dmarc_check, expected_severity",
    [
        (
            {
                "status": "success",
                "policy": "reject",
                "tags": {"p": "reject"},
                "errors": [],
                "warnings": [],
            },
            "info",
        ),
        (
            {
                "status": "success",
                "policy": "quarantine",
                "tags": {"p": "quarantine", "pct": "100"},
                "errors": [],
                "warnings": [],
            },
            "info",
        ),
        (
            {
                "status": "success",
                "policy": "none",
                "tags": {"p": "none"},
                "errors": [],
                "warnings": [],
            },
            "warning",
        ),
        (
            {
                "status": "success",
                "policy": "reject",
                "tags": {"p": "reject", "pct": "20"},
                "errors": [],
                "warnings": [],
            },
            "warning",
        ),
        (
            {
                "status": "missing",
                "policy": None,
                "tags": {},
                "errors": [],
                "warnings": [],
            },
            "warning",
        ),
        (
            {
                "status": "invalid",
                "policy": "reject",
                "tags": {"p": "reject"},
                "errors": ["Invalid DMARC record."],
                "warnings": [],
            },
            "warning",
        ),
        (
            {
                "status": "unverifiable",
                "policy": "reject",
                "tags": {"p": "reject"},
                "errors": ["DNS lookup timed out."],
                "warnings": [],
            },
            "warning",
        ),
    ],
)
def test_spf_softfail_severity_depends_on_dmarc_policy(
    monkeypatch, dmarc_check, expected_severity
):
    import app.audit.domain_audit as audit

    monkeypatch.setattr(
        audit,
        "check_spf",
        lambda domain, resolver: {
            "domain": domain,
            "status": "warning",
            "record": "v=spf1 include:_spf.google.com ~all",
            "issues": [
                {
                    "code": "spf_softfail_all",
                    "severity": "warning",
                    "message": "The SPF record uses ~all.",
                    "recommendation": "Review whether -all is appropriate.",
                }
            ],
        },
    )

    monkeypatch.setattr(
        audit,
        "evaluate_spf",
        lambda domain, resolver: {
            "status": "success",
            "errors": [],
            "warnings": [],
            "limit_exceeded": False,
        },
    )

    monkeypatch.setattr(
        audit,
        "check_dkim",
        lambda domain, selectors, resolver: {
            "domain": domain,
            "status": "success",
            "selectors_checked": [
                {"selector": "google", "status": "valid"}
            ],
        },
    )

    monkeypatch.setattr(
        audit,
        "check_dmarc",
        lambda domain, resolver: dmarc_check,
    )

    result = audit.run_domain_audit(
        "example.com",
        make_resolver(),
        selectors=["google"],
    )

    finding = next(
        item for item in result["findings"]
        if item["code"] == "spf_softfail_all"
    )

    assert finding["severity"] == expected_severity



def test_every_finding_has_required_explanation_fields(monkeypatch):
    import app.audit.domain_audit as audit

    monkeypatch.setattr(
        audit,
        "check_spf",
        lambda domain, resolver: {
            "domain": domain,
            "status": "warning",
            "record": None,
            "issues": [],
        },
    )
    monkeypatch.setattr(
        audit,
        "check_dmarc",
        lambda domain, resolver: {
            "domain": domain,
            "status": "missing",
            "errors": [],
            "warnings": [],
        },
    )

    result = audit.run_domain_audit("example.com", make_resolver())

    required_fields = {
        "meaning",
        "why_it_matters",
        "caution",
        "verification",
    }

    assert result["findings"]

    for finding in result["findings"]:
        assert required_fields.issubset(finding.keys())
        assert all(
            isinstance(finding[field], str) and finding[field].strip()
            for field in required_fields
        )


def test_spf_softfail_explanation_generates_valid_dns_example():
    from app.audit.finding_explanations import get_finding_explanation

    record = (
        "v=spf1 include:_spf.google.com "
        "include:example.com ~all"
    )

    explanation = get_finding_explanation(
        {"code": "spf_softfail_all"},
        {
            "spf": {"configuration": {"record": record}},
            "dmarc": {
                "status": "success",
                "policy": "none",
                "tags": {"p": "none"},
            },
        },
    )

    assert explanation["dns_example"]["current_record"] == record
    assert explanation["dns_example"]["alternative_record"] == (
        "v=spf1 include:_spf.google.com include:example.com -all"
    )


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 include: ~all",
        "v=spf1 include:_spf.google.com ~all -all",
        "v=spf1 include:_spf.google.com -all",
    ],
)
def test_invalid_or_non_softfail_record_has_no_dns_example(record):
    from app.audit.finding_explanations import get_finding_explanation

    explanation = get_finding_explanation(
        {"code": "spf_softfail_all"},
        {
            "spf": {"configuration": {"record": record}},
            "dmarc": {"status": "missing", "tags": {}},
        },
    )

    assert "dns_example" not in explanation


def test_unknown_finding_code_uses_fallback_explanation():
    from app.audit.finding_explanations import (
        DEFAULT_EXPLANATION,
        get_finding_explanation,
    )

    explanation = get_finding_explanation(
        {"code": "future_unknown_finding"},
        {},
    )

    assert explanation == DEFAULT_EXPLANATION
