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

    assert result["checks"]["spf"]["analysis"]["status"] == "fail"
    assert result["overall_status"] == "fail"