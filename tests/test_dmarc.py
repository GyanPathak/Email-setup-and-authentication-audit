
from unittest.mock import Mock

import pytest

from app.checks.dmarc import check_dmarc


@pytest.fixture
def dns_resolver():
    return Mock()


def make_dns_result(status, records=None, error=None):
    return {
        "status": status,
        "records": records or [],
        "error": error,
    }


def test_valid_dmarc_record(dns_resolver):
    dns_resolver.query.return_value = make_dns_result(
        "success",
        ["v=DMARC1; p=reject"]
    )

    result = check_dmarc("example.com", dns_resolver)

    assert result["status"] == "success"
    assert result["policy"] == "reject"
    dns_resolver.query.assert_called_once_with(
        "_dmarc.example.com", "TXT"
    )


def test_valid_none_policy_generates_warning(dns_resolver):
    dns_resolver.query.return_value = make_dns_result(
        "success",
        ["v=DMARC1; p=none"]
    )

    result = check_dmarc("example.com", dns_resolver)

    assert result["status"] == "success"
    assert result["warnings"]


def test_missing_dmarc_record(dns_resolver):
    dns_resolver.query.return_value = make_dns_result("not_found")

    result = check_dmarc("example.com", dns_resolver)

    assert result["status"] == "missing"


def test_no_dmarc_among_txt_records(dns_resolver):
    dns_resolver.query.return_value = make_dns_result(
        "success",
        ["google-site-verification=abc123"]
    )

    result = check_dmarc("example.com", dns_resolver)

    assert result["status"] == "missing"


def test_multiple_dmarc_records(dns_resolver):
    dns_resolver.query.return_value = make_dns_result(
        "success",
        [
            "v=DMARC1; p=reject",
            "v=DMARC1; p=none",
        ]
    )

    result = check_dmarc("example.com", dns_resolver)

    assert result["status"] == "error"
    assert any("Multiple" in error for error in result["errors"])


def test_invalid_dmarc_record(dns_resolver):
    dns_resolver.query.return_value = make_dns_result(
        "success",
        ["v=DMARC1; p=invalid"]
    )

    result = check_dmarc("example.com", dns_resolver)

    assert result["status"] == "invalid"
    assert result["errors"]


def test_dns_timeout(dns_resolver):
    dns_resolver.query.return_value = make_dns_result(
        "timeout",
        error="DNS query timed out"
    )

    result = check_dmarc("example.com", dns_resolver)

    assert result["status"] == "unverifiable"
    assert result["errors"]


@pytest.mark.parametrize(
    "dns_status",
    ["network_error", "invalid_response"]
)
def test_other_dns_failures(dns_resolver, dns_status):
    dns_resolver.query.return_value = make_dns_result(
        dns_status,
        error="DNS lookup failed"
    )

    result = check_dmarc("example.com", dns_resolver)

    assert result["status"] == "error"


def test_invalid_domain_input(dns_resolver):
    result = check_dmarc("", dns_resolver)

    assert result["status"] == "invalid_input"
    dns_resolver.query.assert_not_called()


def test_domain_is_normalized(dns_resolver):
    dns_resolver.query.return_value = make_dns_result(
        "success",
        ["v=DMARC1; p=reject"]
    )

    result = check_dmarc(" EXAMPLE.COM ", dns_resolver)

    assert result["domain"] == "example.com"
    dns_resolver.query.assert_called_once_with(
        "_dmarc.example.com", "TXT"
    )


def test_empty_dns_records(dns_resolver):
    dns_resolver.query.return_value = make_dns_result(
        "success",
        []
    )

    result = check_dmarc("example.com", dns_resolver)

    assert result["status"] == "missing"



def test_unsupported_dmarc_version_is_detected(dns_resolver):
    dns_resolver.query.return_value = make_dns_result(
        "success",
        ["v=DMARC2; p=reject"]
    )

    result = check_dmarc("example.com", dns_resolver)

    assert result["status"] == "invalid"


def test_unexpected_dns_response_type(dns_resolver):
    dns_resolver.query.return_value = None

    result = check_dmarc("example.com", dns_resolver)

    assert result["status"] == "error"


def test_dns_response_without_status(dns_resolver):
    dns_resolver.query.return_value = {"records": []}

    result = check_dmarc("example.com", dns_resolver)

    assert result["status"] == "error"


def test_dns_resolver_raises_exception(dns_resolver):
    dns_resolver.query.side_effect = RuntimeError("Unexpected failure")

    result = check_dmarc("example.com", dns_resolver)

    assert result["status"] == "error"
    assert "Unexpected DNS resolver exception" in result["errors"][0]


def test_invalid_records_collection(dns_resolver):
    dns_resolver.query.return_value = make_dns_result(
        "success",
        records="v=DMARC1; p=reject"
    )

    result = check_dmarc("example.com", dns_resolver)

    assert result["status"] == "error"
