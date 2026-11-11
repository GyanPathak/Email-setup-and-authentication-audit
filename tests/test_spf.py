import pytest

from app.checks.spf import check_spf


class FakeDNSResolver:
    def __init__(self, response):
        self.response = response

    def query(self, domain, record_type):
        return self.response


def success(records):
    return {
        "domain": "example.com",
        "record_type": "TXT",
        "status": "success",
        "records": records,
        "error": None,
    }


def failure(status="timeout"):
    return {
        "domain": "example.com",
        "record_type": "TXT",
        "status": status,
        "records": [],
        "error": "DNS query failed.",
    }


def test_valid_restrictive_spf_record_passes():
    resolver = FakeDNSResolver(
        success(["v=spf1 -all"])
    )

    result = check_spf("example.com", resolver)

    assert result["status"] == "pass"


def test_permissive_spf_record_fails():
    resolver = FakeDNSResolver(
        success(["v=spf1 +all"])
    )

    result = check_spf("example.com", resolver)

    assert result["status"] == "fail"


@pytest.mark.parametrize("all_term", ["~all", "?all"])
def test_non_restrictive_all_mechanisms_warn(all_term):
    resolver = FakeDNSResolver(
        success([f"v=spf1 {all_term}"])
    )

    result = check_spf("example.com", resolver)

    assert result["status"] == "warning"


def test_missing_all_mechanism_warns():
    resolver = FakeDNSResolver(
        success(["v=spf1 include:_spf.google.com"])
    )

    result = check_spf("example.com", resolver)

    assert result["status"] == "warning"


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 unknownmechanism -all",
        "v=spf1 ip4:999.999.1.1 -all",
        "v=spf1 include -all",
    ],
)
def test_invalid_spf_syntax_fails(record):
    resolver = FakeDNSResolver(success([record]))

    result = check_spf("example.com", resolver)

    assert result["status"] == "fail"


def test_missing_spf_record_fails():
    resolver = FakeDNSResolver(
        success(["google-site-verification=abc123"])
    )

    result = check_spf("example.com", resolver)

    assert result["status"] == "fail"


def test_multiple_spf_records_fail():
    resolver = FakeDNSResolver(
        success(["v=spf1 -all", "v=spf1 +all"])
    )

    result = check_spf("example.com", resolver)

    assert result["status"] == "fail"


def test_dns_timeout_is_reported_as_error():
    resolver = FakeDNSResolver(failure("timeout"))

    result = check_spf("example.com", resolver)

    assert result["status"] == "error"
