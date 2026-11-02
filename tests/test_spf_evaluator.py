
import pytest

from app.checks.spf_evaluator import evaluate_spf


class FakeDNSResolver:
    """Mock DNS resolver for isolated SPF evaluator tests."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def query(self, domain, record_type):
        self.calls.append((domain, record_type))

        return self.responses.get(
            domain,
            {
                "domain": domain,
                "record_type": record_type,
                "status": "not_found",
                "records": [],
                "error": None,
            },
        )


def success(domain, records):
    return {
        "domain": domain,
        "record_type": "TXT",
        "status": "success",
        "records": records,
        "error": None,
    }


def failure(domain, status="timeout"):
    return {
        "domain": domain,
        "record_type": "TXT",
        "status": status,
        "records": [],
        "error": "DNS query failed.",
    }


def test_simple_spf_record():
    resolver = FakeDNSResolver({
        "example.com": success(
            "example.com",
            ["v=spf1 ip4:192.0.2.1 -all"],
        )
    })

    result = evaluate_spf("example.com", resolver)

    assert result["status"] == "success"
    assert result["records_checked"] == ["example.com"]
    assert result["dns_lookup_terms"] == 0


def test_include_is_recursively_checked():
    resolver = FakeDNSResolver({
        "example.com": success(
            "example.com",
            ["v=spf1 include:mail.example.com -all"],
        ),
        "mail.example.com": success(
            "mail.example.com",
            ["v=spf1 a -all"],
        ),
    })

    result = evaluate_spf("example.com", resolver)

    assert result["status"] == "success"
    assert "example.com" in result["records_checked"]
    assert "mail.example.com" in result["records_checked"]
    assert result["dns_lookup_terms"] == 2


def test_nested_include_is_recursively_checked():
    resolver = FakeDNSResolver({
        "example.com": success(
            "example.com",
            ["v=spf1 include:mail.example.com -all"],
        ),
        "mail.example.com": success(
            "mail.example.com",
            ["v=spf1 include:third.example.com -all"],
        ),
        "third.example.com": success(
            "third.example.com",
            ["v=spf1 ip4:192.0.2.1 -all"],
        ),
    })

    result = evaluate_spf("example.com", resolver)

    assert result["status"] == "success"
    assert len(result["records_checked"]) == 3
    assert result["dns_lookup_terms"] == 2


def test_redirect_is_recursively_checked():
    resolver = FakeDNSResolver({
        "example.com": success(
            "example.com",
            ["v=spf1 redirect=_spf.example.com"],
        ),
        "_spf.example.com": success(
            "_spf.example.com",
            ["v=spf1 ip4:192.0.2.1 -all"],
        ),
    })

    result = evaluate_spf("example.com", resolver)

    assert result["status"] == "success"
    assert "_spf.example.com" in result["records_checked"]
    assert result["dns_lookup_terms"] == 1


def test_circular_include_is_detected():
    resolver = FakeDNSResolver({
        "example.com": success(
            "example.com",
            ["v=spf1 include:mail.example.com -all"],
        ),
        "mail.example.com": success(
            "mail.example.com",
            ["v=spf1 include:example.com -all"],
        ),
    })

    result = evaluate_spf("example.com", resolver)

    assert result["status"] == "error"
    assert "example.com" in result["circular_references"]


def test_missing_include_record_is_reported():
    resolver = FakeDNSResolver({
        "example.com": success(
            "example.com",
            ["v=spf1 include:missing.example.com -all"],
        ),
    })

    result = evaluate_spf("example.com", resolver)

    assert result["status"] == "error"
    assert result["void_lookups"] == 1
    assert result["dns_lookup_terms"] == 1


def test_more_than_two_void_lookups_is_reported():
    resolver = FakeDNSResolver({
        "example.com": success(
            "example.com",
            [
                "v=spf1 "
                "include:a.example.com "
                "include:b.example.com "
                "include:c.example.com -all"
            ],
        ),
    })

    result = evaluate_spf("example.com", resolver)

    assert result["void_lookups"] == 3
    assert result["status"] == "error"
    assert any(
        "void lookups" in error.lower()
        for error in result["errors"]
    )


def test_dns_timeout_is_reported():
    resolver = FakeDNSResolver({
        "example.com": failure("example.com", "timeout"),
    })

    result = evaluate_spf("example.com", resolver)

    assert result["status"] == "error"
    assert any(
        "timeout" in error.lower()
        for error in result["errors"]
    )


def test_multiple_spf_records_are_reported():
    resolver = FakeDNSResolver({
        "example.com": success(
            "example.com",
            [
                "v=spf1 -all",
                "v=spf1 +all",
            ],
        ),
    })

    result = evaluate_spf("example.com", resolver)

    assert result["status"] == "error"
    assert any(
        "multiple spf records" in error.lower()
        for error in result["errors"]
    )


def test_invalid_spf_record_is_reported():
    resolver = FakeDNSResolver({
        "example.com": success(
            "example.com",
            ["v=spf1 unknownmechanism -all"],
        ),
    })

    result = evaluate_spf("example.com", resolver)

    assert result["status"] == "error"
    assert any(
        "invalid spf record" in error.lower()
        for error in result["errors"]
    )


def test_more_than_ten_dns_lookup_terms_is_reported():
    mechanisms = " ".join(["a"] * 11)

    resolver = FakeDNSResolver({
        "example.com": success(
            "example.com",
            [f"v=spf1 {mechanisms} -all"],
        ),
    })

    result = evaluate_spf("example.com", resolver)

    assert result["dns_lookup_terms"] == 11
    assert result["limit_exceeded"] is True
    assert result["status"] == "error"


def test_exactly_ten_dns_lookup_terms_does_not_exceed_limit():
    mechanisms = " ".join(["a"] * 10)

    resolver = FakeDNSResolver({
        "example.com": success(
            "example.com",
            [f"v=spf1 {mechanisms} -all"],
        ),
    })

    result = evaluate_spf("example.com", resolver)

    assert result["dns_lookup_terms"] == 10
    assert result["limit_exceeded"] is False
    assert result["status"] == "success"


def test_macro_based_include_is_not_resolved():
    resolver = FakeDNSResolver({
        "example.com": success(
            "example.com",
            ["v=spf1 include:%{d}.example.net -all"],
        ),
    })

    result = evaluate_spf("example.com", resolver)

    assert result["status"] == "success"
    assert result["unresolved_macro_targets"] == ["example.com"]
    assert len(result["warnings"]) == 1


def test_repeated_include_target_is_not_queried_twice():
    resolver = FakeDNSResolver({
        "example.com": success(
            "example.com",
            [
                "v=spf1 "
                "include:mail.example.com "
                "include:mail.example.com -all"
            ],
        ),
        "mail.example.com": success(
            "mail.example.com",
            ["v=spf1 ip4:192.0.2.1 -all"],
        ),
    })

    result = evaluate_spf("example.com", resolver)

    assert result["status"] == "success"
    assert result["dns_lookup_terms"] == 2

    mail_queries = [
        call for call in resolver.calls
        if call[0] == "mail.example.com"
    ]

    assert len(mail_queries) == 1
