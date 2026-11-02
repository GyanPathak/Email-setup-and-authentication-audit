
import dns.message
import dns.resolver
import pytest

from app.services.dns_resolver import DNSResolver


class FakeRecord:
    def __init__(self, text, strings=None):
        self._text = text
        self.strings = strings or ()

    def to_text(self):
        return self._text



class FakeResolver:
    def __init__(self, response=None, error=None):
        self.response = response or []
        self.error = error
        self.last_kwargs = {}

    def resolve(self, *args, **kwargs):
        self.last_kwargs = kwargs

        if self.error:
            raise self.error

        return self.response



@pytest.fixture
def resolver():
    return DNSResolver()


def test_successful_txt_query(resolver):
    resolver._resolver = FakeResolver(
        response=[
            FakeRecord(
                '"v=spf1 include:example.com ~all"',
                strings=(b"v=spf1 include:example.com ~all",),
            )
        ]
    )

    result = resolver.query("example.com", "TXT")

    assert result["status"] == "success"
    assert result["records"] == [
        "v=spf1 include:example.com ~all"
    ]
    assert result["error"] is None


def test_successful_mx_query(resolver):
    resolver._resolver = FakeResolver(
        response=[
            FakeRecord("10 mail.example.com.")
        ]
    )

    result = resolver.query("example.com", "MX")

    assert result["status"] == "success"
    assert result["records"] == ["10 mail.example.com."]


def test_missing_record(resolver):
    resolver._resolver = FakeResolver(
        error=dns.resolver.NoAnswer()
    )

    result = resolver.query("example.com", "TXT")

    assert result["status"] == "not_found"
    assert result["records"] == []
    assert result["error"] is None


def test_nonexistent_dns_name(resolver):
    resolver._resolver = FakeResolver(
        error=dns.resolver.NXDOMAIN()
    )

    result = resolver.query("missing.example.com", "TXT")

    assert result["status"] == "not_found"
    assert result["error"] == "The DNS name does not exist."


def test_dns_timeout(resolver):
    resolver._resolver = FakeResolver(
        error=dns.resolver.LifetimeTimeout()
    )

    result = resolver.query("example.com", "TXT")

    assert result["status"] == "timeout"
    assert result["error"] == "DNS query timed out."


def test_invalid_dns_response(resolver):
    resolver._resolver = FakeResolver(
        error=dns.exception.FormError()
    )

    result = resolver.query("example.com", "TXT")

    assert result["status"] == "invalid_response"
    assert result["records"] == []


def test_network_error(resolver):
    resolver._resolver = FakeResolver(
        error=dns.resolver.NoNameservers()
    )

    result = resolver.query("example.com", "TXT")

    assert result["status"] == "network_error"


def test_os_network_error(resolver):
    resolver._resolver = FakeResolver(
        error=OSError("Network unavailable")
    )

    result = resolver.query("example.com", "TXT")

    assert result["status"] == "network_error"


@pytest.mark.parametrize(
    "domain, record_type",
    [
        ("", "TXT"),
        ("example.com", "INVALID_RECORD"),
    ],
)
def test_invalid_query_input(resolver, domain, record_type):
    result = resolver.query(domain, record_type)

    assert result["status"] == "invalid_response"
    assert result["records"] == []



def test_dns_query_uses_configured_lifetime(resolver):
    fake = FakeResolver(
        response=[FakeRecord("10 mail.example.com.")]
    )
    resolver._resolver = fake

    resolver.query("example.com", "MX")

    assert fake.last_kwargs["lifetime"] == resolver.lifetime
    assert fake.last_kwargs["search"] is False

    # The resolver call itself uses the configured lifetime.
    # Its arguments are checked in the dedicated test below.


def test_result_has_consistent_structure(resolver):
    resolver._resolver = FakeResolver(
        error=dns.resolver.NoAnswer()
    )

    result = resolver.query("example.com", "TXT")

    assert set(result.keys()) == {
        "domain",
        "record_type",
        "status",
        "records",
        "error",
    }
