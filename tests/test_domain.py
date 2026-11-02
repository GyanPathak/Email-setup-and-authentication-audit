
import pytest

from app.validators.domain import (
    extract_hostname,
    validate_domain,
)


@pytest.mark.parametrize(
    "input_value, expected",
    [
        ("example.com", "example.com"),
        (" Google.com ", "google.com"),
        ("WWW.Example.com", "example.com"),
        ("example.com.", "example.com"),
        ("https://example.com", "example.com"),
        ("http://example.com", "example.com"),
        ("https://www.example.com/login", "example.com"),
        ("https://example.com/search?q=email", "example.com"),
        ("https://example.com:443", "example.com"),
        ("http://example.com:80", "example.com"),
        ("mail.example.com", "example.com"),
        ("https://shop.example.co.uk", "example.co.uk"),
    ],
)
def test_valid_domains(input_value, expected):
    assert validate_domain(input_value) == expected


@pytest.mark.parametrize(
    "input_value, expected",
    [
        ("www.example.com", "www.example.com"),
        ("https://www.example.com/login", "www.example.com"),
        ("mail.example.com", "mail.example.com"),
        ("shop.example.co.uk", "shop.example.co.uk"),
    ],
)
def test_hostname_extraction(input_value, expected):
    assert extract_hostname(input_value) == expected


@pytest.mark.parametrize(
    "input_value",
    [
        "",
        "   ",
        "ftp://example.com",
        "https://",
        "https://example.com:8080",
        "https://user:password@example.com",
        "example.com/login",
        "hello world",
        "example",
        "user@example.com",
        "192.168.1.1",
        "-example.com",
        "example-.com",
        "example..com",
        "com",
    ],
)
def test_invalid_domains(input_value):
    with pytest.raises(ValueError):
        validate_domain(input_value)
