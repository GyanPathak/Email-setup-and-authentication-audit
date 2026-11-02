
import pytest

from app.checks.spf_parser import parse_spf_record


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 -all",
        "v=spf1 include:_spf.google.com -all",
        "v=spf1 ip4:192.0.2.1 -all",
        "v=spf1 ip6:2001:db8::1 -all",
        "v=spf1 a mx -all",
        "v=spf1 a/24//64 mx -all",
        "v=spf1 exists:%{i}.example.com -all",
        "v=spf1 redirect=_spf.example.com",
        "v=spf1 exp=explain.example.com -all",
        "v=spf1",
    ],
)
def test_valid_spf_records(record):
    result = parse_spf_record(record)

    assert result["valid"] is True
    assert result["errors"] == []


@pytest.mark.parametrize(
    "record",
    [
        "",
        "not-spf",
        "v=spf2 -all",
        "v=spf1 unknownmechanism -all",
        "v=spf1 include -all",
        "v=spf1 ip4:999.999.1.1 -all",
        "v=spf1 ip4:192.0.2.1/99 -all",
        "v=spf1 ip6:192.0.2.1 -all",
        "v=spf1 a/99 -all",
        "v=spf1 mx//129 -all",
        "v=spf1 include: -all",
        "v=spf1 redirect=",
        "v=spf1 include:%{invalid}.example.com -all",
        "v=spf1 include:bad..example.com -all",
    ],
)
def test_invalid_spf_records(record):
    result = parse_spf_record(record)

    assert result["valid"] is False
    assert len(result["errors"]) > 0


def test_mechanism_qualifiers():
    result = parse_spf_record(
        "v=spf1 +ip4:192.0.2.1 -ip6:2001:db8::1 ~all"
    )

    assert result["valid"] is True
    assert [term["qualifier"] for term in result["terms"]] == [
        "+", "-", "~"
    ]


def test_dns_lookup_terms_are_counted():
    result = parse_spf_record(
        "v=spf1 include:a.example.com a mx ptr exists:b.example.com -all"
    )

    assert result["valid"] is True
    assert result["dns_lookup_terms"] == 5


def test_redirect_counts_as_dns_lookup():
    result = parse_spf_record(
        "v=spf1 ip4:192.0.2.1 redirect=_spf.example.com"
    )

    assert result["valid"] is True
    assert result["dns_lookup_terms"] == 1


def test_exp_does_not_count_as_dns_lookup():
    result = parse_spf_record(
        "v=spf1 -all exp=explain.example.com"
    )

    assert result["valid"] is True
    assert result["dns_lookup_terms"] == 0


def test_duplicate_redirect_is_invalid():
    result = parse_spf_record(
        "v=spf1 redirect=a.example.com redirect=b.example.com"
    )

    assert result["valid"] is False


def test_duplicate_exp_is_invalid():
    result = parse_spf_record(
        "v=spf1 -all exp=a.example.com exp=b.example.com"
    )

    assert result["valid"] is False


def test_unknown_modifier_is_accepted():
    result = parse_spf_record(
        "v=spf1 -all custom=value"
    )
    

    assert result["valid"] is True


def test_underscore_domain_spec():
    result = parse_spf_record(
        "v=spf1 include:_spf.google.com -all"
    )

    assert result["valid"] is True


def test_underscore_redirect_domain():
    result = parse_spf_record(
        "v=spf1 redirect=_spf.example.com"
    )

    assert result["valid"] is True
    

def test_multiple_all_mechanisms_are_invalid():
    result = parse_spf_record(
        "v=spf1 ip4:192.0.2.1 -all ~all"
    )

    assert result["valid"] is False
    assert any("multiple all" in error.lower() for error in result["errors"])


def test_multiple_include_mechanisms_are_valid():
    result = parse_spf_record(
        "v=spf1 include:a.example.com include:b.example.com -all"
    )

    assert result["valid"] is True


def test_duplicate_unknown_modifier_is_invalid():
    result = parse_spf_record(
        "v=spf1 -all custom=one custom=two"
    )

    assert result["valid"] is False


def test_valid_macro_with_transformers():
    result = parse_spf_record(
        "v=spf1 exists:%{ir}.example.com -all"
    )

    assert result["valid"] is True


def test_invalid_macro_letter():
    result = parse_spf_record(
        "v=spf1 exists:%{x}.example.com -all"
    )

    assert result["valid"] is False


def test_multiple_modifiers_in_different_positions():
    result = parse_spf_record(
        "v=spf1 redirect=_spf.example.com ip4:192.0.2.1"
    )

    assert result["valid"] is True
