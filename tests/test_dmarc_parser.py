
import pytest

from app.checks.dmarc_parser import parse_dmarc_record


def test_valid_basic_dmarc_record():
    record = "v=DMARC1; p=reject"

    result = parse_dmarc_record(record)

    assert result["valid"] is True
    assert result["version"] == "DMARC1"
    assert result["policy"] == "reject"


def test_valid_complete_dmarc_record():
    record = (
        "v=DMARC1; p=quarantine; "
        "rua=mailto:dmarc@example.com; "
        "pct=100; adkim=s; aspf=r"
    )

    result = parse_dmarc_record(record)

    assert result["valid"] is True
    assert result["tags"]["pct"] == "100"
    assert result["tags"]["adkim"] == "s"
    assert result["tags"]["aspf"] == "r"


def test_missing_version():
    result = parse_dmarc_record("p=reject")

    assert result["valid"] is False
    assert result["errors"]


def test_version_must_appear_first():
    result = parse_dmarc_record("p=reject; v=DMARC1")

    assert result["valid"] is False
    assert any("first" in error for error in result["errors"])


def test_missing_policy():
    result = parse_dmarc_record("v=DMARC1")

    assert result["valid"] is False
    assert any("p tag" in error for error in result["errors"])


@pytest.mark.parametrize("policy", ["none", "quarantine", "reject"])
def test_valid_policies(policy):
    result = parse_dmarc_record(f"v=DMARC1; p={policy}")

    assert result["valid"] is True


@pytest.mark.parametrize("policy", ["allow", "monitor", "invalid"])
def test_invalid_policies(policy):
    result = parse_dmarc_record(f"v=DMARC1; p={policy}")

    assert result["valid"] is False


@pytest.mark.parametrize("percentage", ["0", "50", "100"])
def test_valid_percentage(percentage):
    result = parse_dmarc_record(
        f"v=DMARC1; p=reject; pct={percentage}"
    )

    assert result["valid"] is True


@pytest.mark.parametrize("percentage", ["-1", "101", "abc", "50.5"])
def test_invalid_percentage(percentage):
    result = parse_dmarc_record(
        f"v=DMARC1; p=reject; pct={percentage}"
    )

    assert result["valid"] is False


@pytest.mark.parametrize("alignment", ["r", "s"])
def test_valid_alignment(alignment):
    result = parse_dmarc_record(
        f"v=DMARC1; p=reject; adkim={alignment}; aspf={alignment}"
    )

    assert result["valid"] is True


def test_invalid_alignment():
    result = parse_dmarc_record(
        "v=DMARC1; p=reject; adkim=strict"
    )

    assert result["valid"] is False


def test_valid_reporting_uri():
    result = parse_dmarc_record(
        "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
    )

    assert result["valid"] is True


def test_invalid_reporting_uri():
    result = parse_dmarc_record(
        "v=DMARC1; p=reject; rua=not-an-email"
    )

    assert result["valid"] is False


def test_duplicate_tags():
    result = parse_dmarc_record(
        "v=DMARC1; p=reject; p=none"
    )

    assert result["valid"] is False


def test_unknown_tag_is_preserved():
    result = parse_dmarc_record(
        "v=DMARC1; p=reject; custom=value"
    )

    assert result["valid"] is True
    assert result["tags"]["custom"] == "value"
    assert result["warnings"]


def test_empty_record():
    result = parse_dmarc_record("")

    assert result["valid"] is False


def test_none_policy_generates_warning():
    result = parse_dmarc_record("v=DMARC1; p=none")

    assert result["valid"] is True
    assert result["warnings"]
