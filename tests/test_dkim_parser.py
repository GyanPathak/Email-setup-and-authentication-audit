
import pytest

from app.checks.dkim_parser import parse_dkim_record


VALID_KEY = "QUJDREVGR0g="


@pytest.mark.parametrize(
    "record",
    [
        f"v=DKIM1; k=rsa; p={VALID_KEY}",
        f"v=DKIM1; p={VALID_KEY}",
        f"k=rsa; p={VALID_KEY}",
        f"v=DKIM1; k=ed25519; p={VALID_KEY}",
        f"v=DKIM1; k=rsa; p={VALID_KEY}; t=s",
    ],
)
def test_valid_dkim_records(record):
    result = parse_dkim_record(record)

    assert result["valid"] is True
    assert result["errors"] == []


@pytest.mark.parametrize(
    "record",
    [
        "",
        "not-a-dkim-record",
        "v=DKIM2; p=QUJD",
        "v=DKIM1; k=unknown; p=QUJD",
        "v=DKIM1; k=rsa",
        "v=DKIM1; k=rsa; p=%%%invalid%%%",
        "v=DKIM1; k=rsa; p=QUJD; p=REVG",
        "v=DKIM1; malformed",
    ],
)
def test_invalid_dkim_records(record):
    result = parse_dkim_record(record)

    assert result["valid"] is False
    assert len(result["errors"]) > 0


def test_empty_public_key_is_revoked():
    result = parse_dkim_record("v=DKIM1; k=rsa; p=")

    assert result["revoked"] is True
    assert result["valid"] is False
    assert result["warnings"]


def test_default_key_type_is_rsa():
    result = parse_dkim_record(f"v=DKIM1; p={VALID_KEY}")

    assert result["key_type"] == "rsa"


def test_unknown_tags_are_preserved():
    result = parse_dkim_record(
        f"v=DKIM1; k=rsa; p={VALID_KEY}; custom=value"
    )

    assert result["valid"] is True
    assert result["tags"]["custom"] == "value"
