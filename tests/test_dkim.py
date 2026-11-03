
from unittest.mock import Mock

import pytest

from app.checks.dkim import check_dkim


VALID_RECORD = "v=DKIM1; k=rsa; p=QUJDREVGR0g="


def make_resolver(status="success", records=None, error=None):
    resolver = Mock()

    resolver.query.return_value = {
        "domain": "selector1._domainkey.example.com",
        "record_type": "TXT",
        "status": status,
        "records": records or [],
        "error": error,
    }

    return resolver


def test_valid_dkim_selector():
    resolver = make_resolver(records=[VALID_RECORD])

    result = check_dkim(
        "example.com",
        ["selector1"],
        resolver,
    )

    assert result["status"] == "success"
    assert result["valid_selectors"] == 1
    assert result["selectors_checked"][0]["status"] == "valid"


def test_missing_dkim_selector():
    resolver = make_resolver(status="not_found")

    result = check_dkim(
        "example.com",
        ["selector1"],
        resolver,
    )

    assert result["missing_selectors"] == 1
    assert result["selectors_checked"][0]["status"] == "not_found"


def test_dns_timeout_is_unverifiable():
    resolver = make_resolver(
        status="timeout",
        error="DNS query timed out.",
    )

    result = check_dkim(
        "example.com",
        ["selector1"],
        resolver,
    )

    assert result["unverifiable_selectors"] == 1
    assert result["selectors_checked"][0]["status"] == "unverifiable"


def test_invalid_dkim_record():
    resolver = make_resolver(
        records=["v=DKIM1; k=rsa; p=%%%invalid%%%"]
    )

    result = check_dkim(
        "example.com",
        ["selector1"],
        resolver,
    )

    assert result["invalid_selectors"] == 1
    assert result["selectors_checked"][0]["status"] == "invalid"


def test_revoked_dkim_key():
    resolver = make_resolver(
        records=["v=DKIM1; k=rsa; p="]
    )

    result = check_dkim(
        "example.com",
        ["selector1"],
        resolver,
    )

    assert result["revoked_selectors"] == 1
    assert result["selectors_checked"][0]["status"] == "revoked"


def test_multiple_dkim_records_are_invalid():
    resolver = make_resolver(
        records=[
            VALID_RECORD,
            "v=DKIM1; k=rsa; p=REVGSElKS0w=",
        ]
    )

    result = check_dkim(
        "example.com",
        ["selector1"],
        resolver,
    )

    assert result["invalid_selectors"] == 1


def test_multiple_selectors():
    resolver = Mock()

    resolver.query.side_effect = [
        {
            "status": "success",
            "records": [VALID_RECORD],
            "error": None,
        },
        {
            "status": "not_found",
            "records": [],
            "error": None,
        },
    ]

    result = check_dkim(
        "example.com",
        ["selector1", "selector2"],
        resolver,
    )

    assert result["valid_selectors"] == 1
    assert result["missing_selectors"] == 1
    assert len(result["selectors_checked"]) == 2
    assert resolver.query.call_count == 2


def test_duplicate_selectors_are_ignored():
    resolver = make_resolver(records=[VALID_RECORD])

    result = check_dkim(
        "example.com",
        ["selector1", "selector1"],
        resolver,
    )

    assert resolver.query.call_count == 1
    assert len(result["selectors_checked"]) == 1


def test_empty_selector_list():
    resolver = Mock()

    result = check_dkim(
        "example.com",
        [],
        resolver,
    )

    assert result["status"] == "invalid_input"
    resolver.query.assert_not_called()


def test_empty_domain():
    resolver = Mock()

    result = check_dkim(
        "",
        ["selector1"],
        resolver,
    )

    assert result["status"] == "invalid_input"
    resolver.query.assert_not_called()


def test_non_dkim_txt_record_is_not_mistaken_for_dkim():
    resolver = make_resolver(
        records=["google-site-verification=some-token"]
    )

    result = check_dkim(
        "example.com",
        ["selector1"],
        resolver,
    )

    assert result["missing_selectors"] == 1



def test_invalid_selector_does_not_trigger_dns_query():
    resolver = Mock()

    result = check_dkim(
        "example.com",
        ["invalid.selector"],
        resolver,
    )

    assert result["status"] == "invalid_input"
    assert result["invalid_selector_inputs"] == 1
    resolver.query.assert_not_called()


def test_valid_selector_is_checked_when_another_is_invalid():
    resolver = make_resolver(records=[VALID_RECORD])

    result = check_dkim(
        "example.com",
        ["invalid.selector", "selector1"],
        resolver,
    )

    assert result["invalid_selector_inputs"] == 1
    assert result["valid_selectors"] == 1
    assert result["selectors_checked"][1]["status"] == "valid"
    assert resolver.query.call_count == 1


def test_selectors_with_different_case_are_duplicates():
    resolver = make_resolver(records=[VALID_RECORD])

    result = check_dkim(
        "example.com",
        ["Google", "google"],
        resolver,
    )

    assert resolver.query.call_count == 1
    assert len(result["selectors_checked"]) == 1
    assert result["selectors_checked"][0]["selector"] == "google"


def test_all_invalid_selectors_return_invalid_input():
    resolver = Mock()

    result = check_dkim(
        "example.com",
        ["invalid.selector", "another.selector"],
        resolver,
    )

    assert result["status"] == "invalid_input"
    assert result["invalid_selector_inputs"] == 2
    assert result["valid_selectors"] == 0
    resolver.query.assert_not_called()


def test_mixed_valid_and_invalid_selectors_return_partial():
    resolver = make_resolver(records=[VALID_RECORD])

    result = check_dkim(
        "example.com",
        ["selector1", "invalid.selector"],
        resolver,
    )

    assert result["status"] == "partial"
    assert result["valid_selectors"] == 1
    assert result["invalid_selector_inputs"] == 1
    assert resolver.query.call_count == 1
