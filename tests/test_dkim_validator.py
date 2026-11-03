
import pytest

from app.validators.dkim import validate_dkim_selector


@pytest.mark.parametrize(
    "selector",
    [
        "selector1",
        "google",
        "default",
        "s1",
        "selector_1",
        "selector-1",
        "A1",
    ],
)
def test_valid_selectors(selector):
    result = validate_dkim_selector(selector)

    assert result["valid"] is True
    assert result["error"] is None


@pytest.mark.parametrize(
    "selector",
    [
        "",
        " ",
        ".",
        "selector.example",
        "-selector",
        "selector-",
        "selector with spaces",
        "selector@123",
        "selector!123",
        "a" * 64,
    ],
)
def test_invalid_selectors(selector):
    result = validate_dkim_selector(selector)

    assert result["valid"] is False
    assert result["error"] is not None


def test_selector_is_normalized_to_lowercase():
    result = validate_dkim_selector("GoogleSelector")

    assert result["valid"] is True
    assert result["normalized"] == "googleselector"


def test_selector_with_surrounding_spaces():
    result = validate_dkim_selector(" selector1 ")

    assert result["valid"] is True
    assert result["normalized"] == "selector1"


def test_non_string_selector():
    result = validate_dkim_selector(None)

    assert result["valid"] is False
