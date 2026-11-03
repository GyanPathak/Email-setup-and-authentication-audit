
import re


SELECTOR_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?$"
)


def validate_dkim_selector(selector: str) -> dict:
    """
    Validate a single DKIM selector.

    This checks selector syntax, not whether the selector exists in DNS.
    """

    result = {
        "valid": False,
        "selector": selector,
        "normalized": None,
        "error": None,
    }

    if not isinstance(selector, str) or not selector.strip():
        result["error"] = "DKIM selector must be a non-empty string."
        return result

    selector = selector.strip()

    if len(selector) > 63:
        result["error"] = (
            "DKIM selector must not exceed 63 characters."
        )
        return result

    if not SELECTOR_PATTERN.fullmatch(selector):
        result["error"] = (
            "DKIM selector contains invalid characters or formatting."
        )
        return result

    result["valid"] = True
    result["normalized"] = selector.lower()

    return result
