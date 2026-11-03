
import re


VALID_POLICIES = {"none", "quarantine", "reject"}
VALID_ALIGNMENT_MODES = {"r", "s"}
VALID_FAILURE_OPTIONS = {"0", "1", "d", "s"}
VALID_REPORT_FORMATS = {"afrf"}


def parse_dmarc_record(record: str) -> dict:
    """Parse and validate a DMARC DNS TXT record."""

    result = {
        "valid": False,
        "record": record,
        "version": None,
        "policy": None,
        "tags": {},
        "errors": [],
        "warnings": [],
    }

    if not isinstance(record, str) or not record.strip():
        result["errors"].append(
            "DMARC record must be a non-empty string."
        )
        return result

    tags = {}
    parts = record.strip().split(";")

    for part in parts:
        part = part.strip()

        if not part:
            continue

        if "=" not in part:
            result["errors"].append(
                f"Invalid tag format: '{part}'. Expected tag=value."
            )
            continue

        tag, value = part.split("=", 1)
        tag = tag.strip().lower()
        value = value.strip()

        if not tag or not value:
            result["errors"].append(
                f"Tag '{tag}' has an empty name or value."
            )
            continue

        if not re.fullmatch(r"[a-z][a-z0-9_]*", tag):
            result["errors"].append(
                f"Invalid tag name: '{tag}'."
            )
            continue

        if tag in tags:
            result["errors"].append(
                f"Duplicate DMARC tag: '{tag}'."
            )
            continue

        tags[tag] = value

    result["tags"] = tags

    # Version must be the first tag.
    first_part = parts[0].strip() if parts else ""

    if not re.match(r"^v\s*=", first_part, re.IGNORECASE):
        result["errors"].append("The v tag must appear first.")

    if "v" not in tags:
        result["errors"].append("Missing required v tag.")
    elif tags["v"].upper() != "DMARC1":
        result["errors"].append("Unsupported DMARC version.")

    result["version"] = tags.get("v")

    # Required policy.
    if "p" not in tags:
        result["errors"].append("Missing required p tag.")
    elif tags["p"].lower() not in VALID_POLICIES:
        result["errors"].append(
            "Invalid p policy. Use none, quarantine, or reject."
        )

    result["policy"] = tags.get("p", "").lower() or None

    # Optional policy tags.
    for policy_tag in ("sp", "np"):
        if policy_tag in tags:
            if tags[policy_tag].lower() not in VALID_POLICIES:
                result["errors"].append(
                    f"Invalid {policy_tag} policy. "
                    "Use none, quarantine, or reject."
                )

    # Alignment modes.
    for alignment_tag in ("adkim", "aspf"):
        if alignment_tag in tags:
            if tags[alignment_tag].lower() not in VALID_ALIGNMENT_MODES:
                result["errors"].append(
                    f"Invalid {alignment_tag} value. Use r or s."
                )

    # Percentage.
    if "pct" in tags:
        try:
            percentage = int(tags["pct"])
            if not 0 <= percentage <= 100:
                raise ValueError
        except ValueError:
            result["errors"].append(
                "Invalid pct value. It must be an integer from 0 to 100."
            )

    # Failure reporting options.
    if "fo" in tags:
        options = tags["fo"].split(":")

        if (
            any(option not in VALID_FAILURE_OPTIONS for option in options)
            or len(set(options)) != len(options)
        ):
            result["errors"].append(
                "Invalid fo value. Use unique colon-separated values "
                "from 0, 1, d, s."
            )

    # Reporting format.
    if "rf" in tags:
        formats = tags["rf"].split(":")

        if (
            not formats
            or any(fmt.lower() not in VALID_REPORT_FORMATS for fmt in formats)
            or len(set(fmt.lower() for fmt in formats)) != len(formats)
        ):
            result["errors"].append(
                "Unsupported rf value. Currently supported: afrf."
            )

    # Reporting interval.
    if "ri" in tags:
        try:
            interval = int(tags["ri"])
            if interval <= 0:
                raise ValueError
        except ValueError:
            result["errors"].append(
                "Invalid ri value. It must be a positive integer."
            )

    # Basic reporting URI syntax validation.
    for report_tag in ("rua", "ruf"):
        if report_tag in tags:
            uris = tags[report_tag].split(",")

            for uri in uris:
                uri = uri.strip()

                if not re.fullmatch(
                    r"mailto:[^@\s,;]+@[^@\s,;]+",
                    uri,
                    re.IGNORECASE,
                ):
                    result["errors"].append(
                        f"Invalid {report_tag} reporting URI: '{uri}'."
                    )

    known_tags = {
        "v", "p", "sp", "np", "adkim", "aspf",
        "pct", "rua", "ruf", "fo", "rf", "ri",
    }

    for tag in tags:
        if tag not in known_tags:
            result["warnings"].append(
                f"Unknown DMARC tag '{tag}' was preserved."
            )

    if result["policy"] == "none":
        result["warnings"].append(
            "The p=none policy monitors authentication failures "
            "but does not request quarantine or rejection."
        )

    if not result["errors"]:
        result["valid"] = True

    return result
