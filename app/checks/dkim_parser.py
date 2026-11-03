
import base64
import binascii
import re


SUPPORTED_KEY_TYPES = {"rsa", "ed25519"}

TAG_NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def parse_dkim_record(record: str) -> dict:
    """
    Parse a DKIM DNS TXT record and perform basic syntax validation.

    This validates the published key record, not an email signature.
    """

    result = {
        "valid": False,
        "record": record,
        "version": None,
        "key_type": None,
        "public_key": None,
        "revoked": False,
        "tags": {},
        "errors": [],
        "warnings": [],
    }

    if not isinstance(record, str) or not record.strip():
        result["errors"].append(
            "DKIM record must be a non-empty string."
        )
        return result

    tags = {}

    for part in record.split(";"):
        part = part.strip()

        if not part:
            continue

        if "=" not in part:
            result["errors"].append(
                f"Malformed DKIM tag: {part}"
            )
            continue

        name, value = part.split("=", 1)

        name = name.strip().lower()
        value = value.strip()

        if not TAG_NAME_PATTERN.fullmatch(name):
            result["errors"].append(
                f"Invalid DKIM tag name: {name}"
            )
            continue

        if name in tags:
            result["errors"].append(
                f"Duplicate DKIM tag: {name}"
            )
            continue

        tags[name] = value

    result["tags"] = tags

    if result["errors"]:
        return result

    version = tags.get("v", "DKIM1")

    if version != "DKIM1":
        result["errors"].append(
            "Unsupported DKIM version. Expected DKIM1."
        )

    key_type = tags.get("k", "rsa").lower()

    if key_type not in SUPPORTED_KEY_TYPES:
        result["errors"].append(
            f"Unsupported DKIM key type: {key_type}"
        )

    public_key = tags.get("p")

    if public_key is None:
        result["errors"].append(
            "DKIM public key tag (p) is missing."
        )

    elif public_key == "":
        result["revoked"] = True
        result["warnings"].append(
            "DKIM public key is empty. This indicates a revoked key."
        )

    else:
        try:
            decoded_key = base64.b64decode(
                public_key,
                validate=True,
            )

            if not decoded_key:
                result["errors"].append(
                    "DKIM public key contains no decoded data."
                )

        except (binascii.Error, ValueError):
            result["errors"].append(
                "DKIM public key is not valid Base64."
            )

    result["version"] = version
    result["key_type"] = key_type
    result["public_key"] = public_key

    result["valid"] = (
        len(result["errors"]) == 0
        and not result["revoked"]
    )

    return result
