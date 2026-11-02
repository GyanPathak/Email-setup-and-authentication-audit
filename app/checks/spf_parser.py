
import ipaddress
import re


SPF_MECHANISMS = {
    "all", "include", "a", "mx", "ptr",
    "ip4", "ip6", "exists",
}

SPF_MODIFIERS = {"redirect", "exp"}

DNS_LOOKUP_MECHANISMS = {
    "include", "a", "mx", "ptr", "exists",
}

MACRO_PATTERN = re.compile(
    r"%(?:%|_|-|\{[slodipvh](?:\d+)?r?"
    r"(?:[.\-+,/_=][.\-+,/_=]*)*\})",
    re.IGNORECASE,
)


def _validate_domain_spec(value: str) -> bool:
    """Validate a basic SPF domain-spec, including macro syntax."""

    if not value:
        return False

    # Every percent sign must begin a valid SPF macro or escape.
    matches = list(MACRO_PATTERN.finditer(value))

    remaining = []
    last_position = 0

    for match in matches:
        remaining.append(value[last_position:match.start()])
        remaining.append("x")
        last_position = match.end()

    remaining.append(value[last_position:])
    normalized = "".join(remaining)

    if "%" in normalized:
        return False

    normalized = normalized.rstrip(".")

    if not normalized or len(normalized) > 253:
        return False

    try:
        ascii_domain = normalized.encode("idna").decode("ascii")
    except UnicodeError:
        return False

    labels = ascii_domain.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(r"[A-Za-z0-9_-]+", label)
        ):
            return False

    return True


def _parse_mechanism(token: str) -> dict:
    """Parse and validate one SPF mechanism."""

    qualifier = "+"

    if token and token[0] in "+-~?":
        qualifier = token[0]
        token = token[1:]

    match = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*)(.*)", token)

    if not match:
        return {"valid": False, "error": "Malformed mechanism."}

    name = match.group(1).lower()
    argument = match.group(2)

    if name not in SPF_MECHANISMS:
        return {
            "valid": False,
            "error": f"Unknown SPF mechanism: {name}",
        }

    if name == "all":
        valid = argument == ""

    elif name in {"ip4", "ip6"}:
        valid = argument.startswith(":") and bool(argument[1:])

        if valid:
            try:
                network = ipaddress.ip_network(
                    argument[1:], strict=False
                )
                expected_version = 4 if name == "ip4" else 6
                valid = network.version == expected_version
            except ValueError:
                valid = False

    elif name in {"include", "exists"}:
        valid = (
            argument.startswith(":")
            and _validate_domain_spec(argument[1:])
        )

    elif name == "ptr":
        valid = (
            argument == ""
            or (
                argument.startswith(":")
                and _validate_domain_spec(argument[1:])
            )
        )

    elif name in {"a", "mx"}:
        suffix_match = re.search(
            r"(?P<suffix>(?:/\d{1,2})?(?://\d{1,3})?)$",
            argument,
        )

        suffix = suffix_match.group("suffix")
        domain_part = argument[:suffix_match.start()]

        valid = True

        if domain_part:
            valid = (
                domain_part.startswith(":")
                and _validate_domain_spec(domain_part[1:])
            )

        if valid and suffix:
            cidr4 = re.search(r"/(\d{1,2})", suffix)
            cidr6 = re.search(r"//(\d{1,3})", suffix)

            if cidr4 and int(cidr4.group(1)) > 32:
                valid = False

            if cidr6 and int(cidr6.group(1)) > 128:
                valid = False

    else:
        valid = False

    if not valid:
        return {
            "valid": False,
            "error": f"Invalid syntax for SPF mechanism: {token}",
        }

    return {
        "valid": True,
        "type": "mechanism",
        "name": name,
        "qualifier": qualifier,
        "argument": argument,
        "dns_lookup": name in DNS_LOOKUP_MECHANISMS,
    }


def _parse_modifier(token: str) -> dict:
    """Parse and validate one SPF modifier."""

    if token.count("=") < 1:
        return {"valid": False, "error": "Malformed modifier."}

    name, value = token.split("=", 1)
    name = name.lower()

    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]*", name):
        return {"valid": False, "error": "Invalid modifier name."}

    if not value:
        return {
            "valid": False,
            "error": f"Modifier {name} has an empty value.",
        }

    if name in SPF_MODIFIERS:
        if not _validate_domain_spec(value):
            return {
                "valid": False,
                "error": f"Invalid value for SPF modifier: {name}",
            }

    return {
        "valid": True,
        "type": "modifier",
        "name": name,
        "value": value,
        "dns_lookup": name == "redirect",
    }


def parse_spf_record(record: str) -> dict:
    """
    Parse an SPF record and perform basic syntax validation.

    This is a syntax parser, not a complete SPF evaluator.
    """

    result = {
        "valid": False,
        "record": record,
        "terms": [],
        "errors": [],
        "dns_lookup_terms": 0,
    }

    if not isinstance(record, str) or not record.strip():
        result["errors"].append("SPF record must be a non-empty string.")
        return result

    if "\t" in record or "\n" in record or "\r" in record:
        result["errors"].append(
            "SPF terms must be separated by spaces, not control characters."
        )
        return result

    tokens = record.split()

    if not tokens or tokens[0].lower() != "v=spf1":
        result["errors"].append(
            "SPF record must begin with v=spf1."
        )
        return result

    seen_modifiers = set()
    all_count = 0
    seen_modifier_names = set()

    for token in tokens[1:]:
        if "=" in token:
            parsed = _parse_modifier(token)

            if parsed["valid"]:
                name = parsed["name"]

                if name in seen_modifier_names:
                    parsed = {
                        "valid": False,
                        "error": f"Duplicate SPF modifier: {name}",
                    }
                else:
                    seen_modifier_names.add(name)
        else:
            parsed = _parse_mechanism(token)

            if parsed["valid"] and parsed["name"] == "all":
                all_count += 1

                if all_count > 1:
                    parsed = {
                        "valid": False,
                        "error": "An SPF record must not contain multiple all mechanisms.",
                    }

        if not parsed["valid"]:
            result["errors"].append(parsed["error"])
            continue

        result["terms"].append(parsed)

        if parsed["dns_lookup"]:
            result["dns_lookup_terms"] += 1

    result["valid"] = len(result["errors"]) == 0

    return result
