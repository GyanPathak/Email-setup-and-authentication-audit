
from app.checks.dkim_parser import parse_dkim_record
from app.validators.dkim import validate_dkim_selector


def check_dkim(
    domain: str,
    selectors: list[str],
    dns_resolver,
) -> dict:
    """
    Check DKIM DNS records for explicitly supplied selectors.

    This checks published DNS configuration. It does not verify
    DKIM signatures on actual emails.
    """

    result = {
        "domain": domain,
        "status": "success",
        "selectors_checked": [],
        "valid_selectors": 0,
        "invalid_selectors": 0,
        "invalid_selector_inputs": 0,
        "revoked_selectors": 0,
        "missing_selectors": 0,
        "unverifiable_selectors": 0,
        "errors": [],
        "warnings": [],
    }

    if not isinstance(domain, str) or not domain.strip():
        result["status"] = "invalid_input"
        result["errors"].append("A valid domain is required.")
        return result

    domain = domain.strip().lower()

    if not isinstance(selectors, list) or not selectors:
        result["status"] = "invalid_input"
        result["errors"].append(
            "At least one DKIM selector must be supplied."
        )
        return result

    seen_selectors = set()
    dns_queries_made = 0

    for raw_selector in selectors:

        validation = validate_dkim_selector(raw_selector)

        if not validation["valid"]:
            result["invalid_selector_inputs"] += 1

            result["errors"].append(
                f"Invalid selector input: {validation['error']}"
            )

            result["selectors_checked"].append({
                "selector": raw_selector,
                "record_name": None,
                "status": "invalid_input",
                "record": None,
                "parsed": None,
                "error": validation["error"],
            })

            continue

        selector = validation["normalized"]

        if selector in seen_selectors:
            result["warnings"].append(
                f"Duplicate selector ignored: {selector}"
            )
            continue

        seen_selectors.add(selector)

        record_name = f"{selector}._domainkey.{domain}"

        dns_queries_made += 1

        dns_result = dns_resolver.query(record_name, "TXT")

        selector_result = {
            "selector": selector,
            "record_name": record_name,
            "status": None,
            "record": None,
            "parsed": None,
            "error": None,
        }

        if dns_result["status"] == "not_found":
            selector_result["status"] = "not_found"
            selector_result["error"] = "No TXT record found."
            result["missing_selectors"] += 1

        elif dns_result["status"] != "success":
            selector_result["status"] = "unverifiable"
            selector_result["error"] = (
                f"DNS query failed with status: {dns_result['status']}. "
                f"{dns_result.get('error') or ''}"
            )
            result["unverifiable_selectors"] += 1

        else:
            records = dns_result.get("records", [])

            dkim_records = [
                record
                for record in records
                if isinstance(record, str)
                and any(
                    tag.strip().lower().startswith("v=dkim1")
                    for tag in record.split(";")
                )
            ]

            if not dkim_records:
                selector_result["status"] = "not_found"
                selector_result["error"] = (
                    "No DKIM TXT record found among the returned TXT records."
                )
                result["missing_selectors"] += 1

            elif len(dkim_records) > 1:
                selector_result["status"] = "invalid"
                selector_result["error"] = (
                    "Multiple DKIM records found for this selector."
                )
                result["invalid_selectors"] += 1

            else:
                record = dkim_records[0]
                parsed = parse_dkim_record(record)

                selector_result["record"] = record
                selector_result["parsed"] = parsed

                if parsed["revoked"]:
                    selector_result["status"] = "revoked"
                    result["revoked_selectors"] += 1

                elif not parsed["valid"]:
                    selector_result["status"] = "invalid"
                    selector_result["error"] = "; ".join(
                        parsed["errors"]
                    )
                    result["invalid_selectors"] += 1

                else:
                    selector_result["status"] = "valid"
                    result["valid_selectors"] += 1

        result["selectors_checked"].append(selector_result)

    if dns_queries_made == 0:
        result["status"] = "invalid_input"

    elif (
        result["invalid_selector_inputs"]
        or result["unverifiable_selectors"]
        or result["missing_selectors"]
    ):
        result["status"] = "partial"

    elif result["invalid_selectors"] or result["revoked_selectors"]:
        result["status"] = "warning"

    return result
