
from app.checks.dmarc_parser import parse_dmarc_record


def check_dmarc(domain: str, dns_resolver) -> dict:
    """Check a domain's DMARC DNS TXT record."""

    result = {
        "domain": domain,
        "status": "error",
        "record": None,
        "policy": None,
        "tags": {},
        "errors": [],
        "warnings": [],
    }

    if not isinstance(domain, str) or not domain.strip():
        result["status"] = "invalid_input"
        result["errors"].append(
            "Domain must be a non-empty string."
        )
        return result

    domain = domain.strip().lower()
    result["domain"] = domain

    dmarc_domain = f"_dmarc.{domain}"

    try:
        dns_result = dns_resolver.resolve(dmarc_domain, "TXT")
    except Exception as exc:
        result["status"] = "error"
        result["errors"].append(
            f"Unexpected DNS resolver exception: {exc}"
        )
        return result

    # Validate the resolver response structure.
    if not isinstance(dns_result, dict):
        result["status"] = "error"
        result["errors"].append(
            "DNS resolver returned an invalid response."
        )
        return result

    dns_status = dns_result.get("status")

    if dns_status == "not_found":
        result["status"] = "missing"
        result["errors"].append(
            f"No DMARC TXT record found at {dmarc_domain}."
        )
        return result

    if dns_status != "success":
        result["status"] = (
            "unverifiable"
            if dns_status == "timeout"
            else "error"
        )
        result["errors"].append(
            f"DNS lookup failed with status '{dns_status}': "
            f"{dns_result.get('error', 'Unknown DNS error')}"
        )
        return result

    records = dns_result.get("records")

    if not isinstance(records, list):
        result["status"] = "error"
        result["errors"].append(
            "DNS resolver returned an invalid TXT records collection."
        )
        return result

    if not records:
        result["status"] = "missing"
        result["errors"].append(
            "No TXT records were returned."
        )
        return result

    # Identify DMARC-looking records, including malformed versions.
    dmarc_records = [
        record
        for record in records
        if isinstance(record, str)
        and record.strip().lower().startswith("v=dmarc")
    ]

    if not dmarc_records:
        result["status"] = "missing"
        result["errors"].append(
            "No DMARC-looking record was found among the TXT records."
        )
        return result

    if len(dmarc_records) > 1:
        result["status"] = "error"
        result["errors"].append(
            "Multiple DMARC-looking records found. "
            "A domain must publish only one DMARC record."
        )
        return result

    record = dmarc_records[0]
    result["record"] = record

    parsed = parse_dmarc_record(record)

    result["policy"] = parsed["policy"]
    result["tags"] = parsed["tags"]
    result["errors"].extend(parsed["errors"])
    result["warnings"].extend(parsed["warnings"])

    if not parsed["valid"]:
        result["status"] = "invalid"
        return result

    result["status"] = "success"

    return result
