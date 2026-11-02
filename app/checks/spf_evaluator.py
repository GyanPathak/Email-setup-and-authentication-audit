
from app.checks.spf_parser import parse_spf_record


MAX_DNS_LOOKUPS = 10
MAX_VOID_LOOKUPS = 2


def _extract_domain(term: dict) -> str | None:
    """
    Extract a literal domain from an SPF include or redirect term.

    Macro-based targets are not resolved in this static analysis.
    """
    if term["type"] == "mechanism" and term["name"] == "include":
        value = term["argument"].removeprefix(":")
    elif term["type"] == "modifier" and term["name"] == "redirect":
        value = term["value"]
    else:
        return None

    if "%" in value:
        return None

    return value.rstrip(".").lower()


def evaluate_spf(domain: str, dns_resolver) -> dict:
    """
    Recursively inspect SPF records and their include/redirect targets.

    This is static recursive analysis, not sender-IP SPF evaluation.
    """

    result = {
        "domain": domain,
        "status": "success",
        "records_checked": [],
        "errors": [],
        "warnings": [],
        "dns_lookup_terms": 0,
        "void_lookups": 0,
        "max_dns_lookups": MAX_DNS_LOOKUPS,
        "max_void_lookups": MAX_VOID_LOOKUPS,
        "limit_exceeded": False,
        "circular_references": [],
        "unresolved_macro_targets": [],
    }

    visited = set()
    active = set()

    def visit(current_domain: str):
        current_domain = current_domain.lower().rstrip(".")

        if current_domain in active:
            result["circular_references"].append(current_domain)
            result["errors"].append(
                f"Circular SPF reference detected: {current_domain}"
            )
            return

        if current_domain in visited:
            return

        active.add(current_domain)

        dns_result = dns_resolver.query(current_domain, "TXT")

        if dns_result["status"] == "not_found":
            result["void_lookups"] += 1
            result["errors"].append(
                f"No TXT record found for {current_domain}."
            )
            active.remove(current_domain)
            visited.add(current_domain)
            return

        if dns_result["status"] != "success":
            result["errors"].append(
                f"DNS query failed for {current_domain}. "
                f"Status: {dns_result['status']}. "
                f"Details: {dns_result.get('error') or 'No additional details.'}"
            )   
            active.remove(current_domain)
            visited.add(current_domain)
            return

        spf_records = [
            record
            for record in dns_result["records"]
            if record.strip().lower().startswith("v=spf1")
        ]

        if len(spf_records) == 0:
            result["errors"].append(
                f"No SPF record found for {current_domain}."
            )
            active.remove(current_domain)
            visited.add(current_domain)
            return

        if len(spf_records) > 1:
            result["errors"].append(
                f"Multiple SPF records found for {current_domain}."
            )
            active.remove(current_domain)
            visited.add(current_domain)
            return

        parsed = parse_spf_record(spf_records[0])

        if not parsed["valid"]:
            result["errors"].append(
                f"Invalid SPF record for {current_domain}: "
                f"{'; '.join(parsed['errors'])}"
            )
            active.remove(current_domain)
            visited.add(current_domain)
            return

        result["records_checked"].append(current_domain)

        result["dns_lookup_terms"] += parsed["dns_lookup_terms"]

        for term in parsed["terms"]:
            if (
                term["type"] == "mechanism"
                and term["name"] == "include"
            ) or (
                term["type"] == "modifier"
                and term["name"] == "redirect"
            ):
                target = _extract_domain(term)

                if target is None:
                    result["unresolved_macro_targets"].append(
                        current_domain
                    )
                    continue

                visit(target)

        active.remove(current_domain)
        visited.add(current_domain)

    visit(domain)

    result["limit_exceeded"] = (
        result["dns_lookup_terms"] > MAX_DNS_LOOKUPS
    )

    if result["void_lookups"] > MAX_VOID_LOOKUPS:
        result["errors"].append(
            "The SPF evaluation exceeds the maximum of 2 void lookups."
        )

    if result["limit_exceeded"]:
        result["errors"].append(
            "The SPF record tree exceeds 10 DNS-querying terms."
        )

    if result["errors"]:
        result["status"] = "error"

    if result["unresolved_macro_targets"]:
        result["warnings"].append(
            "Some macro-based SPF targets could not be resolved "
            "during static analysis."
        )

    return result
