
import re
from app.checks.spf_parser import parse_spf_record


def _add_issue(issues, code, severity, message, recommendation):
    issues.append({
        "code": code,
        "severity": severity,
        "message": message,
        "recommendation": recommendation,
    })


def check_spf(domain: str, dns_resolver) -> dict:
    """
    Retrieve and inspect the SPF TXT record for a domain.

    This performs basic SPF configuration checks.
    It does not evaluate SPF authorization or recursively
    resolve mechanisms such as include and redirect.
    """

    result = {
        "domain": domain,
        "status": None,
        "record": None,
        "issues": [],
    }

    # 1. Retrieve TXT records using our existing DNS resolver.
    dns_result = dns_resolver.query(domain, "TXT")

    # 2. Distinguish a missing record from a DNS failure.
    if dns_result["status"] == "not_found":
        result["status"] = "fail"

        _add_issue(
            result["issues"],
            "spf_missing",
            "fail",
            "No SPF record was found for this domain.",
            "Publish an SPF TXT record in your DNS settings.",
        )
        return result

    if dns_result["status"] != "success":
        result["status"] = "error"

        _add_issue(
            result["issues"],
            "spf_dns_error",
            "error",
            "The SPF record could not be verified because the DNS query failed.",
            "Check DNS availability and run the audit again.",
        )
        return result

    # 3. Find TXT records that begin with the SPF version tag.
    spf_records = [
        record.strip()
        for record in dns_result["records"]
        if isinstance(record, str)
        and re.match(r"^v=spf1(?:\s|$)", record.strip(), re.IGNORECASE)
    ]

    # 4. Check whether an SPF record exists.
    if not spf_records:
        result["status"] = "fail"

        _add_issue(
            result["issues"],
            "spf_missing",
            "fail",
            "No SPF record was found among the domain's TXT records.",
            "Publish an SPF TXT record in your DNS settings.",
        )
        return result

    # 5. Multiple SPF records are not valid SPF configuration.
    if len(spf_records) > 1:
        result["status"] = "fail"

        _add_issue(
            result["issues"],
            "spf_multiple_records",
            "fail",
            "Multiple SPF records were found for this domain.",
            "Combine the required SPF mechanisms into one SPF record.",
        )
        return result

    # 6. Inspect the single SPF record.
    spf_record = spf_records[0]
    result["record"] = spf_record
    parsed = parse_spf_record(spf_record)
    if not parsed["valid"]:
        for error in parsed["errors"]:
            _add_issue(
                result["issues"],
                "spf_invalid_syntax",
                "fail",
                f"Invalid SPF syntax: {error}",
                "Correct the SPF record syntax and publish the updated DNS TXT record.",
            )

        result["status"] = "fail"
        return result

    tokens = spf_record.split()

    # Identify all mechanisms, including their qualifiers.
    all_terms = [
        token.lower()
        for token in tokens[1:]
        if re.fullmatch(r"[+\-~?]?all", token, re.IGNORECASE)
    ]

    if len(all_terms) > 1:
        result["status"] = "fail"

        _add_issue(
            result["issues"],
            "spf_multiple_all",
            "fail",
            "The SPF record contains multiple all mechanisms.",
            "Review the SPF policy and keep only the intended all mechanism.",
        )
        return result

    # 7. Check the all mechanism's policy.
    if not all_terms:
        result["status"] = "warning"

        _add_issue(
            result["issues"],
            "spf_missing_all",
            "warning",
            "The SPF record does not contain an all mechanism.",
            "Review the policy and decide how unauthorized senders should be handled.",
        )

    else:
        all_term = all_terms[0]

        if all_term == "+all" or all_term == "all":
            result["status"] = "fail"

            _add_issue(
                result["issues"],
                "spf_permissive_all",
                "fail",
                "The SPF record uses +all, which permits any sending server.",
                "Replace this with an appropriate restrictive policy after verifying authorized senders.",
            )

        elif all_term == "?all":
            result["status"] = "warning"

            _add_issue(
                result["issues"],
                "spf_neutral_all",
                "warning",
                "The SPF record uses ?all, which gives no positive or negative authorization result.",
                "Review whether a soft-fail or hard-fail policy is appropriate.",
            )

        elif all_term == "~all":
            result["status"] = "warning"

            _add_issue(
                result["issues"],
                "spf_softfail_all",
                "warning",
                "The SPF record uses ~all, which marks unauthorized senders as soft-fail.",
                "Consider whether a hard-fail policy is appropriate after testing all legitimate sending sources.",
            )

        else:  # -all
            result["status"] = "pass"

    # 8. Detect the deprecated ptr mechanism.
    if any(token.lower().lstrip("+-~?").startswith("ptr") for token in tokens[1:]):
        _add_issue(
            result["issues"],
            "spf_ptr_deprecated",
            "warning",
            "The SPF record uses the deprecated ptr mechanism.",
            "Avoid ptr and use more reliable SPF mechanisms such as ip4, ip6, or include.",
        )

        if result["status"] == "pass":
            result["status"] = "warning"

    return result
