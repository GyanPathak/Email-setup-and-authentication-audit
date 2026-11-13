from app.checks.spf_parser import parse_spf_record


EXPLANATION_CATALOG = {
    "spf_missing": {
        "meaning": "Your domain does not have an SPF record published.",
        "why_it_matters": "Receiving mail servers cannot use SPF to check which servers are allowed to send email for your domain.",
        "caution": "Include every legitimate email-sending service before publishing an SPF record.",
        "verification": "After publishing the record, run the audit again.",
    },
    "spf_dns_error": {
        "meaning": "We could not retrieve your SPF record because the DNS lookup failed.",
        "why_it_matters": "The audit cannot confirm which servers are authorised to send email for your domain.",
        "caution": "Do not change your DNS records based only on a failed lookup.",
        "verification": "Retry the audit when DNS is responding normally.",
    },
    "spf_multiple_records": {
        "meaning": "Your domain has more than one SPF record.",
        "why_it_matters": "Multiple SPF records can cause receiving mail servers to treat SPF as invalid.",
        "caution": "Combine the required mechanisms into one SPF record. Preserve all legitimate sending services.",
        "verification": "After correcting the record, run the audit again.",
    },
    "spf_invalid_syntax": {
        "meaning": "Your SPF record contains syntax that could not be validated.",
        "why_it_matters": "Receiving mail servers may be unable to evaluate the record correctly.",
        "caution": "Correct the reported syntax without removing legitimate sending services.",
        "verification": "After correcting the record, run the audit again.",
    },
    "spf_multiple_all": {
        "meaning": "Your SPF record contains more than one all mechanism.",
        "why_it_matters": "An SPF record should have only one final all mechanism to define how other senders are handled.",
        "caution": "Choose the intended policy carefully. Do not remove mechanisms that authorise legitimate senders.",
        "verification": "After correcting the record, run the audit again.",
    },
    "spf_missing_all": {
        "meaning": "Your SPF record does not specify an all mechanism.",
        "why_it_matters": "The record does not clearly define how senders that are not listed should be handled.",
        "caution": "Choose an appropriate policy only after reviewing all legitimate sending services.",
        "verification": "After updating the record, run the audit again.",
    },
    "spf_permissive_all": {
        "meaning": "Your SPF record uses +all, which allows any sending server to pass SPF.",
        "why_it_matters": "Unauthorised servers may be able to pass SPF checks for your domain.",
        "caution": "Replace this permissive policy only after confirming that all legitimate senders are covered.",
        "verification": "After updating the record, run the audit again.",
    },
    "spf_neutral_all": {
        "meaning": "Your SPF record uses ?all, which gives no clear pass or fail result for unlisted senders.",
        "why_it_matters": "Receiving mail servers do not get a clear SPF policy for senders that are not listed.",
        "caution": "Review your sending services before choosing a stricter policy.",
        "verification": "After updating the record, run the audit again.",
    },
    "spf_softfail_all": {
        "meaning": "Your SPF record ends with ~all. Senders not listed in the record receive a soft-fail result rather than an SPF pass.",
        "why_it_matters": "A soft-fail result does not itself instruct receiving servers to reject a message. DMARC provides a separate check based on aligned SPF or DKIM results.",
        "caution": "Do not change ~all to -all blindly. A missing legitimate sender could cause its SPF checks to fail.",
        "verification": "After any DNS change, run the audit again.",
    },
    "spf_ptr_deprecated": {
        "meaning": "Your SPF record uses the deprecated ptr mechanism.",
        "why_it_matters": "The ptr mechanism is discouraged and can cause unnecessary DNS lookups.",
        "caution": "Replace it only after identifying the IP addresses or services it currently authorises.",
        "verification": "After updating the record, run the audit again.",
    },
    "spf_analysis_error": {
        "meaning": "We found a problem while checking your SPF record or one of its referenced records.",
        "why_it_matters": "The SPF configuration could not be fully verified.",
        "caution": "Check the specific error before changing your DNS configuration. A DNS lookup failure does not necessarily mean the record is incorrect.",
        "verification": "After resolving the issue, run the audit again.",
    },
    "spf_analysis_warning": {
        "meaning": "Part of your SPF configuration could not be fully analysed.",
        "why_it_matters": "The audit may not have verified every referenced SPF record.",
        "caution": "Review the warning and confirm the referenced sending services with your email provider.",
        "verification": "Run the audit again after resolving any configuration issue.",
    },
    "spf_dns_lookup_limit": {
        "meaning": "Your SPF record tree exceeds the limit of 10 DNS-querying terms.",
        "why_it_matters": "Receiving mail servers may encounter SPF evaluation errors when the DNS lookup limit is exceeded.",
        "caution": "Simplify the SPF configuration carefully. Do not remove required sending services just to reduce the lookup count.",
        "verification": "After updating the SPF configuration, run the audit again.",
    },
    "dkim_not_checked": {
        "meaning": "DKIM was not checked because no selector was supplied.",
        "why_it_matters": "The audit cannot confirm whether your email provider has published a DKIM public key.",
        "caution": "Find the selector used by your email provider. Different providers and domains can use different selectors.",
        "verification": "Run the audit again with the correct selector.",
    },
    "dkim_invalid_selector_input": {
        "meaning": "The supplied DKIM selectors were not provided in the expected format.",
        "why_it_matters": "The audit could not check the requested DKIM selectors.",
        "caution": "Supply selector names as a list of strings.",
        "verification": "Run the audit again with valid selector input.",
    },
    "dkim_unverifiable": {
        "meaning": "We could not check this DKIM selector because its DNS lookup failed.",
        "why_it_matters": "The audit cannot confirm whether the DKIM public key is published.",
        "caution": "Do not assume the key is missing. The DNS lookup may have failed temporarily.",
        "verification": "Retry the audit when DNS is responding normally.",
    },
    "dkim_not_found": {
        "meaning": "We couldn't find a DKIM public key at the queried DNS hostname.",
        "why_it_matters": "Emails signed with this selector may fail DKIM verification. Other selectors may still be active.",
        "caution": "A missing selector does not prove DKIM is completely absent. Don't change DNS until you've confirmed the correct selector.",
        "verification": "Run the audit again after correcting the DNS record.",
    },
    "dkim_invalid_input": {
        "meaning": "The supplied DKIM selector is invalid.",
        "why_it_matters": "The audit cannot look up a DKIM key using this selector.",
        "caution": "Check the selector name in your email provider's settings.",
        "verification": "Run the audit again with the correct selector.",
    },
    "dkim_revoked": {
        "meaning": "The DKIM public key for this selector is marked as revoked.",
        "why_it_matters": "Receiving mail servers should not use a revoked key to verify signatures.",
        "caution": "Confirm the active key and selector with your email provider before replacing DNS records.",
        "verification": "After correcting the key, run the audit again.",
    },
    "dkim_invalid": {
        "meaning": "The published DKIM record could not be validated.",
        "why_it_matters": "Receiving mail servers may be unable to use this public key to verify DKIM signatures.",
        "caution": "Use the exact DKIM record supplied by your email provider. Avoid editing key content manually.",
        "verification": "After correcting the record, run the audit again.",
    },
    "dmarc_error": {
        "meaning": "The DMARC record could not be validated.",
        "why_it_matters": "The audit cannot confirm how your domain handles messages that fail DMARC.",
        "caution": "Check the specific error before changing the record. If DNS could not be reached, retry the audit first.",
        "verification": "After resolving the issue, run the audit again.",
    },
    "dmarc_warning": {
        "meaning": "Your DMARC record has a configuration that needs review.",
        "why_it_matters": "The configuration may affect how receiving mail servers handle messages that fail DMARC or how reports are collected.",
        "caution": "Review your sending sources and reporting configuration before changing your DMARC policy.",
        "verification": "After updating the record, run the audit again.",
    },
    "dmarc_missing": {
        "meaning": "Your domain does not have a DMARC record.",
        "why_it_matters": "Receiving mail servers do not have a DMARC policy from your domain to apply.",
        "caution": "Start with a monitoring policy such as p=none. Review reports and confirm all legitimate sending services before moving to quarantine or reject.",
        "verification": "After publishing the DMARC record, run the audit again.",
    },
}


DEFAULT_EXPLANATION = {
    "meaning": "The audit detected a configuration issue that needs review.",
    "why_it_matters": "This issue may affect how receiving mail servers authenticate or handle your domain's email.",
    "caution": "Review the original finding and confirm the correct configuration with your email provider before making DNS changes.",
    "verification": "After resolving the issue, run the audit again.",
}


def get_finding_explanation(finding, checks):
    """Return deterministic, user-facing explanation fields for a finding."""
    code = finding.get("code", "")
    explanation = dict(
        EXPLANATION_CATALOG.get(code, DEFAULT_EXPLANATION)
    )

    if code == "spf_softfail_all":
        dmarc = checks.get("dmarc", {})
        tags = dmarc.get("tags", {})
        if not isinstance(tags, dict):
            tags = {}

        policy = str(dmarc.get("policy") or tags.get("p") or "").lower()

        try:
            pct = 100 if tags.get("pct") is None else int(tags["pct"])
        except (TypeError, ValueError):
            pct = 0

        if (
            dmarc.get("status") == "success"
            and policy in ("reject", "quarantine")
            and pct == 100
        ):
            explanation["why_it_matters"] = (
                f"Your domain has a DMARC policy of {policy}. "
                "DMARC can provide additional protection for messages "
                "that fail DMARC, but SPF alignment and DKIM still matter."
            )
        else:
            explanation["why_it_matters"] = (
                "Without a fully enforced DMARC policy, messages that fail "
                "SPF may have less protection against spoofing."
            )

        spf = checks.get("spf", {}).get("configuration", {})
        record = spf.get("record")

        if isinstance(record, str):
            parsed = parse_spf_record(record)
            parts = record.rsplit(maxsplit=1)

            all_mechanisms = [
                term
                for term in parsed.get("terms", [])
                if term.get("name") == "all"
            ]

            if (
                parsed.get("valid")
                and len(all_mechanisms) == 1
                and all_mechanisms[0].get("qualifier") == "~"
                and len(parts) == 2
                and parts[-1].lower() == "~all"
            ):
                explanation["dns_example"] = {
                    "label": "Optional alternative to review",
                    "current_record": record,
                    "alternative_record": f"{parts[0]} -all",
                    "note": (
                        "Example only. Preserve your actual SPF mechanisms "
                        "and verify every legitimate sender before publishing."
                    ),
                }

    return explanation
