from app.checks.spf import check_spf
from app.checks.spf_evaluator import evaluate_spf
from app.checks.dkim import check_dkim
from app.checks.dmarc import check_dmarc
from app.validators.domain import extract_hostname, validate_domain
from app.audit.finding_explanations import get_finding_explanation


def _add_finding(findings, check, code, severity, message, recommendation=None):
    findings.append({
        "check": check,
        "code": code,
        "severity": severity,
        "message": message,
        "recommendation": recommendation,
    })


def _safe_run(function, *args):
    """Prevent one unexpected checker exception from crashing the whole audit."""
    try:
        return function(*args)
    except Exception as exc:
        return {
            "status": "error",
            "errors": [f"Unexpected checker error: {exc}"],
        }


def _is_dns_failure(message):
    """Identify errors that indicate DNS could not be checked."""
    text = str(message).lower()

    indicators = (
        "dns query failed",
        "timeout",
        "timed out",
        "network_error",
        "network error",
        "no nameservers",
        "servfail",
        "unverifiable",
    )

    return any(indicator in text for indicator in indicators)


def _add_spf_findings(findings, spf_check, dmarc_check=None):
    dmarc_check = dmarc_check or {}

    dmarc_tags = dmarc_check.get("tags", {})
    if not isinstance(dmarc_tags, dict):
        dmarc_tags = {}

    policy = str(dmarc_check.get("policy") or "").lower()

    pct = dmarc_tags.get("pct")
    try:
        pct = 100 if pct is None else int(pct)
    except (TypeError, ValueError):
        pct = 0

    dmarc_enforces_policy = (
        dmarc_check.get("status") == "success"
        and policy in ("reject", "quarantine")
        and pct == 100
    )

    for issue in spf_check.get("issues", []):
        severity = issue.get("severity", "warning")

        if severity == "error":
            severity = "unverifiable"

        if (
            issue.get("code") == "spf_softfail_all"
            and severity == "warning"
            and dmarc_enforces_policy
        ):
            severity = "info"

        _add_finding(
            findings,
            "spf",
            issue.get("code", "spf_issue"),
            severity,
            issue.get("message", "SPF issue detected."),
            issue.get("recommendation"),
        )


def _add_spf_analysis_findings(findings, analysis):
    for error in analysis.get("errors", []):
        severity = "unverifiable" if _is_dns_failure(error) else "fail"

        _add_finding(
            findings,
            "spf",
            "spf_analysis_error",
            severity,
            str(error),
            "Review the SPF record and any referenced DNS records.",
        )

    for warning in analysis.get("warnings", []):
        _add_finding(
            findings,
            "spf",
            "spf_analysis_warning",
            "warning",
            str(warning),
            "Review the SPF configuration and its DNS dependencies.",
        )

    if analysis.get("limit_exceeded"):
        _add_finding(
            findings,
            "spf",
            "spf_dns_lookup_limit",
            "fail",
            "The SPF analysis detected more than the configured DNS lookup limit.",
            "Reduce unnecessary DNS-lookup mechanisms and simplify the SPF record.",
        )


def _add_dkim_findings(findings, dkim_check):
    for item in dkim_check.get("selectors_checked", []):
        status = item.get("status")
        selector = item.get("selector", "unknown")

        if status == "valid":
            continue

        if status == "unverifiable":
            severity = "unverifiable"
            message = f"Could not verify DKIM selector '{selector}' because of a DNS issue."
        elif status == "not_found":
            severity = "warning"
            record_name = item.get(
                "record_name",
                f"{selector}._domainkey.{dkim_check.get('domain', 'unknown')}",
            )
            message = (
                f"We couldn't find a DKIM public key at '{record_name}'."
            )
        elif status == "invalid_input":
            severity = "warning"
            message = f"The supplied DKIM selector '{selector}' is invalid."
        elif status == "revoked":
            severity = "fail"
            message = f"The DKIM public key for selector '{selector}' is revoked."
        elif status == "invalid":
            severity = "fail"
            message = f"The DKIM record for selector '{selector}' is invalid."
        else:
            severity = "warning"
            message = f"DKIM selector '{selector}' could not be confirmed."

        _add_finding(
            findings,
            "dkim",
            f"dkim_{status or 'unknown'}",
            severity,
            message,
            " Confirm the selector with your email provider before changing DNS.",

        )
        findings[-1]["selector"] = selector

def _add_dmarc_findings(findings, dmarc_check):
    status = dmarc_check.get("status")

    for error in dmarc_check.get("errors", []):
        severity = "unverifiable" if (
            status in ("error", "unverifiable") or _is_dns_failure(error)
        ) else "fail"

        _add_finding(
            findings,
            "dmarc",
            "dmarc_error",
            severity,
            str(error),
            "Review the DMARC checker error and verify the DNS response for the _dmarc record.",
        )

    for warning in dmarc_check.get("warnings", []):
        _add_finding(
            findings,
            "dmarc",
            "dmarc_warning",
            "warning",
            str(warning),
            "Review your DMARC policy and reporting configuration.",
        )

    if status == "missing":
        _add_finding(
            findings,
            "dmarc",
            "dmarc_missing",
            "fail",
            "No DMARC record was found for this domain.",
            "Publish a DMARC TXT record at _dmarc for the domain.",
        )


def _get_overall_status(findings, checks):
    severities = {item["severity"] for item in findings}
    spf_softfail_is_info = any(
    item["check"] == "spf"
    and item["code"] == "spf_softfail_all"
    and item["severity"] == "info"
    for item in findings
    )

    other_spf_warnings = any(
    item["check"] == "spf"
    and item["severity"] == "warning"
    for item in findings
    )

    # Collect statuses from both top-level and nested checks.
    statuses = []

    for check_name, check in checks.items():
        if isinstance(check, dict) and "status" in check:
            statuses.append(check["status"])

        elif isinstance(check, dict):
            for subcheck_name, subcheck in check.items():
                if not isinstance(subcheck, dict):
                    continue

                status = subcheck.get("status")
                if status is None:
                    continue

                if (
                    check_name == "spf"
                    and subcheck_name == "configuration"
                    and status == "warning"
                    and spf_softfail_is_info
                    and not other_spf_warnings
                ):
                    continue

                statuses.append(status)

    # Explicit failures take priority.
    if "fail" in severities or any(
        status in ("fail", "invalid", "missing")
        for status in statuses
    ):
        return "fail"

    # Verification failures mean the audit is incomplete.
    if "unverifiable" in severities or any(
        status in ("error", "unverifiable", "partial", "not_checked")
        for status in statuses
    ):
        return "partial"

    if "warning" in severities or "warning" in statuses:
        return "warning"

    if "invalid_input" in statuses:
        return "partial"

    return "pass"


def run_domain_audit(value, dns_resolver, selectors=None):
    """
    Run SPF, DKIM, and DMARC checks and combine their results.

    DKIM is only checked when the caller supplies selectors.
    """

    try:
        hostname = extract_hostname(value)
        root_domain = validate_domain(value)
    except (ValueError, TypeError) as exc:
        return {
            "domain": None,
            "root_domain": None,
            "overall_status": "invalid_input",
            "checks": {},
            "findings": [],
            "errors": [str(exc)],
        }

    findings = []

    # SPF configuration check
    spf_check = _safe_run(check_spf, hostname, dns_resolver)


    # Recursive SPF analysis only makes sense when a record was found.
    if spf_check.get("record"):
        spf_analysis = _safe_run(evaluate_spf, hostname, dns_resolver)
        _add_spf_analysis_findings(findings, spf_analysis)
    else:
        spf_analysis = {
            "status": "not_run",
            "reason": "No SPF record was available for recursive analysis.",
        }

    # DKIM requires selectors supplied by the caller.
    if selectors is None or selectors == []:
        dkim_check = {
            "status": "not_checked",
            "reason": "No DKIM selectors were supplied.",
            "selectors_checked": [],
        }

        _add_finding(
        findings,
        "dkim",
        "dkim_not_checked",
        "info",
        "DKIM was not checked because no selector was supplied.",
        "Find the DKIM selector used by your email provider and run the audit again.",
    )
    elif not isinstance(selectors, list):
        dkim_check = {
            "status": "invalid_input",
            "reason": "Selectors must be supplied as a list of strings.",
            "selectors_checked": [],
        }
        _add_finding(
            findings,
            "dkim",
            "dkim_invalid_selector_input",
            "warning",
            dkim_check["reason"],
            "Supply the DKIM selector names used by your email provider.",
        )
    else:
        dkim_check = _safe_run(check_dkim, hostname, selectors, dns_resolver)
        _add_dkim_findings(findings, dkim_check)

    # DMARC check
    dmarc_check = _safe_run(check_dmarc, hostname, dns_resolver)

    # SPF finding severity can depend on the verified DMARC policy.
    _add_spf_findings(findings, spf_check, dmarc_check)

    _add_dmarc_findings(findings, dmarc_check)

    checks = {
        "spf": {
            "configuration": spf_check,
            "analysis": spf_analysis,
        },
        "dkim": dkim_check,
        "dmarc": dmarc_check,
    }
    for finding in findings:
        finding.update(get_finding_explanation(finding, checks))

    return {
        "domain": hostname,
        "root_domain": root_domain,
        "overall_status": _get_overall_status(findings, checks),
        "checks": checks,
        "findings": findings,
        "errors": [],
    }
