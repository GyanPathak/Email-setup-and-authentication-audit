
import ipaddress
import re
from urllib.parse import urlsplit

import tldextract


# Use the bundled Public Suffix List snapshot.
# This avoids requiring a network request during validation.
_extract = tldextract.TLDExtract(
    suffix_list_urls=(),
    fallback_to_snapshot=True,
)


def extract_hostname(value: str) -> str:
    """
    Extract and normalize a hostname from a domain or HTTP/HTTPS URL.
    """

    if not isinstance(value, str):
        raise ValueError("Input must be a string.")

    value = value.strip()

    if not value:
        raise ValueError("Domain cannot be empty.")

    if "://" in value:
        try:
            parsed = urlsplit(value)

            if parsed.scheme.lower() not in ("http", "https"):
                raise ValueError("Only HTTP and HTTPS URLs are supported.")

            if not parsed.hostname or not parsed.netloc:
                raise ValueError("Invalid URL.")

            if parsed.username or parsed.password:
                raise ValueError("URLs containing credentials are not accepted.")

            if parsed.port not in (None, 80, 443):
                raise ValueError("Custom ports are not supported.")

            hostname = parsed.hostname

        except ValueError as error:
            raise ValueError(f"Invalid URL: {error}") from error

    else:
        if any(char in value for char in ["/", "?", "#", "@", ":"]):
            raise ValueError("Enter a valid domain or HTTP/HTTPS URL.")

        hostname = value

    hostname = hostname.rstrip(".")

    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("Invalid domain name.") from error

    # Reject IP addresses.
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not accepted.")

    if len(hostname) > 253:
        raise ValueError("Domain name is too long.")

    labels = hostname.split(".")

    label_pattern = re.compile(
        r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    if len(labels) < 2:
        raise ValueError("Enter a complete domain, such as example.com.")

    for label in labels:
        if not label or len(label) > 63:
            raise ValueError("Invalid domain label length.")

        if not label_pattern.fullmatch(label):
            raise ValueError("Domain contains invalid characters.")

    return hostname


def validate_domain(value: str) -> str:
    """
    Return the registrable root domain.

    Examples:
        www.example.com -> example.com
        shop.example.co.uk -> example.co.uk
    """

    hostname = extract_hostname(value)

    extracted = _extract(hostname)

    if not extracted.domain or not extracted.suffix:
        raise ValueError("Could not identify a valid registrable domain.")

    return f"{extracted.domain}.{extracted.suffix}"
