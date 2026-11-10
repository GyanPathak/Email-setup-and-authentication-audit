

import dns.exception
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver


class DNSResolver:
    """
    Reusable DNS resolver.

    Supports different DNS record types and returns
    structured results instead of exposing raw exceptions.
    """

    def __init__(self, timeout: float = 3.0, lifetime: float = 5.0):
        self.timeout = timeout
        self.lifetime = lifetime

        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = lifetime

    def query(self, domain: str, record_type: str) -> dict:
        """
        Query DNS and return a standardized result.

        Possible statuses:
        success, not_found, timeout,
        invalid_response, network_error
        """

        result = {
            "domain": domain,
            "record_type": record_type.upper(),
            "status": None,
            "records": [],
            "error": None,
        }

        # Validate the DNS query name.
        if not isinstance(domain, str) or not domain.strip():
            result["status"] = "invalid_response"
            result["error"] = "A valid DNS name is required."
            return result

        try:
            query_name = dns.name.from_text(domain.strip())

            if query_name.is_absolute():
                query_name = query_name.derelativize(dns.name.root)

            rdtype = dns.rdatatype.from_text(record_type.upper())

        except (ValueError, dns.exception.DNSException):
            result["status"] = "invalid_response"
            result["error"] = "Invalid DNS name or record type."
            return result

        try:
            answer = self._resolver.resolve(
                query_name,
                rdtype,
                lifetime=self.lifetime,
                search=False,
            )

            records = []

            for record in answer:
                if rdtype == dns.rdatatype.TXT:
                    # TXT records can contain multiple byte chunks.
                    text_record = b"".join(record.strings).decode(
                        "utf-8", errors="replace"
                    )
                    records.append(text_record)
                else:
                    records.append(record.to_text())

            if not records:
                result["status"] = "not_found"
            else:
                result["status"] = "success"
                result["records"] = records

        except dns.resolver.NXDOMAIN:
            result["status"] = "not_found"
            result["error"] = "The DNS name does not exist."

        except dns.resolver.NoAnswer:
            result["status"] = "not_found"

        except dns.resolver.LifetimeTimeout:
            result["status"] = "timeout"
            result["error"] = "DNS query timed out."

        except dns.exception.FormError:
            result["status"] = "invalid_response"
            result["error"] = "The DNS server returned a malformed response."

        except dns.resolver.NoNameservers:
            result["status"] = "network_error"
            result["error"] = "No DNS server returned a usable response."

        except OSError:
            result["status"] = "network_error"
            result["error"] = "A DNS or network error occurred."

        except dns.exception.DNSException:
            result["status"] = "network_error"
            result["error"] = "An unexpected DNS error occurred."

        except dns.resolver.NoNameservers:
            result["status"] = "network_error"
            result["error"] = "No DNS server returned a usable response."

        except (OSError, dns.exception.DNSException):
            result["status"] = "network_error"
            result["error"] = "A DNS or network error occurred."

        return result
