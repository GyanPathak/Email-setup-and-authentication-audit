
import logging
from fastapi import FastAPI, Depends
from pydantic import BaseModel

from app.services.dns_resolver import DNSResolver
from app.audit.domain_audit import run_domain_audit


from fastapi import HTTPException

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Email Setup & Authentication Audit",
    description="API for auditing email authentication configurations.",
    version="1.0.0"
)


class AuditRequest(BaseModel):
    domain: str
    selectors: list[str] | None = None


def get_dns_resolver():
    return DNSResolver()


@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "service": "email-audit-api"
    }


@app.post("/api/audits")
def create_audit(
    request: AuditRequest,
    dns_resolver: DNSResolver = Depends(get_dns_resolver)
):
    try:
        result = run_domain_audit(
            value=request.domain,
            dns_resolver=dns_resolver,
            selectors=request.selectors
        )

        return result

    except Exception as exc:
        logger.exception(
            "Unexpected error while auditing domain: %s",
            request.domain
        )

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while processing the audit."
        ) from exc
