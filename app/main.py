
import logging
import uuid

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.audit.domain_audit import run_domain_audit
from app.database import get_db
from app.models.audit import Audit
from app.services.dns_resolver import DNSResolver


logger = logging.getLogger(__name__)

app = FastAPI(
    title="Email Setup & Authentication Audit",
    description="API for auditing email authentication configurations.",
    version="1.0.0",
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
        "service": "email-audit-api",
    }


@app.post("/api/audits")
def create_audit(
    request: AuditRequest,
    dns_resolver: DNSResolver = Depends(get_dns_resolver),
    db: Session = Depends(get_db),
):
    try:
        result = run_domain_audit(
            value=request.domain,
            dns_resolver=dns_resolver,
            selectors=request.selectors,
        )

        # Invalid inputs should not be stored as completed audits.
        if result.get("overall_status") == "invalid_input":
            return result

        audit = Audit(
            domain=result["domain"],
            root_domain=result["root_domain"],
            overall_status=result["overall_status"],
            report=result,
        )

        db.add(audit)
        db.commit()
        db.refresh(audit)

        return {
            **result,
            "audit_id": str(audit.audit_id),
        }

    except Exception as exc:
        db.rollback()

        logger.exception(
            "Unexpected error while auditing domain: %s",
            request.domain,
        )

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while processing the audit.",
        ) from exc


@app.get("/api/audits/{audit_id}")
def get_audit(
    audit_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    try:
        audit = db.get(Audit, audit_id)

    except SQLAlchemyError as exc:
        logger.exception(
            "Database error while retrieving audit: %s",
            audit_id,
        )

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while retrieving the audit.",
        ) from exc

    if audit is None:
        raise HTTPException(
            status_code=404,
            detail="Audit not found.",
        )

    return {
        **audit.report,
        "audit_id": str(audit.audit_id),
        "created_at": audit.created_at.isoformat()
        if audit.created_at
        else None,
    }


@app.post("/api/audits/{audit_id}/recheck")
def recheck_audit(
    audit_id: uuid.UUID,
    dns_resolver: DNSResolver = Depends(get_dns_resolver),
    db: Session = Depends(get_db),
):
    # Retrieve the original audit.
    try:
        original_audit = db.get(Audit, audit_id)

    except SQLAlchemyError as exc:
        logger.exception(
            "Database error while retrieving audit for recheck: %s",
            audit_id,
        )
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while retrieving the audit.",
        ) from exc

    if original_audit is None:
        raise HTTPException(
            status_code=404,
            detail="Audit not found.",
        )

    # Recover the DKIM selectors used in the original audit.
    dkim_check = original_audit.report.get(
        "checks", {}
    ).get("dkim", {})

    selectors_checked = dkim_check.get("selectors_checked", [])

    selectors = [
        item["selector"]
        for item in selectors_checked
        if isinstance(item, dict)
        and isinstance(item.get("selector"), str)
    ]

    try:
        # Run a fresh audit.
        result = run_domain_audit(
            value=original_audit.domain,
            dns_resolver=dns_resolver,
            selectors=selectors,
        )

        if result.get("overall_status") == "invalid_input":
            raise HTTPException(
                status_code=400,
                detail="The original domain is no longer valid for auditing.",
            )

        # Save the new result as a separate audit record.
        new_audit = Audit(
            domain=result["domain"],
            root_domain=result["root_domain"],
            overall_status=result["overall_status"],
            report=result,
        )

        db.add(new_audit)
        db.commit()
        db.refresh(new_audit)

        return {
            **result,
            "audit_id": str(new_audit.audit_id),
        }

    except HTTPException:
        raise

    except Exception as exc:
        db.rollback()

        logger.exception(
            "Unexpected error while rechecking audit: %s",
            audit_id,
        )

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while rechecking the audit.",
        ) from exc
