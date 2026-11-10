
import uuid

from sqlalchemy import DateTime, JSON, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Audit(Base):
    __tablename__ = "audits"

    audit_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    domain: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
        index=True,
    )

    root_domain: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
    )

    overall_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    report: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
    )

    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
