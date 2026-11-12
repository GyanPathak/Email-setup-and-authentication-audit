
from fastapi.testclient import TestClient

from app.main import app, get_dns_resolver

import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.models.audit import Audit

from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timezone

class FakeDNSResolver:
    def query(self, domain: str, record_type: str) -> dict:
        records = {
            "example.com": ["v=spf1 -all"],
            "_dmarc.example.com": [
                "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"
            ],
        }

        return {
            "domain": domain,
            "record_type": record_type.upper(),
            "status": "success" if domain in records else "not_found",
            "records": records.get(domain, []),
            "error": None,
        }


def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "email-audit-api"
    }



def test_create_audit_endpoint():
    app.dependency_overrides[get_dns_resolver] = (
        lambda: FakeDNSResolver()
    )

    try:
        with TestClient(app) as client:
            response = client.post(
                "/api/audits",
                json={
                    "domain": "example.com",
                    "selectors": [],
                },
            )

            assert response.status_code == 200

            data = response.json()

            assert data["domain"] == "example.com"
            assert data["checks"]["spf"]["configuration"]["status"] == "pass"
            assert data["checks"]["dkim"]["status"] == "not_checked"
            assert data["checks"]["dmarc"]["status"] == "success"

            # Verify that the API returned an audit ID.
            audit_id = data["audit_id"]
            assert audit_id

            # Retrieve the saved audit.
            retrieved_response = client.get(
                f"/api/audits/{audit_id}"
            )

            assert retrieved_response.status_code == 200

            retrieved_data = retrieved_response.json()

            assert retrieved_data["audit_id"] == audit_id
            assert retrieved_data["domain"] == "example.com"
            assert retrieved_data["checks"] == data["checks"]
            assert retrieved_data["overall_status"] == data["overall_status"]
            assert retrieved_data["created_at"]

    finally:
        app.dependency_overrides.pop(get_dns_resolver, None)



def test_get_audit_not_found():
    with TestClient(app) as client:
        response = client.get(
            "/api/audits/00000000-0000-0000-0000-000000000000"
        )

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Audit not found."
    }




def test_create_audit_rejects_missing_domain():
    with TestClient(app) as client:
        response = client.post(
            "/api/audits",
            json={"selectors": []}
        )

    assert response.status_code == 422


def test_create_audit_rejects_invalid_selectors_type():
    with TestClient(app) as client:
        response = client.post(
            "/api/audits",
            json={
                "domain": "example.com",
                "selectors": "default"
            }
        )

    assert response.status_code == 422



def test_create_audit_handles_invalid_domain():
    with TestClient(app) as client:
        response = client.post(
            "/api/audits",
            json={
                "domain": "not a valid domain",
                "selectors": []
            }
        )

    assert response.status_code == 200

    data = response.json()

    assert data["overall_status"] == "invalid_input"
    assert data["errors"]



from unittest.mock import patch


def test_create_audit_handles_unexpected_error():
    with patch(
        "app.main.run_domain_audit",
        side_effect=RuntimeError("Internal database details")
    ):
        with TestClient(app) as client:
            response = client.post(
                "/api/audits",
                json={
                    "domain": "example.com",
                    "selectors": []
                }
            )

    assert response.status_code == 500

    assert response.json() == {
        "detail": "An unexpected error occurred while processing the audit."
    }

    assert "Internal database details" not in response.text


@pytest.fixture(autouse=True)
def test_database():
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=test_engine)

    TestingSessionLocal = sessionmaker(
        bind=test_engine,
        autoflush=False,
        autocommit=False,
    )

    def override_get_db():
        db = TestingSessionLocal()

        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    yield

    app.dependency_overrides.pop(get_db, None)
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()

@pytest.fixture
def db_session(test_database):
    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        yield db
    finally:
        db_generator.close()

def test_create_audit_handles_database_commit_failure():
    app.dependency_overrides[get_dns_resolver] = (
        lambda: FakeDNSResolver()
    )

    rollback_calls = []
    original_rollback = Session.rollback

    def tracked_rollback(db):
        rollback_calls.append(True)
        return original_rollback(db)

    try:
        with patch(
            "sqlalchemy.orm.Session.commit",
            side_effect=SQLAlchemyError("Simulated database failure"),
        ), patch(
            "sqlalchemy.orm.Session.rollback",
            new=tracked_rollback,
        ):
            with TestClient(app) as client:
                response = client.post(
                    "/api/audits",
                    json={
                        "domain": "example.com",
                        "selectors": [],
                    },
                )

        assert response.status_code == 500

        assert response.json() == {
            "detail": "An unexpected error occurred while processing the audit."
        }

        assert "Simulated database failure" not in response.text
        assert rollback_calls

    finally:
        app.dependency_overrides.pop(get_dns_resolver, None)


def test_get_audit_handles_database_error():
    with patch(
        "sqlalchemy.orm.Session.get",
        side_effect=SQLAlchemyError("Simulated database read failure"),
    ):
        with TestClient(app) as client:
            response = client.get(
                "/api/audits/00000000-0000-0000-0000-000000000000"
            )

    assert response.status_code == 500

    assert response.json() == {
        "detail": "An unexpected error occurred while retrieving the audit."
    }

    assert "Simulated database read failure" not in response.text



def test_recheck_audit_creates_new_record_and_preserves_original():
    app.dependency_overrides[get_dns_resolver] = (
        lambda: FakeDNSResolver()
    )

    try:
        with TestClient(app) as client:
            # Create the original audit with a DKIM selector.
            original_response = client.post(
                "/api/audits",
                json={
                    "domain": "example.com",
                    "selectors": ["google"],
                },
            )

            assert original_response.status_code == 200

            original_data = original_response.json()
            original_id = original_data["audit_id"]

            # Recheck the original audit.
            recheck_response = client.post(
                f"/api/audits/{original_id}/recheck"
            )

            assert recheck_response.status_code == 200

            recheck_data = recheck_response.json()
            new_id = recheck_data["audit_id"]

            # A recheck must create a different audit record.
            assert new_id != original_id

            assert recheck_data["domain"] == "example.com"

            # Verify the original audit was not overwritten.
            retrieved_original = client.get(
                f"/api/audits/{original_id}"
            )

            assert retrieved_original.status_code == 200

            assert (
                retrieved_original.json()["audit_id"]
                == original_id
            )

            assert (
                retrieved_original.json()["checks"]
                == original_data["checks"]
            )

            # Verify the new audit was saved.
            retrieved_new = client.get(
                f"/api/audits/{new_id}"
            )

            assert retrieved_new.status_code == 200

            assert retrieved_new.json()["audit_id"] == new_id

            assert retrieved_new.json()["domain"] == "example.com"

            # Verify the original DKIM selector was checked again.
            assert (
                retrieved_new.json()["checks"]["dkim"]
                ["selectors_checked"][0]["selector"]
                == "google"
            )

    finally:
        app.dependency_overrides.pop(get_dns_resolver, None)


def test_recheck_audit_not_found():
    with TestClient(app) as client:
        response = client.post(
            "/api/audits/00000000-0000-0000-0000-000000000000/recheck"
        )

    assert response.status_code == 404

    assert response.json() == {
        "detail": "Audit not found."
    }


def test_recheck_audit_handles_database_read_error():
    with patch(
        "sqlalchemy.orm.Session.get",
        side_effect=SQLAlchemyError(
            "Simulated database read failure"
        ),
    ):
        with TestClient(app) as client:
            response = client.post(
                "/api/audits/00000000-0000-0000-0000-000000000000/recheck"
            )

    assert response.status_code == 500

    assert response.json() == {
        "detail": (
            "An unexpected error occurred while retrieving the audit."
        )
    }

    assert "Simulated database read failure" not in response.text


def test_recheck_audit_handles_database_commit_failure():
    app.dependency_overrides[get_dns_resolver] = (
        lambda: FakeDNSResolver()
    )

    try:
        with TestClient(app) as client:
            # First create a valid original audit.
            original_response = client.post(
                "/api/audits",
                json={
                    "domain": "example.com",
                    "selectors": [],
                },
            )

            assert original_response.status_code == 200

            original_id = original_response.json()["audit_id"]

            # Simulate failure only during the recheck commit.
            with patch(
                "sqlalchemy.orm.Session.commit",
                side_effect=SQLAlchemyError(
                    "Simulated database commit failure"
                ),
            ):
                response = client.post(
                    f"/api/audits/{original_id}/recheck"
                )

            assert response.status_code == 500

            assert response.json() == {
                "detail": (
                    "An unexpected error occurred while rechecking the audit."
                )
            }

            assert (
                "Simulated database commit failure"
                not in response.text
            )

            # Original record must still be available.
            original_check = client.get(
                f"/api/audits/{original_id}"
            )

            assert original_check.status_code == 200

    finally:
        app.dependency_overrides.pop(get_dns_resolver, None)



def test_get_audit_history_returns_saved_audits(db_session):
    audit = Audit(
        domain="example.com",
        root_domain="example.com",
        overall_status="pass",
        report={"domain": "example.com"},
    )

    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)

    with TestClient(app) as client:
        response = client.get("/api/audits")

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["audit_id"] == str(audit.audit_id)
    assert data[0]["domain"] == "example.com"
    assert data[0]["root_domain"] == "example.com"
    assert data[0]["overall_status"] == "pass"
    assert data[0]["created_at"]


def test_get_audit_history_returns_newest_first(db_session):
    older_audit = Audit(
        domain="older.com",
        root_domain="older.com",
        overall_status="pass",
        report={},
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    newer_audit = Audit(
        domain="newer.com",
        root_domain="newer.com",
        overall_status="pass",
        report={},
        created_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
    )

    db_session.add_all([older_audit, newer_audit])
    db_session.commit()

    with TestClient(app) as client:
        response = client.get("/api/audits")

    assert response.status_code == 200

    data = response.json()

    assert [item["domain"] for item in data] == [
        "newer.com",
        "older.com",
    ]


def test_get_audit_history_filters_by_domain(db_session):
    db_session.add_all([
        Audit(
            domain="example.com",
            root_domain="example.com",
            overall_status="pass",
            report={},
        ),
        Audit(
            domain="other.com",
            root_domain="other.com",
            overall_status="fail",
            report={},
        ),
    ])
    db_session.commit()

    with TestClient(app) as client:
        response = client.get(
            "/api/audits",
            params={"domain": "EXAMPLE.COM"},
        )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["domain"] == "example.com"


def test_get_audit_history_returns_empty_list():
    with TestClient(app) as client:
        response = client.get("/api/audits")

    assert response.status_code == 200
    assert response.json() == []


def test_get_audit_history_handles_database_error():
    with patch(
        "sqlalchemy.orm.Session.scalars",
        side_effect=SQLAlchemyError(
            "Simulated database read failure"
        ),
    ):
        with TestClient(app) as client:
            response = client.get("/api/audits")

    assert response.status_code == 500

    assert response.json() == {
        "detail": (
            "An unexpected error occurred while retrieving audit history."
        )
    }

    assert "Simulated database read failure" not in response.text
