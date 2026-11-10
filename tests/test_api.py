
from fastapi.testclient import TestClient

from app.main import app, get_dns_resolver


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
                    "selectors": []
                }
            )

        assert response.status_code == 200

        data = response.json()

        assert data["domain"] == "example.com"
        assert data["checks"]["spf"]["configuration"]["status"] == "pass"
        assert data["checks"]["dkim"]["status"] == "not_checked"
        assert data["checks"]["dmarc"]["status"] == "success"

    finally:
        app.dependency_overrides.pop(get_dns_resolver, None)



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
