"""
API and Integration Tests for FastAPI Endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from server.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ONLINE_AIR_GAPPED"
    assert data["offline_guarantee"] is True


def test_list_benchmark_samples():
    response = client.get("/api/dataset/samples")
    assert response.status_code == 200
    samples = response.json()
    assert isinstance(samples, list)
    assert len(samples) >= 5


def test_load_sample_endpoint():
    response = client.get("/api/dataset/load-sample/sample_pqc_mlkem768_voip.pcap")
    assert response.status_code == 200
    data = response.json()
    assert "report_id" in data
    assert data["protocol"]["summary"]["pqc_ready"] is True
    assert data["traffic_classification"]["predicted_class"] == "VoIP"

    # Test Executive Report generation
    report_id = data["report_id"]
    exec_res = client.get(f"/api/reports/executive/{report_id}")
    assert exec_res.status_code == 200
    assert "Executive IPsec VPN Security Assessment" in exec_res.text

    # Test Technical Report generation
    tech_res = client.get(f"/api/reports/technical/{report_id}")
    assert tech_res.status_code == 200
    assert "TECHNICAL FORENSIC AUDIT" in tech_res.text
