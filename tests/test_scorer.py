"""
Unit tests for NIST SP 800-77 Rev. 1 & RFC Compliance Scorer and Threat Matrix.
"""

import pytest
from engine.security.nist_rules import NISTComplianceRules
from engine.security.scorer import IPsecSecurityScorer


@pytest.fixture
def scorer():
    return IPsecSecurityScorer()


def test_nist_high_assurance_scoring(scorer):
    mock_data = {
        "summary": {
            "encryption_algorithm": "AES-256-GCM",
            "dh_group": "ECP-384",
            "prf_algorithm": "PRF_HMAC_SHA2_384",
            "integrity_algorithm": "None (AEAD Combined Mode)",
            "pfs_enabled": True,
            "pqc_ready": True,
            "ike_version": "IKEv2",
        },
        "metadata_exposure": [],
        "esp_packets": [{"seq": 1}, {"seq": 2}, {"seq": 3}],
    }
    res = scorer.score_assessment(mock_data, {"vendor": "strongSwan", "os_environment": "Linux"})

    assert res["composite_security_score"] >= 90.0
    assert res["overall_risk_score"] <= 15.0
    assert "A" in res["security_grade"]
    assert res["dimension_scores"]["cryptographic_strength"] >= 95.0
    assert res["dimension_scores"]["perfect_forward_secrecy"] == 100.0


def test_deprecated_config_scoring(scorer):
    mock_data = {
        "summary": {
            "encryption_algorithm": "3DES-CBC",
            "dh_group": "MODP-1024",
            "prf_algorithm": "PRF_HMAC_MD5",
            "integrity_algorithm": "AUTH_HMAC_MD5_96",
            "pfs_enabled": False,
            "pqc_ready": False,
            "ike_version": "IKEv1",
        },
        "metadata_exposure": [{"category": "VID Leakage", "finding": "VID exposed", "severity": "HIGH", "standards_ref": "NIST"}],
        "esp_packets": [{"seq": 1}, {"seq": 2}],
    }
    res = scorer.score_assessment(mock_data, {"vendor": "Generic", "os_environment": "Unknown"})

    assert res["composite_security_score"] < 45.0
    assert res["overall_risk_score"] >= 80.0
    assert "F" in res["security_grade"]
    # Check Threat Matrix MITRE tags
    threats = res["threat_matrix"]
    mitre_tags = [t["mitre_technique"] for t in threats]
    assert any("T1557" in tag for tag in mitre_tags)
    assert any("T1040" in tag for tag in mitre_tags)
