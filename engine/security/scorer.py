"""
Comprehensive IPsec Security Scorer.
Computes multi-dimensional standards compliance scores against:
- NIST SP 800-77 Rev. 1 (June 2020)
- RFC 8221 / RFC 8247
- RFC 9370 / FIPS 203 PQC
Never collapses to a single score without providing the full per-dimension breakdown.
"""

from typing import Dict, List, Any
from engine.security.nist_rules import NISTComplianceRules
from engine.security.threat_matrix import ThreatMatrixBuilder


class IPsecSecurityScorer:
    """
    Evaluates empirical protocol parameters and calculates security posture
    and risk ratings across 6 independent dimensions.
    """

    DIMENSION_WEIGHTS = {
        "crypto_strength": 0.25,
        "config_compliance": 0.20,
        "key_management": 0.15,
        "pfs": 0.15,
        "replay_protection": 0.10,
        "metadata_exposure": 0.15,
    }

    def __init__(self):
        self.rules = NISTComplianceRules()
        self.threat_builder = ThreatMatrixBuilder()

    def score_assessment(self, parsed_data: Dict[str, Any], fingerprint_data: Dict[str, Any]) -> Dict[str, Any]:
        summary = parsed_data.get("summary", {})
        metadata_findings = parsed_data.get("metadata_exposure", [])

        # 1. Cryptographic Evaluations
        cipher_str = summary.get("encryption_algorithm", "AES-256-GCM")
        dh_str = summary.get("dh_group", "ECP-384")
        prf_str = summary.get("prf_algorithm", "PRF_HMAC_SHA2_384")
        integ_str = summary.get("integrity_algorithm", "None")
        pfs_enabled = summary.get("pfs_enabled", True)
        pqc_ready = summary.get("pqc_ready", False)

        eval_cipher = self.rules.evaluate_cipher(cipher_str)
        eval_dh = self.rules.evaluate_dh_group(dh_str)
        eval_prf = self.rules.evaluate_prf(prf_str)
        eval_integ = self.rules.evaluate_integrity(integ_str)

        # -------------------------------------------------------------
        # Dimension 1: Cryptographic Strength (0 - 100)
        # -------------------------------------------------------------
        crypto_score = (
            eval_cipher["score"] * 0.40 +
            eval_dh["score"] * 0.35 +
            eval_prf["score"] * 0.15 +
            eval_integ["score"] * 0.10
        )
        # Bonus for Quantum Readiness
        if pqc_ready:
            crypto_score = min(100.0, crypto_score + 5.0)

        # -------------------------------------------------------------
        # Dimension 2: Configuration & Protocol Compliance (0 - 100)
        # -------------------------------------------------------------
        config_score = 100.0
        ike_ver = summary.get("ike_version", "IKEv2")
        if "IKEv1" in ike_ver:
            config_score -= 30.0  # IKEv1 legacy penalty
        if eval_cipher["status"] in ("DEPRECATED", "INSECURE"):
            config_score -= 40.0
        if eval_dh["status"] in ("DEPRECATED", "INSECURE"):
            config_score -= 30.0
        config_score = max(0.0, min(100.0, config_score))

        # -------------------------------------------------------------
        # Dimension 3: Key Management & Lifetime (0 - 100)
        # -------------------------------------------------------------
        key_score = 90.0
        if eval_dh["status"] == "INSECURE":
            key_score = 10.0
        elif eval_dh["status"] == "DEPRECATED":
            key_score = 35.0
        elif eval_dh["status"] == "ACCEPTABLE_LEGACY":
            key_score = 70.0
        elif pqc_ready:
            key_score = 100.0

        # -------------------------------------------------------------
        # Dimension 4: Perfect Forward Secrecy (PFS) (0 - 100)
        # -------------------------------------------------------------
        pfs_score = 100.0 if pfs_enabled else 20.0

        # -------------------------------------------------------------
        # Dimension 5: Anti-Replay Protection (0 - 100)
        # -------------------------------------------------------------
        replay_score = 95.0
        esp_packets = parsed_data.get("esp_packets", [])
        if len(esp_packets) > 1:
            seqs = [p.get("seq", 0) for p in esp_packets]
            if len(seqs) > len(set(seqs)):
                replay_score = 25.0  # Duplicate sequence numbers observed
        else:
            replay_score = 85.0  # Default assumed compliant

        # -------------------------------------------------------------
        # Dimension 6: Metadata Exposure & Privacy (0 - 100)
        # -------------------------------------------------------------
        meta_score = 100.0
        for mf in metadata_findings:
            if mf["severity"] == "HIGH":
                meta_score -= 25.0
            elif mf["severity"] == "MEDIUM":
                meta_score -= 15.0
            elif mf["severity"] == "LOW":
                meta_score -= 5.0
        meta_score = max(20.0, min(100.0, meta_score))

        # -------------------------------------------------------------
        # Composite Score Calculation (Weighted)
        # -------------------------------------------------------------
        dimensions = {
            "cryptographic_strength": round(crypto_score, 1),
            "configuration_compliance": round(config_score, 1),
            "key_management": round(key_score, 1),
            "perfect_forward_secrecy": round(pfs_score, 1),
            "anti_replay_protection": round(replay_score, 1),
            "metadata_privacy": round(meta_score, 1),
        }

        composite_score = sum(dimensions[k] * self.DIMENSION_WEIGHTS[w] for k, w in zip(
            dimensions.keys(),
            ["crypto_strength", "config_compliance", "key_management", "pfs", "replay_protection", "metadata_exposure"]
        ))
        composite_score = round(composite_score, 1)

        # Risk Score (Inverse of composite, scaled with severe finding penalties)
        risk_score = round(max(0.0, min(100.0, 100.0 - composite_score)), 1)
        if eval_cipher["status"] == "INSECURE" or eval_dh["status"] == "INSECURE":
            risk_score = max(risk_score, 85.0)

        # Grade Mapping
        if composite_score >= 92.0:
            grade = "A+ (Quantum-Safe / High-Assurance)"
            posture = "EXEMPLARY"
        elif composite_score >= 80.0:
            grade = "A (NIST Compliant)"
            posture = "STRONG"
        elif composite_score >= 68.0:
            grade = "B (Acceptable / Legacy)"
            posture = "MODERATE"
        elif composite_score >= 50.0:
            grade = "C (Non-Compliant Weaknesses)"
            posture = "DEFICIENT"
        else:
            grade = "F (Critical Vulnerabilities)"
            posture = "CRITICAL_RISK"

        # Build Threat Matrix
        threat_matrix = self.threat_builder.build_threat_matrix(
            parsed_summary=summary,
            cipher_eval=eval_cipher,
            dh_eval=eval_dh,
            prf_eval=eval_prf,
            integ_eval=eval_integ,
            metadata_findings=metadata_findings,
            pfs_enabled=pfs_enabled,
            pqc_ready=pqc_ready
        )

        return {
            "composite_security_score": composite_score,
            "overall_risk_score": risk_score,
            "security_grade": grade,
            "posture_assessment": posture,
            "dimension_scores": dimensions,
            "dimension_weights": self.DIMENSION_WEIGHTS,
            "algorithm_evaluations": {
                "cipher": eval_cipher,
                "dh_group": eval_dh,
                "prf": eval_prf,
                "integrity": eval_integ,
            },
            "pqc_status": {
                "is_pqc_ready": pqc_ready,
                "rfc_standard": "RFC 9370 (Multiple Key Exchanges) / FIPS 203 (ML-KEM)",
                "details": summary.get("pqc_details", []),
            },
            "threat_matrix": threat_matrix,
            "threat_count": len(threat_matrix),
            "standards_basis": "NIST SP 800-77 Rev. 1 (June 2020), RFC 8221, RFC 8247, RFC 9370",
        }


if __name__ == "__main__":
    scorer = IPsecSecurityScorer()
    mock_data = {
        "summary": {
            "encryption_algorithm": "AES-256-GCM",
            "dh_group": "ML-KEM-768 + ECP-384",
            "prf_algorithm": "PRF_HMAC_SHA2_384",
            "integrity_algorithm": "None (AEAD)",
            "pfs_enabled": True,
            "pqc_ready": True,
            "ike_version": "IKEv2",
        },
        "metadata_exposure": [],
        "esp_packets": [{"seq": 1}, {"seq": 2}, {"seq": 3}],
    }
    res = scorer.score_assessment(mock_data, {})
    print(f"Composite Score: {res['composite_security_score']}, Grade: {res['security_grade']}")
