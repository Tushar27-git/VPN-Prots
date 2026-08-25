"""
Threat & Vulnerability Matrix Builder.
Generates an actionable IPsec threat assessment mapped exclusively to genuine
MITRE ATT&CK techniques (T1040 & T1557 only per research dossier §6).
Zero forced mappings — every finding includes a concrete remediation plan.
"""

from typing import Dict, List, Any


class ThreatMatrixBuilder:
    """
    Constructs the threat matrix from parsed protocol parameters and security ratings.
    """

    def __init__(self):
        pass

    def build_threat_matrix(
        self,
        parsed_summary: Dict[str, Any],
        cipher_eval: Dict[str, Any],
        dh_eval: Dict[str, Any],
        prf_eval: Dict[str, Any],
        integ_eval: Dict[str, Any],
        metadata_findings: List[Dict[str, Any]],
        pfs_enabled: bool,
        pqc_ready: bool
    ) -> List[Dict[str, Any]]:
        threats = []

        # 1. Cipher Weakness (T1557 Downgrade)
        if cipher_eval["status"] in ("DEPRECATED", "INSECURE"):
            threats.append({
                "id": "THREAT-01",
                "category": "Cryptographic Downgrade",
                "finding": f"Insecure / Deprecated Encryption Cipher: {cipher_eval['matched_name']}",
                "severity": "CRITICAL" if cipher_eval["status"] == "INSECURE" else "HIGH",
                "mitre_technique": "T1557 (Adversary-in-the-Middle — Downgrade Sub-behavior)",
                "impact": "Vulnerable to SWEET32 block collision attacks or cryptanalytic key recovery.",
                "remediation": "Migrate proposal to AES-256-GCM or AES-128-GCM per NIST SP 800-77 Rev. 1.",
                "standards_citation": cipher_eval["standards"],
            })

        # 2. Key Exchange / DH Group Weakness (T1557 Downgrade)
        if dh_eval["status"] in ("DEPRECATED", "INSECURE"):
            threats.append({
                "id": "THREAT-02",
                "category": "Key Exchange Vulnerability",
                "finding": f"Weak Diffie-Hellman Group: {dh_eval['matched_name']}",
                "severity": "CRITICAL" if dh_eval["status"] == "INSECURE" else "HIGH",
                "mitre_technique": "T1557 (Adversary-in-the-Middle — Downgrade Sub-behavior)",
                "impact": "Discrete logarithm precomputation attacks (e.g. Logjam on MODP-1024) enable passive decryption.",
                "remediation": "Upgrade DH group to ECP-384 (Group 20), ECP-256 (Group 19), or hybrid ML-KEM-768.",
                "standards_citation": dh_eval["standards"],
            })

        # 3. Missing Perfect Forward Secrecy (T1557 Downgrade)
        if not pfs_enabled:
            threats.append({
                "id": "THREAT-03",
                "category": "Session Key Compromise",
                "finding": "Perfect Forward Secrecy (PFS) is Disabled in Child SA",
                "severity": "HIGH",
                "mitre_technique": "T1557 (Adversary-in-the-Middle — Downgrade Sub-behavior)",
                "impact": "Long-term private key compromise enables retroactive bulk decryption of all historical recorded traffic.",
                "remediation": "Configure 'esp_proposals' to explicitly include a DH group (e.g., esp=aes256gcm16-ecp384!).",
                "standards_citation": "NIST SP 800-77 Rev. 1 Section 5.4.2 / RFC 8247 Section 4",
            })

        # 4. Hash / PRF Deprecation (T1557 Downgrade)
        if prf_eval["status"] in ("DEPRECATED", "INSECURE") or integ_eval["status"] in ("DEPRECATED", "INSECURE"):
            bad_algo = prf_eval['matched_name'] if prf_eval['status'] in ('DEPRECATED', 'INSECURE') else integ_eval['matched_name']
            threats.append({
                "id": "THREAT-04",
                "category": "Integrity / PRF Weakness",
                "finding": f"Deprecated Hash / PRF Function: {bad_algo}",
                "severity": "HIGH",
                "mitre_technique": "T1557 (Adversary-in-the-Middle — Downgrade Sub-behavior)",
                "impact": "Collision vulnerabilities permit forged key derivation or authentication bypass.",
                "remediation": "Require HMAC-SHA2-384 or HMAC-SHA2-256 PRF algorithms per RFC 8247 Section 3.",
                "standards_citation": prf_eval["standards"],
            })

        # 5. Metadata Exposure Findings (T1040 Network Sniffing)
        for meta in metadata_findings:
            threats.append({
                "id": f"THREAT-META-{len(threats)+1}",
                "category": meta["category"],
                "finding": meta["finding"],
                "severity": meta["severity"],
                "mitre_technique": "T1040 (Network Sniffing — Passive Reconnaissance)",
                "impact": "Passive network observers can catalog gateway hardware, software versions, and topology.",
                "remediation": "Disable redundant Vendor ID payloads in charon.conf and utilize IKEv2 IDr masking.",
                "standards_citation": meta["standards_ref"],
            })

        # 6. Post-Quantum Exposure (Self-defined IPsec Weakness - No forced MITRE)
        if not pqc_ready:
            threats.append({
                "id": "THREAT-PQC-01",
                "category": "Post-Quantum Cryptographic Preparedness",
                "finding": "Tunnel Relies Exclusively on Classical Discrete-Log / Elliptic-Curve Cryptography",
                "severity": "MEDIUM",
                "mitre_technique": "None (Self-defined IPsec Architectural Gap)",
                "impact": "Vulnerable to 'Store-Now-Decrypt-Later' adversary collection against future quantum cryptanalysis.",
                "remediation": "Deploy hybrid RFC 9370 key exchange (e.g. strongSwan ke1_mlkem768 hybrid with ECP384).",
                "standards_citation": "FIPS 203 (ML-KEM) / RFC 9370 / NIST IR 8547",
            })

        return threats


if __name__ == "__main__":
    builder = ThreatMatrixBuilder()
    tm = builder.build_threat_matrix(
        parsed_summary={},
        cipher_eval={"matched_name": "3DES-CBC", "status": "DEPRECATED", "standards": "NIST SP 800-77r1"},
        dh_eval={"matched_name": "MODP-1024", "status": "INSECURE", "standards": "RFC 8247"},
        prf_eval={"matched_name": "PRF_HMAC_SHA2_256", "status": "APPROVED", "standards": "RFC 8247"},
        integ_eval={"matched_name": "None", "status": "APPROVED", "standards": "NIST"},
        metadata_findings=[{"category": "VID Leakage", "finding": "strongSwan VID visible", "severity": "LOW", "standards_ref": "NIST"}],
        pfs_enabled=False,
        pqc_ready=False
    )
    print(f"Generated {len(tm)} threats.")
