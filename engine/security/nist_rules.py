"""
Standards & Compliance Rules Engine.
Maps observed algorithms and parameters directly to:
- NIST SP 800-77 Rev. 1 (June 2020) — Guide to IPsec VPNs
- RFC 8221 — Cryptographic Algorithm Implementation Requirements for ESP/AH
- RFC 8247 — Algorithm Implementation Requirements for IKEv2
- RFC 9370 / FIPS 203 — Post-Quantum Key Exchange (ML-KEM)
"""

from typing import Dict, List, Any
import re


class NISTComplianceRules:
    """
    Evaluates cryptographic algorithms against authoritative NIST and IETF RFC standards.
    """

    CIPHER_RATINGS = [
        # Modern AEAD Ciphers
        {"patterns": [r"aes.*gcm.*256", r"aes.*256.*gcm"], "name": "AES-256-GCM", "status": "APPROVED", "score": 100, "standards": "NIST SP 800-77r1 Sec 5.4.1 / RFC 8221 Sec 5"},
        {"patterns": [r"aes.*gcm.*128", r"aes.*128.*gcm"], "name": "AES-128-GCM", "status": "APPROVED", "score": 90, "standards": "NIST SP 800-77r1 Sec 5.4.1 / RFC 8221 Sec 5"},
        {"patterns": [r"chacha20"], "name": "ChaCha20-Poly1305", "status": "APPROVED", "score": 95, "standards": "RFC 8221 Sec 5 / RFC 7634"},
        
        # CBC Ciphers
        {"patterns": [r"aes.*cbc.*256", r"aes.*256.*cbc", r"aes.*256"], "name": "AES-256-CBC", "status": "APPROVED", "score": 85, "standards": "NIST SP 800-77r1 Sec 5.4.1 / RFC 8221 Sec 5"},
        {"patterns": [r"aes.*cbc.*128", r"aes.*128.*cbc", r"aes.*128"], "name": "AES-128-CBC", "status": "ACCEPTABLE_LEGACY", "score": 70, "standards": "NIST SP 800-77r1 Sec 5.4.1 (Transitioning)"},
        
        # Insecure / Deprecated
        {"patterns": [r"3des", r"triple.*des"], "name": "3DES-CBC", "status": "DEPRECATED", "score": 10, "standards": "NIST SP 800-77r1 Sec 5.4.1 Disallowed (Sweet32 attack)"},
        {"patterns": [r"des"], "name": "DES-CBC", "status": "INSECURE", "score": 0, "standards": "NIST SP 800-77r1 Disallowed (56-bit key broken)"},
        {"patterns": [r"blowfish"], "name": "BLOWFISH", "status": "DEPRECATED", "score": 20, "standards": "RFC 8221 Disallowed (64-bit block weakness)"},
    ]

    DH_RATINGS = [
        {"patterns": [r"ml-kem", r"mlkem", r"pqc"], "name": "ML-KEM-768", "status": "PQC_READY", "score": 100, "standards": "FIPS 203 / RFC 9370 (Quantum-Resilient Key Exchange)"},
        {"patterns": [r"curve25519", r"x25519"], "name": "Curve25519", "status": "APPROVED", "score": 95, "standards": "RFC 8247 Sec 4 / RFC 8031"},
        {"patterns": [r"ecp.*384", r"group.*20", r"p-384", r"384-bit random ecp"], "name": "ECP-384", "status": "APPROVED", "score": 100, "standards": "NIST SP 800-77r1 Sec 5.4.1 (Group 20 / P-384)"},
        {"patterns": [r"ecp.*256", r"group.*19", r"p-256", r"256-bit random ecp"], "name": "ECP-256", "status": "APPROVED", "score": 90, "standards": "NIST SP 800-77r1 Sec 5.4.1 (Group 19 / P-256)"},
        {"patterns": [r"modp.*3072", r"group.*15", r"3072-bit modp"], "name": "MODP-3072", "status": "APPROVED", "score": 90, "standards": "NIST SP 800-77r1 Sec 5.4.1 (Group 15)"},
        {"patterns": [r"modp.*2048", r"group.*14", r"2048-bit modp"], "name": "MODP-2048", "status": "ACCEPTABLE_LEGACY", "score": 65, "standards": "NIST SP 800-77r1 Sec 5.4.1 (Group 14, min acceptable)"},
        {"patterns": [r"modp.*1536", r"group.*5", r"1536-bit modp"], "name": "MODP-1536", "status": "DEPRECATED", "score": 25, "standards": "NIST SP 800-77r1 Disallowed (Group 5)"},
        {"patterns": [r"modp.*1024", r"group.*2", r"1024-bit modp"], "name": "MODP-1024", "status": "INSECURE", "score": 0, "standards": "NIST SP 800-77r1 & RFC 8247 Disallowed (Logjam vulnerability)"},
        {"patterns": [r"modp.*768", r"group.*1", r"768-bit modp"], "name": "MODP-768", "status": "INSECURE", "score": 0, "standards": "NIST SP 800-77r1 Disallowed (Group 1)"},
    ]

    PRF_RATINGS = [
        {"patterns": [r"sha2_512", r"sha512", r"sha-512"], "name": "PRF_HMAC_SHA2_512", "status": "APPROVED", "score": 100, "standards": "RFC 8247 Sec 3"},
        {"patterns": [r"sha2_384", r"sha384", r"sha-384"], "name": "PRF_HMAC_SHA2_384", "status": "APPROVED", "score": 100, "standards": "RFC 8247 Sec 3"},
        {"patterns": [r"sha2_256", r"sha256", r"sha-256"], "name": "PRF_HMAC_SHA2_256", "status": "APPROVED", "score": 90, "standards": "RFC 8247 Sec 3"},
        {"patterns": [r"aes.*xcbc", r"aes128_xcbc"], "name": "PRF_AES128_XCBC", "status": "ACCEPTABLE_LEGACY", "score": 70, "standards": "RFC 8247 Sec 3"},
        {"patterns": [r"sha1", r"sha-1"], "name": "PRF_HMAC_SHA1", "status": "DEPRECATED", "score": 30, "standards": "RFC 8247 Disallowed"},
        {"patterns": [r"md5"], "name": "PRF_HMAC_MD5", "status": "INSECURE", "score": 0, "standards": "RFC 8247 Disallowed (Collision vulnerabilities)"},
    ]

    INTEG_RATINGS = [
        {"patterns": [r"none", r"aead"], "name": "None (AEAD Combined Mode)", "status": "APPROVED", "score": 100, "standards": "NIST SP 800-77r1 (Built-in AEAD Authentication)"},
        {"patterns": [r"sha2_512", r"sha512", r"sha-512"], "name": "AUTH_HMAC_SHA2_512_256", "status": "APPROVED", "score": 100, "standards": "RFC 8221 Sec 5"},
        {"patterns": [r"sha2_384", r"sha384", r"sha-384"], "name": "AUTH_HMAC_SHA2_384_192", "status": "APPROVED", "score": 100, "standards": "RFC 8221 Sec 5"},
        {"patterns": [r"sha2_256", r"sha256", r"sha-256"], "name": "AUTH_HMAC_SHA2_256_128", "status": "APPROVED", "score": 85, "standards": "RFC 8221 Sec 5"},
        {"patterns": [r"sha1", r"sha-1"], "name": "AUTH_HMAC_SHA1_96", "status": "DEPRECATED", "score": 20, "standards": "RFC 8221 Disallowed"},
        {"patterns": [r"md5"], "name": "AUTH_HMAC_MD5_96", "status": "INSECURE", "score": 0, "standards": "RFC 8221 Disallowed"},
    ]

    @classmethod
    def evaluate_cipher(cls, cipher_name: str) -> Dict[str, Any]:
        c_clean = cipher_name.lower()
        for item in cls.CIPHER_RATINGS:
            for pat in item["patterns"]:
                if re.search(pat, c_clean):
                    return {"matched_name": item["name"], "status": item["status"], "score": item["score"], "standards": item["standards"]}
        return {"matched_name": cipher_name, "status": "UNKNOWN", "score": 50, "standards": "Unrecognized in NIST/RFC database"}

    @classmethod
    def evaluate_dh_group(cls, dh_name: str) -> Dict[str, Any]:
        d_clean = dh_name.lower()
        for item in cls.DH_RATINGS:
            for pat in item["patterns"]:
                if re.search(pat, d_clean):
                    return {"matched_name": item["name"], "status": item["status"], "score": item["score"], "standards": item["standards"]}
        return {"matched_name": dh_name, "status": "UNKNOWN", "score": 50, "standards": "Unrecognized DH/KE Group"}

    @classmethod
    def evaluate_prf(cls, prf_name: str) -> Dict[str, Any]:
        p_clean = prf_name.lower()
        for item in cls.PRF_RATINGS:
            for pat in item["patterns"]:
                if re.search(pat, p_clean):
                    return {"matched_name": item["name"], "status": item["status"], "score": item["score"], "standards": item["standards"]}
        return {"matched_name": prf_name, "status": "UNKNOWN", "score": 50, "standards": "Unrecognized PRF"}

    @classmethod
    def evaluate_integrity(cls, integ_name: str) -> Dict[str, Any]:
        i_clean = integ_name.lower()
        for item in cls.INTEG_RATINGS:
            for pat in item["patterns"]:
                if re.search(pat, i_clean):
                    return {"matched_name": item["name"], "status": item["status"], "score": item["score"], "standards": item["standards"]}
        return {"matched_name": integ_name, "status": "UNKNOWN", "score": 50, "standards": "Unrecognized Integrity"}
