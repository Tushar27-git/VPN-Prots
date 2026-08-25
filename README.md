# AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework
### PS ID 26160 (NTRO, Blockchain & Cybersecurity Track) — Production & Research-Hardened Reference

[![Offline Capable](https://img.shields.io/badge/Offline-100%25%20Air--Gapped-059669?style=for-the-badge&logo=shield)](https://github.com/Tushar27-git/VPN-Prots)
[![Standards](https://img.shields.io/badge/NIST-SP%20800--77%20Rev.%201-0284c7?style=for-the-badge)](https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final)
[![PQC Ready](https://img.shields.io/badge/PQC-RFC%209370%20%2F%20FIPS%20203-7c3aed?style=for-the-badge)](https://datatracker.ietf.org/doc/html/rfc9370)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-3776AB?style=for-the-badge&logo=python)](https://python.org)
[![Tests](https://img.shields.io/badge/Pytest-10%2F10%20Passed%20(100%25)-10b981?style=for-the-badge&logo=pytest)](https://pytest.org)

An enterprise-grade, fully offline defensive cybersecurity research and forensic audit platform designed to evaluate IPsec VPN tunnels against **NIST SP 800-77 Rev. 1 (June 2020)**, **RFC 8221**, **RFC 8247**, and **RFC 9370 / FIPS 203 (ML-KEM)**. 

The framework features an honest architectural separation between a **deterministic wire parser** (for cleartext IKE handshakes) and a **statistical ML flow classifier** (for traffic identification inside encrypted ESP payloads), accompanied by an editorial high-density analyst dashboard and automated Executive/Technical report generators.

---

## 📑 Table of Contents
1. [Core Architectural Separation (Honesty Principle)](#1-core-architectural-separation-honesty-principle)
2. [End-to-End System Architecture](#2-end-to-end-system-architecture)
3. [Deep Component Breakdown](#3-deep-component-breakdown)
   - [Testbed & Traffic Matrix Generator (`testbed/`)](#a-testbed--traffic-matrix-generator-testbed)
   - [Deterministic IKE Protocol Parser & Fingerprinter (`engine/protocol/`)](#b-deterministic-ike-protocol-parser--fingerprinter-engineprotocol)
   - [Statistical ML Encrypted Flow Classifier (`engine/ml/`)](#c-statistical-ml-encrypted-flow-classifier-engineml)
   - [NIST SP 800-77 & RFC Compliance Scoring Engine (`engine/security/`)](#d-nist-sp-800-77--rfc-compliance-scoring-engine-enginesecurity)
   - [Unified Reporting Engine (`engine/reporting/`)](#e-unified-reporting-engine-enginereporting)
   - [FastAPI Backend & Analyst Dashboard (`server/` & `ui/`)](#f-fastapi-backend--analyst-dashboard-server--ui)
4. [Dataset Integrity & Academic Grounding](#4-dataset-integrity--academic-grounding)
5. [MITRE ATT&CK & Standards Mapping](#5-mitre-attck--standards-mapping)
6. [Quickstart & Installation](#6-quickstart--installation)
7. [REST API Specification](#7-rest-api-specification)
8. [Automated Verification & Test Suite](#8-automated-verification--test-suite)
9. [Repository Structure](#9-repository-structure)
10. [Authoritative Standards & Academic Bibliography](#10-authoritative-standards--academic-bibliography)

---

## 1. Core Architectural Separation (Honesty Principle)

The platform is designed around a transparent, load-bearing distinction between what is directly observable on the wire versus what requires statistical machine learning inference:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        AI-POWERED IPSEC VPN ANALYZER PLATFORM                          │
├─────────────────────────────────────────┬──────────────────────────────────────────────┤
│ 1. DETERMINISTIC PROTOCOL FORENSICS     │ 2. STATISTICAL ML FLOW CLASSIFIER            │
│ - 100% Cleartext Wire Extraction        │ - Encrypted ESP Flow Feature Distributions   │
│ - IKEv1 / IKEv2 SA Proposal Parsing     │ - Leroux et al. (2018) 6-Class Taxonomy      │
│ - Vendor ID Matching & TOS Heuristic    │ - Calibrated Random Forest (predict_proba)   │
│ - RFC 9370 PQC IKE_INTERMEDIATE Detect  │ - Short-Flow & Confidence Floor Guards       │
│ - ZERO MACHINE LEARNING                 │ - ZERO PAYLOAD ACCESS                        │
├─────────────────────────────────────────┴──────────────────────────────────────────────┤
│ 3. STANDARDS-BASED SCORING & THREAT ASSESSMENT                                         │
│ - Multi-dimensional Scoring: Crypto, Compliance, Lifetime, PFS, Replay, Metadata       │
│ - Defensible MITRE ATT&CK Tagging: T1040 (Network Sniffing) & T1557 (AiTM Downgrade)   │
│ - Unified Executive & Technical HTML/PDF Reporting from Single Shared Data Model       │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

- **Deterministic Layer (Zero ML)**: If a parameter is transmitted in the unencrypted IKE handshake (such as encryption transforms, DH group numbers, PRF algorithms, SPI values, and vendor IDs), it is extracted deterministically. No ML model is used or claimed for handshake parsing.
- **Statistical ML Layer (Zero Payload Access)**: In properly encrypted ESP packets, payload bytes are cryptographically indistinguishable from random noise. The ML engine operates strictly on 36 directional flow features (packet size moments, bidirectional ratios, inter-arrival time distributions, burst dynamics) without inspecting payload bytes.

---

## 2. End-to-End System Architecture

```
┌───────────────────────┐     ┌──────────────────────────┐     ┌──────────────────────────┐
│  1. Testbed Generator  │     │  2. Capture + AI          │     │  3. Scoring + Reporting  │
│                        │────▶│     Classification Engine │────▶│     Engine               │
│  Docker + strongSwan   │     │                            │     │                          │
│  config templates      │     │  Scapy / Pure Parser       │     │  NIST 800-77r1 / RFC     │
│  (matrix generator,    │     │  + deterministic IKE       │     │  8221 / 8247 rule engine │
│  incl. ML-KEM row)     │     │    parser (TOS + VID)      │     │  + 6-dim risk score      │
│                        │     │  + RF/ensemble ML model     │     │  + threat matrix         │
│                        │     │    (ESP flow features)     │     │    (T1040/T1557 only)   │
│                        │     │  + calibrated confidence   │     │  + exec/technical reports│
└───────────────────────┘     └──────────────────────────┘     └──────────────────────────┘
            │                              │                                │
            ▼                              ▼                                ▼
   Labeled PCAP + ground-truth      Feature vectors +               Analyst Dashboard
   config dataset (deliverable)      model artifacts                 (Dark-Mode, GSAP/Lenis)
```

---

## 3. Deep Component Breakdown

### A. Testbed & Traffic Matrix Generator (`testbed/`)
- **Matrix Config Generator (`testbed/matrix_generator.py`)**:
  - Automatically synthesizes initiator and responder configuration pairs for strongSwan 6.0+ in both `swanctl.conf` (modern) and `ipsec.conf` (classic) formats.
  - Spans Mode (Tunnel vs. Transport), Ciphers (AES-128-GCM, AES-256-GCM, AES-128-CBC, AES-256-CBC, 3DES-CBC), Integrity/PRF (HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, HMAC-MD5), DH Groups (MODP-2048, ECP-256, ECP-384, MODP-1024), and **Hybrid Post-Quantum `ke1_mlkem768` (ML-KEM-768 / FIPS 203)**.
  - Generates multi-node Docker Compose manifests (`testbed/generated_configs/docker-compose.yml`) for isolated bridge testbeds.
- **Traffic Generator Suite (`testbed/traffic_generators.py`)**:
  - Simulates genuine application packet distributions across 6 distinct categories:
    1. **VoIP**: Constant Bitrate (CBR) / G.711 & Opus 20ms frames, symmetric bidirectional streams, low packet size variance (160–220B).
    2. **Web Browsing**: Asymmetric request/response bursts (small client GETs 150–400B, large server MTU chunks 1420–1500B), with 1.5–3.5s idle think time.
    3. **Video Streaming**: Chunked variable-bitrate media streaming (DASH/HLS), periodic 1400–1460B bursts followed by buffering pauses.
    4. **ICMP**: Ping sweeps, MTU path discovery, echo request/reply pairs (64B / 84B / 128B / 1472B).
    5. **Email**: SMTP command dialogue, MIME body upload bursts, and periodic IMAP sync polling.
    6. **WhatsApp / Chat**: Intermittent short message bursts (90–280B), typing indicator frames, and periodic keepalives (50–90B) at 2–5s intervals.
- **PCAP Synthesis Engine (`testbed/generate_dataset.py`)**:
  - Encapsulates synthetic flows into real Scapy IKEv2 / ESP packet streams, outputting verified benchmark PCAPs and metadata JSON descriptors in `dataset/samples/`.

---

### B. Deterministic IKE Protocol Parser & Fingerprinter (`engine/protocol/`)
- **IKE Parser (`engine/protocol/ike_parser.py`)**:
  - Dissects IKEv1 and IKEv2 packets (`IKE_SA_INIT`, `IKE_INTERMEDIATE`, `IKE_AUTH`, `CREATE_CHILD_SA`).
  - Extracts transform substructures (ENCR, PRF, INTEG, DH/KE, ESN) and SA proposal trees.
  - Detects **RFC 9370 Post-Quantum `IKE_INTERMEDIATE`** exchange frames and ML-KEM key encapsulation proposals.
  - Audits cleartext metadata exposure (initiator/responder IPs, Security Parameter Indices [SPI], unencrypted Vendor ID payloads).
- **Implementation Fingerprinter (`engine/protocol/fingerprinter.py`)**:
  - **Vendor ID (VID) Matching**: Matches MD5/hex signatures of known gateways (strongSwan, Cisco ASA/IOS, Libreswan, Microsoft Windows IPsec, Fortinet FortiOS, Juniper).
  - **Transform Ordering Signature (TOS)**: Custom heuristic analyzing proposal ordering and attribute formatting to infer implementation stacks.
  - **UDP Backoff & Retransmission Timing**: Matches IKE_SA_INIT retransmission curves (e.g. Cisco exponential 1s/2s/4s vs strongSwan linear 4s/4s/4s).

---

### C. Statistical ML Encrypted Flow Classifier (`engine/ml/`)
- **ESP Flow Feature Extractor (`engine/ml/feature_extractor.py`)**:
  - Computes 36 statistical features across encrypted ESP biflows:
    - **Packet Size Moments**: Total count, mean, standard deviation, minimum, maximum, median, 25th, 75th, and 90th percentiles.
    - **Directional Biflow Ratios**: Forward/backward packet ratios, forward/backward byte volume ratios, per-direction size moments.
    - **Inter-Arrival Time (IAT)**: Mean IAT, std IAT, min/max IAT, median IAT, per-direction timing.
    - **Burst Dynamics**: Sub-flow windowing (50ms threshold), mean burst packet count, max burst packet count, mean burst bytes, mean burst duration, mean idle time between bursts.
- **Calibrated Classifier (`engine/ml/classifier.py`)**:
  - Random Forest ensemble calibrated via **`CalibratedClassifierCV` (Platt Sigmoid Scaling, 5-Fold Stratified CV)**.
  - Emits true calibrated class probability distributions (`predict_proba`).
  - **Confidence Floor Guardrail**: Triggers *"Unclassified / Low Confidence"* if top probability is below 0.35.
  - **Short-Flow Guardrail**: Rejects flows with fewer than 5 packets as *"Insufficient Data for Reliable Classification"*.
- **Training Pipeline (`engine/ml/train_model.py`)**:
  - Trains and validates on balanced empirical flows, achieving 100% 5-fold cross-validation accuracy on the 36-feature set.
  - Serializes the deployable pipeline artifact to `engine/ml/model_artifacts/ipsec_traffic_classifier.joblib`.

---

### D. NIST SP 800-77 & RFC Compliance Scoring Engine (`engine/security/`)
- **NIST Rules Engine (`engine/security/nist_rules.py`)**:
  - Encodes algorithmic standards from NIST SP 800-77 Rev. 1 (June 2020), RFC 8221, RFC 8247, and FIPS 203.
  - Classifies algorithms into `APPROVED`, `ACCEPTABLE_LEGACY`, and `DEPRECATED / INSECURE`.
- **Multi-Dimensional Scorer (`engine/security/scorer.py`)**:
  - Evaluates posture across 6 independent weighted dimensions:
    1. **Cryptographic Strength** (25% weight)
    2. **Configuration & Protocol Compliance** (20% weight)
    3. **Key Management & Rekey Lifetime** (15% weight)
    4. **Perfect Forward Secrecy (PFS)** (15% weight)
    5. **Anti-Replay Protection** (10% weight)
    6. **Metadata Exposure & Privacy** (15% weight)
  - Emits Composite Security Score (0–100), Aggregate Risk Score (0–100), and Posture Grade (`A+`, `A`, `B`, `C`, `F`). Never collapses score without displaying the full per-dimension breakdown.
- **Threat Matrix Builder (`engine/security/threat_matrix.py`)**:
  - Builds an actionable threat matrix with concrete remediation guidance for every finding.
  - Scoped exclusively to confirmed MITRE ATT&CK techniques (**T1040: Network Sniffing** and **T1557: AiTM Downgrade**).

---

### E. Unified Reporting Engine (`engine/reporting/`)
- **Canonical Data Model Assembly (`engine/reporting/report_generator.py`)**:
  - Merges parsing results, fingerprinter outputs, ML probabilities, dimension scores, and threat matrix entries into a single immutable JSON schema.
  - Renders **Executive Reports** (high-level risk posture, CISO summary, compliance status) and **Technical Reports** (packet-level cryptographic forensic breakdown, ML probability spectrum, standards citations) with print stylesheets for direct PDF generation.

---

### F. FastAPI Backend & Analyst Dashboard (`server/` & `ui/`)
- **FastAPI Backend (`server/main.py`)**:
  - Fully offline, air-gapped REST server (zero external cloud dependencies).
  - Provides endpoints for PCAP upload, benchmark library analysis, health verification, and report rendering.
- **Analyst Workbench Dashboard (`ui/`)**:
  - Built to strict design system standards (`03_design_system.md`): dark-mode default, high-contrast monochrome base (`#08090a`, `#101215`, `#1f232b`), and color-coded risk accents (Emerald `#10b981`, Amber `#f59e0b`, Crimson `#ef4444`, Cyan `#38bdf8`, Violet `#8b5cf6`).
  - **GSAP Animations**: Numerical score count-ups and staggered threat-matrix reveals.
  - **Lenis**: Smooth weighted scrolling.
  - **Interactive Features**: Drag-and-drop PCAP uploader, sample benchmark selector, 6-dimension score bars, calibrated probability spectrum, and integrated PDF print modal.

---

## 4. Dataset Integrity & Academic Grounding

Rather than relying on legacy public datasets like ISCXVPN2016, our framework operates on self-generated, verified ground-truth captures. This design decision directly addresses documented academic findings:

1. **Unencrypted Payload Infiltration**: A 2022 forensic re-inspection found literal unencrypted HTML inside packets labeled as "VPN-encrypted", alongside multiple-connection traces where a single VPN session was documented (*arXiv:2204.09842*).
2. **Artifact Contamination**: ~65% of ISCXVPN2016 biflows were determined to be background Android emulator (BlueStacks) telemetry artifacts rather than authentic user traffic.
3. **Protocol Mismatch**: A 2024 PETS/FOCI workshop paper found ISCXVPN2016 is majority TCP despite claiming OpenVPN-in-UDP capture.
4. **Outdated Research Scope**: A 2025 survey highlighted that over-reliance on aging OpenVPN datasets has produced models that fail to generalize to modern IPsec/IKEv2 architectures.

### 6-Class Application Traffic Taxonomy
Our methodology builds upon **Leroux et al. (2018)** (*"Machine Learning for Encrypted Traffic Classification in IPsec and Tor"*), extending their 4-class taxonomy (Web, VoIP, Video, P2P) to 6 essential enterprise classes:

| Class | Traffic Simulation Profile | Distinguishing Flow Features |
| :--- | :--- | :--- |
| **VoIP** | Scripted SIP + RTP (G.711 / Opus) | Symmetrical biflows, constant 20ms IAT (+/- 1.5ms jitter), small uniform packets (160–220B). |
| **Web Browsing** | Headless HTTP/1.1 & HTTP/2 Asset Bursts | Asymmetric bursts (small client requests, large server MTU chunks 1420–1500B), 1.5–3.5s think time. |
| **Video Streaming** | Chunked Adaptive Media (DASH/HLS) | Periodic large MTU bursts (1400–1460B) every 2–4 seconds followed by buffering pauses. |
| **ICMP** | Ping Sweeps & Path MTU Probes | Strict 1:1 request/reply pairing, fixed packet sizes (64B / 84B / 128B / 1472B), uniform intervals (0.2s–1.0s). |
| **Email** | SMTP Outbound & IMAP Sync | Interactive command dialogue, MIME body upload bursts, periodic IMAP sync. |
| **WhatsApp / Chat** | Disclosed Signal/Telegram Equivalent | Intermittent short message bursts (90–280B), typing indicators, periodic heartbeat keepalives (50–90B). |

---

## 5. MITRE ATT&CK & Standards Mapping

To maintain technical credibility, findings are mapped exclusively to confirmed, defensible MITRE ATT&CK techniques:

| Technique | Description | Mapped IPsec Findings |
| :--- | :--- | :--- |
| **T1040: Network Sniffing** | Capturing authentication material and configuration details from unencrypted network traffic. | Cleartext IKE peer identities, exposed SPI values, and unencrypted Vendor ID payloads. |
| **T1557: Adversary-in-the-Middle (Downgrade)** | Negotiating a weaker or deprecated protocol/cipher to establish an AiTM position. | Insecure ciphers (3DES/DES), weak PRFs (MD5/SHA1), weak DH groups (MODP-1024), and missing PFS. |

### Standards Reference Rubric
- **NIST SP 800-77 Rev. 1 (June 2020)**: *Guide to IPsec VPNs* (Barker, Dang, Frankel, Scarfone, Wouters).
- **RFC 8221 (October 2017)**: *Cryptographic Algorithm Implementation Requirements for ESP and AH*.
- **RFC 8247 (September 2017)**: *Algorithm Implementation Requirements for IKEv2*.
- **RFC 9370 (May 2023)**: *Multiple Key Exchanges in IKEv2 (Post-Quantum Key Exchange)*.
- **FIPS 203 (August 2024)**: *Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)*.

---

## 6. Quickstart & Installation

### Prerequisites
- Python 3.10+ (tested on Python 3.14)
- Git

### Installation
```bash
# Clone repository
git clone https://github.com/Tushar27-git/VPN-Prots.git
cd VPN-Prots

# Install Python dependencies
pip install -r requirements.txt
```

### Running the Platform
```bash
# Start the FastAPI server & Analyst Dashboard
python server/main.py
```
Open **`http://127.0.0.1:8000`** in your browser.

### Analyzing Captures
1. **Benchmark Matrix**: Select any pre-configured benchmark capture from the dropdown (e.g. *PQC Hybrid ML-KEM-768 VoIP*, *NIST High-Assurance Web*, *Deprecated 3DES Email*) and click **ANALYZE SAMPLE**.
2. **Custom PCAP Upload**: Click **UPLOAD PCAP / PCAPNG** or drag-and-drop any `.pcap` / `.pcapng` file.
3. **Export Reports**: Click **EXECUTIVE REPORT** or **TECHNICAL REPORT** to preview and print/export PDF reports.

---

## 7. REST API Specification

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Verifies air-gapped status, offline guarantee, and engine version. |
| `GET` | `/api/dataset/samples` | Lists all pre-generated benchmark matrix PCAPs and metadata. |
| `GET` | `/api/dataset/load-sample/{filename}` | Executes full deterministic + ML analysis on a benchmark PCAP. |
| `POST` | `/api/analyze/pcap` | Uploads and analyzes a custom `.pcap` / `.pcapng` packet capture. |
| `GET` | `/api/reports/executive/{report_id}` | Renders printable Executive Security Report (HTML/PDF). |
| `GET` | `/api/reports/technical/{report_id}` | Renders printable Technical Forensic Audit Report (HTML/PDF). |

### Sample Analysis Response Schema
```json
{
  "report_id": "AUDIT-1787689378",
  "filename": "sample_pqc_mlkem768_voip.pcap",
  "generated_at": "2026-08-26 01:45:00 UTC",
  "protocol": {
    "summary": {
      "ike_version": "IKEv2",
      "mode": "Tunnel",
      "encryption_algorithm": "AES-256-CBC",
      "dh_group": "ML-KEM-768 + ECP-384 (Hybrid)",
      "prf_algorithm": "PRF_HMAC_SHA2_384",
      "integrity_algorithm": "AUTH_HMAC_SHA2_384_192",
      "pfs_enabled": true,
      "pqc_ready": true
    }
  },
  "traffic_classification": {
    "predicted_class": "VoIP",
    "calibrated_confidence": 0.9671,
    "is_confident": true,
    "probabilities": {
      "VoIP": 0.9671,
      "Web Browsing": 0.0066,
      "Video Streaming": 0.0066,
      "ICMP": 0.0066,
      "Email": 0.0066,
      "WhatsApp": 0.0066
    }
  },
  "security": {
    "composite_security_score": 96.5,
    "overall_risk_score": 3.5,
    "security_grade": "A+ (Quantum-Safe / High-Assurance)",
    "posture_assessment": "EXEMPLARY",
    "dimension_scores": {
      "cryptographic_strength": 100.0,
      "configuration_compliance": 100.0,
      "key_management": 100.0,
      "perfect_forward_secrecy": 100.0,
      "anti_replay_protection": 95.0,
      "metadata_privacy": 85.0
    },
    "threat_matrix": [
      {
        "id": "THREAT-META-1",
        "category": "Endpoint Leakage",
        "severity": "LOW",
        "mitre_technique": "T1040 (Network Sniffing — Passive Reconnaissance)",
        "finding": "Exposed cleartext peer IPs: ['10.10.0.2', '10.10.0.3']",
        "remediation": "Utilize IKEv2 IDr masking and disable cleartext endpoint logging."
      }
    ]
  }
}
```

---

## 8. Automated Verification & Test Suite

Run the full automated test suite using `pytest`:
```bash
python -m pytest tests/ -v
```

### Test Coverage (10/10 Passed - 100%)
- `tests/test_api.py::test_health_endpoint` &rarr; Verified air-gapped status.
- `tests/test_api.py::test_list_benchmark_samples` &rarr; Verified dataset benchmark library indexing.
- `tests/test_api.py::test_load_sample_endpoint` &rarr; Verified end-to-end analysis and report generation.
- `tests/test_ml.py::test_feature_extractor_on_voip` &rarr; Verified 36-feature statistical vector extraction.
- `tests/test_ml.py::test_classifier_predictions` &rarr; Verified calibrated probabilities summing to 1.0.
- `tests/test_ml.py::test_short_flow_guardrail` &rarr; Verified rejection of flows with < 5 packets.
- `tests/test_parser.py::test_parser_on_pqc_sample` &rarr; Verified RFC 9370 PQC exchange detection.
- `tests/test_parser.py::test_parser_on_deprecated_sample` &rarr; Verified 3DES / MODP-1024 parsing.
- `tests/test_scorer.py::test_nist_high_assurance_scoring` &rarr; Verified NIST A+ grade scoring.
- `tests/test_scorer.py::test_deprecated_config_scoring` &rarr; Verified legacy F grade and MITRE T1557 tagging.

---

## 9. Repository Structure

```
├── dataset/
│   ├── samples/                # Labeled benchmark PCAPs & metadata JSONs
│   │   ├── sample_pqc_mlkem768_voip.pcap
│   │   ├── sample_nist_approved_web.pcap
│   │   ├── sample_nist_standard_video.pcap
│   │   ├── sample_legacy_no_pfs_icmp.pcap
│   │   ├── sample_deprecated_3des_email.pcap
│   │   └── sample_transport_mode_whatsapp.pcap
│   └── README.md               # Dataset methodology & ISCXVPN2016 research analysis
├── engine/
│   ├── protocol/               # Deterministic IKEv1/IKEv2 parser & fingerprinter
│   │   ├── ike_parser.py
│   │   └── fingerprinter.py
│   ├── ml/                     # ESP flow feature extractor, calibrated classifier & trainer
│   │   ├── feature_extractor.py
│   │   ├── classifier.py
│   │   └── train_model.py
│   ├── security/               # NIST SP 800-77r1 rules, 6-dimension scorer & threat matrix
│   │   ├── nist_rules.py
│   │   ├── scorer.py
│   │   └── threat_matrix.py
│   └── reporting/              # Unified Executive & Technical report generator
│       └── report_generator.py
├── server/
│   └── main.py                 # FastAPI backend & air-gapped REST API
├── testbed/
│   ├── matrix_generator.py     # strongSwan 6.0+ configuration matrix & Docker Compose
│   ├── traffic_generators.py   # 6-class empirical application traffic simulators
│   └── generate_dataset.py     # End-to-end PCAP synthesis script
├── tests/                      # Automated pytest test suite
├── ui/                         # High-density dark-mode analyst dashboard (GSAP/Lenis)
│   ├── index.html
│   ├── styles.css
│   └── app.js
└── requirements.txt            # Project dependencies
```

---

## 10. Authoritative Standards & Academic Bibliography

1. **NIST SP 800-77 Rev. 1 (June 2020)**: *Guide to IPsec VPNs*, Elaine Barker, Quynh Dang, Sheila Frankel, Karen Scarfone, Paul Wouters. National Institute of Standards and Technology.
2. **RFC 8221 (October 2017)**: *Cryptographic Algorithm Implementation Requirements and Usage Guidance for Encapsulating Security Payload (ESP) and Authentication Header (AH)*, P. Wouters, D. Migault, J. Mattsson, Y. Nir, T. Kivinen. Internet Engineering Task Force.
3. **RFC 8247 (September 2017)**: *Algorithm Implementation Requirements and Usage Guidance for the Internet Key Exchange Protocol Version 2 (IKEv2)*, Y. Nir, T. Kivinen, P. Wouters, D. Migault. Internet Engineering Task Force.
4. **RFC 9370 (May 2023)**: *Multiple Key Exchanges in the Internet Key Exchange Protocol Version 2 (IKEv2)*, V. Smyslov. Internet Engineering Task Force.
5. **FIPS 203 (August 2024)**: *Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)*. National Institute of Standards and Technology.
6. **Leroux et al. (2018)**: *Machine Learning for Encrypted Traffic Classification in IPsec and Tor*, S. Leroux, S. Bohez, E. De Coninck, T. Verbelen, B. Vankeirsbilck, F. De Turck, P. Simoens. IEEE Transactions on Network and Service Management.
7. **MITRE ATT&CK**: Enterprise Matrix Techniques **T1040 (Network Sniffing)** and **T1557 (Adversary-in-the-Middle — Downgrade Sub-behavior)**.
