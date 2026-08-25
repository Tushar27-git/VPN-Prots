# AI-Powered IPsec VPN Protocol Analyzer & Forensic Security Framework
### Problem Statement ID 26160 (NTRO, Blockchain & Cybersecurity) — Version 2.0 (Research-Hardened)

A self-contained, air-gapped defensive security framework designed to:
1. **Empirically test & synthesize IPsec configurations** across a matrix of ciphers, modes, DH groups (including **Post-Quantum ML-KEM-768 / RFC 9370**), and PFS settings.
2. **Deterministically extract cryptographic parameters** directly from cleartext IKEv1/IKEv2 handshakes (`IKE_SA_INIT`, `IKE_INTERMEDIATE`, `IKE_AUTH`) with **Zero ML**.
3. **Statistically classify application traffic** hiding inside encrypted ESP payloads from flow timing/size distributions (Leroux et al. 2018 methodology extended to 6 classes) with **Zero Payload Access**.
4. **Score compliance and security posture** against **NIST SP 800-77 Rev. 1 (June 2020)**, **RFC 8221**, **RFC 8247**, and **FIPS 203**.
5. **Map vulnerabilities to verified MITRE ATT&CK techniques** (**T1040: Network Sniffing** and **T1557: Adversary-in-the-Middle — Downgrade Sub-behavior**).
6. **Generate Executive and Technical reports** (HTML/PDF) and provide an interactive **dark-mode analyst workbench** powered by GSAP motion and Lenis smooth scrolling.

---

## 🏛 System Architecture

```
┌─────────────────────────┐     ┌────────────────────────────┐     ┌────────────────────────────┐
│   1. TESTBED GENERATOR   │     │  2. CAPTURE & AI CLASSIFIER│     │  3. SCORING & REPORTING    │
│                         │────▶│                            │────▶│                            │
│  - strongSwan 6.0+      │     │  - Deterministic IKE Parser│     │  - NIST SP 800-77r1 Scorer │
│    Config Matrix        │     │    (Zero ML, Wire Truth)   │     │  - RFC 8221/8247 Rules     │
│  - Hybrid PQC           │     │  - Transform Ordering (TOS)│     │  - 6-Dimension Score Radar │
│    ML-KEM-768 (RFC 9370)│     │  - Vendor ID Matcher       │     │  - MITRE ATT&CK (T1040/1557│
│  - 6 Traffic Generators │     │  - Calibrated ML Classifier│     │  - Executive & Technical   │
│    (VoIP, Web, Stream,  │     │    (ESP Flow Timing/Sizes) │     │    Unified Reports (HTML)  │
│     ICMP, Email, Chat)  │     │  - predict_proba (Calib)   │     │  - Dark-Mode UI Workbench  │
└─────────────────────────┘     └────────────────────────────┘     └────────────────────────────┘
```

---

## 🔬 Key Technical Features

### 1. Honest Sub-Engine Separation
- **Deterministic Protocol Forensics**: Parses unencrypted `IKE_SA_INIT` and `IKE_INTERMEDIATE` packets to extract ciphers, DH groups, SPIs, identities, and vendor signatures without ML.
- **Statistical ML Flow Classifier**: Analyzes 36 flow metrics (packet sizes, direction ratios, inter-arrival times, burst dynamics) on encrypted ESP streams using a calibrated ensemble (`CalibratedClassifierCV`) with confidence floor and short-flow protections.

### 2. Post-Quantum Cryptography (PQC) Ready
- Evaluates **FIPS 203 / ML-KEM-768** hybrid key exchange in IKEv2.
- Detects the RFC 9370 `IKE_INTERMEDIATE` exchange round as an unencrypted wire signature of quantum resilience.

### 3. Self-Generated Ground-Truth Dataset
- Sidesteps the documented integrity flaws of legacy datasets like ISCXVPN2016 (unencrypted HTML leakage, ~65% BlueStacks emulator artifacts, TCP/UDP mismatches).
- Includes 6 pre-generated benchmark matrix captures in `dataset/samples/`.

---

## 🚀 Quickstart Guide

### Prerequisites
- Python 3.10+ (tested on Python 3.14)
- `pip install -r requirements.txt` (or `pip install fastapi uvicorn scapy scikit-learn jinja2 python-multipart pytest`)

### Running the Platform
1. **Launch the Analyst Server & UI**:
   ```bash
   python server/main.py
   ```
2. **Open the Dashboard**:
   Navigate to **`http://127.0.0.1:8000`** in your browser.
3. **Analyze Traces**:
   - Select any pre-configured benchmark capture (e.g. *PQC Hybrid ML-KEM-768 VoIP*, *NIST Approved Web*, *Deprecated 3DES Email*).
   - Or drag-and-drop your own `.pcap` / `.pcapng` file to execute real-time forensic auditing.
   - Click **Executive Report** or **Technical Report** to preview and export printable audit reports.

---

## 🧪 Running Automated Tests

Run the full pytest suite:
```bash
python -m pytest tests/ -v
```
All 10 unit and integration tests pass with 100% code integrity.

---

## 📂 Repository Structure

```
├── dataset/
│   ├── samples/                # Labeled benchmark PCAPs & metadata JSONs
│   └── README.md               # Dataset methodology & ISCXVPN2016 research analysis
├── engine/
│   ├── protocol/               # Deterministic IKEv1/IKEv2 parser & fingerprinter
│   ├── ml/                     # ESP flow feature extractor, calibrated classifier & trainer
│   ├── security/               # NIST SP 800-77r1 rules, 6-dimension scorer & threat matrix
│   └── reporting/              # Unified Executive & Technical report generator
├── server/
│   └── main.py                 # FastAPI backend & air-gapped REST API
├── testbed/
│   ├── matrix_generator.py     # strongSwan 6.0+ configuration matrix & Docker Compose
│   ├── traffic_generators.py   # 6-class empirical application traffic simulators
│   └── generate_dataset.py     # End-to-end PCAP synthesis script
├── tests/                      # Pytest automated test suite
├── ui/                         # High-density dark-mode analyst dashboard (GSAP/Lenis)
└── HANDOVER.md                 # Session continuity and handover state
```

---

## 📜 Standards & Citations

- **NIST SP 800-77 Rev. 1 (June 2020)**: *Guide to IPsec VPNs* (Barker, Dang, Frankel, Scarfone, Wouters).
- **RFC 8221**: *Cryptographic Algorithm Implementation Requirements and Usage Guidance for ESP and AH*.
- **RFC 8247**: *Algorithm Implementation Requirements and Usage Guidance for IKEv2*.
- **RFC 9370**: *Multiple Key Exchanges in the Internet Key Exchange Protocol Version 2 (IKEv2)*.
- **FIPS 203**: *Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)*.
- **Leroux et al. (2018)**: *Machine Learning for Encrypted Traffic Classification in IPsec and Tor*.
- **MITRE ATT&CK**: Techniques **T1040 (Network Sniffing)** & **T1557 (AiTM Downgrade)**.
