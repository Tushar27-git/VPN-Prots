# Requirements — AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework
### PS ID 26160 (NTRO, Blockchain & Cybersecurity) — Requirements Spec v2

---

## 1. One-paragraph summary

A self-contained, fully offline platform that spins up a controlled IPsec VPN lab across a configuration matrix, captures genuine traffic through it, deterministically parses the cleartext IKE handshake, statistically infers the traffic type hidden in encrypted ESP via a real ML model, and scores the resulting security posture against NIST SP 800-77 Rev. 1 (June 2020) and RFC 8221/8247 — producing an executive report, technical report, risk score, threat matrix, and calibrated AI confidence score.

**Core honesty principle:** the "AI Classification Engine" is two sub-engines, documented as such — a **deterministic parser** (cleartext IKE fields, zero ML) and a **statistical ML classifier** (ESP flow features only, real inference). Never blur which one produced a given output.

---

## 2. Functional requirements

### 2a. VPN Testbed Generation
- strongSwan (Docker) as primary IPsec stack. Libreswan is stretch-only, cut first under time pressure.
- Config matrix template axes: Mode (Tunnel/Transport), Cipher (AES-128, AES-256, AES-GCM, AES-CBC+HMAC), DH Group (classical: MODP2048, ECP256 + **PQC/hybrid: ML-KEM-768 via `ke1_mlkem768` proposal syntax**, native in strongSwan ≥6.0), PFS (on/off via DH-group presence/absence in ESP proposal), IP version (v4/v6).
- AH support: optional, deprioritized — PS marks it optional explicitly.

### 2b. Traffic Capture
- `tshark`/`tcpdump` as primary capture, plus a thin custom wrapper utility (satisfies PS's literal "custom packet capture utilities" language).
- Capture scope: IKE negotiation, ESP packets, unencrypted baseline traffic for comparison.
- **Required traffic types, all generated live through the testbed (never replayed from a public dataset):**
  - VoIP — scripted SIP/RTP session generator
  - Web-browsing — headless browser automation (Playwright/Selenium) or scripted curl sessions
  - Video streaming — `iperf3` or scripted video-pull
  - ICMP — scripted ping sweep through tunnel
  - Email — scripted SMTP/IMAP against a local test mail server
  - **WhatsApp — flagged decision required (see §6 open items).** Preferred: real WhatsApp Web / Android-emulator session through the tunnel. Fallback: Signal/Telegram substitute, **disclosed transparently** in the dataset README, never silently relabeled.

### 2c. AI-Based Protocol Identification (two honestly-separated sub-engines, one deliverable)

**Deterministic fingerprinting module** — parses cleartext IKE fields, no ML, say so out loud:
- IPsec protocol (AH/ESP), IKE version, Tunnel vs Transport mode
- Encryption/auth algorithm, key exchange method, DH group (including ML-KEM/hybrid detection via IKE_INTERMEDIATE exchange presence, per RFC 9370)
- SA characteristics (lifetime, negotiated proposals)
- Implementation fingerprinting via **transform-enumeration + UDP backoff-timing + Vendor-ID matching** (ike-scan-inspired methodology — see research dossier §1 for the naming correction from the earlier "TAVO" draft)

**ML inference module** — statistical classifier on ESP flow features only (packet size, direction, inter-arrival timing, burst size/time — never payload bytes):
- Predicts traffic type hidden in encrypted ESP
- Model: Random Forest or stacked ensemble (RF + SVM + shallow NN) — matches Leroux et al. (2018) methodology, extended to 2 additional classes (Email, ICMP) beyond the original paper's 4 (web/VoIP/video/P2P) — **disclose this extension explicitly**, don't imply the paper covered your full taxonomy.
- Explicitly not deep learning on raw bytes — no exploitable byte-level signal in properly encrypted payload.
- Output: calibrated confidence score (`predict_proba` / `CalibratedClassifierCV`), a real number from the model, never hand-typed.

### 2d. Security Assessment
Rule-based scoring engine mapped to NIST SP 800-77 Rev. 1 (June 2020) + RFC 8221 + RFC 8247, evaluating:
- Cryptographic strength (cipher + DH group tiered NIST-approved / deprecated / legacy)
- Configuration compliance vs. recommended baseline
- SA parameters, key lifetime (flag if exceeding recommended rekey interval)
- Replay protection (flag if window disabled/zero)
- PFS presence/absence, cipher suite strength
- Metadata exposure — reuses the deterministic module's own extracted fields as scoring evidence (self-referential demo point)

### 2e. Output
- Composite security score + per-dimension breakdown (never collapse to one number without the breakdown)
- Traffic analysis: ML classification + calibrated confidence
- Metadata inference summary
- Executive report (plain-language, PDF/HTML) + Technical report (full detail, standards citations, traceable findings, PDF/HTML) from one shared data model
- Risk score
- Threat matrix: self-defined IPsec weakness matrix, with **only genuinely-mappable entries tagged to MITRE ATT&CK** — confirmed genuine mappings are **T1040 (Network Sniffing)** for metadata-exposure findings and **T1557 (Adversary-in-the-Middle, downgrade-attack sub-behavior)** for weak-cipher/no-PFS findings. Do not force further mappings.
- Calibrated AI Confidence Score
- Actionable recommendation attached to every finding — no bare scores/matrices

---

## 3. Non-functional requirements
- **Fully offline / air-gapped core pipeline** — no external network calls anywhere in capture, parsing, ML inference, scoring, or report generation. No cloud LLM call for report prose (it's templated).
- Offline PCAP upload-and-analyze is the primary, reliable demo mode; live capture is a same-code-path bonus overlay, never the judged-demo dependency.
- Modular monolith with internal REST API boundaries between testbed / capture+AI / scoring+reporting — behaves like client-server without microservice deployment overhead.
- Dashboard must not look "AI-generated" — see `03_design_system.md`.

## 4. Tech stack

| Layer | Choice | Why |
|---|---|---|
| IPsec stack | strongSwan (Docker), ≥6.0 for native ML-KEM/RFC 9370 | Best docs, active dev, native IKEv2, PQC-ready |
| Capture / parsing | tshark, PyShark, Scapy | Scriptable, identical code path live/offline |
| ML | scikit-learn (Random Forest / stacked ensemble) | Matches literature, explainable, fast to calibrate |
| Backend | Python (FastAPI) | Ecosystem fit, fast iteration |
| Reporting | Jinja2 + WeasyPrint/ReportLab | One shared data model, two renderers |
| Dashboard | React / Next.js | See design system doc |
| Environment | Fully offline by default | Correct default for NTRO/defense-adjacent audience |

## 5. Deliverables checklist

| PS deliverable | Covered by |
|---|---|
| Working software prototype | Full pipeline: testbed → capture → classification → scoring → report |
| AI classification engine | Hybrid deterministic + ML module, documented split |
| Interactive dashboard | React/Next.js, design system |
| Security assessment report | Executive + Technical reports |
| Demonstration video | Offline PCAP mode run (lower risk than live capture) |
| Technical documentation | Deterministic-vs-ML split, standards mapping, dataset methodology |
| Dataset used for training/testing | Self-generated, verified-real, README with methodology + any substitutions |

## 6. Open items requiring an explicit team decision before scope lock
1. Timeline structure (build sprint vs. SIH-style build-then-finale).
2. WhatsApp: real session vs. disclosed Signal/Telegram substitute — affects testbed scripting effort significantly, decide early.
3. Libreswan cross-implementation support — stretch-only, first cut if time is short.
4. Confirm the exact strongSwan build/version in the team's environment actually supports `ke1_mlkem768` before committing to the PQC narrative in the demo script (verify with `strongswan version` / plugin list, not assumption).
5. Team skill mapping against actual team size (suggested: 1–2 testbed/protocol, 1–2 ML, 1 backend/API, 1 frontend+reporting).
