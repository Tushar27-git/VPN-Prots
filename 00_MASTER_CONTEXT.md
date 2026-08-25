# MASTER CONTEXT — AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework
### PS ID 26160 (NTRO, Blockchain & Cybersecurity) — v2, research-hardened, single complete reference

> This file consolidates everything: the enhanced build doc, the fact-checked research, the architecture, the design system, and the guardrails, into one document. Companion files (same folder) break each section out standalone: `01_requirements.md`, `02_architecture_workflow.md`, `03_design_system.md`, `04_guardrails.md`, `05_research_dossier.md`, `06_gemini_build_prompt.md`.

---

## 1. What we're building, in one paragraph

A self-contained platform that (a) spins up a controlled IPsec VPN lab across a matrix of real configurations, (b) captures genuine traffic through that lab, (c) automatically fingerprints the protocol/crypto characteristics from the cleartext IKE handshake and infers what kind of traffic is hiding inside the encrypted ESP payload using a real ML model, and (d) scores the resulting security posture against named standards (NIST SP 800-77 Rev. 1, June 2020; RFC 8221/8247), producing an executive report, a technical report, a risk score, a threat matrix, and a calibrated AI confidence score. Everything runs fully offline — no cloud API calls anywhere in the core pipeline.

**Core design principle — say this out loud in every demo:** the system is honestly split into a **deterministic protocol-fingerprinting layer** (parses cleartext IKE fields — genuinely visible, not inferred, not ML) and a **statistical ML layer** (infers what's inside encrypted ESP, where nothing is directly observable). Both live under one "AI Classification Engine" deliverable, documented transparently. A judge asking "what model decided the DH group?" should get "there isn't one, it's literally unencrypted in the handshake — here's the ML component that's doing real inference, on the traffic-type problem" as the answer.

---

## 2. Why this approach — research grounding (fact-checked, corrected, strengthened)

### 2.1 IKE handshake fingerprinting — real, but rename the acronym
The unencrypted Phase 1/IKE_SA_INIT exchange carries enough structure to fingerprint implementations. **Correction from v1:** the earlier draft cited a "TAVO" acronym as an established academic term — this could not be verified in the literature and is a real credibility risk if a judge looks it up and finds nothing. What's actually real and citable is `ike-scan`'s (Roy Hills) three genuine mechanisms: **UDP backoff fingerprinting** (retransmission timing vs. known patterns), **Vendor ID payload matching**, and **transform enumeration** (probing accepted cipher/hash/DH/auth combinations). If you build your own proposal-ordering heuristic on top of this, label it as your own team's original contribution with an honest name — don't attribute it to a fabricated citation.

### 2.2 Encrypted traffic-type classification — real, but disclose the category gap
Leroux et al. (2018) classified traffic inside IPsec and Tor tunnels using only packet size, direction, and inter-arrival timing/burst features — no payload access — with Naive Bayes, Logistic Regression, and Random Forest. Confirmed accurate. **Correction from v1:** their actual labeled classes were **web browsing, VoIP, video streaming, and P2P** — not Email or ICMP. Your 6-class taxonomy extends 2 classes beyond the cited paper's scope; say so explicitly in the technical report rather than implying full coverage. Current best practice has moved to ensemble/stacked classifiers (RF + SVM + shallow NN), not deep learning on raw bytes, because encrypted payload is statistically indistinguishable from noise at the byte level.

### 2.3 Public VPN dataset integrity — now much stronger evidence
ISCXVPN2016, the standard public dataset, has three independent, dated, citable integrity findings:
- A 2022 forensic re-inspection found literal unencrypted HTML payload inside a packet labeled as VPN-encrypted traffic, plus multiple-connection PCAPs where a single VPN session was expected, on top of a prior finding that ~65% of the dataset's biflows are BlueStacks-emulator artifacts that should be filtered.
- A 2024 PETS/FOCI workshop paper independently found the dataset is majority TCP despite its own documentation claiming OpenVPN-in-UDP-mode capture.
- A 2025 survey notes the field's extensive reliance on this one aging, OpenVPN-only dataset has produced results that may not generalize to contemporary traffic or other VPN protocols.

Self-generating a verified-real dataset through your own tunnels sidesteps this entirely and turns a documented field weakness into a differentiator — now with three citable receipts instead of one vague sentence.

### 2.4 Standards backbone
**NIST SP 800-77 Rev. 1 (June 2020)** — confirmed the current, active publication (authors: Barker, Dang, Frankel, Scarfone, Wouters). Only the original 2005 edition and the 2019 public draft of Rev. 1 are withdrawn/superseded — cite Rev. 1 specifically, dated June 2020. **RFC 8221** (ESP/AH cipher suite recommendations) and **RFC 8247** (IKEv2 algorithm recommendations) round out the rubric, both confirmed current and correctly named.

### 2.5 strongSwan as testbed vehicle — stronger and more current than v1 assumed
strongSwan (Docker initiator/responder containers) is the standard reproducible-testbed pattern. Its proposal-string syntax maps directly onto your config matrix (cipher, DH group, PFS via presence/absence of a DH group in the ESP proposal). Confirmed: strongSwan's **current stable release (6.0.7, June 2026)** natively supports **multiple classic and post-quantum key exchanges per RFC 9370, including ML-KEM (FIPS 203)** — this is in the stable release, not an experimental fork. Mechanically, ML-KEM's public keys/ciphertexts (up to 1568 bytes for ML-KEM-1024) exceed safe unfragmented UDP payload size, so RFC 9370 defines an additional `IKE_INTERMEDIATE` exchange round to carry them — **detecting the presence of this exchange is itself a PQC-readiness signal**, independent of parsing KE payload contents, and a good demoable detail. A concrete usable proposal string: `ike=aes256-sha384-ecp384-ke1_mlkem768!` (hybrid ECP384 classical + ML-KEM-768 PQC in one IKE proposal). Hybrid PQC key exchange is now mainstream on the public internet (30–50% of major-browser TLS handshakes in 2026 use a hybrid PQC group), which supports framing this as a timely, not speculative, differentiator. **Caveat:** the ML-KEM-in-IKEv2 negotiation spec is still an IETF Internet-Draft (not yet an RFC) — frame your check as "detects presence/use of ML-KEM key exchange," not "certifies final IETF PQC compliance."

### 2.6 MITRE ATT&CK — confirmed genuine mappings, don't force more
Two techniques are directly and defensibly relevant:
- **T1040 — Network Sniffing** (Credential Access/Discovery): passively capturing authentication material and configuration details from unencrypted traffic. Maps to your metadata-exposure finding (cleartext IKE identities, SPI values, endpoint IPs) — literally what T1040 describes doing to the exact data your fingerprinting module extracts.
- **T1557 — Adversary-in-the-Middle**, downgrade-attack sub-behavior: negotiating a weaker/deprecated protocol or cipher to establish an AiTM position. Maps to your weak-cipher/no-PFS/deprecated-DH findings.
Do not force further mappings onto every threat-matrix entry — a judge who knows the framework will spot a forced mapping and it costs more credibility than not using it.

---

## 3. System architecture — three pillars

```
┌───────────────────────┐     ┌──────────────────────────┐     ┌──────────────────────────┐
│  1. Testbed Generator  │     │  2. Capture + AI          │     │  3. Scoring + Reporting  │
│                        │────▶│     Classification Engine │────▶│     Engine               │
│  Docker + strongSwan   │     │                            │     │                          │
│  config templates      │     │  tshark / PyShark / Scapy │     │  NIST 800-77r1 / RFC     │
│  (matrix generator,    │     │  + deterministic IKE       │     │  8221 / 8247 rule engine │
│  incl. ML-KEM row)     │     │    parser (transform-      │     │  + risk score +          │
│                        │     │    enumeration fingerprint)│     │    threat matrix         │
│                        │     │  + RF/ensemble ML model     │     │    (T1040/T1557 only)   │
│                        │     │    (ESP flow features)     │     │  + exec/technical reports│
│                        │     │  + calibrated confidence   │     │                          │
└───────────────────────┘     └──────────────────────────┘     └──────────────────────────┘
            │                              │                                │
            ▼                              ▼                                ▼
   Labeled PCAP + ground-truth      Feature CSVs +                  Dashboard
   config dataset (deliverable)      model artifacts                 (React/Next.js, dark-mode)
```

Modular monolith with clean internal REST API boundaries between the three pillars — behaves like a client-server app without full microservice deployment overhead. Split into real services later only with a concrete reason.

**Deployment model:** offline PCAP upload-and-analyze is the primary, reliable demo mode (parse/classify code path is source-agnostic — `tshark -r file` vs `-i interface` is nearly identical code). Live capture rides the same code path as a demo-mode overlay, never the judged-run dependency.

---

## 4. Functional requirements (PS sections a–e)

### 4a. VPN Testbed Generation
- strongSwan (Docker) primary; Libreswan stretch-only, cut first under time pressure.
- Matrix axes: Mode (Tunnel/Transport) × Cipher (AES-128, AES-256, AES-GCM, AES-CBC+HMAC) × DH Group (MODP2048, ECP256, plus PQC/hybrid `ke1_mlkem768` row) × PFS (via DH-group presence/absence in ESP proposal) × IP version (v4/v6).
- AH support optional, explicitly deprioritized per the PS.

### 4b. Traffic Capture
- tshark/tcpdump primary + a thin custom capture wrapper (literally satisfies the PS's "custom packet capture utilities" language).
- Capture IKE negotiation, ESP packets, and non-tunneled baseline traffic.
- Required types, all generated **live through the testbed**, never replayed from a public dataset: VoIP (scripted SIP/RTP), Web-browsing (Playwright/Selenium or scripted curl), Video streaming (`iperf3`/scripted pull), ICMP (scripted ping sweep), Email (scripted SMTP/IMAP vs local test server), and **WhatsApp — flagged decision**: preferred is a real WhatsApp Web/emulator session through the tunnel; fallback is a disclosed Signal/Telegram substitute, documented transparently in the dataset README, never silently relabeled.

### 4c. AI-Based Protocol Identification — one deliverable, two honestly-separated sub-engines
**Deterministic fingerprinting module** (cleartext IKE fields, no ML): IPsec protocol (AH/ESP), IKE version, Tunnel/Transport mode, encryption/auth algorithm, key exchange method, DH group (incl. ML-KEM/IKE_INTERMEDIATE detection), SA characteristics, and implementation fingerprinting via transform-enumeration + backoff-timing + Vendor-ID matching (ike-scan-inspired; do not use the term "TAVO").

**ML inference module** (ESP flow features only — size, direction, inter-arrival timing, burst size/time; never payload bytes): predicts traffic type inside encrypted ESP. Model: Random Forest or stacked ensemble (RF+SVM+shallow NN), matching Leroux et al. (2018) methodology extended by 2 classes (state this extension explicitly). Not deep learning — no exploitable byte-level signal in properly encrypted payload. Output includes a calibrated confidence score (`predict_proba`/`CalibratedClassifierCV`) — a real number from the model, never hand-typed.

### 4d. Security Assessment
Rule-based engine mapped to NIST SP 800-77 Rev. 1 (June 2020) + RFC 8221 + RFC 8247, evaluating: cryptographic strength (tiered NIST-approved/deprecated/legacy), configuration compliance, SA parameters, key lifetime (flag if exceeding recommended rekey interval), replay protection (flag if disabled/zero window), PFS presence/absence, cipher suite strength, and metadata exposure (reuses the deterministic module's own output as scoring evidence — a good self-referential demo point).

### 4e. Output
Composite security score with visible per-dimension breakdown (never collapse to one number), traffic analysis + calibrated confidence, metadata inference summary, Executive Report (plain-language, PDF/HTML), Technical Report (full detail, standards citations, traceable findings, PDF/HTML), Risk Score, Threat Matrix (self-defined IPsec weaknesses, T1040/T1557-only ATT&CK tagging), AI Confidence Score, and an actionable recommendation attached to every finding. Both reports and the dashboard render from one shared data model (Jinja2 + WeasyPrint/ReportLab) — one source of truth, two renderers.

---

## 5. Tech stack

| Layer | Choice | Why |
|---|---|---|
| IPsec stack | strongSwan ≥6.0 (Docker) | Native IKEv2, native RFC 9370/ML-KEM support, well-documented |
| Capture / parsing | tshark, PyShark, Scapy | Scriptable, identical code path live/offline |
| ML | scikit-learn (Random Forest / stacked ensemble) | Matches literature, explainable, fast to calibrate |
| Backend | Python (FastAPI) | Ecosystem fit, fast iteration |
| Reporting | Jinja2 + WeasyPrint/ReportLab | One shared data model, two renderers |
| Dashboard | React / Next.js | See §6 design system |
| Environment | Fully offline / air-gapped by default | No external calls anywhere in the core pipeline; report prose templated, not LLM-generated |

---

## 6. Design system — the dashboard must not look "AI-generated"

Real requirement, not preference. Avoid: default purple/blue gradients, glassmorphism-by-default, generic rounded-everything soft-shadow cards, stock AI-orb graphics, emoji-as-icons, centered-gradient-hero landing sections.

**Direction:** minimal, editorial, high-contrast, dark-mode-default, motion as a functional layer, not decoration. Dense information display (security-analyst tool, not a marketing site).

**Required libraries:**
- **Lenis** — smooth, weighted scroll on dashboard/report views.
- **GSAP** — all real animation: score count-ups (risk score, confidence score), staggered threat-matrix row reveals, dashboard state transitions, live-capture timeline scrubbing. Deliberate easing/duration/what-moves choices still required — GSAP doesn't supply taste.
- **Vanta** — background effects, sparingly, one hero/landing spot only.
- **React Bits** — component reference; customize color/spacing/timing, never drop in unmodified.
- **animos.app** — reference for motion restraint/quality bar, not an asset source.

**Guardrails:** near-black/near-white base + single accent color for risk-severity coding (red/amber/green must read clearly). Type pairing: technical monospace for protocol/packet data, clean sans for prose. Motion animates state changes only — test: if a judge could screenshot two states and the animation added nothing, cut it. Data density is a feature (tables, sparklines, compact badges), not something to hide behind whitespace.

---

## 7. Deliverables checklist

| PS deliverable | Covered by |
|---|---|
| Working software prototype | Full pipeline: testbed → capture → classification → scoring → report |
| AI classification engine | §4c — hybrid deterministic + ML module, documented split |
| Interactive dashboard | React/Next.js, §6 design system |
| Security assessment report | Executive + Technical reports, §4e |
| Demonstration video | Offline PCAP mode run (lower risk than live capture) |
| Technical documentation | Deterministic-vs-ML split, standards mapping, dataset methodology |
| Dataset used for training/testing | Self-generated, verified-real, README with methodology + substitution disclosure |

---

## 8. Error handling, debugging & failure modes (design for these explicitly — a judge will try to break this)

**Testbed / capture layer:** proposal mismatch → specific `ike: no acceptable proposal found` error, not a silent hang or generic stack trace. Capture started after handshake completed → "IKE_SA_INIT not observed in capture window — protocol ID confidence reduced." Truncated/corrupted PCAP → validate (magic bytes, tshark parse check) before running, fail fast with specifics. Non-IPsec traffic uploaded → detect absence of IKE/ESP markers, say so, don't force a classification.

**Parsing layer:** unknown IKE transform value → degrade to "unrecognized/unknown," log as a parser-extension gap, never mis-label. IKEv1 vs IKEv2 → detect and branch, don't assume. Fragmented IKE payloads (large certs, or PQC IKE_INTERMEDIATE fragments) → reassemble or explicitly flag "unparsed — reassembly not implemented."

**ML layer:** traffic type outside trained label set → confidence floor triggers "unclassified / low confidence," never a false-certain guess. Class imbalance → document in dataset README, address with stratified sampling/class weighting. Very short flows → flag "insufficient data for reliable classification."

**Scoring/reporting layer:** mixed strong/weak config → composite score AND per-dimension breakdown both always visible. Missing/ambiguous SA lifetime → "not observed," never assume a default. Report generation failure → validate shared data model against template schema first, fail with a field-level error.

**General:** every user-facing error states what failed and why, in plain language. Log every classification decision (deterministic and ML) with its inputs for full traceability.

---

## 9. Non-negotiable rules (guardrails)

1. No external network calls anywhere in the core analysis pipeline.
2. Never present a deterministic parse result as an ML output, or vice versa.
3. Every score traces to a named standard or an explicit documented rule — flag judgment-call weights as such.
4. Every ML confidence number comes from the model call, never hand-typed.
5. AH parsing is optional and deprioritized.
6. Any traffic-type substitution must be disclosed in the dataset README, never silently relabeled.
7. Do not cite "TAVO" or any unverified academic term — use the corrected, honestly-labeled terminology from §2.1.
8. Don't imply Leroux et al. (2018) covers your full 6-class taxonomy — disclose the 2-class extension.
9. Don't force MITRE ATT&CK mappings beyond T1040/T1557 — only genuine ones.
10. Don't reach for deep learning unless there's a specific, defensible reason classical ML + flow features can't do the job — there isn't one here.
11. Never collapse a mixed-config score to a single number without the breakdown.
12. Verify the actual strongSwan build supports `ke1_mlkem768` before committing to the PQC narrative in the demo script.

---

## 10. Open assumptions — lock before build sprint starts

1. Timeline structure (defined build period + live finale, SIH-style, vs. single sprint) — confirm.
2. WhatsApp: real session vs. disclosed Signal/Telegram substitute — decide early, affects scripting effort significantly.
3. Libreswan cross-implementation support — stretch-only, first cut if time is short.
4. Live-capture demo mode — secondary to offline PCAP mode for the judged demonstration.
5. PQC/ML-KEM support — confirm the actual strongSwan version in use supports `ke1_mlkem768` before committing to it in the narrative or demo script.
6. Team skill mapping — suggested split 1–2 testbed/protocol, 1–2 ML, 1 backend/API, 1 frontend+reporting — confirm against actual team size/skills.

---

## 11. Suggested build order (engineering sequence)

1. Docker + strongSwan config-matrix generator (incl. PQC row, version-verified).
2. Traffic generation scripts per type.
3. Deterministic IKE parser — fast win, demoable standalone.
4. Feature extraction pipeline for ESP flows.
5. ML classifier training + calibration on self-generated dataset.
6. Rule-based scoring engine mapped to NIST 800-77r1 / RFC 8221/8247.
7. Report templates (executive + technical) from the shared data model.
8. Dashboard wiring against the internal API, design system applied.
9. Threat matrix + T1040/T1557-only MITRE tagging.
10. PQC/ML-KEM wiring end-to-end (parser → rubric → dashboard/report).
11. Error-handling/debugging pass against §8's failure-mode list.
12. Hardening pass + demo-video capture (offline mode).

---

*This master file plus its five companion files (`01_requirements.md`, `02_architecture_workflow.md`, `03_design_system.md`, `04_guardrails.md`, `05_research_dossier.md`, and the `06_gemini_build_prompt.md` build prompt) together form the complete reference set for this build. Treat §10 as a live checklist — resolve each item explicitly before locking scope.*
