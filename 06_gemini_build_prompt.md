# Gemini Build Prompt — PS 26160 IPsec VPN Analyzer
### Paste this into Gemini (or use it as the system/first-turn prompt) to drive the actual build

---

You are building **an AI-powered IPsec VPN Protocol Analyzer & Security Assessment Framework** for a government hackathon problem statement (NTRO, Blockchain & Cybersecurity track, PS ID 26160). This is a defensive security research/audit tool — not an attack tool. Treat the following as your full spec. Do not silently resolve open questions marked below; ask or flag them.

## What you're building
A fully offline platform that: (1) spins up a controlled IPsec VPN lab across a config matrix using Dockerized strongSwan, (2) captures real traffic through that lab, (3) deterministically parses the cleartext IKE handshake AND separately uses a real ML model to infer traffic type hidden in encrypted ESP, (4) scores the resulting security posture against NIST SP 800-77 Rev. 1 (June 2020), RFC 8221, and RFC 8247, producing an executive report, technical report, risk score, threat matrix, and calibrated confidence score. Everything runs offline — no cloud API calls anywhere in the core pipeline.

## The one rule that matters most
There are **two sub-engines under one "AI Classification Engine" deliverable**, and they must never be blurred:
1. A **deterministic parser** — reads cleartext IKE fields. Zero ML. Not inferred. Genuinely visible on the wire.
2. A **statistical ML classifier** — infers traffic type inside *encrypted* ESP from flow features only (packet size, direction, inter-arrival timing, burst size/time). Never touches payload bytes. This is where real inference happens.
If asked "what model decided the DH group," the correct answer is "there is no model — it's unencrypted in the handshake; here's the ML component doing the actual inference, on the traffic-type problem." Build the code and the UI so this split is visually and structurally obvious, not something you have to explain apologetically.

## Build in this order (don't skip ahead)
1. Docker + strongSwan config-matrix generator. Axes: Mode (Tunnel/Transport) × Cipher (AES-128, AES-256, AES-GCM, AES-CBC+HMAC) × DH Group (MODP2048, ECP256, **plus one PQC/hybrid row using strongSwan's native proposal syntax** `ike=aes256-sha384-ecp384-ke1_mlkem768!` for ML-KEM-768 hybrid key exchange, strongSwan ≥6.0) × PFS (on/off via DH-group presence in ESP proposal) × IP version (v4/v6). **Before relying on the PQC row in your demo, run `strongswan version` and check the plugin list to confirm ML-KEM support actually exists in your build — don't assume from docs alone.**
2. Traffic generation scripts, one per required type, all live through the actual tunnel (never replay a public dataset): VoIP (scripted SIP/RTP), web-browsing (Playwright/Selenium or scripted curl), video streaming (`iperf3` or scripted pull), ICMP (scripted ping sweep), Email (scripted SMTP/IMAP against a local test server), WhatsApp (flagged decision — see open items below).
3. Deterministic IKE parser (tshark/PyShark/Scapy). Extract: AH/ESP, IKE version, mode, encryption/auth algorithm, key exchange method, DH group, SA lifetime, negotiated proposals, and an implementation/vendor fingerprint using **transform-enumeration + UDP backoff-timing + Vendor-ID matching (ike-scan-inspired methodology)** — do NOT call this "TAVO," that acronym isn't a verified academic term; use an honestly-labeled name for any proposal-ordering heuristic you build yourself. Also detect presence of an `IKE_INTERMEDIATE` exchange (RFC 9370) as a PQC-readiness signal, independent of parsing the KE payload contents.
4. ESP flow feature extraction: packet size, direction, inter-arrival timing, burst size/time. This methodology follows Leroux et al. (2018), whose original paper covered web-browsing/VoIP/video/P2P — **your Email and ICMP classes are your own extension beyond that paper's scope; say so explicitly in your technical docs, don't imply the citation covers all six classes.**
5. Train a Random Forest or stacked ensemble (RF + SVM + shallow NN) on your self-generated dataset. Not deep learning on raw bytes — encrypted payload has no exploitable byte-level signal, a CNN/transformer buys nothing and adds unexplainable complexity. Calibrate with `predict_proba` or `CalibratedClassifierCV` — every confidence number displayed anywhere must come from this call, never hand-typed.
6. Rule-based scoring engine against NIST SP 800-77 Rev. 1 (June 2020) + RFC 8221 + RFC 8247. Every score traces to a named standard or an explicit documented rule — flag judgment-call weights as such. Evaluate: cryptographic strength (tiered NIST-approved/deprecated/legacy), configuration compliance, key lifetime (flag if exceeding recommended rekey interval), replay protection (flag if window disabled/zero), PFS presence/absence, cipher suite strength, and metadata exposure (reuse the deterministic parser's own output as evidence for this sub-score — this is a good live-demo talking point).
7. Report templates (Jinja2 + WeasyPrint/ReportLab) — Executive (plain language) and Technical (full detail, standards citations, traceable findings) — both rendered from **one shared data model**, never duplicated logic between UI and PDF.
8. Dashboard (React/Next.js) — see the design system section below. Wire against an internal REST API shared with the report renderer.
9. Threat matrix: self-defined IPsec weakness matrix (weak DH groups, missing PFS, deprecated ciphers, weak PRFs, replay disabled). Tag to MITRE ATT&CK **only** where genuine: **T1040 (Network Sniffing)** for metadata-exposure findings, **T1557 (Adversary-in-the-Middle, downgrade-attack sub-behavior)** for weak-cipher/no-PFS findings. Do not force any other mapping.
10. Wire the PQC/ML-KEM row end-to-end: parser detection → scoring rubric row → dashboard/report display.
11. Error handling pass — see failure-mode list below, build each one, don't discover it live.
12. Hardening + demo video, filmed on the **offline PCAP upload mode** (lower risk than live capture for a judged demo).

## Dashboard design requirements (non-negotiable, not a style suggestion)
The dashboard must **not** look AI-generated. Avoid: purple/blue gradient hero backgrounds, glassmorphism-by-default, generic rounded-everything soft-shadow cards, stock AI-orb graphics, emoji-as-icons, centered-gradient-hero landing sections.

Direction: **minimal, editorial, high-contrast, dark-mode-default, motion as a functional layer.** Use these libraries as required building blocks:
- **Lenis** for smooth, weighted scroll on the dashboard/report views.
- **GSAP** for all real animation — score count-ups, staggered threat-matrix row reveals, dashboard state transitions, live-capture timeline scrubbing. Make deliberate easing/duration/what-animates-vs-what-stays-still decisions; GSAP doesn't do the taste-work for you.
- **Vanta** for background effects, used sparingly — one hero/landing background only, not throughout.
- **React Bits** as a component reference — customize colors/spacing/timing, never drop in unmodified.
- Reference **animos.app** for motion restraint/quality bar, not as an asset source.

Palette: near-black/near-white base, one accent color mapped to risk-severity states (red/amber/green must read clearly against the base). Typography: technical monospace for protocol/packet data, clean sans for prose. Motion must be functional — animate state changes only, never decorate static content (test: if a judge could screenshot two states and the animation added nothing, cut it). Data density is a feature — dense tables/sparklines/compact badges, not a sparse marketing layout.

## Failure modes to build handling for, explicitly (a judge will try to break this)
- strongSwan proposal mismatch → surface `ike: no acceptable proposal found`, not a silent hang or raw stack trace.
- Capture started after handshake completed → "IKE_SA_INIT not observed in capture window — protocol ID confidence reduced," don't guess.
- Truncated/corrupted PCAP upload → validate (magic bytes + tshark parse check) before running the pipeline, fail fast with a specific message.
- Non-IPsec traffic uploaded → detect absence of IKE/ESP markers, say so, don't force a classification.
- Unknown IKE transform value → degrade to "unrecognized/unknown," log as a parser gap, never mis-label.
- IKEv1 vs IKEv2 → detect and branch on version explicitly.
- Fragmented IKE payloads (large certs, or PQC IKE_INTERMEDIATE fragments) → reassemble or flag "unparsed — reassembly not implemented."
- Traffic type outside trained label set → confidence floor triggers "unclassified / low confidence," never false-certain.
- Class imbalance in self-generated dataset → document in README, address with stratified sampling/class weighting.
- Very short flows → flag "insufficient data," don't classify meaningless feature vectors.
- Mixed strong/weak config → composite score AND per-dimension breakdown both always visible.
- Missing/ambiguous SA lifetime → report "not observed," never assume a default.
- Report generation failure → validate shared data model against template schema first, fail with a field-level error.
- Every user-facing error: what failed, why, in plain language.
- Log every classification decision (deterministic and ML) with its inputs for traceability.

## Open items — ask the team, don't silently decide
1. WhatsApp real-session vs. Signal/Telegram documented fallback (affects scripting effort significantly).
2. Libreswan stretch goal — in scope or cut?
3. Actual strongSwan version/build available — confirm ML-KEM support before finalizing PQC narrative.
4. Timeline structure (single sprint vs. build-period-then-finale).

## Dataset deliverable requirements
Self-generated, verified-real (never synthetic-only or replayed) labeled dataset: PCAPs + feature CSVs + ground-truth config labels. README must document generation methodology, capture conditions, class-imbalance handling, and any traffic-type substitutions (never silent relabeling). State explicitly why this sidesteps ISCXVPN2016's documented integrity problems (unencrypted payload found inside "VPN-labeled" captures, ~65% BlueStacks-artifact biflows, TCP/UDP metadata mismatches found by independent researchers in 2022/2024/2025 — full citations in the research dossier) rather than just asserting it.

## Style/tone for anything you write (reports, README, comments)
Confident but not oversold. State assumptions and extensions explicitly rather than implying more coverage than you have (e.g., the Leroux et al. citation covers 4 of your 6 traffic classes — say so). If a rubric weight is a judgment call, label it as one. Never invent an academic term or citation that doesn't check out — an unverifiable name in a technical report is worse for credibility than no citation at all.
