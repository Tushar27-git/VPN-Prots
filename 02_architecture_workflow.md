# Architecture & Workflow — PS 26160 IPsec VPN Analyzer

---

## 1. System architecture — three pillars

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

Modular monolith with clean internal REST API boundaries between the three pillars — behaves like a client-server app from the dashboard's point of view, without full microservice deployment overhead. Split into real services later only with a concrete reason.

## 2. Deployment model
- **Primary mode: offline PCAP upload-and-analyze.** The parse/classify code path is source-agnostic (`tshark -r file` vs `tshark -i interface` is nearly identical code) — costs nothing extra to support, and is the safer path for a judged demo in an unfamiliar venue with unreliable network conditions.
- **Live capture:** same code path, offered as a demo-mode overlay. Real capability if conditions allow, never what the judged run depends on.
- Internal REST boundaries: capture/parse ↔ ML ↔ scoring ↔ reporting, consumed by the dashboard.

## 3. Data flow, end to end

1. **Matrix generator** produces N strongSwan `.conf` pairs (initiator/responder) spanning Mode × Cipher × DH-Group (incl. `ke1_mlkem768` PQC row) × PFS × IP version.
2. **Docker orchestrator** spins up initiator/responder container pairs per config, establishes the tunnel, and drives each of the 6 traffic-type generators through it.
3. **Capture wrapper** records IKE + ESP + baseline traffic per session into labeled PCAPs; ground-truth config + traffic-type label is written alongside each PCAP (this is the dataset deliverable, §9 of requirements).
4. **Deterministic parser** runs on every PCAP: extracts IKE version, mode, cipher, DH group, SA lifetime, proposal order, transform-enumeration/backoff/Vendor-ID fingerprint, and (for PQC configs) detects the `IKE_INTERMEDIATE` exchange as an ML-KEM presence signal.
5. **Feature extraction** computes ESP flow features (packet size, direction, inter-arrival timing, burst size/time) — payload bytes are never touched.
6. **ML classifier** (trained offline on the self-generated dataset, stratified/weighted for class imbalance) predicts traffic type + calibrated confidence per flow.
7. **Scoring engine** takes the deterministic parser's output as its evidence, applies the NIST 800-77r1 / RFC 8221 / RFC 8247 rule set, and produces the composite + per-dimension score, replay/PFS/lifetime flags, and the metadata-exposure sub-score (reusing parser output).
8. **Threat matrix builder** maps qualifying findings to T1040/T1557 only; every other finding stays a self-defined IPsec weakness entry with an attached remediation line.
9. **Report renderer** (Jinja2 + WeasyPrint/ReportLab) takes the one shared data model and emits Executive + Technical PDF/HTML from the same source of truth the dashboard reads.
10. **Dashboard** consumes the same internal REST API, renders score, breakdown, traffic classification, threat matrix, and report download links.

## 4. Suggested build order (engineering sequence, not calendar)

1. Docker + strongSwan config-matrix generator (unblocks everything downstream) — include the PQC row from day one, verify `ke1_mlkem768` actually negotiates in your strongSwan build before relying on it.
2. Traffic generation scripts per type (unblocks dataset creation + testing).
3. Deterministic IKE parser (fast win, no ML dependency, demoable standalone).
4. Feature extraction pipeline for ESP flows.
5. ML classifier training + calibration on the self-generated dataset.
6. Rule-based scoring engine mapped to NIST 800-77r1 / RFC 8221/8247.
7. Report templates (executive + technical) from the shared data model.
8. Dashboard wiring against the internal API, design system applied.
9. Threat matrix + T1040/T1557-only MITRE tagging.
10. PQC/ML-KEM row wired end-to-end (parser detection → scoring rubric row → dashboard/report display).
11. Error-handling/debugging pass against the failure-mode list (see guardrails doc).
12. Hardening pass + demo-video capture (offline mode).

## 5. Failure modes to design for explicitly (a judge will try to break this)

**Testbed / capture layer**
- strongSwan SA-establishment failure (proposal mismatch) → surface `ike: no acceptable proposal found`, not a silent hang or raw Docker stack trace.
- Capture started after IKE handshake completed → report "IKE_SA_INIT not observed in capture window — protocol ID confidence reduced," don't guess.
- Truncated/corrupted PCAP upload → validate (magic bytes, tshark parse check) before running the pipeline; fail fast with a specific message.
- Non-IPsec traffic uploaded → detect absence of IKE/ESP markers, say so, don't force a classification.

**Parsing / fingerprinting layer**
- Unknown IKE transform value → degrade to "unrecognized/unknown," log as a parser-extension gap, never mis-label.
- IKEv1 vs IKEv2 → detect and branch on version; don't assume IKEv2 everywhere.
- Fragmented IKE payloads (large cert payloads, or PQC `IKE_INTERMEDIATE` fragments) → reassemble before parsing, or explicitly flag "unparsed — reassembly not implemented."

**ML layer**
- Traffic type outside the trained label set → confidence floor triggers "unclassified / low confidence," never a false-certain best guess.
- Class imbalance in the self-generated dataset → document in dataset README, address with stratified sampling / class weighting.
- Very short flows → flag "insufficient data for reliable classification," don't run the classifier on meaningless feature vectors.

**Scoring / reporting layer**
- Mixed strong/weak config (e.g. AES-256 but no PFS + weak DH group) → composite score AND per-dimension breakdown both visible, always.
- Missing/ambiguous SA lifetime → report "not observed," never assume a default and score against the assumption.
- Report generation failure → validate shared data model against template schema before rendering; fail with a specific field-level error.

**General**
- Every user-facing error states *what* failed and *why*, in non-expert language.
- Log every classification decision (deterministic and ML) with its inputs, so any report number traces back to the exact packet/field or feature vector that produced it.

## 6. Team skill mapping (suggested, confirm against actual team)
1–2 on testbed/protocol (Docker + strongSwan + IKE/ESP parsing), 1–2 on ML (feature engineering + classifier + calibration), 1 backend/API, 1 frontend+reporting.
