# Guardrails & Non-Negotiable Rules — PS 26160

These override convenience, deadline pressure, and "it'll probably be fine" under demo stress. If Gemini (or anyone building this) is about to violate one of these, stop and flag it rather than proceeding.

---

## Architectural constraints (non-negotiable)

1. **No external network calls in the core analysis pipeline.** Capture, parsing, ML inference, scoring, and report-text generation all run locally, always. No hosted-LLM shortcut for report prose — it's templated by design, and that's a stated architectural decision worth presenting proudly, not hiding.
2. **Never present a deterministic parse result as an ML output, or vice versa.** This split is load-bearing for the project's credibility. Under demo pressure, do not blur it — if a judge asks "what model decided the DH group," the correct answer is "there isn't one, it's unencrypted in the handshake."
3. **Every score must trace to a named standard (NIST SP 800-77 Rev. 1, June 2020 / RFC 8221 / RFC 8247) or an explicit, documented rule.** No unexplained weights. If a rubric weight is a judgment call rather than a standards citation, say so in the technical documentation — don't present it as equally authoritative.
4. **Every ML confidence number comes from the model** (`predict_proba` / `CalibratedClassifierCV`), never hand-typed or approximated for display.
5. **AH parsing is optional and explicitly deprioritized** — don't let it eat build time needed elsewhere.
6. **Any traffic-type substitution (e.g. WhatsApp → Signal/Telegram fallback) must be disclosed in the dataset README**, never silently relabeled.
7. **Do not cite "TAVO" or any unverified academic term.** Use "transform-enumeration + backoff-timing fingerprinting (ike-scan-inspired)" or an honestly self-labeled term instead — see research dossier §1. A judge who looks up a fabricated citation and finds nothing costs you more credibility than not citing anything at all.
8. **Don't imply Leroux et al. (2018) covers your full 6-class traffic taxonomy.** Their paper covers web/VoIP/video/P2P; Email and ICMP are your own extension. State this explicitly in the technical report.

## Process guardrails

- Lock the open assumptions (timeline structure, WhatsApp go/no-go, Libreswan stretch status, PQC version confirmation, team skill mapping) before starting the build sprint — don't let them stay ambiguous into week two.
- **Cut frontend polish before cutting the ML/protocol core** if time runs short. A plain UI with a real pipeline beats a polished UI in front of a broken or faked one.
- Treat offline PCAP-analysis as the path the live judged demo depends on; live capture is a bonus shown only if conditions cooperate.
- **Don't force MITRE ATT&CK mappings onto every threat-matrix entry.** Only T1040 (Network Sniffing → metadata-exposure findings) and T1557 (Adversary-in-the-Middle, downgrade sub-behavior → weak-cipher/no-PFS findings) are confirmed genuine per the research dossier. Everything else stays a self-defined IPsec weakness with a remediation line, undecorated.
- **Don't reach for deep learning anywhere in this project** unless there's a specific, defensible reason flow-features + classical ML can't do the job. For this problem there isn't one, and the literature backs that call.
- **Never collapse a mixed config's score to a single number without the per-dimension breakdown visible** — an unfalsifiable single score invites (correct) judge pushback.
- **Every user-facing error names what failed and why**, in language a non-protocol-expert can act on.
- **Log every classification decision (deterministic and ML) with its inputs** so any reported number traces back to the exact packet/field or feature vector that produced it — this is what makes the technical report actually technical.

## Dashboard-specific guardrail
- No default AI-tool visual patterns (purple/blue gradients, glassmorphism-by-default, stock AI-orb graphics, emoji-as-icons, centered-gradient-hero). See `03_design_system.md` for the full positive spec.

## Verification-before-narrative guardrail
- Before committing to the PQC/ML-KEM differentiator in the demo script, **verify the actual strongSwan build/version in your environment supports `ke1_mlkem768`** (`strongswan version`, check plugin list for `oqs` or built-in ML-KEM support) — don't assume from documentation alone.
