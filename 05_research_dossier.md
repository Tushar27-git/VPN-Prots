# Research Dossier — PS 26160 (IPsec VPN Protocol Analyzer)
### Fact-checked, deep-dived, corrected against live sources — August 2026

> Purpose of this file: every load-bearing technical claim in the build doc, re-verified against current sources. Where the original v1 doc had a claim that's shaky, vague, or slightly wrong, it's flagged and fixed here. This is the file to quote from when a judge asks "where does that number/name/standard come from."

---

## 1. Correction — "TAVO" fingerprinting is NOT a verified academic term

The v1 doc names "TAVO (Transform-payload Attribute Value Order)" as a formalized academic fingerprint. **I could not verify this acronym exists in the published literature** — it doesn't surface in searches against `ike-scan` documentation, IETF drafts, or academic IPsec-fingerprinting papers. This is a real risk in a judged setting: a security-literate judge who tries to look up "TAVO" and finds nothing will read it as a fabricated citation, which damages credibility on the *whole* document, not just this line.

**What is real and well-documented** (use this instead, cite it correctly):
- **`ike-scan`** (Roy Hills, NTA Monitor) is the canonical open-source tool for this and does it via **three distinct, real mechanisms**: (1) **UDP backoff fingerprinting** — timing/retransmission pattern of IKE responses compared against a reference pattern file; (2) **Vendor ID (VID) payload matching** against known implementation signatures; (3) **transform enumeration** — probing which cipher/hash/DH/auth combinations a responder accepts, which indirectly reveals implementation and policy.
- The general *principle* the v1 doc wanted to invoke — that the **order and content of proposed transform attributes in the cleartext IKE_SA_INIT / Phase-1 exchange is itself a distinguishing signal**, independent of vendor ID — is a reasonable, defensible engineering observation, but it should be presented as **"a fingerprinting heuristic we built, inspired by `ike-scan`'s transform-enumeration approach"**, not as an established named academic method. Naming it something honest like **"Transform Ordering Signature (TOS)" and explicitly labeling it as your own team's coined term** is safer and still sounds sharp in a demo.

**Action for the build:** Rename the deterministic sub-module's implementation/vendor fingerprint feature from "TAVO-style" to **"transform-enumeration + backoff-timing fingerprinting (ike-scan-inspired)"** in all documentation, and if you keep a proposal-ordering heuristic, label it as an original contribution, not a citation.

---

## 2. Confirmed, strengthened — Leroux et al. (2018) encrypted traffic-type classification

Confirmed real and correctly characterized in spirit, but the original doc slightly overstated category coverage. Leroux et al. (2018) built an ML pipeline that classified traffic **inside IPsec and Tor tunnels** using only **packet size, inter-arrival time, burst size, and burst time** — no payload access — fed into **Naive Bayes, Logistic Regression, and Random Forest** classifiers. <cite index="20-1">Leroux et al. employed machine learning techniques including Naive Bayes, Logistic Regression, and Random Forest to predict the sort of traffic passing through an IPsec or TOR tunnel, using packet size, inter-arrival time, and burst time and burst size from the encrypted streams</cite>.

**Important nuance to state honestly in your technical report:** their actual labeled classes were **web browsing, VoIP, video streaming, and P2P** <cite index="24-1">Leroux et al. distinguished between four types of traffic: web browsing, voip, video streaming, and P2P, using Naive Bayes, logistic regression, and random forest as classifiers trained on packet timing and size</cite> — **not** Email or ICMP. Those two are your own extensions beyond the cited paper's scope. Say so explicitly: *"We extend the Leroux et al. feature methodology to two additional traffic classes (Email, ICMP) not covered in the original paper, verified against our own self-generated ground truth."* This is a stronger, more defensible statement than implying the paper already covered your full 6-class taxonomy.

Current best practice has indeed moved toward **ensemble/stacked classifiers** rather than deep learning directly on encrypted bytes, precisely because there's no exploitable byte-level structure in properly encrypted ESP payload — keep this architectural decision, it's sound and citable as a "the literature agrees deep learning buys nothing here" position.

---

## 3. Strengthened significantly — ISCXVPN2016 dataset integrity problems

The v1 doc gestured at this vaguely. There is now **much stronger, specific, citable evidence** — use this instead of the vague version:

- A 2022 arXiv paper doing forensic inspection of the dataset found **literal unencrypted HTML payload inside a file labeled as VPN-encrypted traffic**: <cite index="38-1">upon closer inspection of the PCAP files from the VPN captures, packets with unencrypted payloads were found — for example, the payload of the 17th packet in the PCAP file for the ICQ Chat VPN capture contains body HTML text, viewable directly in Wireshark, and PCAP files for VPN-labeled captures were found to contain multiple connections despite the expectation of a single client-to-server connection for a VPN session</cite>.
- The same source notes a prior finding that **65% of the dataset's biflows are attributable to BlueStacks (Android emulator) artifacts and should be filtered out entirely** <cite index="38-1">these discrepancies are in addition to a prior observation that 65% of the biflows are due to BlueStacks and should be filtered out</cite>.
- A 2024 PETS/FOCI workshop paper independently found the dataset's own metadata claims don't match the packet captures: <cite index="41-1">a portion of the ISCXVPN2016 dataset was downloaded and found to be majority TCP traffic despite the dataset's own documentation stating that OpenVPN in UDP mode was used to capture the traffic</cite>.
- A 2025 survey adds the broader field critique: <cite index="40-1">extensive reuse of ISCXVPN2016 without a clear understanding of its creation and content has caused researchers to rely on outdated data no longer representative of contemporary traffic, and has constrained the research scope almost entirely to OpenVPN, preventing consideration of alternative VPN protocols</cite>.

**This is a much better differentiator slide than the original vague version** — you now have three independent, dated, citable findings (2022, 2024, 2025) instead of one hand-wavy sentence. Put this exact citation chain in the dataset README and the technical report; it's the single strongest "why we didn't just download a public dataset" argument you have.

---

## 4. Confirmed, strengthened, and dated — strongSwan native PQC/ML-KEM support (your primary differentiator)

This is now even stronger than the v1 doc assumed, and it's very current (good for a "why is this a 2026 project" narrative):

- strongSwan's own site (checked directly) states current support: <cite index="30-1">strongSwan supports multiple classic and post-quantum key exchanges per RFC 9370, including ML-KEM (FIPS 203)</cite>, with the **latest release being version 6.0.7 (June 7, 2026)** <cite index="30-1">the latest release version is 6.0.7, dated 2026-06-07</cite> — meaning this capability is in the *current stable release*, not a forked experimental branch.
- Mechanically: ML-KEM doesn't drop into classic IKEv2 unmodified — its public keys/ciphertexts are large enough to require **IKEv2 fragmentation and an additional IKE_INTERMEDIATE exchange round**, which is exactly what **RFC 9370** (multiple key exchanges in IKEv2) defines. <cite index="36-1">ML-KEM public keys and ciphertexts are much larger than DH/ECDH values — ML-KEM-1024 alone includes a 1568-byte public key, exceeding safe unfragmented UDP payload size, so large PQC payloads stress UDP transport limits and require IKEv2 fragmentation, which RFC 9370 addresses by extending IKEv2 with additional exchange rounds (the IKE_INTERMEDIATE phase) before IKE-AUTH</cite>. This is a genuinely interesting, demoable technical detail: your parser should specifically detect and call out an `IKE_INTERMEDIATE` exchange in a capture, since its mere *presence* is itself a PQC-readiness signal before you even parse the KE payload contents.
- A concrete strongSwan config snippet you can adapt directly for your testbed matrix (from a 2026 quantum-resilient-networking paper): a hybrid classical+PQC child SA is expressed as `ike=aes256-sha384-ecp384-ke1_mlkem768!` <cite index="32-1">an example strongSwan configuration for a quantum-resistant IPsec tunnel uses ike=aes256-sha384-ecp384-ke1_mlkem768! for the IKE proposal and esp=aes256gcm128-sha384-ecp384! for the child SA, combining ML-KEM-768 post-quantum key encapsulation with classical ECP384 key exchange</cite> — i.e., strongSwan's proposal syntax lets you literally chain a classical DH group and an ML-KEM group in one proposal string with `-ke1_mlkem768`. **Put this exact proposal string in your config-matrix generator as a first-class row**, not an afterthought.
- Broader relevance for the narrative: hybrid PQC key exchange is now mainstream on the public internet, not experimental — as of mid-2026, <cite index="37-1">between 30 and 50 percent of all TLS handshakes initiated by major browsers use a hybrid post-quantum group</cite>. Cite this to justify why a VPN auditing tool checking for PQC-readiness is timely rather than speculative.

**Caveat worth stating honestly in the technical report:** the underlying ML-KEM-in-IKEv2 negotiation mechanics are still standardizing at the IETF — <cite index="34-1">the IKEv2 ML-KEM specification is an Internet-Draft that is inappropriate to cite as reference material other than as work in progress</cite>. Frame your PQC row as "checks for the presence and use of ML-KEM key exchange in the observed proposal," not "certifies IETF-final PQC compliance" — this is a defensible, judge-proof framing.

---

## 5. Confirmed — NIST SP 800-77 Rev. 1 status (correcting a subtle risk)

Direct check of the NIST CSRC record: **SP 800-77 Rev. 1 (June 2020) is the current, active, non-withdrawn publication.** The only withdrawn items in this family are the *original 2005 SP 800-77* (superseded by Rev. 1) and the *2019 public draft* of Rev. 1 (superseded by the final). Authors: Barker, Dang, Frankel, Scarfone, and Wouters. Cite it as **"NIST SP 800-77 Rev. 1, June 2020"** — do not cite a page or section number you haven't personally pulled from the PDF, since page numbering can shift between draft/final copies circulating online.

RFC 8221 (ESP/AH cryptographic algorithm requirements) and RFC 8247 (IKEv2 algorithm requirements) are both real, current, and correctly named in the v1 doc — no correction needed there. Keep the three-standard rubric (SP 800-77 Rev 1 + RFC 8221 + RFC 8247) as your scoring backbone.

---

## 6. Confirmed, narrowed — MITRE ATT&CK mappings that are actually genuine

Do **not** invent mappings. Two techniques are directly and defensibly relevant to what this tool detects:

- **T1040 — Network Sniffing** (Credential Access / Discovery): <cite index="69-1">adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network, by placing a network interface into promiscuous mode or using span ports</cite>. Map this to your **"metadata exposure" finding** (cleartext IKE identities, SPI values, endpoint IPs) — that's literally what T1040 describes an adversary doing to the exact data your fingerprinting module extracts.
- **T1557 — Adversary-in-the-Middle**, specifically its downgrade-attack angle: <cite index="66-1">downgrade attacks can be used to establish an AiTM position, such as by negotiating a less secure, deprecated, or weaker version of a communication protocol or encryption algorithm</cite>. Map this to your **weak-cipher / deprecated-DH-group / no-PFS findings** — a weak negotiated proposal is exactly the precondition T1557's downgrade sub-behavior exploits.

Do not force-map PFS-absence, replay-window, or key-lifetime findings to a specific ATT&CK ID unless you find a genuine one during the build — per the v1 doc's own (correct) guardrail, an unforced two-technique mapping is more credible than a padded eight-technique one.

---

## 7. Net effect on the build doc

- Rename "TAVO" → "transform-enumeration + backoff-timing fingerprinting, ike-scan-inspired" (or your own honestly-labeled term).
- State the Leroux et al. category gap (VoIP/web/video/P2P in the paper vs. your 6-class taxonomy) honestly as a documented extension.
- Replace the vague ISCXVPN2016 sentence with the three-citation chain (§3) in the dataset README and technical report.
- Elevate the PQC section with the concrete `ke1_mlkem768` proposal syntax and the RFC 9370 / IKE_INTERMEDIATE detection detail — this is your strongest, most current differentiator and it now has real engineering meat, not just a buzzword.
- Cite NIST SP 800-77 **Rev. 1, June 2020** specifically (not the withdrawn 2005 original or the withdrawn 2019 draft).
- Threat matrix: only auto-map T1040 and T1557 with confidence; leave everything else as self-defined IPsec-specific findings, per the original guardrail.
