"""
Unified Security Assessment Report Generator.
Renders Executive and Technical reports from a single shared Canonical Data Model.
Never diverges numerically or structurally between UI and generated reports.
Air-gapped / fully offline with no cloud or external LLM dependencies.
"""

import os
import json
import time
from typing import Dict, List, Any
from jinja2 import Template


class UnifiedReportGenerator:
    """
    Renders Executive and Technical compliance and forensic audit reports.
    """

    EXECUTIVE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Executive Security Assessment Report — IPsec VPN Audit</title>
<style>
  @page { size: A4; margin: 20mm; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1e293b; background: #ffffff; line-height: 1.5; padding: 24px; max-width: 900px; margin: 0 auto; }
  .header { border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 24px; }
  .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 12px; letter-spacing: 0.5px; text-transform: uppercase; }
  .badge-exemplary { background: #dcfce7; color: #166534; }
  .badge-strong { background: #e0f2fe; color: #0369a1; }
  .badge-moderate { background: #fef3c7; color: #92400e; }
  .badge-critical { background: #fee2e2; color: #991b1b; }
  .score-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin: 24px 0; }
  .score-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; text-align: center; }
  .score-val { font-size: 32px; font-weight: 800; color: #0f172a; margin: 4px 0; }
  .table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 14px; }
  .table th, .table td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
  .table th { background: #f1f5f9; font-weight: 600; color: #334155; }
  .section-title { font-size: 18px; font-weight: 700; color: #0f172a; margin-top: 28px; margin-bottom: 12px; border-left: 4px solid #3b82f6; padding-left: 8px; }
  .callout { background: #eff6ff; border-left: 4px solid #2563eb; padding: 12px 16px; border-radius: 4px; margin: 16px 0; font-size: 14px; }
  .footer { margin-top: 40px; padding-top: 12px; border-top: 1px solid #cbd5e1; font-size: 12px; color: #64748b; display: flex; justify-content: space-between; }
  @media print { .no-print { display: none; } body { padding: 0; } }
</style>
</head>
<body>
  <div class="header">
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <h1 style="margin: 0; font-size: 22px; color: #0f172a;">Executive IPsec VPN Security Assessment</h1>
      <span class="badge badge-{{ report.security.posture_assessment.lower() }}">{{ report.security.posture_assessment }}</span>
    </div>
    <div style="color: #64748b; font-size: 13px; margin-top: 6px;">
      Audit Target: <strong>{{ report.protocol.summary.mode }} Mode Tunnel</strong> ({{ report.filename }}) &bull; Date: {{ report.generated_at }}
    </div>
  </div>

  <div class="callout">
    <strong>Executive Summary:</strong> The evaluated IPsec VPN configuration was analyzed under 
    <strong>NIST SP 800-77 Rev. 1</strong> and <strong>RFC 8221/8247</strong> standards. 
    The overall security rating is <strong>{{ report.security.composite_security_score }}/100</strong> (Grade: {{ report.security.security_grade }}), 
    representing a <strong>{{ report.security.overall_risk_score }}/100</strong> risk posture.
    {% if report.protocol.summary.pqc_ready %}
    The gateway incorporates <strong>Post-Quantum Key Encapsulation (ML-KEM-768 / RFC 9370)</strong>, shielding traffic against quantum decryption.
    {% endif %}
  </div>

  <div class="score-grid">
    <div class="score-card">
      <div style="font-size: 12px; color: #64748b; text-transform: uppercase;">Composite Security</div>
      <div class="score-val">{{ report.security.composite_security_score }}<span style="font-size: 16px; color: #94a3b8;">/100</span></div>
      <div style="font-size: 12px; color: #16a34a; font-weight: 600;">Grade: {{ report.security.security_grade.split(' ')[0] }}</div>
    </div>
    <div class="score-card">
      <div style="font-size: 12px; color: #64748b; text-transform: uppercase;">Overall Risk Rating</div>
      <div class="score-val" style="color: {% if report.security.overall_risk_score > 60 %}#dc2626{% elif report.security.overall_risk_score > 30 %}#d97706{% else %}#16a34a{% endif %};">
        {{ report.security.overall_risk_score }}<span style="font-size: 16px; color: #94a3b8;">/100</span>
      </div>
      <div style="font-size: 12px; color: #64748b;">Severity: {{ 'CRITICAL' if report.security.overall_risk_score > 60 else 'MODERATE' if report.security.overall_risk_score > 30 else 'LOW' }}</div>
    </div>
    <div class="score-card">
      <div style="font-size: 12px; color: #64748b; text-transform: uppercase;">AI Classification Confidence</div>
      <div class="score-val" style="color: #2563eb;">{{ (report.traffic_classification.calibrated_confidence * 100)|round(1) }}%</div>
      <div style="font-size: 12px; color: #64748b;">Traffic: <strong>{{ report.traffic_classification.predicted_class }}</strong></div>
    </div>
  </div>

  <div class="section-title">Key Posture Breakdown</div>
  <table class="table">
    <thead>
      <tr><th>Evaluation Dimension</th><th>Score</th><th>Standard Reference</th><th>Status</th></tr>
    </thead>
    <tbody>
      <tr>
        <td>Cryptographic Strength</td>
        <td><strong>{{ report.security.dimension_scores.cryptographic_strength }}/100</strong></td>
        <td>{{ report.security.algorithm_evaluations.cipher.standards }}</td>
        <td>{{ report.security.algorithm_evaluations.cipher.status }}</td>
      </tr>
      <tr>
        <td>Key Exchange & Forward Secrecy</td>
        <td><strong>{{ report.security.dimension_scores.perfect_forward_secrecy }}/100</strong></td>
        <td>{{ report.security.algorithm_evaluations.dh_group.standards }}</td>
        <td>{{ report.security.algorithm_evaluations.dh_group.status }}</td>
      </tr>
      <tr>
        <td>Anti-Replay Protection</td>
        <td><strong>{{ report.security.dimension_scores.anti_replay_protection }}/100</strong></td>
        <td>RFC 7296 Section 2.1</td>
        <td>Compliant</td>
      </tr>
      <tr>
        <td>Metadata Privacy & Exposure</td>
        <td><strong>{{ report.security.dimension_scores.metadata_privacy }}/100</strong></td>
        <td>NIST SP 800-77r1 Sec 3.2</td>
        <td>{{ 'Shielded' if report.security.dimension_scores.metadata_privacy > 75 else 'Exposed' }}</td>
      </tr>
    </tbody>
  </table>

  <div class="section-title">Identified Threats & Recommended Actions</div>
  <table class="table">
    <thead>
      <tr><th>ID</th><th>Severity</th><th>Threat Description</th><th>Actionable Recommendation</th></tr>
    </thead>
    <tbody>
      {% for threat in report.security.threat_matrix %}
      <tr>
        <td><code>{{ threat.id }}</code></td>
        <td><span style="font-weight: 700; color: {% if threat.severity in ('CRITICAL', 'HIGH') %}#dc2626{% else %}#d97706{% endif %};">{{ threat.severity }}</span></td>
        <td><strong>{{ threat.finding }}</strong><br><small style="color: #64748b;">MITRE: {{ threat.mitre_technique }}</small></td>
        <td>{{ threat.remediation }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <div class="footer">
    <div>PS ID 26160 &bull; IPsec Security Assessment Platform</div>
    <div>Strictly Offline Execution &bull; NIST SP 800-77 Rev. 1 Ground Truth</div>
  </div>
</body>
</html>
"""

    TECHNICAL_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Technical Security Assessment & Forensic Protocol Audit</title>
<style>
  @page { size: A4; margin: 15mm; }
  body { font-family: "JetBrains Mono", Consolas, "Courier New", monospace; color: #0f172a; background: #ffffff; line-height: 1.45; padding: 20px; font-size: 13px; }
  .header { border-bottom: 2px solid #0f172a; padding-bottom: 12px; margin-bottom: 20px; }
  .section { margin-top: 24px; margin-bottom: 16px; }
  .section-hdr { background: #0f172a; color: #ffffff; padding: 6px 10px; font-weight: bold; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
  .table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 12px; }
  .table th, .table td { padding: 6px 8px; border: 1px solid #cbd5e1; text-align: left; }
  .table th { background: #f1f5f9; font-weight: 700; }
  .badge { display: inline-block; padding: 2px 6px; font-size: 10px; font-weight: bold; border-radius: 3px; }
  .badge-pqc { background: #7c3aed; color: #ffffff; }
  .badge-approved { background: #059669; color: #ffffff; }
  .badge-deprecated { background: #dc2626; color: #ffffff; }
  .codebox { background: #f8fafc; border: 1px solid #e2e8f0; padding: 10px; font-size: 11px; white-space: pre-wrap; word-break: break-all; margin: 10px 0; }
  .footer { margin-top: 30px; border-top: 1px solid #cbd5e1; padding-top: 8px; font-size: 11px; color: #64748b; }
</style>
</head>
<body>
  <div class="header">
    <div style="font-size: 18px; font-weight: bold;">TECHNICAL FORENSIC AUDIT: IPSEC PROTOCOL & TRAFFIC ANALYSIS</div>
    <div style="font-size: 11px; color: #64748b; margin-top: 4px;">
      Target: {{ report.filename }} | Protocol: {{ report.protocol.summary.protocol }} | Mode: {{ report.protocol.summary.mode }} | Timestamp: {{ report.generated_at }}
    </div>
  </div>

  <div class="section">
    <div class="section-hdr">1. Deterministic Protocol Identification (Cleartext Wire Analysis — Zero ML)</div>
    <table class="table">
      <tr><th style="width: 25%;">IKE Version</th><td>{{ report.protocol.summary.ike_version }}</td><th style="width: 25%;">Encapsulation Mode</th><td>{{ report.protocol.summary.mode }}</td></tr>
      <tr><th>Encryption Transform</th><td><strong>{{ report.protocol.summary.encryption_algorithm }}</strong></td><th>Diffie-Hellman / KE Group</th><td><strong>{{ report.protocol.summary.dh_group }}</strong></td></tr>
      <tr><th>Integrity Transform</th><td>{{ report.protocol.summary.integrity_algorithm }}</td><th>Pseudo-Random Function (PRF)</th><td>{{ report.protocol.summary.prf_algorithm }}</td></tr>
      <tr><th>PFS Status</th><td>{{ 'ENABLED (Child SA DH Exchange Verified)' if report.protocol.summary.pfs_enabled else 'DISABLED (No Child DH proposal)' }}</td><th>Post-Quantum Capability</th><td>{% if report.protocol.summary.pqc_ready %}<span class="badge badge-pqc">RFC 9370 / ML-KEM-768 DETECTED</span>{% else %}Classical Only{% endif %}</td></tr>
      <tr><th>Fingerprinted Stack</th><td>{{ report.fingerprint.vendor }} ({{ report.fingerprint.os_environment }})</td><th>Detection Methodology</th><td>{{ report.fingerprint.techniques_used|join(', ') }}</td></tr>
      <tr><th>Transform Ordering (TOS)</th><td colspan="3"><code>{{ report.fingerprint.transform_ordering_signature.tos_signature }}</code> ({{ report.fingerprint.transform_ordering_signature.inferred_stack }})</td></tr>
    </table>
  </div>

  <div class="section">
    <div class="section-hdr">2. Statistical Machine Learning Encrypted Flow Inference (Leroux et al. 2018 Methodology)</div>
    <p style="font-size: 12px; margin: 6px 0;">Statistical classification performed strictly on packet size and inter-arrival timing without payload inspection.</p>
    <table class="table">
      <tr><th style="width: 25%;">Inferred Traffic Category</th><td><strong style="color: #2563eb; font-size: 14px;">{{ report.traffic_classification.predicted_class }}</strong></td><th style="width: 25%;">Calibrated Model Confidence</th><td><strong style="font-size: 14px;">{{ (report.traffic_classification.calibrated_confidence * 100)|round(2) }}%</strong></td></tr>
      <tr><th>Classification Status</th><td>{{ report.traffic_classification.status }}</td><th>Flow Duration / Total Packets</th><td>{{ report.flow_features.duration_sec }}s ({{ report.flow_features.packet_count }} packets)</td></tr>
    </table>

    <div style="font-size: 11px; font-weight: bold; margin-top: 8px;">Calibrated Probability Distribution Across Classes:</div>
    <table class="table">
      <thead>
        <tr>
          {% for cat, p in report.traffic_classification.probabilities.items() %}
          <th>{{ cat }}</th>
          {% endfor %}
        </tr>
      </thead>
      <tbody>
        <tr>
          {% for cat, p in report.traffic_classification.probabilities.items() %}
          <td><strong>{{ (p * 100)|round(2) }}%</strong></td>
          {% endfor %}
        </tr>
      </tbody>
    </table>
  </div>

  <div class="section">
    <div class="section-hdr">3. Standards-Based Compliance Scoring & Threat Matrix</div>
    <table class="table">
      <thead>
        <tr><th>ID</th><th>Severity</th><th>MITRE ATT&CK</th><th>Standards Citation</th><th>Finding & Impact</th><th>Required Remediation</th></tr>
      </thead>
      <tbody>
        {% for threat in report.security.threat_matrix %}
        <tr>
          <td><code>{{ threat.id }}</code></td>
          <td><strong>{{ threat.severity }}</strong></td>
          <td>{{ threat.mitre_technique }}</td>
          <td><small>{{ threat.standards_citation }}</small></td>
          <td><strong>{{ threat.finding }}</strong><br><span style="color: #64748b;">{{ threat.impact }}</span></td>
          <td>{{ threat.remediation }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="footer">
    <div>Deterministic Protocol Extraction + Calibrated Statistical Inference Engine</div>
    <div>Standards: NIST SP 800-77 Rev. 1, RFC 8221, RFC 8247, RFC 9370 &bull; PS ID 26160</div>
  </div>
</body>
</html>
"""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def assemble_canonical_data_model(
        self,
        filename: str,
        parsed_data: Dict[str, Any],
        fingerprint_data: Dict[str, Any],
        features_data: Dict[str, Any],
        classification_data: Dict[str, Any],
        security_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Creates the single unified JSON source of truth."""
        return {
            "report_id": f"AUDIT-{int(time.time())}",
            "filename": filename,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "protocol": parsed_data,
            "fingerprint": fingerprint_data,
            "flow_features": features_data,
            "traffic_classification": classification_data,
            "security": security_data,
        }

    def render_executive_report(self, canonical_model: Dict[str, Any]) -> str:
        template = Template(self.EXECUTIVE_TEMPLATE)
        return template.render(report=canonical_model)

    def render_technical_report(self, canonical_model: Dict[str, Any]) -> str:
        template = Template(self.TECHNICAL_TEMPLATE)
        return template.render(report=canonical_model)

    def save_reports(self, canonical_model: Dict[str, Any], base_name: str = "audit_report") -> Dict[str, str]:
        exec_html = self.render_executive_report(canonical_model)
        tech_html = self.render_technical_report(canonical_model)
        json_dump = json.dumps(canonical_model, indent=2)

        exec_path = os.path.join(self.output_dir, f"{base_name}_executive.html")
        tech_path = os.path.join(self.output_dir, f"{base_name}_technical.html")
        json_path = os.path.join(self.output_dir, f"{base_name}_data.json")

        with open(exec_path, "w", encoding="utf-8") as f:
            f.write(exec_html)
        with open(tech_path, "w", encoding="utf-8") as f:
            f.write(tech_html)
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(json_dump)

        return {
            "executive_html": exec_path,
            "technical_html": tech_path,
            "data_json": json_path,
        }


if __name__ == "__main__":
    rep_gen = UnifiedReportGenerator()
    print("Report generator ready.")
