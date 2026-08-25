/**
 * Antigravity IPsec Analyzer — Frontend Application Logic
 * Integrates Lenis Smooth Scroll, GSAP Numerical Count-Ups, & REST API Pipeline.
 */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Initialize Lenis Smooth Scroll
  let lenis;
  try {
    lenis = new Lenis({
      duration: 1.2,
      easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      smoothWheel: true,
    });
    function raf(time) {
      lenis.raf(time);
      requestAnimationFrame(raf);
    }
    requestAnimationFrame(raf);
  } catch (e) {
    console.warn('Lenis scroll fallback', e);
  }

  // DOM Elements
  const pcapFileInput = document.getElementById('pcapFileInput');
  const benchmarkSelector = document.getElementById('benchmarkSelector');
  const btnLoadBenchmark = document.getElementById('btnLoadBenchmark');
  const btnViewExecutive = document.getElementById('btnViewExecutive');
  const btnViewTechnical = document.getElementById('btnViewTechnical');
  const currentReportIdBadge = document.getElementById('currentReportId');

  // Metrics Elements
  const numSecurityScore = document.getElementById('numSecurityScore');
  const numRiskScore = document.getElementById('numRiskScore');
  const numConfidence = document.getElementById('numConfidence');
  const badgeGrade = document.getElementById('badgeGrade');
  const labelPosture = document.getElementById('labelPosture');
  const pillRiskLevel = document.getElementById('pillRiskLevel');
  const txtThreatCount = document.getElementById('txtThreatCount');
  const badgeTrafficType = document.getElementById('badgeTrafficType');
  const badgePQC = document.getElementById('badgePQC');
  const txtPQCStandard = document.getElementById('txtPQCStandard');

  // Protocol KV Elements
  const valProtoMode = document.getElementById('valProtoMode');
  const valEncryption = document.getElementById('valEncryption');
  const valDHGroup = document.getElementById('valDHGroup');
  const valIntegrityPRF = document.getElementById('valIntegrityPRF');
  const valPFS = document.getElementById('valPFS');
  const valVendorFingerprint = document.getElementById('valVendorFingerprint');
  const valTOS = document.getElementById('valTOS');
  const dimBarsContainer = document.getElementById('dimBarsContainer');

  // ML Elements
  const mlInferredClass = document.getElementById('mlInferredClass');
  const mlInferredDesc = document.getElementById('mlInferredDesc');
  const probSpectrumContainer = document.getElementById('probSpectrumContainer');
  const flowFeaturesGrid = document.getElementById('flowFeaturesGrid');

  // Threat Matrix Elements
  const threatTableBody = document.getElementById('threatTableBody');
  const filterBtns = document.querySelectorAll('.filter-btn');

  // Modal Elements
  const reportModal = document.getElementById('reportModal');
  const modalReportTitle = document.getElementById('modalReportTitle');
  const reportFrame = document.getElementById('reportFrame');
  const btnPrintReport = document.getElementById('btnPrintReport');
  const btnCloseModal = document.getElementById('btnCloseModal');

  let currentAuditData = null;
  let activeThreatFilter = 'ALL';

  // -------------------------------------------------------------
  // API Calls
  // -------------------------------------------------------------

  async function fetchBenchmarkSamples() {
    try {
      const res = await fetch('/api/dataset/samples');
      const samples = await res.json();
      benchmarkSelector.innerHTML = '<option value="" disabled selected>Select pre-configured benchmark capture...</option>';
      samples.forEach((s) => {
        const opt = document.createElement('option');
        opt.value = s.filename;
        const pqcLabel = s.is_pqc ? ' [PQC ML-KEM-768]' : '';
        opt.textContent = `${s.title} — ${s.traffic_type}${pqcLabel}`;
        benchmarkSelector.appendChild(opt);
      });
      // Auto select first sample if available
      if (samples.length > 0) {
        benchmarkSelector.selectedIndex = 1;
      }
    } catch (err) {
      console.error('Failed to load benchmark samples:', err);
    }
  }

  async function loadBenchmarkAnalysis(filename) {
    if (!filename) return;
    setLoadingState(true, `Analyzing benchmark PCAP: ${filename}...`);
    try {
      const res = await fetch(`/api/dataset/load-sample/${filename}`);
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      renderAuditResults(data);
    } catch (err) {
      alert(`Analysis Failed: ${err.message}`);
    } finally {
      setLoadingState(false);
    }
  }

  async function uploadAndAnalyzePCAP(file) {
    if (!file) return;
    setLoadingState(true, `Uploading & dissecting ${file.name}...`);
    const formData = new FormData();
    formData.append('file', file);
    try {
      const res = await fetch('/api/analyze/pcap', {
        method: 'POST',
        body: formData,
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      renderAuditResults(data);
    } catch (err) {
      alert(`Upload Analysis Failed: ${err.message}`);
    } finally {
      setLoadingState(false);
    }
  }

  // -------------------------------------------------------------
  // Render Audit Results with GSAP Motion
  // -------------------------------------------------------------

  function renderAuditResults(data) {
    currentAuditData = data;
    currentReportIdBadge.textContent = data.report_id;
    btnViewExecutive.disabled = false;
    btnViewTechnical.disabled = false;

    const sec = data.security || {};
    const proto = data.protocol?.summary || {};
    const fp = data.fingerprint || {};
    const ml = data.traffic_classification || {};
    const feats = data.flow_features || {};

    // 1. GSAP Animated Numerical Count-Ups
    animateScoreCount(numSecurityScore, sec.composite_security_score || 0);
    animateScoreCount(numRiskScore, sec.overall_risk_score || 0);
    animateScoreCount(numConfidence, (ml.calibrated_confidence || 0) * 100, '%');

    // Badges & Status
    badgeGrade.textContent = `GRADE: ${sec.security_grade?.split(' ')[0] || '--'}`;
    labelPosture.textContent = sec.posture_assessment || 'ASSESSED';

    const riskVal = sec.overall_risk_score || 0;
    if (riskVal >= 60) {
      pillRiskLevel.textContent = 'CRITICAL RISK';
      pillRiskLevel.className = 'risk-pill sev-critical';
    } else if (riskVal >= 30) {
      pillRiskLevel.textContent = 'ELEVATED RISK';
      pillRiskLevel.className = 'risk-pill sev-high';
    } else {
      pillRiskLevel.textContent = 'MINIMAL RISK';
      pillRiskLevel.className = 'risk-pill sev-low';
    }

    txtThreatCount.textContent = `${sec.threat_count || 0} Threats Tagged`;
    badgeTrafficType.textContent = ml.predicted_class || 'UNKNOWN';

    // Quantum Status
    if (proto.pqc_ready) {
      badgePQC.textContent = 'QUANTUM-SAFE';
      badgePQC.style.color = 'var(--accent-pqc)';
      txtPQCStandard.textContent = 'ML-KEM-768 / RFC 9370';
    } else {
      badgePQC.textContent = 'CLASSICAL ONLY';
      badgePQC.style.color = 'var(--text-muted)';
      txtPQCStandard.textContent = 'Discrete Logarithm / ECC';
    }

    // 2. Deterministic Protocol Table
    valProtoMode.textContent = `${proto.ike_version || 'IKEv2'} / ${proto.mode || 'Tunnel'} Mode`;
    valEncryption.textContent = proto.encryption_algorithm || 'AES-256-GCM';
    valDHGroup.textContent = proto.dh_group || 'ECP-384';
    valIntegrityPRF.textContent = `${proto.integrity_algorithm || 'None'} / ${proto.prf_algorithm || 'PRF_HMAC_SHA384'}`;
    valPFS.textContent = proto.pfs_enabled ? 'ENABLED (Child DH Verified)' : 'DISABLED (No Child DH Proposal)';
    valPFS.style.color = proto.pfs_enabled ? 'var(--accent-emerald)' : 'var(--accent-amber)';
    valVendorFingerprint.textContent = `${fp.vendor || 'Unknown'} (${fp.os_environment || 'Generic'})`;
    valTOS.textContent = fp.transform_ordering_signature?.tos_signature || 'NONE';

    // 3. 6-Dimension Score Breakdown Bars
    renderDimensionBars(sec.dimension_scores || {});

    // 4. ML Flow Classification
    mlInferredClass.textContent = ml.predicted_class || '--';
    mlInferredDesc.textContent = ml.message || '';
    renderProbabilitySpectrum(ml.probabilities || {});
    renderFlowFeaturesGrid(feats.features || {});

    // 5. Threat Matrix Table
    renderThreatTable(sec.threat_matrix || []);
  }

  function animateScoreCount(element, targetVal, suffix = '') {
    const obj = { val: 0 };
    gsap.to(obj, {
      val: targetVal,
      duration: 1.2,
      ease: 'power2.out',
      onUpdate: () => {
        element.textContent = obj.val.toFixed(1) + suffix;
      }
    });
  }

  function renderDimensionBars(dimScores) {
    const dimNames = {
      cryptographic_strength: 'Cryptographic Strength',
      configuration_compliance: 'Protocol Compliance',
      key_management: 'Key Exchange & Lifetime',
      perfect_forward_secrecy: 'Forward Secrecy (PFS)',
      anti_replay_protection: 'Anti-Replay Window',
      metadata_privacy: 'Metadata Privacy',
    };

    dimBarsContainer.innerHTML = '';
    Object.entries(dimScores).forEach(([k, score]) => {
      const item = document.createElement('div');
      item.className = 'dim-bar-item';
      const label = dimNames[k] || k;
      const barColor = score >= 85 ? 'var(--accent-emerald)' : score >= 60 ? 'var(--accent-amber)' : 'var(--accent-crimson)';

      item.innerHTML = `
        <div class="dim-bar-header">
          <span class="dim-bar-title">${label}</span>
          <span class="dim-bar-score">${score}/100</span>
        </div>
        <div class="dim-track">
          <div class="dim-fill" style="width: 0%; background: ${barColor};"></div>
        </div>
      `;
      dimBarsContainer.appendChild(item);

      // Animate fill bar width
      const fillEl = item.querySelector('.dim-fill');
      setTimeout(() => {
        fillEl.style.width = `${Math.max(4, score)}%`;
      }, 50);
    });
  }

  function renderProbabilitySpectrum(probs) {
    probSpectrumContainer.innerHTML = '';
    const sorted = Object.entries(probs).sort((a, b) => b[1] - a[1]);

    sorted.forEach(([cat, prob]) => {
      const pct = (prob * 100).toFixed(1);
      const isTop = prob === sorted[0][1] && prob > 0.3;
      const barColor = isTop ? 'var(--accent-cyan)' : 'var(--border-focus)';

      const row = document.createElement('div');
      row.className = 'prob-row';
      row.innerHTML = `
        <div class="prob-label">${cat}</div>
        <div class="prob-bar-track">
          <div class="prob-bar-fill" style="width: 0%; background: ${barColor};"></div>
        </div>
        <div class="prob-value">${pct}%</div>
      `;
      probSpectrumContainer.appendChild(row);

      const fill = row.querySelector('.prob-bar-fill');
      setTimeout(() => {
        fill.style.width = `${pct}%`;
      }, 80);
    });
  }

  function renderFlowFeaturesGrid(features) {
    flowFeaturesGrid.innerHTML = '';
    const highlightKeys = [
      { k: 'pkt_count_total', label: 'TOTAL PACKETS', fmt: (v) => v },
      { k: 'bytes_total', label: 'TOTAL BYTES', fmt: (v) => `${(v/1024).toFixed(1)} KB` },
      { k: 'pkt_size_mean', label: 'MEAN PKT SIZE', fmt: (v) => `${v.toFixed(0)} B` },
      { k: 'pkt_size_std', label: 'SIZE STD DEV', fmt: (v) => `${v.toFixed(1)}` },
      { k: 'iat_mean', label: 'MEAN IAT', fmt: (v) => `${(v * 1000).toFixed(1)} ms` },
      { k: 'burst_count', label: 'BURST COUNT', fmt: (v) => `${v.toFixed(0)}` },
    ];

    highlightKeys.forEach(({ k, label, fmt }) => {
      const val = features[k] !== undefined ? fmt(features[k]) : '--';
      const chip = document.createElement('div');
      chip.className = 'feat-chip';
      chip.innerHTML = `
        <div class="feat-chip-name">${label}</div>
        <div class="feat-chip-val">${val}</div>
      `;
      flowFeaturesGrid.appendChild(chip);
    });
  }

  function renderThreatTable(threats) {
    threatTableBody.innerHTML = '';
    const filtered = threats.filter((t) => {
      if (activeThreatFilter === 'ALL') return true;
      return t.severity === activeThreatFilter;
    });

    if (filtered.length === 0) {
      threatTableBody.innerHTML = `
        <tr>
          <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 24px;">
            No ${activeThreatFilter !== 'ALL' ? activeThreatFilter : ''} security threats identified for this capture.
          </td>
        </tr>
      `;
      return;
    }

    filtered.forEach((t, idx) => {
      const row = document.createElement('tr');
      row.className = 'threat-row';
      row.style.opacity = '0';

      const sevClass = `sev-${t.severity.toLowerCase()}`;
      row.innerHTML = `
        <td><code>${t.id}</code></td>
        <td><span class="sev-badge ${sevClass}">${t.severity}</span></td>
        <td><div class="mitre-tag">${t.mitre_technique}</div><small style="color: var(--text-muted);">${t.category}</small></td>
        <td><strong>${t.finding}</strong><div class="impact-text">${t.impact}</div></td>
        <td><div class="remediation-text">${t.remediation}</div><small style="color: var(--accent-cyan);">${t.standards_citation}</small></td>
      `;
      threatTableBody.appendChild(row);
    });

    // Staggered animated reveal via GSAP
    gsap.to('.threat-row', {
      opacity: 1,
      y: 0,
      stagger: 0.06,
      duration: 0.4,
      ease: 'power2.out',
    });
  }

  function setLoadingState(isLoading, message = 'Processing...') {
    if (isLoading) {
      btnLoadBenchmark.disabled = true;
      btnLoadBenchmark.textContent = 'ANALYZING...';
    } else {
      btnLoadBenchmark.disabled = false;
      btnLoadBenchmark.textContent = 'ANALYZE SAMPLE';
    }
  }

  // -------------------------------------------------------------
  // Event Listeners
  // -------------------------------------------------------------

  btnLoadBenchmark.addEventListener('click', () => {
    const selected = benchmarkSelector.value;
    if (selected) loadBenchmarkAnalysis(selected);
  });

  pcapFileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) {
      uploadAndAnalyzePCAP(e.target.files[0]);
    }
  });

  filterBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      filterBtns.forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      activeThreatFilter = btn.dataset.filter;
      if (currentAuditData?.security?.threat_matrix) {
        renderThreatTable(currentAuditData.security.threat_matrix);
      }
    });
  });

  // Modal Handlers
  btnViewExecutive.addEventListener('click', () => {
    if (!currentAuditData) return;
    modalReportTitle.textContent = `EXECUTIVE SECURITY REPORT — ${currentAuditData.filename}`;
    reportFrame.src = `/api/reports/executive/${currentAuditData.report_id}`;
    reportModal.style.display = 'flex';
  });

  btnViewTechnical.addEventListener('click', () => {
    if (!currentAuditData) return;
    modalReportTitle.textContent = `TECHNICAL FORENSIC AUDIT REPORT — ${currentAuditData.filename}`;
    reportFrame.src = `/api/reports/technical/${currentAuditData.report_id}`;
    reportModal.style.display = 'flex';
  });

  btnCloseModal.addEventListener('click', () => {
    reportModal.style.display = 'none';
    reportFrame.src = 'about:blank';
  });

  btnPrintReport.addEventListener('click', () => {
    if (reportFrame.contentWindow) {
      reportFrame.contentWindow.focus();
      reportFrame.contentWindow.print();
    }
  });

  // Initial Load
  fetchBenchmarkSamples().then(() => {
    // Auto load the PQC hybrid sample on first start
    loadBenchmarkAnalysis('sample_pqc_mlkem768_voip.pcap');
  });
});
