/**
 * AegisGraph-CTI Main Dashboard Application Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  // Initialize Graph and Timeline Controllers
  const graphViz = new ProvenanceGraphVisualizer('provenance-graph-svg', 'graph-container');
  const timelineCtrl = new AttackTimelineController('timeline-track', 'replay-step-indicator');

  // DOM Elements
  const datasetSelect = document.getElementById('dataset-select');
  const btnRunAnalysis = document.getElementById('btn-run-analysis');
  const btnResetZoom = document.getElementById('btn-reset-zoom');
  const btnToggleLabels = document.getElementById('btn-toggle-labels');
  const btnCloseInspector = document.getElementById('btn-close-inspector');
  const btnReplayPlay = document.getElementById('btn-replay-play');

  // Modals
  const btnOpenEval = document.getElementById('btn-open-eval');
  const modalBenchmark = document.getElementById('modal-benchmark');
  const btnCloseEvalModal = document.getElementById('btn-close-eval-modal');
  const btnDismissEval = document.getElementById('btn-dismiss-eval');
  const btnRerunEval = document.getElementById('btn-rerun-eval');

  const btnOpenIngest = document.getElementById('btn-open-ingest');
  const modalIngest = document.getElementById('modal-ingest');
  const btnCloseIngestModal = document.getElementById('btn-close-ingest-modal');
  const btnDismissIngest = document.getElementById('btn-dismiss-ingest');
  const btnSubmitCustomLogs = document.getElementById('btn-submit-custom-logs');
  const customLogInput = document.getElementById('custom-log-input');

  // Load Available Datasets
  async function loadDatasets() {
    try {
      const res = await fetch('/api/datasets');
      const datasets = await res.json();
      datasetSelect.innerHTML = '';
      datasets.forEach(ds => {
        const opt = document.createElement('option');
        opt.value = ds.id;
        opt.textContent = `${ds.title}`;
        if (ds.id === 'insider_usb_exfil') opt.selected = true; // Default to prompt scenario
        datasetSelect.appendChild(opt);
      });
      // Run initial analysis on load
      analyzeSelectedDataset();
    } catch (err) {
      console.error('Failed to load datasets:', err);
    }
  }

  // Analyze Dataset Scenario
  async function analyzeSelectedDataset() {
    const datasetId = datasetSelect.value;
    btnRunAnalysis.disabled = true;
    btnRunAnalysis.innerHTML = '<span class="btn-icon">⏳</span> Analyzing...';

    try {
      const res = await fetch(`/api/analyze/preset/${datasetId}`, { method: 'POST' });
      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      const report = await res.json();
      renderIncidentReport(report);
    } catch (err) {
      console.error('Analysis error:', err);
      alert('Error analyzing dataset. Please ensure backend server is running.');
    } finally {
      btnRunAnalysis.disabled = false;
      btnRunAnalysis.innerHTML = '<span class="btn-icon">⚡</span> Analyze Threat';
    }
  }

  // Render Incident Report
  function renderIncidentReport(report) {
    // 1. Verdict Card
    const verdictHeading = document.getElementById('verdict-heading');
    const verdictDesc = document.getElementById('verdict-desc');
    const verdictIcon = document.getElementById('verdict-icon');
    const verdictBadge = document.getElementById('badge-verdict-type');

    if (report.is_attack) {
      verdictHeading.textContent = 'MALICIOUS ATTACK CHAIN';
      verdictHeading.style.color = '#f43f5e';
      verdictIcon.textContent = '🚨';
      verdictBadge.textContent = 'COORDINATED THREAT';
      verdictBadge.className = 'badge danger';
      verdictDesc.textContent = report.summary_explanation;
    } else {
      verdictHeading.textContent = 'BENIGN OPERATIONAL BASELINE';
      verdictHeading.style.color = '#10b981';
      verdictIcon.textContent = '🛡️';
      verdictBadge.textContent = 'ZERO FALSE ALARMS';
      verdictBadge.className = 'badge success';
      verdictDesc.textContent = report.summary_explanation;
    }

    // 2. Risk Meter & Radial Gauge
    const gaugeFill = document.getElementById('gauge-fill-circle');
    const gaugeNumber = document.getElementById('gauge-number');
    const badgeRiskLevel = document.getElementById('badge-risk-level');
    const valProgression = document.getElementById('val-progression-score');
    const valBlast = document.getElementById('val-blast-score');

    const score = report.overall_risk_score;
    gaugeNumber.textContent = Math.round(score);
    badgeRiskLevel.textContent = `${report.risk_level} (${score}/100)`;

    // Stroke dashoffset: 264 max length
    const offset = 264 - (264 * (score / 100));
    gaugeFill.style.strokeDashoffset = offset;

    if (score >= 80) {
      gaugeFill.style.stroke = 'var(--accent-red)';
      badgeRiskLevel.className = 'badge danger';
    } else if (score >= 40) {
      gaugeFill.style.stroke = 'var(--accent-amber)';
      badgeRiskLevel.className = 'badge';
    } else {
      gaugeFill.style.stroke = 'var(--accent-green)';
      badgeRiskLevel.className = 'badge success';
    }

    valProgression.textContent = report.timeline.length > 0 ? `${report.timeline.length * 20}%` : '0%';
    const totalBlastNodes = (report.actors_involved.length + report.devices_involved.length + report.ips_involved.length);
    valBlast.textContent = `${totalBlastNodes} Nodes`;

    // 3. Who Was Involved Pills
    const badgeEntityCount = document.getElementById('badge-entity-count');
    badgeEntityCount.textContent = `${totalBlastNodes} Entities`;

    renderPillList('pills-users', report.actors_involved, true);
    renderPillList('pills-hosts', report.devices_involved, true);
    renderPillList('pills-ips', report.ips_involved, false);
    renderPillList('pills-apps', report.apps_involved, false);

    // 4. Graph Visualizer
    graphViz.setData(report.graph_nodes, report.graph_edges);

    // 5. Timeline Storyline
    const emptyTimeline = document.getElementById('timeline-empty-state');
    if (report.timeline.length === 0) {
      emptyTimeline.style.display = 'flex';
      timelineCtrl.setStages([]);
    } else {
      emptyTimeline.style.display = 'none';
      timelineCtrl.setStages(report.timeline);
    }

    // Connect timeline stage click to graph highlight
    timelineCtrl.onStageSelect = (stage) => {
      // Find and select corresponding node if exists
      const targetNode = report.graph_nodes.find(n => n.label === stage.actor || n.label === stage.technique_name);
      if (targetNode) {
        graphViz.selectNode(targetNode);
      }
    };

    // 6. Evidence Proof Citations
    renderEvidenceProofs(report.timeline);

    // 7. Incident Response Mitigations
    renderMitigations(report.mitigations);
  }

  function renderPillList(containerId, items, isCompromised) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!items || items.length === 0) {
      container.innerHTML = '<span class="empty-hint">None</span>';
      return;
    }

    container.innerHTML = items.map(item => `
      <span class="pill-item ${isCompromised ? 'compromised' : ''}">${escapeHtml(item)}</span>
    `).join('');
  }

  function renderEvidenceProofs(stages) {
    const container = document.getElementById('evidence-table-container');
    const badgeProofs = document.getElementById('badge-verified-proofs');

    if (!stages || stages.length === 0) {
      container.innerHTML = '<p class="empty-hint-text">Clean operational baseline. No forensic proof citations generated.</p>';
      badgeProofs.textContent = '0 Proofs';
      return;
    }

    badgeProofs.textContent = `${stages.length} Verifiable Proofs`;
    let html = '';

    stages.forEach((stage, idx) => {
      const p = stage.proof;
      const confPct = Math.round(p.confidence * 100);

      html += `
        <div class="proof-card">
          <div class="proof-header">
            <span class="proof-id">${escapeHtml(p.evidence_id)} (Stage ${stage.stage_id})</span>
            <span class="proof-confidence-tag">Forensic Confidence: ${confPct}%</span>
          </div>
          <div class="proof-justification">
            <strong>Anomaly &amp; Heuristic Proof:</strong> ${escapeHtml(p.justification)}
          </div>
          <div class="proof-raw-box">${escapeHtml(p.raw_citation)}</div>
        </div>
      `;
    });

    container.innerHTML = html;
  }

  function renderMitigations(mitigations) {
    const container = document.getElementById('mitigation-actions-container');
    const badgeCount = document.getElementById('badge-actions-count');

    if (!mitigations || mitigations.length === 0) {
      container.innerHTML = '<p class="empty-hint-text">No active threats detected. No containment actions required.</p>';
      badgeCount.textContent = '0 Actions';
      return;
    }

    badgeCount.textContent = `${mitigations.length} Actions`;
    let html = '';

    mitigations.forEach(act => {
      const prioClass = act.priority.toLowerCase();
      html += `
        <div class="mitigation-card ${prioClass}">
          <div class="mitigation-header">
            <span class="mitigation-title">${escapeHtml(act.title)}</span>
            <span class="mitigation-priority ${prioClass}">${act.priority} [${act.category}]</span>
          </div>
          <p class="mitigation-desc">${escapeHtml(act.description)}</p>
          ${act.automated_command ? `
            <div class="command-box">
              <code class="command-code">${escapeHtml(act.automated_command)}</code>
              <button class="btn-copy" data-cmd="${escapeAttr(act.automated_command)}">Copy Command</button>
            </div>
          ` : ''}
        </div>
      `;
    });

    container.innerHTML = html;

    // Attach copy listeners
    container.querySelectorAll('.btn-copy').forEach(btn => {
      btn.addEventListener('click', () => {
        const cmd = btn.getAttribute('data-cmd');
        navigator.clipboard.writeText(cmd).then(() => {
          const original = btn.textContent;
          btn.textContent = 'COPIED!';
          btn.style.background = 'var(--accent-green)';
          btn.style.color = '#fff';
          setTimeout(() => {
            btn.textContent = original;
            btn.style.background = '';
            btn.style.color = '';
          }, 1500);
        });
      });
    });
  }

  // Benchmark Evaluation Suite Modal
  async function runBenchmarkSuite() {
    try {
      const res = await fetch('/api/benchmark');
      const data = await res.json();
      const m = data.summary_metrics;

      document.getElementById('m-precision').textContent = `${(m.precision * 100).toFixed(1)}%`;
      document.getElementById('m-recall').textContent = `${(m.recall * 100).toFixed(1)}%`;
      document.getElementById('m-fpr').textContent = `${(m.false_positive_rate * 100).toFixed(1)}%`;
      document.getElementById('m-f1').textContent = m.f1_score.toFixed(2);
      document.getElementById('m-evidence').textContent = `${m.evidence_citation_rate_pct.toFixed(1)}%`;
      document.getElementById('m-timeline').textContent = `${m.timeline_accuracy_pct.toFixed(1)}%`;

      const tbody = document.getElementById('tbody-benchmark');
      tbody.innerHTML = data.scenario_details.map(sc => `
        <tr>
          <td><strong>${escapeHtml(sc.scenario_name)}</strong></td>
          <td>${sc.log_count}</td>
          <td>${sc.expected_attack ? '<span style="color:#f43f5e">ATTACK</span>' : '<span style="color:#10b981">CLEAN</span>'}</td>
          <td>${sc.predicted_attack ? '<span style="color:#f43f5e">ATTACK</span>' : '<span style="color:#10b981">CLEAN</span>'}</td>
          <td><span class="badge ${sc.verdict_status.includes('TRUE') ? 'success' : 'danger'}">${sc.verdict_status}</span></td>
          <td>${sc.risk_score}/100</td>
        </tr>
      `).join('');

      modalBenchmark.classList.remove('hidden');
    } catch (err) {
      console.error('Benchmark suite error:', err);
      alert('Failed to run benchmark suite.');
    }
  }

  // Custom Log Submission
  async function submitCustomLogs() {
    const rawText = customLogInput.value.trim();
    if (!rawText) {
      alert('Please enter or paste JSON log records.');
      return;
    }

    try {
      const parsedLogs = JSON.parse(rawText);
      if (!Array.isArray(parsedLogs)) {
        alert('Input must be a JSON array of log records.');
        return;
      }

      btnSubmitCustomLogs.disabled = true;
      btnSubmitCustomLogs.textContent = 'Processing...';

      const res = await fetch('/api/analyze/custom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ logs: parsedLogs })
      });

      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      const report = await res.json();

      modalIngest.classList.add('hidden');
      renderIncidentReport(report);
    } catch (err) {
      console.error('Custom log parsing error:', err);
      alert('Invalid JSON format or analysis error: ' + err.message);
    } finally {
      btnSubmitCustomLogs.disabled = false;
      btnSubmitCustomLogs.innerHTML = '<span class="btn-icon">⚡</span> Analyze Custom Logs';
    }
  }

  // Helpers
  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function escapeAttr(str) {
    if (!str) return '';
    return String(str).replace(/"/g, '&quot;');
  }

  // Event Listeners
  btnRunAnalysis.addEventListener('click', analyzeSelectedDataset);
  datasetSelect.addEventListener('change', analyzeSelectedDataset);

  btnResetZoom.addEventListener('click', () => graphViz.resetView());
  btnToggleLabels.addEventListener('click', () => graphViz.toggleLabels());
  btnCloseInspector.addEventListener('click', () => {
    document.getElementById('node-inspector-flyout').classList.add('hidden');
  });

  btnReplayPlay.addEventListener('click', () => timelineCtrl.togglePlay());

  btnOpenEval.addEventListener('click', runBenchmarkSuite);
  btnRerunEval.addEventListener('click', runBenchmarkSuite);
  btnCloseEvalModal.addEventListener('click', () => modalBenchmark.classList.add('hidden'));
  btnDismissEval.addEventListener('click', () => modalBenchmark.classList.add('hidden'));

  btnOpenIngest.addEventListener('click', () => modalIngest.classList.remove('hidden'));
  btnCloseIngestModal.addEventListener('click', () => modalIngest.classList.add('hidden'));
  btnDismissIngest.addEventListener('click', () => modalIngest.classList.add('hidden'));
  btnSubmitCustomLogs.addEventListener('click', submitCustomLogs);

  // Load and bootstrap
  loadDatasets();
});
