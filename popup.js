/**
 * AI Endpoint Scanner — Popup Controller
 *
 * Manages the popup UI, communicates with the background service worker,
 * and renders scan results, probe findings, and reports.
 */

// ──────────────────────────────────────────────
//  DOM References
// ──────────────────────────────────────────────

const DOM = {
  statusDot: document.getElementById('status-dot'),
  statusText: document.getElementById('status-text'),
  scanUrl: document.getElementById('scan-url'),
  riskBadge: document.getElementById('risk-badge'),
  riskScore: document.querySelector('.risk-score'),
  riskLabel: document.querySelector('.risk-label'),
  btnScan: document.getElementById('btn-scan'),
  btnProbe: document.getElementById('btn-probe'),
  btnReport: document.getElementById('btn-report'),
  btnClear: document.getElementById('btn-clear'),
  endpointsCount: document.getElementById('endpoints-count'),
  widgetsCount: document.getElementById('widgets-count'),
  probesCount: document.getElementById('probes-count'),
  endpointsList: document.getElementById('endpoints-list'),
  endpointsEmpty: document.getElementById('endpoints-empty'),
  widgetsList: document.getElementById('widgets-list'),
  widgetsEmpty: document.getElementById('widgets-empty'),
  probesList: document.getElementById('probes-list'),
  probesEmpty: document.getElementById('probes-empty'),
  reportEmpty: document.getElementById('report-empty'),
  reportContainer: document.getElementById('report-container'),
  reportPreview: document.getElementById('report-preview'),
  reportFormat: document.getElementById('report-format'),
  btnDownloadReport: document.getElementById('btn-download-report'),
  btnCopyReport: document.getElementById('btn-copy-report'),
  btnExportRaw: document.getElementById('btn-export-raw'),
  footerInfo: document.getElementById('footer-info'),
};

// ──────────────────────────────────────────────
//  State
// ──────────────────────────────────────────────

let currentTabId = null;
let scanState = {
  status: 'none',
  endpoints: [],
  widgets: [],
  probeResults: [],
  detectedHeaders: [],
  leakedKeys: [],
  riskScore: 0,
  riskRating: { label: 'Minimal', color: '#22c55e' },
};
let currentReport = null;

// ──────────────────────────────────────────────
//  Initialization
// ──────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  setupTabNavigation();
  setupButtonHandlers();
  setupMessageListeners();

  // Get current tab
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
      currentTabId = tab.id;
      DOM.scanUrl.textContent = truncateUrl(tab.url, 45);
      DOM.scanUrl.title = tab.url;

      // Load existing scan state
      await refreshScanState();
    }
  } catch (e) {
    DOM.footerInfo.textContent = 'Error: Cannot access tab';
  }
});

// ──────────────────────────────────────────────
//  Tab Navigation
// ──────────────────────────────────────────────

function setupTabNavigation() {
  const tabs = document.querySelectorAll('.tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetPanel = tab.dataset.tab;

      // Update active tab
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      // Update active panel
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      document.getElementById(`panel-${targetPanel}`).classList.add('active');
    });
  });
}

// ──────────────────────────────────────────────
//  Button Handlers
// ──────────────────────────────────────────────

function setupButtonHandlers() {
  DOM.btnScan.addEventListener('click', handleScan);
  DOM.btnProbe.addEventListener('click', handleProbe);
  DOM.btnReport.addEventListener('click', handleReport);
  DOM.btnClear.addEventListener('click', handleClear);
  DOM.btnDownloadReport.addEventListener('click', handleDownloadReport);
  DOM.btnCopyReport.addEventListener('click', handleCopyReport);
  DOM.btnExportRaw.addEventListener('click', handleExportRaw);
}

async function handleScan() {
  if (!currentTabId) return;

  DOM.btnScan.disabled = true;
  updateStatus('scanning', 'Scanning...');

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'START_SCAN',
      tabId: currentTabId,
    });

    if (response && response.success) {
      updateStatus('scanning', 'Scanning in progress...');
      DOM.footerInfo.textContent = `Scan started: ${response.scanId}`;

      // Refresh state after a brief delay
      setTimeout(() => refreshScanState(), 1500);
    } else {
      updateStatus('error', 'Scan failed to start');
    }
  } catch (e) {
    updateStatus('error', 'Error starting scan');
  }

  DOM.btnScan.disabled = false;
}

async function handleProbe() {
  if (!currentTabId || scanState.endpoints.length === 0) return;

  DOM.btnProbe.disabled = true;
  updateStatus('probing', 'Running security probes...');

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'RUN_PROBES',
      tabId: currentTabId,
    });

    if (response && response.results) {
      scanState.probeResults = response.results;
      scanState.riskScore = response.riskScore || 0;
      scanState.riskRating = response.riskRating || { label: 'Minimal', color: '#22c55e' };

      updateRiskBadge();
      renderProbes();
      updateStatus('complete', `Probes complete — Risk: ${scanState.riskScore}/100`);

      // Enable report button
      DOM.btnReport.disabled = false;

      DOM.footerInfo.textContent = `${response.results.length} probes completed`;
    }
  } catch (e) {
    updateStatus('error', 'Error running probes');
  }

  DOM.btnProbe.disabled = false;
}

async function handleReport() {
  if (!currentTabId) return;

  const format = DOM.reportFormat.value;

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'GENERATE_REPORT',
      tabId: currentTabId,
      format,
    });

    if (response && response.content) {
      currentReport = response;

      // Switch to report tab
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelector('[data-tab="report"]').classList.add('active');
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      document.getElementById('panel-report').classList.add('active');

      // Show report
      DOM.reportEmpty.style.display = 'none';
      DOM.reportContainer.style.display = 'block';
      DOM.reportPreview.textContent = response.content;

      DOM.footerInfo.textContent = `Report generated (${format})`;
    } else if (response && response.error) {
      DOM.footerInfo.textContent = `Report error: ${response.error}`;
    }
  } catch (e) {
    DOM.footerInfo.textContent = 'Error generating report';
  }
}

async function handleClear() {
  if (!currentTabId) return;

  try {
    await chrome.runtime.sendMessage({
      type: 'CLEAR_SCAN',
      tabId: currentTabId,
    });

    // Reset UI
    scanState = {
      status: 'none',
      endpoints: [],
      widgets: [],
      probeResults: [],
      detectedHeaders: [],
      leakedKeys: [],
      riskScore: 0,
      riskRating: { label: 'Minimal', color: '#22c55e' },
    };
    currentReport = null;

    renderEndpoints();
    renderWidgets();
    renderProbes();
    updateRiskBadge();
    updateStatus('idle', 'Ready to scan');

    DOM.btnProbe.disabled = true;
    DOM.btnReport.disabled = true;
    DOM.reportEmpty.style.display = 'flex';
    DOM.reportContainer.style.display = 'none';

    DOM.footerInfo.textContent = 'Scan cleared';
  } catch (e) {
    DOM.footerInfo.textContent = 'Error clearing scan';
  }
}

function handleDownloadReport() {
  if (!currentReport) return;

  const format = currentReport.format;
  const content = currentReport.content;
  const ext = format === 'markdown' ? 'md' : format === 'html' ? 'html' : 'json';
  const mime = format === 'html' ? 'text/html' : format === 'json' ? 'application/json' : 'text/markdown';

  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ai-scan-report-${Date.now()}.${ext}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  DOM.footerInfo.textContent = `Report downloaded as .${ext}`;
}

async function handleCopyReport() {
  if (!currentReport) return;

  try {
    await navigator.clipboard.writeText(currentReport.content);
    DOM.footerInfo.textContent = 'Report copied to clipboard';
  } catch (e) {
    // Fallback
    const textarea = document.createElement('textarea');
    textarea.value = currentReport.content;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    DOM.footerInfo.textContent = 'Report copied to clipboard';
  }
}

async function handleExportRaw() {
  if (!currentTabId) return;

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'EXPORT_RAW',
      tabId: currentTabId,
    });

    if (response && response.data) {
      const content = JSON.stringify(response.data, null, 2);
      const blob = new Blob([content], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `ai-scan-raw-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      DOM.footerInfo.textContent = 'Raw data exported';
    }
  } catch (e) {
    DOM.footerInfo.textContent = 'Error exporting raw data';
  }
}

// ──────────────────────────────────────────────
//  Message Listeners (Real-time Updates)
// ──────────────────────────────────────────────

function setupMessageListeners() {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.tabId && message.tabId !== currentTabId) return;

    switch (message.type) {
      case 'ENDPOINT_FOUND':
        onEndpointFound(message.endpoint);
        break;

      case 'WIDGETS_UPDATED':
        scanState.widgets = message.widgets;
        renderWidgets();
        break;

      case 'KEYS_UPDATED':
        scanState.leakedKeys = message.leakedKeys;
        break;

      case 'PROBES_STARTED':
        updateStatus('probing', 'Running security probes...');
        break;

      case 'PROBES_COMPLETE':
        scanState.probeResults = message.results || [];
        scanState.riskScore = message.riskScore || 0;
        scanState.riskRating = message.riskRating || { label: 'Minimal', color: '#22c55e' };
        updateRiskBadge();
        renderProbes();
        updateStatus('complete', `Probes complete — Risk: ${scanState.riskScore}/100`);
        DOM.btnReport.disabled = false;
        break;
    }
  });
}

function onEndpointFound(endpoint) {
  // Avoid duplicates
  if (!scanState.endpoints.some(ep => ep.id === endpoint.id)) {
    scanState.endpoints.push(endpoint);
  }
  renderEndpoints();
  updateStatus('found', `${scanState.endpoints.length} endpoint(s) found`);

  // Enable probe button
  DOM.btnProbe.disabled = false;

  DOM.footerInfo.textContent = `New endpoint: ${endpoint.label}`;
}

// ──────────────────────────────────────────────
//  State Refresh
// ──────────────────────────────────────────────

async function refreshScanState() {
  if (!currentTabId) return;

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'GET_SCAN_STATE',
      tabId: currentTabId,
    });

    if (response) {
      scanState.status = response.status;
      scanState.endpoints = response.endpoints || [];
      scanState.widgets = response.widgets || [];
      scanState.probeResults = response.probeResults || [];
      scanState.detectedHeaders = response.detectedHeaders || [];
      scanState.leakedKeys = response.leakedKeys || [];

      // Calculate risk
      if (scanState.endpoints.length > 0 || scanState.probeResults.length > 0) {
        const riskResult = calculateRiskFromState(scanState);
        scanState.riskScore = riskResult.score;
        scanState.riskRating = riskResult.rating;
      }

      updateUI();
    }
  } catch (e) {
    // Background might not be ready
  }
}

function updateUI() {
  renderEndpoints();
  renderWidgets();
  renderProbes();
  updateRiskBadge();

  // Update status
  if (scanState.endpoints.length > 0) {
    updateStatus('found', `${scanState.endpoints.length} endpoint(s) found`);
    DOM.btnProbe.disabled = scanState.endpoints.length === 0;
  }

  if (scanState.probeResults.length > 0) {
    DOM.btnReport.disabled = false;
  }

  // If there's a report in state, show it
  if (scanState.probeResults.length > 0) {
    updateStatus('complete', `Scan complete — Risk: ${scanState.riskScore}/100`);
  }
}

// ──────────────────────────────────────────────
//  Rendering
// ──────────────────────────────────────────────

function renderEndpoints() {
  const count = scanState.endpoints.length;
  DOM.endpointsCount.textContent = count;

  if (count === 0) {
    DOM.endpointsEmpty.style.display = 'flex';
    DOM.endpointsList.style.display = 'none';
    return;
  }

  DOM.endpointsEmpty.style.display = 'none';
  DOM.endpointsList.style.display = 'block';

  // Group by type
  const grouped = {};
  for (const ep of scanState.endpoints) {
    const key = ep.label || ep.type || 'Unknown';
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(ep);
  }

  let html = '';
  for (const [group, endpoints] of Object.entries(grouped)) {
    for (const ep of endpoints) {
      const methodClass = (ep.method || 'GET').toLowerCase();
      const url = truncateUrl(ep.url, 70);
      const headersHtml = (ep.headers || []).map(h =>
        `<span class="endpoint-header-item"><span class="key">${escapeHtml(h.name)}:</span> <span class="value">${escapeHtml(h.value)}</span></span>`
      ).join(' ');

      html += `
        <div class="endpoint-card">
          <div class="endpoint-header">
            <span class="method-badge ${methodClass}">${escapeHtml(ep.method || 'GET')}</span>
            <span class="type-badge">${escapeHtml(group)}</span>
          </div>
          <div class="endpoint-url">${escapeHtml(url)}</div>
          ${headersHtml ? `<div class="endpoint-meta">${headersHtml}</div>` : ''}
          ${ep.hitCount > 1 ? `<div class="endpoint-meta"><span>Hit count: ${ep.hitCount}</span></div>` : ''}
        </div>
      `;
    }
  }

  DOM.endpointsList.innerHTML = html;
}

function renderWidgets() {
  const count = scanState.widgets.length;
  DOM.widgetsCount.textContent = count;

  if (count === 0) {
    DOM.widgetsEmpty.style.display = 'flex';
    DOM.widgetsList.style.display = 'none';
    return;
  }

  DOM.widgetsEmpty.style.display = 'none';
  DOM.widgetsList.style.display = 'block';

  let html = '';
  for (const w of scanState.widgets) {
    const visibleClass = w.visible ? 'visible' : 'hidden';
    const visibleText = w.visible ? 'Visible' : 'Hidden';

    html += `
      <div class="widget-card">
        <div class="widget-header">
          <span class="widget-provider">${escapeHtml(w.provider || 'Unknown')}</span>
          <span class="widget-type-badge">${escapeHtml(w.type || 'widget')}</span>
        </div>
        ${w.src ? `<div class="widget-detail">${escapeHtml(truncateUrl(w.src, 60))}</div>` : ''}
        ${w.selector ? `<div class="widget-selector">${escapeHtml(truncateSelector(w.selector, 60))}</div>` : ''}
        <div class="widget-visible ${visibleClass}">${visibleText}</div>
      </div>
    `;
  }

  DOM.widgetsList.innerHTML = html;
}

function renderProbes() {
  const count = scanState.probeResults.length;
  DOM.probesCount.textContent = count;

  if (count === 0) {
    DOM.probesEmpty.style.display = 'flex';
    DOM.probesList.style.display = 'none';
    return;
  }

  DOM.probesEmpty.style.display = 'none';
  DOM.probesList.style.display = 'block';

  let html = '';
  for (const pr of scanState.probeResults) {
    const vulnClass = pr.vulnerable ? 'vulnerable' : (pr.error ? 'error' : 'safe');
    const statusClass = pr.vulnerable ? 'vulnerable' : (pr.error ? 'error' : 'safe');
    const statusText = pr.vulnerable ? 'VULNERABLE' : (pr.error ? 'ERROR' : 'SAFE');

    html += `
      <div class="probe-card ${vulnClass}">
        <div class="probe-header">
          <span class="probe-label">${escapeHtml(pr.label || pr.category || 'Unknown')}</span>
          <span class="probe-status ${statusClass}">${statusText}</span>
        </div>
        <div class="probe-endpoint">${escapeHtml(truncateUrl(pr.endpointUrl || '', 70))}</div>
        <div class="probe-analysis">${escapeHtml(pr.analysis || pr.error || 'No analysis available')}</div>
        ${pr.category ? `<div class="probe-category">Category: ${escapeHtml(pr.category)}</div>` : ''}
        ${pr.httpStatus ? `<div class="probe-category">HTTP Status: ${pr.httpStatus}</div>` : ''}
      </div>
    `;
  }

  DOM.probesList.innerHTML = html;
}

// ──────────────────────────────────────────────
//  UI Helpers
// ──────────────────────────────────────────────

function updateStatus(status, text) {
  DOM.statusDot.className = `status-dot ${status}`;
  DOM.statusText.textContent = text;
}

function updateRiskBadge() {
  const score = scanState.riskScore;
  const rating = scanState.riskRating;

  DOM.riskScore.textContent = score;
  DOM.riskLabel.textContent = rating.label;

  // Update badge class
  DOM.riskBadge.className = 'risk-badge';
  if (score >= 80) DOM.riskBadge.classList.add('critical');
  else if (score >= 60) DOM.riskBadge.classList.add('high');
  else if (score >= 40) DOM.riskBadge.classList.add('medium');
  else if (score >= 20) DOM.riskBadge.classList.add('low');
  else DOM.riskBadge.classList.add('minimal');
}

/**
 * Local risk calculation (mirrors utils.js for popup context).
 */
function calculateRiskFromState(state) {
  let score = 0;

  // Endpoints
  const typeWeight = { openai: 12, anthropic: 12, google: 10, cohere: 10, generic: 8, streaming: 6, widget: 5 };
  for (const ep of (state.endpoints || [])) {
    score += typeWeight[ep.type] || 5;
  }

  // Headers
  score += (state.detectedHeaders || []).length * 3;

  // Key leaks
  score += Math.min((state.leakedKeys || []).length * 25, 50);

  // Widgets
  score += (state.widgets || []).length * 2;

  // Probe results
  const probeWeights = { 'info-disclosure': 8, 'injection': 12, 'jailbreak': 15, 'filter-evasion': 10 };
  for (const pr of (state.probeResults || [])) {
    if (pr.vulnerable && probeWeights[pr.category]) {
      score += probeWeights[pr.category];
    }
  }

  score = Math.min(Math.max(Math.round(score), 0), 100);

  let rating;
  if (score >= 80) rating = { label: 'Critical', color: '#dc2626' };
  else if (score >= 60) rating = { label: 'High', color: '#ea580c' };
  else if (score >= 40) rating = { label: 'Medium', color: '#ca8a04' };
  else if (score >= 20) rating = { label: 'Low', color: '#16a34a' };
  else rating = { label: 'Minimal', color: '#22c55e' };

  return { score, rating };
}

function truncateUrl(url, maxLen = 50) {
  if (!url) return '';
  try {
    const u = new URL(url);
    const display = u.hostname + u.pathname + u.search;
    if (display.length <= maxLen) return display;
    return display.substring(0, maxLen - 3) + '...';
  } catch {
    if (url.length <= maxLen) return url;
    return url.substring(0, maxLen - 3) + '...';
  }
}

function truncateSelector(selector, maxLen = 50) {
  if (!selector) return '';
  if (selector.length <= maxLen) return selector;
  return selector.substring(0, maxLen - 3) + '...';
}

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
