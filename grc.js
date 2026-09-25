const controlSets = {
  'ISO/IEC 27001': [
    ['Context and interested parties', 'Define the ISMS scope, internal context, external obligations, and interested-party requirements.', 'Scope statement, interested-party register, and management review record.'],
    ['Information security risk assessment', 'Maintain a repeatable method to identify, analyze, evaluate, and prioritize information-security risks.', 'Risk methodology, current risk register, and treatment decisions.'],
    ['Information security policy', 'Approve, communicate, and periodically review a policy that establishes information-security direction.', 'Signed policy, publication record, and review history.'],
    ['Asset ownership and inventory', 'Maintain ownership, classification, and lifecycle information for information assets.', 'Asset inventory, owner assignments, and classification rules.'],
    ['Access control lifecycle', 'Authorize least-privilege access and remove or change access when roles change.', 'Access requests, approval evidence, joiner-mover-leaver samples.'],
    ['Incident management and lessons learned', 'Provide a tested process to detect, report, respond to, and learn from security incidents.', 'Incident register, response runbook, exercise results, and post-incident review.'],
  ],
  'PCI DSS': [
    ['Cardholder-data inventory and flow', 'Document where account data enters, is processed, stored, transmitted, and deleted.', 'Data-flow diagram, scope statement, and retention schedule.'],
    ['Network security controls', 'Use documented network controls to isolate and protect systems in the cardholder-data environment.', 'Firewall rules, segmentation test, and rule review record.'],
    ['Secure configuration and vulnerability management', 'Harden systems and address vulnerabilities according to risk-based timelines.', 'Configuration baseline, scan reports, remediation tickets, and exceptions.'],
    ['Strong access authentication', 'Use unique identities, strong authentication, and controlled privileged access for in-scope systems.', 'Identity configuration, MFA evidence, and privileged-access review.'],
    ['Logging and monitoring', 'Capture, protect, review, and retain security events that can identify suspicious activity.', 'Central log samples, alert rules, review logs, and retention settings.'],
    ['Security testing and incident response', 'Test security controls and maintain a response plan for suspected account-data compromise.', 'Penetration test, segmentation validation, response plan, and exercise record.'],
  ],
  'DPDP Act': [
    ['Lawful notice and consent', 'Explain purposes and processing practices in clear language and capture valid, specific consent where required.', 'Privacy notice versions, consent records, and withdrawal workflow.'],
    ['Purpose limitation and minimization', 'Collect only data needed for declared purposes and prevent incompatible reuse.', 'Data inventory, purpose register, and collection-field review.'],
    ['Data principal rights', 'Provide practical channels for access, correction, erasure, grievance, and nomination requests.', 'Request procedure, ticket samples, SLAs, and grievance register.'],
    ['Processor and third-party governance', 'Control processors through contracts, due diligence, instructions, and ongoing oversight.', 'Processor register, agreements, due-diligence reviews, and subprocessor list.'],
    ['Children and consent safeguards', 'Identify child data and apply parental-consent and prohibited-tracking safeguards where applicable.', 'Age-assurance design, consent evidence, and child-data handling procedure.'],
    ['Breach response and retention', 'Detect, contain, document, and notify personal-data breaches while enforcing retention and deletion rules.', 'Incident playbook, notification decision log, retention schedule, and deletion evidence.'],
  ],
  'SOC 2': [
    ['Security governance', 'Assign security responsibilities and communicate policies, objectives, and accountability.', 'Policy set, org chart, role descriptions, and review minutes.'],
    ['Logical access', 'Provision, review, and revoke access based on job responsibility and least privilege.', 'Access review samples, approvals, and termination evidence.'],
    ['Change management', 'Authorize, test, approve, and deploy changes through a controlled lifecycle.', 'Change tickets, test results, approvals, and deployment logs.'],
    ['Risk and vendor management', 'Assess risks and service providers and track mitigations to completion.', 'Risk register, vendor reviews, contracts, and remediation plans.'],
    ['Monitoring and incident response', 'Monitor controls, investigate deviations, and respond to incidents within defined responsibilities.', 'Monitoring alerts, incident tickets, exercises, and corrective actions.'],
    ['Availability and confidentiality', 'Protect service availability and confidential information through resilience and data-handling controls.', 'Continuity tests, backup restores, encryption evidence, and data classification.'],
  ],
  'NIST CSF': [
    ['Govern: cybersecurity strategy', 'Establish policy, roles, oversight, and risk appetite for cybersecurity decisions.', 'Strategy, governance charter, roles matrix, and risk appetite statement.'],
    ['Identify: asset and risk context', 'Understand assets, suppliers, vulnerabilities, threats, and business impact.', 'Asset inventory, dependency map, risk assessment, and criticality ratings.'],
    ['Protect: identity and safeguards', 'Apply access, training, data security, platform security, and technology safeguards.', 'Access reviews, training records, standards, and control configuration.'],
    ['Detect: continuous monitoring', 'Detect anomalies, events, and indicators through monitoring and analysis.', 'Detection use cases, alert samples, triage process, and metrics.'],
    ['Respond: incident coordination', 'Contain, analyze, communicate, and mitigate cybersecurity incidents.', 'Response plan, communications matrix, incident records, and exercises.'],
    ['Recover: restoration and improvement', 'Restore capabilities, communicate recovery status, and incorporate lessons learned.', 'Recovery plan, restore tests, stakeholder updates, and improvement backlog.'],
  ],
  'ISO/IEC 42001': [
    ['AI management-system scope', 'Define the AI management-system boundaries, intended outcomes, and affected interested parties.', 'AIMS scope, system inventory, context analysis, and stakeholder register.'],
    ['AI policy and accountability', 'Set responsible-AI principles, leadership accountability, and decision rights across the AI lifecycle.', 'AI policy, governance charter, RACI, and management approvals.'],
    ['AI risk and impact assessment', 'Identify, assess, treat, and monitor risks and impacts to people, organizations, and society.', 'AI risk register, impact assessments, treatment plans, and review records.'],
    ['AI data governance', 'Control data quality, provenance, suitability, privacy, and lifecycle use for AI systems.', 'Dataset cards, lineage, quality checks, consent basis, and retention rules.'],
    ['AI lifecycle and supplier controls', 'Apply requirements for design, development, deployment, monitoring, change, and external providers.', 'Lifecycle gates, testing results, supplier assessments, and release approvals.'],
    ['AI incident and performance monitoring', 'Monitor AI performance and incidents, investigate harms, and drive corrective action.', 'Performance logs, incident register, monitoring thresholds, and corrective actions.'],
  ],
};

const frameworks = [
  { name: 'ISO/IEC 27001', version: 'ISO 27001:2022', category: 'Information Security', region: 'International', description: 'Build and certify an information security management system (ISMS): scope, risk treatment and the 93 Annex A controls, run as a cycle of continual improvement.' },
  { name: 'PCI DSS', version: 'PCI DSS v4.0', category: 'Payments Security', region: 'Global (card brands)', description: 'Required wherever card data is stored, processed or transmitted. Covers network security, access, vulnerability management, monitoring and testing across 12 requirements.' },
  { name: 'DPDP Act', version: 'DPDP Act, 2023', category: 'Data Privacy', region: 'India', description: 'India\u2019s Digital Personal Data Protection Act. Sets out how Data Fiduciaries collect and use personal data with consent, and the rights every Data Principal holds.' },
  { name: 'SOC 2', version: 'SOC 2 (TSC 2017)', category: 'Service Assurance', region: 'US / Global', description: 'An independent CPA attestation that shows customers how your service protects their data, measured against the Trust Services Criteria.' },
  { name: 'NIST CSF', version: 'NIST CSF 2.0', category: 'Cyber Risk Management', region: 'US / Global', description: 'A flexible, outcome-based way to understand and reduce cyber risk across six Functions: Govern, Identify, Protect, Detect, Respond and Recover.' },
  { name: 'ISO/IEC 42001', version: 'ISO 42001:2023', category: 'AI Governance', region: 'International', description: 'The certifiable management-system standard for AI. Puts governance, risk assessment and lifecycle controls around the AI systems you build, supply or use.' },
];

const scanAreas = [
  ['Consent & cookies', 'What loads before a choice, and whether the banner\u2019s Reject and Accept really work.'],
  ['Privacy notice', 'Is there a notice, and does it name the data, the purposes, withdrawal and how to complain.'],
  ['Data principal rights', 'Access, correction and erasure, grievances, and the right to nominate.'],
  ['Data handling & sharing', 'How long data is kept, who it is shared with, and trackers the notice never names.'],
  ["Children's data", 'Verifiable parental consent, and no tracking or targeted ads for under-18s.'],
  ['Governance & security', 'A named privacy contact, HTTPS and security headers.'],
];

const dpdpControls = [
  { id: 'DPDP-NOTICE-001', area: 'Privacy notice', title: 'Privacy notice linked from homepage', severity: 'high', test: 'A privacy notice link is available before a visitor submits personal data.', legal: 'DPDP Act 2023, section 5; DPDP Rules 2025, Rule 3', fix: 'Publish a clear privacy notice and link it from the homepage, forms, and collection points.' },
  { id: 'DPDP-NOTICE-002', area: 'Privacy notice', title: 'Notice content covers purposes and data', severity: 'high', test: 'The linked notice identifies data categories and each processing purpose.', legal: 'DPDP Act 2023, section 5', fix: 'Describe the personal-data categories collected and the purpose for each use.' },
  { id: 'DPDP-CONSENT-001', area: 'Consent & cookies', title: 'Consent interface is discoverable', severity: 'high', test: 'A visible consent interface is presented before optional processing.' },
  { id: 'DPDP-CONSENT-002', area: 'Consent & cookies', title: 'Non-essential processing waits for consent', severity: 'high', test: 'Tracker requests and non-essential cookies are absent before a choice.' },
  { id: 'DPDP-CONSENT-003', area: 'Consent & cookies', title: 'Reject or decline choice is available', severity: 'high', test: 'A visitor can decline optional processing at the first layer.' },
  { id: 'DPDP-CONSENT-004', area: 'Consent & cookies', title: 'Withdrawal remains available', severity: 'medium', test: 'A visitor can later change or withdraw an optional consent choice.' },
  { id: 'DPDP-RIGHTS-001', area: 'Data principal rights', title: 'Rights request channel is published', severity: 'medium', test: 'The site identifies a practical channel for access, correction, erasure, or grievance requests.' },
  { id: 'DPDP-SHARING-001', area: 'Data handling & sharing', title: 'Processor and third-party disclosure', severity: 'medium', test: 'The notice explains relevant processors, sharing purposes, or service providers.' },
  { id: 'DPDP-SHARING-002', area: 'Data handling & sharing', title: 'Retention and deletion information', severity: 'medium', test: 'The site explains retention criteria or deletion practices.' },
  { id: 'DPDP-CHILDREN-001', area: "Children's data", title: 'Children and parental-consent safeguards', severity: 'high', test: 'The site addresses child-data handling and parental-consent safeguards where applicable.' },
  { id: 'DPDP-SECURITY-001', area: 'Governance & security', title: 'HTTPS transport', severity: 'high', test: 'The target is served over HTTPS.' },
  { id: 'DPDP-SECURITY-002', area: 'Governance & security', title: 'Security response headers', severity: 'low', test: 'Recommended security headers are present on the initial response.' },
  { id: 'DPDP-SECURITY-003', area: 'Governance & security', title: 'Breach and privacy contact information', severity: 'medium', test: 'The public notice identifies a privacy or grievance contact and relevant incident information.' },
];

const templates = [
  ['Access Control Policy', 'ISO 27001:2022 · SOC 2 (TSC 2017)', 'Policy'],
  ['Access review procedure', 'NIST CSF 2.0', 'Procedure'],
  ['AI acceptable use policy', 'ISO 42001:2023', 'Policy'],
  ['AI data governance standard', 'ISO 42001:2023', 'Policy'],
  ['AI incident response procedure', 'ISO 42001:2023', 'Procedure'],
  ['AI risk assessment procedure', 'ISO 42001:2023', 'Procedure'],
  ['Business continuity plan', 'ISO 27001:2022 · SOC 2', 'Plan'],
  ['Incident response plan', 'ISO 27001:2022 · NIST CSF 2.0', 'Plan'],
  ['Privacy notice', 'DPDP Act, 2023', 'Notice'],
  ['Supplier security questionnaire', 'ISO 27001:2022 · PCI DSS v4.0', 'Questionnaire'],
];

const storageKey = 'hypensec-astra-state';
const state = JSON.parse(localStorage.getItem(storageKey) || '{"assessments":{},"checklists":{},"scans":[]}');
const main = document.querySelector('#main-content');
const toast = document.querySelector('#toast');
let toastTimer;
let activeScanTarget = null;

function save() { localStorage.setItem(storageKey, JSON.stringify(state)); }
function showToast(message) {
  toast.textContent = message; toast.classList.add('show'); clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 3000);
}
function esc(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[char]));
}
function frameworkByName(name) { return frameworks.find((item) => item.name === name); }
function controlsFor(item) { return controlSets[item.name] || []; }
function assessment(name) { return state.assessments[name] || {}; }
function score(name) {
  const values = Object.values(assessment(name));
  return values.length ? Math.round(values.reduce((sum, value) => sum + Number(value), 0) / values.length * 25) : 0;
}

function greeting() {
  const hour = new Date().getHours();
  return hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening';
}

function dashboard() {
  main.innerHTML = `
    <section class="hero"><div class="eyebrow">Compliance readiness</div><h1>${greeting()}</h1><p>See where you stand on six security and privacy frameworks in minutes. Your answers stay in this browser until you export them as a plan, policies or evidence checklists.</p></section>
    <section class="promo"><div class="promo-art" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12l6.4-6.4"/><circle cx="16" cy="9" r="1" fill="currentColor"/></svg></div><div><strong>DPDPA website scan</strong><span>We visit your site as a new visitor, click Reject and Accept, read your privacy notice, and show proof for every gap.</span></div><button class="button button-primary" data-view-target="scan">Start a scan <span>→</span></button></section>
    <section class="overview"><div class="health-card"><span class="label">Overall health</span><div class="health-score">${Object.keys(state.assessments).length ? '✓' : '–'} <span>${Object.keys(state.assessments).length ? 'in progress' : 'not started'}</span></div><strong>${Object.keys(state.assessments).length ? 'In progress' : 'Not started'}</strong><small>Across ${Object.keys(state.assessments).length} started frameworks</small></div><div class="metrics"><div><span>Frameworks started</span><strong>${Object.keys(state.assessments).length}/6</strong><small>assessment coverage</small></div><div><span>Controls assessed</span><strong>${Object.values(state.assessments).reduce((sum, item) => sum + Object.keys(item).length, 0)}</strong><small>across all frameworks</small></div><div><span>Open gaps</span><strong>${Object.values(state.assessments).reduce((sum, item) => sum + Object.values(item).filter((value) => value < 3).length, 0)}</strong><small>controls below target</small></div><div><span>Critical gaps</span><strong>${Object.values(state.assessments).reduce((sum, item) => sum + Object.values(item).filter((value) => value === 1).length, 0)}</strong><small>need immediate action</small></div></div></section>
    <section class="framework-section"><div class="section-heading"><h2>Frameworks</h2><button class="text-button" data-view-target="frameworks">Browse all <span>→</span></button></div><div id="framework-grid" class="framework-grid">${frameworks.map(frameworkCard).join('')}</div></section>`;
}

function frameworkCard(item) {
  const done = Object.keys(assessment(item.name)).length;
  const total = controlsFor(item).length;
  return `<article class="framework-card"><div class="card-top"><div><h3>${esc(item.name)}</h3><div class="meta">${esc(item.version)}</div></div><span class="status">${done ? `${score(item.name)}% complete` : 'Not started'}</span></div><p class="description">${esc(item.description)}</p><div class="progress" aria-label="${done} of ${total} controls complete"><i style="width:${done / total * 100}%"></i></div><div class="progress-meta"><span>${done ? `${score(item.name)}%` : '—'}</span><span>${done}/${total} controls</span></div><button class="outline-button" data-assess="${esc(item.name)}">${done ? 'Continue assessment →' : 'Start assessment →'}</button></article>`;
}

function frameworksView() {
  main.innerHTML = `<section class="hero"><div class="eyebrow">Framework library</div><h1>Frameworks</h1><p>Six frameworks, one method. Open any of them to see what it covers, browse the controls and score your gaps.</p></section><div class="search-row"><input id="framework-search" type="search" placeholder="Try ‘privacy’, ‘AI’, ‘India’ or ‘PCI’" /></div><div id="framework-library" class="library-list">${frameworks.map(libraryCard).join('')}</div>`;
  document.querySelector('#framework-search').addEventListener('input', (event) => {
    const query = event.target.value.toLowerCase();
    document.querySelector('#framework-library').innerHTML = frameworks.filter((item) => `${item.name} ${item.category} ${item.region}`.toLowerCase().includes(query)).map(libraryCard).join('') || '<div class="empty-state">No frameworks match that search.</div>';
  });
}
function libraryCard(item) { return `<article class="library-card"><div><div class="card-top"><div><h3>${esc(item.name)}</h3><div class="meta">${esc(item.version)} · ${esc(item.region)}</div></div><span class="category">${esc(item.category)}</span></div><p>${esc(item.description)}</p><div class="library-meta">${controlsFor(item).length} representative controls · ${Object.keys(assessment(item.name)).length ? `${score(item.name)}% assessed` : 'Not started'}</div></div><button class="outline-button" data-assess="${esc(item.name)}">Open assessment →</button></article>`; }

function assessmentView(name) {
  const item = frameworkByName(name); const current = assessment(name);
  const controls = controlsFor(item);
  main.innerHTML = `<section class="hero"><button class="back-button" data-view-target="frameworks">← Framework library</button><div class="eyebrow">${esc(item.category)} · ${esc(item.region)}</div><h1>${esc(item.name)}</h1><p>${esc(item.description)} Your responses are saved only on this device.</p></section><div class="assessment-head"><div><strong>${Object.keys(current).length}/${controls.length} controls assessed</strong><span>Use the maturity scale to identify gaps. These are representative implementation checks, not verbatim standard text.</span></div><strong class="assessment-score">${score(name)}%</strong></div><section class="control-list">${controls.map((control, index) => `<article class="control-card"><div><span class="control-id">CONTROL ${String(index + 1).padStart(2, '0')} · ${esc(item.name)}</span><h3>${esc(control[0])}</h3><p>${esc(control[1])}</p><div class="evidence-hint"><b>Evidence:</b> ${esc(control[2])}</div></div><div class="maturity" role="group" aria-label="Maturity for ${esc(control[0])}">${[['1','Gap'],['2','Partial'],['3','Implemented'],['4','Optimized']].map(([value, label]) => `<button class="${current[index] == value ? 'selected' : ''}" data-control="${index}" data-value="${value}">${value}<small>${label}</small></button>`).join('')}</div></article>`).join('')}</section><div class="report-actions"><button class="button button-primary" data-report="${esc(name)}">Download assessment report</button></div>`;
}

function scanView() {
  main.innerHTML = `<section class="hero"><div class="eyebrow">Website scan · DPDP Act, 2023</div><h1>Check a website against the <span class="grad">DPDP Act</span></h1><p>Load your site in a clean browser as a first-time visitor, record every tracker and cookie before consent, then reject and accept to test whether your banner is honoured. This is an automated readiness check, not a legal opinion or audit.</p></section><section class="scan-layout"><div class="scan-panel"><label for="scan-url">Website address</label><div class="scan-form"><input id="scan-url" type="url" placeholder="yourcompany.com" /><button class="button button-primary" id="run-scan">Scan →</button></div><label class="attest"><input type="checkbox" id="scan-authorised" /><span>I own this website or am authorised by its owner to test it, and I accept the <a href="terms.html" target="_blank" rel="noopener">Terms of Use</a>.</span></label><div class="access-row" id="access-row" hidden><label for="access-key">Access key</label><div class="scan-form"><input id="access-key" type="password" autocomplete="off" placeholder="Paste your HypenSec access key" /><button class="outline-button" id="save-key" type="button">Save key</button></div><small></small></div><small>Reports stay in this browser. See our <a href="privacy.html" target="_blank" rel="noopener">privacy notice</a>.</small><div id="scan-result"></div></div><aside class="scan-summary"><div class="label">Scan summary</div><p><span>Target</span><strong id="scan-target">—</strong></p><p><span>Framework</span><strong>DPDP Act, 2023 & Rules, 2025</strong></p><p><span>Method</span><strong>Clean browser: before consent, after Reject, after Accept, plus privacy notice analysis</strong></p><p><span>Takes about</span><strong>30–90 seconds</strong></p></aside></section><section class="checks"><div class="section-heading"><h2>Areas to check</h2><div><button class="text-button" id="select-all">Select all</button> · <button class="text-button" id="clear-checks">Clear</button></div></div><div class="check-grid">${scanAreas.map(([title, text], index) => `<label class="check-option"><input type="checkbox" checked data-scan-check="${index}" /><span><strong>${title}</strong><small>${text}</small></span></label>`).join('')}</div></section>`;
  document.querySelector('#run-scan').addEventListener('click', runScan);
  document.querySelector('#save-key').addEventListener('click', () => {
    const value = document.querySelector('#access-key').value.trim();
    if (value.length < 16) { showToast('That access key looks too short.'); return; }
    saveAccessKey(value);
    document.querySelector('#access-row').hidden = true;
    showToast('Access key saved in this browser.');
  });
  document.querySelector('#select-all').addEventListener('click', () => document.querySelectorAll('[data-scan-check]').forEach((input) => { input.checked = true; }));
  document.querySelector('#clear-checks').addEventListener('click', () => document.querySelectorAll('[data-scan-check]').forEach((input) => { input.checked = false; }));
}

// The website scan runs in scanner-service/ (headless Chromium). Override the address by
// setting window.ASTRA_SCANNER_URL before this script loads.
const SCANNER_URL = globalThis.ASTRA_SCANNER_URL || (/^https?:$/.test(location.protocol) ? location.origin : 'http://localhost:8787');
const ACCESS_KEY_STORE = 'hypensec-astra-access-key';

// The access key stays in this browser only. Storage can be unavailable (private mode), so every access is guarded.
function accessKey() { try { return localStorage.getItem(ACCESS_KEY_STORE) || ''; } catch { return ''; } }
function saveAccessKey(value) { try { localStorage.setItem(ACCESS_KEY_STORE, value); } catch { /* not persisted */ } }
function apiHeaders() {
  const key = accessKey();
  return { 'Content-Type': 'application/json', ...(key ? { 'X-Access-Key': key } : {}) };
}
function showAccessKeyRow(message) {
  const row = document.querySelector('#access-row');
  if (!row) return;
  row.hidden = false;
  row.querySelector('small').textContent = message || 'Enter the access key HypenSec gave you. It is kept only in this browser.';
  row.querySelector('input').focus();
}
const CHECK_WEIGHT = { High: 3, Medium: 2, Low: 1 };
const STATUS_LABEL = { fail: 'Failed', review: 'Needs review', 'not-evaluated': 'Not tested', pass: 'Passed' };
// Screenshots are too large for localStorage, so they live only for this session.
const scanScreenshots = new Map();

const COVERAGE_LABEL = { full: 'Full coverage', partial: 'Partial coverage', limited: 'Limited coverage' };

function coverageOf(checks) {
  const total = checks.length;
  const tested = checks.filter((check) => check.status === 'pass' || check.status === 'fail').length;
  const untested = checks.filter((check) => check.status === 'not-evaluated');
  const percent = total ? Math.round((tested / total) * 100) : 0;
  const level = percent >= 80 ? 'full' : percent >= 50 ? 'partial' : 'limited';
  const grouped = new Map();
  untested.forEach((check) => {
    const reason = String(check.detail || '').replace(/^Not tested:\s*/i, '').trim() || 'The scanner could not run this check.';
    grouped.set(reason, (grouped.get(reason) || 0) + 1);
  });
  const reasons = [...grouped].map(([reason, n]) => ({ reason, count: n })).sort((a, b) => b.count - a.count);
  const byArea = scanAreas.map(([area]) => {
    const inArea = checks.filter((check) => check.area === area);
    return { area, total: inArea.length, tested: inArea.filter((check) => check.status === 'pass' || check.status === 'fail').length, failed: inArea.filter((check) => check.status === 'fail').length };
  }).filter((entry) => entry.total);
  return { tested, total, percent, level, reasons, byArea };
}

function coverageLine(coverage) {
  return `${coverage.tested} of ${coverage.total} checks tested · ${COVERAGE_LABEL[coverage.level]}`;
}

function scoreChecks(checks) {
  const tested = checks.filter((check) => check.status === 'pass' || check.status === 'fail');
  const possible = tested.reduce((sum, check) => sum + CHECK_WEIGHT[check.severity], 0);
  const earned = tested.filter((check) => check.status === 'pass').reduce((sum, check) => sum + CHECK_WEIGHT[check.severity], 0);
  return possible ? Math.round((earned / possible) * 100) : null;
}

async function runScan() {
  const input = document.querySelector('#scan-url'); const url = input.value.trim();
  if (!url) { showToast('Enter a website address first.'); input.focus(); return; }
  const target = /^https?:\/\//i.test(url) ? url : `https://${url}`;
  const selectedAreas = [...document.querySelectorAll('[data-scan-check]:checked')].map((box) => scanAreas[Number(box.dataset.scanCheck)][0]);
  if (!selectedAreas.length) { showToast('Select at least one area to check.'); return; }
  if (!document.querySelector('#scan-authorised').checked) { showToast('Confirm you own this website or are authorised to test it.'); document.querySelector('#scan-authorised').focus(); return; }
  const scanButton = document.querySelector('#run-scan');
  const result = document.querySelector('#scan-result');
  document.querySelector('#scan-target').textContent = target;
  scanButton.disabled = true;
  scanButton.textContent = 'Scanning…';
  result.innerHTML = '<div class="scan-progress"><span>Loading the site in a clean browser, recording trackers and cookies before consent, then rejecting and accepting. This takes 30–90 seconds.</span><i class="indeterminate"></i></div>';

  try {
    const response = await fetch(`${SCANNER_URL}/scan`, { method: 'POST', headers: apiHeaders(), body: JSON.stringify({ url: target, authorised: true }) });
    const data = await response.json().catch(() => ({}));
    if (response.status === 401) showAccessKeyRow(data.error);
    if (!response.ok) throw new Error(data.error || `The scanner returned HTTP ${response.status}.`);
    const { screenshots, ...report } = data;
    report.target = target;
    report.checks = report.checks.filter((check) => selectedAreas.includes(check.area));
    report.score = scoreChecks(report.checks);
    report.coverage = coverageOf(report.checks);
    scanScreenshots.set(target, screenshots || {});
    const failed = report.checks.filter((check) => check.status === 'fail');
    activeScanTarget = target;
    state.scans = [{ target, date: report.scannedAt, gaps: failed.length, report }, ...state.scans.filter((scan) => scan.target !== target)].slice(0, 5);
    save();
    result.innerHTML = `<div class="scan-complete"><strong>Scan complete</strong><span>${report.score ?? '–'}/100 · ${coverageLine(report.coverage)} · ${failed.length} failed · ${report.checks.filter((check) => check.status === 'review').length} to review · ${Math.round(report.durationMs / 1000)}s</span><div class="finding-list">${failed.slice(0, 4).map((check) => `<div><b>${esc(check.title)}</b><span class="gap">${esc(check.severity)} · ${esc(check.detail)}</span></div>`).join('')}</div><div class="report-actions"><button class="button button-primary" data-scan-report="${esc(target)}">Open detailed report →</button></div></div>`;
    showToast('Website scan complete.');
  } catch (error) {
    const message = error instanceof TypeError
      ? `Could not reach the scanner service at ${SCANNER_URL}. Start it with "npm start" in the scanner-service folder.`
      : error.message;
    result.innerHTML = `<div class="scan-error"><strong>Scan failed</strong><span>${esc(message)}</span><small>No findings were saved.</small></div>`;
    showToast('Website scan failed.');
  } finally {
    scanButton.disabled = false;
    scanButton.textContent = 'Scan →';
  }
}

function checkCard(check) {
  const evidence = check.evidence?.length
    ? `<div><strong>Evidence</strong><ul class="evidence-lines">${check.evidence.map((line) => `<li>${esc(line)}</li>`).join('')}</ul></div>`
    : '';
  const actions = check.status === 'pass' ? '' : `<div><strong>How to fix</strong><p>${esc(check.fix)}</p></div><div><strong>How to verify manually</strong><p>${esc(check.verify)}</p></div>`;
  return `<article class="detailed-finding"><div class="finding-header"><span>${esc(check.controlId)}</span><b class="${check.severity.toLowerCase()}">${esc(check.severity)}</b><b class="check-status ${check.status}">${STATUS_LABEL[check.status]}</b><em>${esc(check.area)}</em></div><h3>${esc(check.title)}</h3><p>${esc(check.detail)}</p>${evidence}${actions}<small><b>Mapping:</b> ${esc(check.legal)}<br><b>Confidence:</b> ${esc(check.confidence)}</small></article>`;
}

function scanReportView(report) {
  const back = '<button class="back-button" data-view-target="scan">← Website scan</button>';
  if (!report.checks) {
    main.innerHTML = `<section class="hero">${back}<h1>${esc(new URL(report.target).hostname)}</h1></section><div class="empty-state">This report came from the old HTML-only scanner and is no longer shown. Scan the site again to get browser evidence.</div>`;
    return;
  }
  const host = new URL(report.finalUrl || report.target).hostname;
  const count = (status) => report.checks.filter((check) => check.status === status).length;
  const statusOrder = { fail: 0, review: 1, 'not-evaluated': 2, pass: 3 };
  const severityOrder = { High: 0, Medium: 1, Low: 2 };
  const sorted = [...report.checks].sort((a, b) => statusOrder[a.status] - statusOrder[b.status] || severityOrder[a.severity] - severityOrder[b.severity]);
  const pre = report.phases.preConsent;
  const preTrackers = pre.trackers.filter((tracker) => tracker.nonEssential && !tracker.deniedPingsOnly).length;
  const preCookies = pre.cookies.filter((cookie) => cookie.nonEssential).length;
  const enabledByAccept = report.summary?.trackersEnabledByAccept || [];
  // Always recomputed from the checks, so reports saved before coverage existed show it too.
  const coverage = coverageOf(report.checks);
  const coverageNote = coverage.reasons.length
    ? `<div class="coverage-note ${coverage.level}"><strong>${coverage.level === 'limited' ? 'This score rests on few checks' : 'Some checks could not run'}</strong>${coverage.reasons.map((item) => `<span>${item.count} check${item.count === 1 ? '' : 's'} couldn’t run: ${esc(item.reason)}</span>`).join('')}</div>`
    : '';
  const areaCoverage = `<section class="domain-summaries">${coverage.byArea.map((entry) => `<article class="domain-summary"><strong>${esc(entry.area)}</strong><span>${entry.tested} of ${entry.total} tested · ${entry.failed} failed</span><i class="area-meter"><b style="width:${entry.total ? Math.round((entry.tested / entry.total) * 100) : 0}%"></b></i></article>`).join('')}</section>`;
  const verdict = report.score === null ? 'Not enough tested checks' : report.score >= 85 ? 'Strong consent posture' : report.score >= 60 ? 'Gaps to fix' : 'Significant consent gaps';
  const shots = scanScreenshots.get(report.target) || {};
  const shotItems = [['preConsent', 'Before any choice'], ['afterReject', 'After Reject, reloaded'], ['afterAccept', 'After Accept, reloaded']].filter(([key]) => shots[key]);
  const gallery = shotItems.length
    ? `<section class="shot-grid">${shotItems.map(([key, label]) => `<figure><img src="${esc(shots[key])}" alt="${esc(label)}: ${esc(host)}" loading="lazy" /><figcaption>${esc(label)}</figcaption></figure>`).join('')}</section>`
    : '<div class="evidence-notice"><strong>Screenshots not available</strong><span>Screenshots are kept only for the session in which the scan ran. Scan again to see them.</span></div>';

  main.innerHTML = `<section class="hero">${back}<div class="eyebrow">Website scan / Report · ${esc(report.engine?.method || 'consent journey')}</div><h1>${esc(host)}</h1><p>${count('fail')} failed · ${count('review')} to review · DPDP Act, 2023 · scanned ${new Date(report.scannedAt).toLocaleString()} in ${Math.round(report.durationMs / 1000)}s</p></section><div class="report-toolbar"><button class="button button-primary" data-download-pdf="${esc(report.target)}">Download PDF</button><button class="outline-button" data-download-scan="${esc(report.target)}">Download JSON</button><button class="outline-button" data-view-target="scan">Scan again</button></div><section class="readiness-card"><div><div class="label">DPDPA consent readiness</div><strong>${report.score ?? '–'}</strong><span>/ 100</span><b>${verdict}</b><em class="coverage-pill ${coverage.level}">${coverageLine(coverage)}</em><small>${count('pass')} passed · ${count('fail')} failed. ${count('review')} to review and ${count('not-evaluated')} not tested are left out of the score.</small></div><div class="report-stats"><div><span>Trackers before consent</span><strong>${preTrackers}</strong></div><div><span>Tracking cookies before consent</span><strong>${preCookies}</strong></div><div><span>Consent banner</span><strong class="stat-text">${esc(report.banner?.cmp || 'None found')}</strong></div><div><span>Trackers enabled by Accept</span><strong>${enabledByAccept.length}</strong></div></div></section>${coverageNote}${areaCoverage}${gallery}<h2 class="report-heading">Findings</h2><section class="detailed-findings">${sorted.map(checkCard).join('')}</section>`;
}

function checklistView() {
  main.innerHTML = `<section class="hero"><div class="eyebrow">Audit readiness</div><h1>Evidence checklists</h1><p>For each framework, tick the evidence you could hand to an auditor today and see how ready you are.</p></section><div class="checklist-grid">${frameworks.map((item) => { const total = controlsFor(item).length; const done = Object.values(state.checklists[item.name] || {}).filter(Boolean).length; return `<article class="checklist-card"><div class="card-top"><div><h3>${item.name}</h3><div class="meta">${item.version}</div></div><span class="status">${done}/${total} ready</span></div><p>Confirm you can produce evidence for each representative implementation check.</p><div class="progress"><i style="width:${done / total * 100}%"></i></div><div class="progress-meta"><span>${Math.round(done / total * 100)}%</span><span>evidence ready</span></div><button class="outline-button" data-checklist="${item.name}">Open checklist →</button></article>`; }).join('')}</div>`;
}
function checklistDetail(name) {
  const item = frameworkByName(name); state.checklists[name] ||= {};
  main.innerHTML = `<section class="hero"><button class="back-button" data-view-target="checklists">← Checklists</button><div class="eyebrow">Evidence checklist</div><h1>${name}</h1><p>Tick an item once you can produce the evidence. Progress saves in this browser.</p></section><div class="evidence-list">${controlsFor(item).map((control, index) => `<label><input type="checkbox" data-evidence="${index}" ${state.checklists[name][index] ? 'checked' : ''}/><span><strong>CONTROL ${String(index + 1).padStart(2, '0')} · ${esc(control[0])}</strong><small>${esc(control[2])}</small></span></label>`).join('')}</div><div class="report-actions"><button class="button button-primary" data-checklist-report="${esc(name)}">Download evidence report</button></div>`;
  document.querySelectorAll('[data-evidence]').forEach((input) => input.addEventListener('change', (event) => { state.checklists[name][event.target.dataset.evidence] = event.target.checked; save(); showToast('Checklist progress saved.'); }));
}

function templatesView() {
  main.innerHTML = `<section class="hero"><div class="eyebrow">Template library</div><h1>Policy & procedure templates</h1><p>Starting points for the policies and procedures auditors ask for, each mapped to its framework with purpose, scope, roles and revision history. Download as text or print to PDF.</p></section><div class="search-row"><input id="template-search" type="search" placeholder="Try ‘incident’, ‘access’ or ‘AI’" /></div><div id="template-list" class="template-list">${templates.map(templateCard).join('')}</div>`;
  document.querySelector('#template-search').addEventListener('input', (event) => { const query = event.target.value.toLowerCase(); document.querySelector('#template-list').innerHTML = templates.filter((item) => item.join(' ').toLowerCase().includes(query)).map(templateCard).join('') || '<div class="empty-state">No templates match that search.</div>'; });
}
function templateCard([name, framework, type]) { return `<article class="template-card"><div class="template-icon">▤</div><div><strong>${name}</strong><span>${framework}</span></div><em>${type}</em><button class="download-button" data-template="${name}" data-format="TXT">TXT</button><button class="download-button" data-template="${name}" data-format="PDF">Print / PDF</button></article>`; }
function downloadTemplate(name, format) {
  const content = `${name}\n\nHypenSec Astra template\nDocument owner: ____________________\nVersion: 1.0\n\nPurpose\nDefine the organization’s approach to ${name.toLowerCase()}.\n\nScope\nThis document applies to all relevant people, systems, suppliers and processes.\n\nRoles and responsibilities\nOwner: ____________________\nApprover: ____________________\n\nImplementation notes\nTailor this template to your organization, retain evidence, and review at least annually.\n`;
  if (format === 'PDF') { const printWindow = window.open('', '_blank'); if (printWindow) { printWindow.document.write(`<pre style="font:14px system-ui;white-space:pre-wrap">${esc(content)}</pre>`); printWindow.document.close(); printWindow.print(); } return; }
  const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([content], { type: 'text/plain' })); link.download = `${name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.txt`; link.click(); URL.revokeObjectURL(link.href); showToast('Template downloaded.');
}

function downloadFile(filename, content, type) {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([content], { type }));
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}
function downloadAssessmentReport(name) {
  const item = frameworkByName(name);
  const controls = controlsFor(item);
  const rows = controls.map((control, index) => ({
    id: `CONTROL-${String(index + 1).padStart(2, '0')}`,
    title: control[0],
    maturity: Number(assessment(name)[index] || 0),
    evidence: control[2],
    gap: !assessment(name)[index] || Number(assessment(name)[index]) < 3,
  }));
  const report = {
    product: 'HypenSec Astra',
    generatedAt: new Date().toISOString(),
    framework: item.version,
    methodology: 'Representative implementation checks mapped to the selected framework domain; not a reproduction of copyrighted standard text.',
    score: score(name),
    controls: rows,
  };
  downloadFile(`${name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-assessment.json`, JSON.stringify(report, null, 2), 'application/json');
  showToast('Assessment evidence report downloaded.');
}
function downloadChecklistReport(name) {
  const item = frameworkByName(name);
  const checklist = controlsFor(item).map((control, index) => ({ evidence: `CONTROL-${String(index + 1).padStart(2, '0')} · ${control[0]}`, description: control[2], ready: Boolean(state.checklists[name]?.[index]) }));
  downloadFile(`${name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-evidence.json`, JSON.stringify({ product: 'HypenSec Astra', generatedAt: new Date().toISOString(), framework: item.version, checklist }, null, 2), 'application/json');
  showToast('Evidence report downloaded.');
}
// The PDF is rendered by the scanner service so it matches the app theme on every device.
async function downloadScanPdf(target, button) {
  const scan = state.scans.find((item) => item.target === target);
  if (!scan?.report?.checks) { showToast('Scan the site again to create a PDF.'); return; }
  const label = button.textContent;
  button.disabled = true;
  button.textContent = 'Preparing PDF…';
  try {
    const response = await fetch(`${SCANNER_URL}/report.pdf`, {
      method: 'POST',
      headers: apiHeaders(),
      body: JSON.stringify({
        report: scan.report,
        screenshots: scanScreenshots.get(target) || {},
        theme: document.body.classList.contains('light') ? 'light' : 'dark',
      }),
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      if (response.status === 401) throw new Error('Add your access key on the Website Scan page, then try again.');
      throw new Error(data.error || `The scanner returned HTTP ${response.status}.`);
    }
    const url = URL.createObjectURL(await response.blob());
    const link = Object.assign(document.createElement('a'), { href: url, download: `${new URL(target).hostname}-dpdp-report.pdf` });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast('PDF report downloaded.');
  } catch (error) {
    showToast(error instanceof TypeError ? `Could not reach the scanner service at ${SCANNER_URL}.` : error.message);
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
}

function downloadScanReport(target) {
  const scan = state.scans.find((item) => item.target === target);
  if (!scan?.report) { showToast('No saved report is available for this target.'); return; }
  downloadFile(`${new URL(target).hostname}-dpdp-report.json`, JSON.stringify({ ...scan.report, screenshots: scanScreenshots.get(target) }, null, 2), 'application/json');
  showToast('JSON report downloaded.');
}

function toolkitView() {
  const gaps = Object.entries(state.assessments).flatMap(([name, values]) => Object.entries(values).filter(([, value]) => value < 3).map(([control]) => `${name} · Control ${control}`));
  main.innerHTML = `<section class="hero"><div class="eyebrow">My toolkit</div><h1>Your implementation toolkit</h1><p>Your open gaps, website scans and templates in one place. Nothing leaves this browser.</p></section>${Object.keys(state.assessments).length || state.scans.length ? `<section class="toolkit-grid"><div class="toolkit-card"><div class="label">Priority gaps</div><strong>${gaps.length}</strong><p>${gaps.length ? gaps.slice(0, 5).join('<br>') : 'No open gaps yet.'}</p></div><div class="toolkit-card"><div class="label">Website scans</div><strong>${state.scans.length}</strong><p>${state.scans.slice(0, 3).map((scan) => `${esc(scan.target)} · ${scan.gaps} gaps`).join('<br>') || 'No scans yet.'}</p></div></section>` : '<div class="empty-state">No assessments yet. Choose a framework to build your toolkit.</div>'}<button class="button button-primary" data-view-target="frameworks">Choose a framework →</button>`;
}
function aboutView() {
  main.innerHTML = `<section class="hero"><div class="eyebrow">About</div><h1>About <span class="grad">HypenSec Astra</span></h1><p>Compliance readiness from HypenSec: fast, focused and evidence-first.</p></section><div class="about-grid"><article><h3>What it does</h3><p>Score your maturity against ISO 27001, PCI DSS, the DPDP Act, SOC 2, NIST CSF and ISO/IEC 42001, then turn the gaps into a ranked plan with policies and evidence checklists. No account needed.</p></article><article><h3>Privacy by default</h3><p>Assessment answers and checklist progress never leave your browser. Website scans record what a new visitor\u2019s browser sees and what your privacy notice says. They are readiness checks, not legal advice or certification.</p></article><article><h3>Need implementation help?</h3><p>HypenSec\u2019s team can close the gaps with you, from DPDP consent flows to ISO 27001 certification.</p><button class="button button-primary" data-contact>Talk to HypenSec →</button></article></div>`;
}

function navigate(view) {
  document.querySelectorAll('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.view === view));
  ({ dashboard, frameworks: frameworksView, scan: scanView, checklists: checklistView, templates: templatesView, toolkit: toolkitView, about: aboutView }[view] || dashboard)();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

dashboard();
document.addEventListener('click', (event) => {
  const nav = event.target.closest('.nav-item'); if (nav) { navigate(nav.dataset.view); return; }
  const target = event.target.closest('[data-view-target]'); if (target) { navigate(target.dataset.viewTarget); return; }
  const assess = event.target.closest('[data-assess]'); if (assess) { assessmentView(assess.dataset.assess); return; }
  const checklist = event.target.closest('[data-checklist]'); if (checklist) { checklistDetail(checklist.dataset.checklist); return; }
  const template = event.target.closest('[data-template]'); if (template) { downloadTemplate(template.dataset.template, template.dataset.format); return; }
  const report = event.target.closest('[data-report]'); if (report) { downloadAssessmentReport(report.dataset.report); return; }
  const checklistReport = event.target.closest('[data-checklist-report]'); if (checklistReport) { downloadChecklistReport(checklistReport.dataset.checklistReport); return; }
  const scanReport = event.target.closest('[data-scan-report]'); if (scanReport) { const scan = state.scans.find((item) => item.target === scanReport.dataset.scanReport); if (scan?.report) scanReportView(scan.report); return; }
  const downloadPdf = event.target.closest('[data-download-pdf]'); if (downloadPdf) { downloadScanPdf(downloadPdf.dataset.downloadPdf, downloadPdf); return; }
  const downloadScan = event.target.closest('[data-download-scan]'); if (downloadScan) { downloadScanReport(downloadScan.dataset.downloadScan); return; }
  if (event.target.closest('[data-contact]')) { window.open('https://hypensec.com', '_blank', 'noopener'); return; }
  const control = event.target.closest('[data-control]'); if (control) { const current = assessment(document.querySelector('h1').textContent); current[control.dataset.control] = Number(control.dataset.value); state.assessments[document.querySelector('h1').textContent] = current; save(); assessmentView(document.querySelector('h1').textContent); showToast('Assessment progress saved.'); }
});
document.querySelector('.theme-toggle').addEventListener('click', () => { document.body.classList.toggle('light'); showToast(document.body.classList.contains('light') ? 'Light theme enabled.' : 'Dark theme enabled.'); });
