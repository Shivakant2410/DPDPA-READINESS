/**
 * AI Endpoint Scanner — Report Generator
 *
 * Generates professional security reports in three formats:
 *   - Markdown (.md): Full-featured security report
 *   - HTML (.html): Styled, email-ready report
 *   - JSON (.json): Machine-readable raw data
 *
 * Reports include risk scoring, executive summaries, endpoint inventories,
 * widget details, probe results with vulnerability classification,
 * remediation guidance, and methodology notes.
 */

// ──────────────────────────────────────────────
//  Markdown Report
// ──────────────────────────────────────────────

function generateMarkdownReport(scanData, riskResult) {
  const ts = formatTs(scanData.timestamp);
  const risk = riskResult || { score: 0, rating: { label: 'Minimal', color: '#22c55e' }, details: {} };

  const vulnerableProbes = (scanData.probeResults || []).filter(p => p.vulnerable);
  const safeProbes = (scanData.probeResults || []).filter(p => !p.vulnerable && !p.error);
  const errorProbes = (scanData.probeResults || []).filter(p => p.error);

  const sections = [];

  // ── Title & Metadata ──
  sections.push(`# AI Endpoint Scanner — Security Assessment Report`);
  sections.push('');
  sections.push(`| Field | Value |`);
  sections.push(`|-------|-------|`);
  sections.push(`| **Scan ID** | \`${scanData.scanId || 'N/A'}\` |`);
  sections.push(`| **Target URL** | ${scanData.url || 'N/A'} |`);
  sections.push(`| **Scan Date** | ${ts} |`);
  sections.push(`| **Risk Score** | **${risk.score}/100** |`);
  sections.push(`| **Risk Rating** | **${risk.rating.label}** |`);
  sections.push(`| **Endpoints Found** | ${(scanData.endpoints || []).length} |`);
  sections.push(`| **Widgets Detected** | ${(scanData.widgets || []).length} |`);
  sections.push(`| **Vulnerabilities** | ${vulnerableProbes.length} |`);
  sections.push(`| **Leaked Keys** | ${(scanData.leakedKeys || []).length} |`);
  sections.push('');

  // ── Executive Summary ──
  sections.push(`## Executive Summary`);
  sections.push('');
  sections.push(generateExecutiveSummary(scanData, risk, vulnerableProbes));
  sections.push('');

  // ── Risk Assessment ──
  sections.push(`## Risk Assessment`);
  sections.push('');
  sections.push(`**Overall Risk Score: ${risk.score}/100 (${risk.rating.label})**`);
  sections.push('');

  if (risk.details) {
    sections.push(`| Risk Component | Points |`);
    sections.push(`|---------------|--------|`);
    sections.push(`| Endpoint Exposure | ${risk.details.endpointPoints || 0} |`);
    sections.push(`| AI Header Detection | ${risk.details.headerPoints || 0} |`);
    sections.push(`| API Key Leaks | ${risk.details.keyLeakPoints || 0} |`);
    sections.push(`| Widget Exposure | ${risk.details.widgetPoints || 0} |`);
    sections.push(`| Probe Vulnerabilities | ${risk.details.probePoints || 0} |`);
    sections.push(`| **Total (capped at 100)** | **${risk.score}** |`);
    sections.push('');
  }

  // Risk rating descriptions
  sections.push(`### Risk Rating Descriptions`);
  sections.push('');
  sections.push(`- **Critical (80-100)**: Severe vulnerabilities detected. Immediate action required. AI endpoints are exposed, leaking sensitive data, and susceptible to prompt injection attacks.`);
  sections.push(`- **High (60-79)**: Significant security concerns. Multiple AI endpoints detected with at least one serious vulnerability such as prompt injection or system prompt leakage.`);
  sections.push(`- **Medium (40-59)**: Moderate risk. AI endpoints are present but security controls appear to be in place. Some configuration weaknesses may exist.`);
  sections.push(`- **Low (20-39)**: Minor concerns. Limited AI endpoint exposure with no critical vulnerabilities detected. Basic security measures appear effective.`);
  sections.push(`- **Minimal (0-19)**: No significant AI security issues detected. Either no AI endpoints were found, or all detected endpoints are well-secured.`);
  sections.push('');

  // ── Discovered Endpoints ──
  sections.push(`## Discovered Endpoints`);
  sections.push('');

  const endpoints = scanData.endpoints || [];
  if (endpoints.length === 0) {
    sections.push(`No AI endpoints were discovered during this scan.`);
  } else {
    sections.push(`| # | Method | Type | URL | Headers | Hit Count |`);
    sections.push(`|---|--------|------|-----|---------|-----------|`);

    endpoints.forEach((ep, i) => {
      const method = ep.method || 'GET';
      const type = ep.label || ep.type || 'Unknown';
      const url = ep.url || 'N/A';
      const headerCount = (ep.headers || []).length;
      const hits = ep.hitCount || 1;
      sections.push(`| ${i + 1} | ${method} | ${type} | \`${truncateStr(url, 80)}\` | ${headerCount} | ${hits} |`);
    });

    sections.push('');

    // Detailed endpoint descriptions
    sections.push(`### Endpoint Details`);
    sections.push('');
    endpoints.forEach((ep, i) => {
      sections.push(`#### ${i + 1}. ${ep.label || 'Unknown'} — ${ep.method || 'GET'} ${truncateStr(ep.url, 100)}`);
      sections.push('');
      sections.push(`- **Type:** ${ep.type || 'Unknown'}`);
      sections.push(`- **First Seen:** ${formatTs(ep.firstSeen)}`);
      sections.push(`- **Last Seen:** ${formatTs(ep.lastSeen)}`);
      sections.push(`- **Hit Count:** ${ep.hitCount || 1}`);

      if (ep.headers && ep.headers.length > 0) {
        sections.push(`- **AI-Related Headers:**`);
        ep.headers.forEach(h => {
          sections.push(`  - \`${h.name}\`: \`${h.value}\``);
        });
      }

      if (ep.requestBodyPreview) {
        sections.push(`- **Request Body Preview:** \`${truncateStr(ep.requestBodyPreview, 150)}\``);
      }

      sections.push('');
    });
  }

  // ── Detected Headers ──
  const detectedHeaders = scanData.detectedHeaders || [];
  if (detectedHeaders.length > 0) {
    sections.push(`## Detected AI Headers`);
    sections.push('');
    sections.push(`The following AI-related HTTP headers were detected during network interception. These headers reveal the use of specific AI services and may expose configuration details.`);
    sections.push('');
    sections.push(`| Header Name | Value (Redacted) | Direction | Source URL |`);
    sections.push(`|-------------|-------------------|-----------|------------|`);

    detectedHeaders.forEach(h => {
      sections.push(`| \`${h.name}\` | \`${h.value}\` | ${h.direction || 'N/A'} | ${truncateStr(h.url || '', 60)} |`);
    });

    sections.push('');
  }

  // ── Widget Inventory ──
  const widgets = scanData.widgets || [];
  if (widgets.length > 0) {
    sections.push(`## Widget Inventory`);
    sections.push('');
    sections.push(`The following AI/chat widgets were detected in the page DOM. Widgets represent user-facing AI touchpoints that may interact with backend AI services.`);
    sections.push('');
    sections.push(`| # | Type | Provider | Selector / Source | Visible |`);
    sections.push(`|---|------|----------|-------------------|---------|`);

    widgets.forEach((w, i) => {
      const selector = w.src || w.selector || 'N/A';
      const visible = w.visible ? 'Yes' : 'No';
      sections.push(`| ${i + 1} | ${w.type || 'N/A'} | ${w.provider || 'Unknown'} | \`${truncateStr(selector, 60)}\` | ${visible} |`);
    });

    sections.push('');
  }

  // ── Leaked Keys ──
  const leakedKeys = scanData.leakedKeys || [];
  if (leakedKeys.length > 0) {
    sections.push(`## Leaked API Keys`);
    sections.push('');
    sections.push(`**CRITICAL:** The following API keys were detected in client-accessible code. Exposed API keys can be extracted by any visitor and used to make unauthorized API calls, potentially incurring significant costs.`);
    sections.push('');
    sections.push(`| # | Type | Key (Redacted) | Source |`);
    sections.push(`|---|------|----------------|--------|`);

    leakedKeys.forEach((k, i) => {
      sections.push(`| ${i + 1} | ${k.type || 'Unknown'} | \`${k.redacted || k.key || 'N/A'}\` | ${k.source || 'N/A'} |`);
    });

    sections.push('');
  }

  // ── Probe Results ──
  const probeResults = scanData.probeResults || [];
  if (probeResults.length > 0) {
    sections.push(`## Security Probe Results`);
    sections.push('');

    if (vulnerableProbes.length > 0) {
      sections.push(`### Vulnerabilities Found (${vulnerableProbes.length})`);
      sections.push('');
      sections.push(`The following probes identified security vulnerabilities:`);
      sections.push('');

      vulnerableProbes.forEach((pr, i) => {
        sections.push(`#### Vulnerability ${i + 1}: ${pr.label || pr.category || 'Unknown'}`);
        sections.push('');
        sections.push(`- **Category:** ${pr.category || 'N/A'}`);
        sections.push(`- **Endpoint:** \`${truncateStr(pr.endpointUrl || '', 80)}\``);
        sections.push(`- **HTTP Status:** ${pr.httpStatus || 'N/A'}`);
        sections.push(`- **Vulnerability Type:** ${pr.vulnerabilityType || 'N/A'}`);
        sections.push(`- **Analysis:** ${pr.analysis || 'No analysis available'}`);
        if (pr.responsePreview) {
          sections.push(`- **Response Preview:** \`${truncateStr(pr.responsePreview, 200)}\``);
        }
        sections.push('');
      });
    }

    if (safeProbes.length > 0) {
      sections.push(`### Safe Probes (${safeProbes.length})`);
      sections.push('');
      sections.push(`The following probes did not identify vulnerabilities:`);
      sections.push('');
      safeProbes.forEach(pr => {
        sections.push(`- **${pr.label || pr.category}:** ${pr.analysis || 'No issues detected'}`);
      });
      sections.push('');
    }

    if (errorProbes.length > 0) {
      sections.push(`### Probe Errors (${errorProbes.length})`);
      sections.push('');
      sections.push(`The following probes encountered errors (typically CORS restrictions or timeouts):`);
      sections.push('');
      errorProbes.forEach(pr => {
        sections.push(`- **${pr.label || pr.category}:** ${pr.error || 'Unknown error'} — ${pr.analysis || ''}`);
      });
      sections.push('');
    }

    // Summary table
    sections.push(`### Probe Summary Table`);
    sections.push('');
    sections.push(`| Payload | Endpoint | Status | Vulnerable |`);
    sections.push(`|---------|----------|--------|------------|`);

    probeResults.forEach(pr => {
      const status = pr.vulnerable ? 'VULNERABLE' : (pr.error ? 'ERROR' : 'SAFE');
      sections.push(`| ${pr.label || pr.category || 'N/A'} | \`${truncateStr(pr.endpointUrl || '', 50)}\` | ${status} | ${pr.vulnerable ? 'Yes' : 'No'} |`);
    });

    sections.push('');
  }

  // ── Remediation ──
  sections.push(`## Remediation Recommendations`);
  sections.push('');
  sections.push(generateRemediation(scanData, risk, vulnerableProbes, leakedKeys));

  // ── Methodology ──
  sections.push(`## Methodology & Limitations`);
  sections.push('');
  sections.push(`### Scanning Methodology`);
  sections.push('');
  sections.push(`This assessment was performed using the AI Endpoint Scanner browser extension, which employs the following techniques:`);
  sections.push('');
  sections.push(`1. **Network Interception:** All HTTP and WebSocket traffic from the target page is monitored using Chrome's webRequest API. Request URLs are matched against known AI endpoint patterns for OpenAI, Anthropic, Google AI, Cohere, and generic AI services. Request and response headers are inspected for AI-specific headers (x-openai-*, x-anthropic-*, etc.).`);
  sections.push('');
  sections.push(`2. **DOM Scanning:** The page DOM is scanned for chat widgets, AI assistant containers, and interactive bot elements. This includes inspecting iframes, div elements, buttons, meta tags, and inline scripts for AI-related identifiers and configurations.`);
  sections.push('');
  sections.push(`3. **Key Detection:** All network traffic and DOM scripts are scanned for common API key patterns (OpenAI sk-*, Anthropic sk-ant-*, Google AI AIza*). Detected keys are redacted in this report but their presence indicates a security risk.`);
  sections.push('');
  sections.push(`4. **Security Probing:** Discovered endpoints are tested with five safe probe payloads designed to test for information disclosure, prompt injection, jailbreak susceptibility, and filter evasion. Each probe is rate-limited to 1 request per 500ms with a 10-second timeout.`);
  sections.push('');
  sections.push(`### Limitations`);
  sections.push('');
  sections.push(`- This scan only tests endpoints accessible from the browser context. Server-side vulnerabilities are not assessed.`);
  sections.push(`- CORS restrictions may prevent probing of cross-origin endpoints, which could mask vulnerabilities.`);
  sections.push(`- The scan is a point-in-time assessment. AI service configurations may change after the scan.`);
  sections.push(`- Only known endpoint patterns are detected. Custom or obfuscated endpoints may not be identified.`);
  sections.push(`- Probe results are based on heuristic analysis of responses and may produce false positives or false negatives.`);
  sections.push(`- This tool is intended for authorized security testing only. Unauthorized scanning may violate terms of service or applicable laws.`);
  sections.push('');

  return sections.join('\n');
}

// ──────────────────────────────────────────────
//  HTML Report
// ──────────────────────────────────────────────

function generateHTMLReport(scanData, riskResult) {
  const ts = formatTs(scanData.timestamp);
  const risk = riskResult || { score: 0, rating: { label: 'Minimal', color: '#22c55e' }, details: {} };
  const vulnerableProbes = (scanData.probeResults || []).filter(p => p.vulnerable);
  const leakedKeys = scanData.leakedKeys || [];

  const riskColor = risk.rating.color || '#22c55e';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Security Assessment Report — ${escape(scanData.url || 'Unknown')}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      line-height: 1.6;
      color: #1e293b;
      background: #f8fafc;
      max-width: 800px;
      margin: 0 auto;
      padding: 32px 24px;
    }
    .header {
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #f1f5f9;
      padding: 32px;
      border-radius: 12px;
      margin-bottom: 24px;
    }
    .header h1 { font-size: 24px; margin-bottom: 8px; }
    .header .subtitle { color: #94a3b8; font-size: 14px; }
    .risk-display {
      display: inline-flex;
      align-items: center;
      gap: 12px;
      margin-top: 16px;
      padding: 12px 20px;
      background: rgba(255,255,255,0.05);
      border-radius: 8px;
      border: 1px solid rgba(255,255,255,0.1);
    }
    .risk-number { font-size: 36px; font-weight: 700; color: ${riskColor}; }
    .risk-text { font-size: 14px; font-weight: 600; color: ${riskColor}; text-transform: uppercase; letter-spacing: 0.5px; }
    .meta-table { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
    .meta-table th, .meta-table td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #e2e8f0; font-size: 13px; }
    .meta-table th { color: #64748b; font-weight: 500; width: 160px; }
    h2 { font-size: 18px; color: #0f172a; margin: 28px 0 12px; padding-bottom: 8px; border-bottom: 2px solid #e2e8f0; }
    h3 { font-size: 15px; color: #334155; margin: 20px 0 8px; }
    p { margin-bottom: 12px; font-size: 14px; color: #475569; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 13px; }
    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e2e8f0; }
    th { background: #f1f5f9; color: #475569; font-weight: 600; }
    code { background: #f1f5f9; padding: 2px 6px; border-radius: 3px; font-size: 12px; font-family: 'SF Mono', Consolas, monospace; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
    .badge-critical { background: #fef2f2; color: #dc2626; }
    .badge-high { background: #fff7ed; color: #ea580c; }
    .badge-medium { background: #fefce8; color: #ca8a04; }
    .badge-low { background: #f0fdf4; color: #16a34a; }
    .badge-safe { background: #f0fdf4; color: #16a34a; }
    .badge-vulnerable { background: #fef2f2; color: #dc2626; }
    .alert { padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; font-size: 13px; }
    .alert-critical { background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; }
    .alert-warning { background: #fff7ed; border: 1px solid #fed7aa; color: #9a3412; }
    .alert-info { background: #eff6ff; border: 1px solid #bfdbfe; color: #1e40af; }
    .card { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 12px; }
    .footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center; }
  </style>
</head>
<body>
  <div class="header">
    <h1>AI Endpoint Scanner</h1>
    <div class="subtitle">Security Assessment Report</div>
    <div class="risk-display">
      <div class="risk-number">${risk.score}</div>
      <div>
        <div class="risk-text">${risk.rating.label} Risk</div>
        <div style="color:#94a3b8; font-size:12px;">Score out of 100</div>
      </div>
    </div>
  </div>

  <table class="meta-table">
    <tr><th>Scan ID</th><td><code>${escape(scanData.scanId || 'N/A')}</code></td></tr>
    <tr><th>Target URL</th><td>${escape(scanData.url || 'N/A')}</td></tr>
    <tr><th>Scan Date</th><td>${ts}</td></tr>
    <tr><th>Endpoints</th><td>${(scanData.endpoints || []).length}</td></tr>
    <tr><th>Widgets</th><td>${(scanData.widgets || []).length}</td></tr>
    <tr><th>Vulnerabilities</th><td><span class="badge ${vulnerableProbes.length > 0 ? 'badge-vulnerable' : 'badge-safe'}">${vulnerableProbes.length}</span></td></tr>
    <tr><th>Leaked Keys</th><td><span class="badge ${leakedKeys.length > 0 ? 'badge-critical' : 'badge-safe'}">${leakedKeys.length}</span></td></tr>
  </table>

  ${leakedKeys.length > 0 ? `<div class="alert alert-critical"><strong>CRITICAL:</strong> ${leakedKeys.length} API key(s) were detected in client-accessible code. Exposed keys can be used for unauthorized API access.</div>` : ''}

  ${vulnerableProbes.length > 0 ? `<div class="alert alert-warning"><strong>WARNING:</strong> ${vulnerableProbes.length} security vulnerability(ies) were detected through probe testing.</div>` : ''}

  <h2>Executive Summary</h2>
  <p>${escape(generateExecutiveSummary(scanData, risk, vulnerableProbes))}</p>

  ${(scanData.endpoints || []).length > 0 ? `
  <h2>Discovered Endpoints</h2>
  <table>
    <tr><th>#</th><th>Method</th><th>Type</th><th>URL</th><th>Headers</th></tr>
    ${(scanData.endpoints || []).map((ep, i) => `<tr><td>${i + 1}</td><td><code>${escape(ep.method || 'GET')}</code></td><td><span class="badge badge-medium">${escape(ep.label || ep.type || 'Unknown')}</span></td><td><code>${escape(truncateStr(ep.url || '', 70))}</code></td><td>${(ep.headers || []).length}</td></tr>`).join('')}
  </table>
  ` : ''}

  ${(scanData.widgets || []).length > 0 ? `
  <h2>Widget Inventory</h2>
  <table>
    <tr><th>#</th><th>Type</th><th>Provider</th><th>Selector / Source</th><th>Visible</th></tr>
    ${(scanData.widgets || []).map((w, i) => `<tr><td>${i + 1}</td><td>${escape(w.type || 'N/A')}</td><td>${escape(w.provider || 'Unknown')}</td><td><code>${escape(truncateStr(w.src || w.selector || 'N/A', 60))}</code></td><td>${w.visible ? 'Yes' : 'No'}</td></tr>`).join('')}
  </table>
  ` : ''}

  ${(scanData.probeResults || []).length > 0 ? `
  <h2>Security Probe Results</h2>
  <table>
    <tr><th>Probe</th><th>Category</th><th>Status</th><th>Analysis</th></tr>
    ${(scanData.probeResults || []).map(pr => `<tr><td>${escape(pr.label || 'N/A')}</td><td>${escape(pr.category || 'N/A')}</td><td><span class="badge ${pr.vulnerable ? 'badge-vulnerable' : (pr.error ? 'badge-medium' : 'badge-safe')}">${pr.vulnerable ? 'VULNERABLE' : (pr.error ? 'ERROR' : 'SAFE')}</span></td><td>${escape(truncateStr(pr.analysis || pr.error || 'N/A', 120))}</td></tr>`).join('')}
  </table>
  ` : ''}

  <h2>Remediation Recommendations</h2>
  <p>${escape(generateRemediation(scanData, risk, vulnerableProbes, leakedKeys)).replace(/\n/g, '<br>')}</p>

  <div class="footer">
    <p>Generated by AI Endpoint Scanner v1.0.0 &mdash; For authorized security testing only</p>
  </div>
</body>
</html>`;

  return html;
}

// ──────────────────────────────────────────────
//  JSON Report
// ──────────────────────────────────────────────

function generateJSONReport(scanData, riskResult) {
  const risk = riskResult || { score: 0, rating: { label: 'Minimal', color: '#22c55e' }, details: {} };
  const vulnerableProbes = (scanData.probeResults || []).filter(p => p.vulnerable);

  const report = {
    schema: 'ai-endpoint-scanner-report-v1',
    generatedAt: new Date().toISOString(),
    scan: {
      id: scanData.scanId || null,
      targetUrl: scanData.url || null,
      timestamp: scanData.timestamp || null,
      formattedDate: formatTs(scanData.timestamp),
    },
    risk: {
      score: risk.score,
      rating: risk.rating.label,
      color: risk.rating.color,
      breakdown: risk.details || {},
    },
    summary: {
      totalEndpoints: (scanData.endpoints || []).length,
      totalWidgets: (scanData.widgets || []).length,
      totalHeaders: (scanData.detectedHeaders || []).length,
      totalLeakedKeys: (scanData.leakedKeys || []).length,
      totalProbes: (scanData.probeResults || []).length,
      vulnerableProbes: vulnerableProbes.length,
      safeProbes: (scanData.probeResults || []).filter(p => !p.vulnerable && !p.error).length,
      errorProbes: (scanData.probeResults || []).filter(p => p.error).length,
    },
    endpoints: (scanData.endpoints || []).map(ep => ({
      id: ep.id,
      url: ep.url,
      method: ep.method,
      type: ep.type,
      label: ep.label,
      headers: ep.headers || [],
      requestBodyPreview: ep.requestBodyPreview || null,
      hitCount: ep.hitCount || 1,
      firstSeen: ep.firstSeen,
      lastSeen: ep.lastSeen,
    })),
    detectedHeaders: scanData.detectedHeaders || [],
    leakedKeys: (scanData.leakedKeys || []).map(k => ({
      type: k.type,
      redacted: k.redacted || k.key,
      source: k.source,
    })),
    widgets: (scanData.widgets || []).map(w => ({
      type: w.type,
      provider: w.provider,
      src: w.src || null,
      selector: w.selector || null,
      visible: w.visible,
      keyword: w.keyword,
    })),
    probeResults: (scanData.probeResults || []).map(pr => ({
      endpointId: pr.endpointId,
      endpointUrl: pr.endpointUrl,
      payloadId: pr.payloadId,
      category: pr.category,
      label: pr.label,
      httpStatus: pr.httpStatus || null,
      vulnerable: pr.vulnerable,
      vulnerabilityType: pr.vulnerabilityType || null,
      analysis: pr.analysis || null,
      error: pr.error || null,
    })),
    executiveSummary: generateExecutiveSummary(scanData, risk, vulnerableProbes),
    remediation: generateRemediation(scanData, risk, vulnerableProbes, scanData.leakedKeys || []),
  };

  return JSON.stringify(report, null, 2);
}

// ──────────────────────────────────────────────
//  Shared Content Generators
// ──────────────────────────────────────────────

function generateExecutiveSummary(scanData, risk, vulnerableProbes) {
  const endpoints = scanData.endpoints || [];
  const widgets = scanData.widgets || [];
  const keys = scanData.leakedKeys || [];
  const probes = scanData.probeResults || [];

  let summary = '';

  if (endpoints.length === 0 && widgets.length === 0) {
    summary = `No AI chatbot endpoints or widgets were detected on the target website during this scan. The site does not appear to integrate AI services in a way that is detectable through browser-based network interception or DOM scanning. This results in a minimal risk score of ${risk.score}/100. However, it is possible that AI services are integrated server-side or through obfuscated methods that this scan cannot detect. We recommend server-side code review for comprehensive assessment.`;
  } else {
    summary = `This security assessment identified ${endpoints.length} AI endpoint(s) and ${widgets.length} chat widget(s) on the target website. `;

    if (keys.length > 0) {
      summary += `CRITICAL: ${keys.length} API key(s) were detected in client-accessible code, representing a severe security vulnerability that could enable unauthorized API usage and significant financial exposure. `;
    }

    if (vulnerableProbes.length > 0) {
      const vulnTypes = [...new Set(vulnerableProbes.map(p => p.vulnerabilityType).filter(Boolean))];
      summary += `Security probing revealed ${vulnerableProbes.length} vulnerability(ies), including: ${vulnTypes.join(', ')}. These findings indicate that the AI endpoints may be susceptible to prompt injection attacks, information disclosure, or safety filter bypasses. `;
    }

    const endpointTypes = [...new Set(endpoints.map(e => e.label).filter(Boolean))];
    if (endpointTypes.length > 0) {
      summary += `The detected AI services include: ${endpointTypes.join(', ')}. `;
    }

    summary += `The overall risk score is ${risk.score}/100 (${risk.rating.label}). `;

    if (risk.score >= 60) {
      summary += `We strongly recommend immediate remediation of identified vulnerabilities, particularly any exposed API keys and prompt injection susceptibilities. A follow-up assessment should be scheduled after remediation to verify that issues have been resolved.`;
    } else if (risk.score >= 40) {
      summary += `While the overall risk is moderate, we recommend addressing identified weaknesses and implementing additional security controls around AI endpoint access.`;
    } else {
      summary += `The current security posture appears reasonable, but ongoing monitoring is recommended as AI integrations evolve and new attack vectors emerge.`;
    }
  }

  return summary;
}

function generateRemediation(scanData, risk, vulnerableProbes, leakedKeys) {
  const lines = [];
  const endpoints = scanData.endpoints || [];
  const keys = leakedKeys || [];

  lines.push(`Based on the findings of this assessment, the following remediation steps are recommended, prioritized by severity:`);
  lines.push('');

  let stepNum = 1;

  // API key leaks — always highest priority
  if (keys.length > 0) {
    lines.push(`${stepNum}. **Immediately Rotate Exposed API Keys** — ${keys.length} API key(s) were detected in client-accessible code. All exposed keys should be revoked and replaced immediately. New keys must be stored server-side only and never embedded in client-side JavaScript, HTML, or configuration files. Consider using a backend proxy for all AI API calls rather than calling services directly from the browser.`);
    lines.push('');
    stepNum++;
  }

  // Prompt injection vulnerabilities
  const injectionVulns = vulnerableProbes.filter(p => p.vulnerabilityType === 'prompt_injection' || p.vulnerabilityType === 'filter_evasion');
  if (injectionVulns.length > 0) {
    lines.push(`${stepNum}. **Implement Input Sanitization for AI Endpoints** — ${injectionVulns.length} endpoint(s) were susceptible to prompt injection attacks. Deploy server-side input validation and sanitization before forwarding user inputs to AI models. Consider implementing a separate input processing layer that filters known injection patterns, strips system-level keywords, and enforces maximum input lengths. Implement prompt hardening techniques such as input/output boundaries in system prompts.`);
    lines.push('');
    stepNum++;
  }

  // Information disclosure
  const disclosureVulns = vulnerableProbes.filter(p => p.vulnerabilityType === 'info_disclosure' || p.vulnerabilityType === 'jailbreak');
  if (disclosureVulns.length > 0) {
    lines.push(`${stepNum}. **Harden System Prompts Against Extraction** — ${disclosureVulns.length} endpoint(s) revealed system prompt information through probing. Review and strengthen system prompts to resist extraction attempts. Implement output filtering that detects and redacts system prompt content before it reaches the user. Consider using a separate "guard" model or classifier to screen responses for sensitive information leakage.`);
    lines.push('');
    stepNum++;
  }

  // Endpoint exposure
  if (endpoints.length > 0) {
    lines.push(`${stepNum}. **Restrict Direct AI Endpoint Access** — ${endpoints.length} AI endpoint(s) were directly accessible from the browser. Implement a backend API gateway or proxy that sits between client applications and AI services. This allows you to add authentication, rate limiting, input validation, and audit logging at the gateway level. Direct client-to-AI-service communication should be avoided in production environments.`);
    lines.push('');
    stepNum++;
  }

  // Widget security
  const visibleWidgets = (scanData.widgets || []).filter(w => w.visible);
  if (visibleWidgets.length > 0) {
    lines.push(`${stepNum}. **Secure Chat Widget Implementations** — ${visibleWidgets.length} visible chat widget(s) were detected. Ensure that all chat widgets are loaded from verified, integrity-checked sources (using Subresource Integrity hashes). Implement Content Security Policy (CSP) headers that restrict which domains can be loaded as iframes or scripts. Monitor widget configurations for exposed sensitive settings.`);
    lines.push('');
    stepNum++;
  }

  // CORS and headers
  const detectedHeaders = scanData.detectedHeaders || [];
  if (detectedHeaders.length > 0) {
    lines.push(`${stepNum}. **Review and Minimize AI-Related HTTP Headers** — ${detectedHeaders.length} AI-specific HTTP header(s) were detected in network traffic. Excessive header information can help attackers fingerprint your AI infrastructure. Remove or minimize version identifiers and implementation details from HTTP headers. Configure your API gateway to strip internal headers before responses reach the client.`);
    lines.push('');
    stepNum++;
  }

  // General best practices
  lines.push(`${stepNum}. **Implement Comprehensive AI Security Controls** — Regardless of the specific findings above, we recommend implementing the following AI security best practices:`);
  lines.push(`   - Deploy Content Security Policy (CSP) headers with strict directives`);
  lines.push(`   - Implement rate limiting on all AI-facing endpoints`);
  lines.push(`   - Add authentication and authorization checks to all AI API calls`);
  lines.push(`   - Enable audit logging for all interactions with AI services`);
  lines.push(`   - Regularly rotate API keys and use short-lived tokens`);
  lines.push(`   - Conduct periodic security assessments as AI integrations evolve`);
  lines.push(`   - Consider using a dedicated AI security gateway or firewall`);
  lines.push('');

  return lines.join('\n');
}

// ──────────────────────────────────────────────
//  Utility Functions
// ──────────────────────────────────────────────

function formatTs(ts) {
  if (!ts) return 'N/A';
  const d = new Date(ts);
  return d.toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function truncateStr(str, maxLen = 80) {
  if (!str) return '';
  if (str.length <= maxLen) return str;
  return str.substring(0, maxLen - 3) + '...';
}

function escape(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ──────────────────────────────────────────────
//  Exports
// ──────────────────────────────────────────────

if (typeof globalThis !== 'undefined') {
  globalThis.ReportGenerator = {
    generateMarkdownReport,
    generateHTMLReport,
    generateJSONReport,
  };
}

if (typeof exports !== 'undefined') {
  module.exports = {
    generateMarkdownReport,
    generateHTMLReport,
    generateJSONReport,
  };
}
