# AI Endpoint Scanner — Testing Setup

## Prerequisites

```bash
# Install Node.js (v18+)
nvm install 18
nvm use 18

# Install dev dependencies
npm install
```

## 1. Static Analysis

```bash
# Lint all JS files
npm run lint

# Auto-fix lint issues
npm run lint:fix
```

## 2. Manual Extension Testing

### Load the Extension
1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode** (toggle in top-right)
3. Click **Load unpacked** → select the `ai-endpoint-scanner` folder
4. The extension icon appears in the toolbar

### Test Network Interception
1. Open DevTools → Network tab on any website
2. Navigate to a site known to use AI (e.g., chat.openai.com, any Intercom-powered site)
3. Click the extension icon → Click **Start Scan**
4. Verify endpoints appear in the Endpoints tab

### Test DOM Scanning
1. Navigate to a site with a chat widget (e.g., intercom.com, crisp.chat)
2. Click **Start Scan**
3. Verify widgets appear in the Widgets tab
4. Test on a SPA: navigate within the site and verify MutationObserver catches dynamically loaded widgets

### Test Security Probes
1. Find a site with a POST-able AI endpoint
2. Click **Run Probes**
3. Verify each probe result appears with proper status (SAFE/VULNERABLE/ERROR)
4. Test with CORS-blocked endpoints — should show "CORS_BLOCKED" gracefully

### Test Report Generation
1. After running probes, click **Report**
2. Test all 3 formats: Markdown, HTML, JSON
3. Verify **Download Report** creates a valid file
4. Verify **Copy to Clipboard** works
5. Verify **Export Raw JSON** contains complete data

## 3. Unit Testing with Jest

### Setup
```bash
npm install --save-dev jest jest-environment-jsdom sinon-chrome sinon
```

### Example Test File: `__tests__/utils.test.js`
```javascript
const { classifyEndpoint, calculateRiskScore, redactHeaderValue } = require('../utils');

describe('classifyEndpoint', () => {
  test('classifies OpenAI endpoints', () => {
    const result = classifyEndpoint('https://api.openai.com/v1/chat/completions');
    expect(result.type).toBe('openai');
    expect(result.label).toBe('OpenAI');
  });

  test('classifies Anthropic endpoints', () => {
    const result = classifyEndpoint('https://api.anthropic.com/v1/messages');
    expect(result.type).toBe('anthropic');
  });

  test('classifies generic AI endpoints', () => {
    const result = classifyEndpoint('https://example.com/api/chat');
    expect(result.type).toBe('generic');
  });

  test('returns unknown for non-AI URLs', () => {
    const result = classifyEndpoint('https://example.com/about');
    expect(result.type).toBe('unknown');
  });

  test('handles invalid URLs', () => {
    const result = classifyEndpoint('not-a-url');
    expect(result.type).toBe('unknown');
  });
});

describe('redactHeaderValue', () => {
  test('redacts long values', () => {
    expect(redactHeaderValue('sk-abc123456789xyz')).toBe('sk-a****9xyz');
  });

  test('handles short values', () => {
    expect(redactHeaderValue('short')).toBe('****');
  });

  test('handles non-string values', () => {
    expect(redactHeaderValue(null)).toBe('[REDACTED]');
  });
});

describe('calculateRiskScore', () => {
  test('returns 0 for empty scan data', () => {
    const result = calculateRiskScore({});
    expect(result.score).toBe(0);
    expect(result.rating.label).toBe('Minimal');
  });

  test('caps score at 100', () => {
    const data = {
      endpoints: Array(20).fill({ type: 'openai' }),
      leakedKeys: Array(5).fill({ key: 'sk-xxx' }),
      probeResults: [{ vulnerable: true, category: 'jailbreak' }],
    };
    const result = calculateRiskScore(data);
    expect(result.score).toBeLessThanOrEqual(100);
  });
});
```

### Example Test File: `__tests__/report-generator.test.js`
```javascript
const { generateMarkdownReport, generateHTMLReport, generateJSONReport } = require('../report-generator');

const mockScanData = {
  scanId: 'test_scan',
  url: 'https://example.com',
  timestamp: Date.now(),
  endpoints: [{ id: 'ep1', url: 'https://api.openai.com/v1/chat/completions', method: 'POST', type: 'openai', label: 'OpenAI', headers: [], hitCount: 1, firstSeen: Date.now(), lastSeen: Date.now() }],
  widgets: [],
  probeResults: [],
  detectedHeaders: [],
  leakedKeys: [],
};

const mockRisk = { score: 12, rating: { label: 'Low', color: '#16a34a' }, details: { endpointPoints: 12 } };

describe('generateMarkdownReport', () => {
  test('generates valid markdown', () => {
    const report = generateMarkdownReport(mockScanData, mockRisk);
    expect(report).toContain('# AI Endpoint Scanner');
    expect(report).toContain('Low');
    expect(report).toContain('OpenAI');
  });

  test('handles empty data gracefully', () => {
    const report = generateMarkdownReport({}, { score: 0, rating: { label: 'Minimal', color: '#22c55e' }, details: {} });
    expect(report).toContain('Minimal');
    expect(report).toContain('No AI endpoints');
  });
});

describe('generateHTMLReport', () => {
  test('generates valid HTML', () => {
    const report = generateHTMLReport(mockScanData, mockRisk);
    expect(report).toContain('<!DOCTYPE html>');
    expect(report).toContain('</html>');
    // Check XSS prevention — raw scan data should be escaped
    expect(report).not.toContain('<script>alert(');
  });
});

describe('generateJSONReport', () => {
  test('generates parseable JSON', () => {
    const report = generateJSONReport(mockScanData, mockRisk);
    const parsed = JSON.parse(report);
    expect(parsed.schema).toBe('ai-endpoint-scanner-report-v1');
    expect(parsed.summary.totalEndpoints).toBe(1);
  });
});
```

### Run Tests
```bash
npm test
npm run test:watch
```

## 4. Integration Testing Checklist

| Scenario | Steps | Expected Result |
|----------|-------|-----------------|
| Install extension | Load unpacked in chrome://extensions | No errors in service worker console |
| Scan page with AI | Navigate to ChatGPT → Start Scan | OpenAI endpoints appear |
| Scan page with widget | Navigate to Intercom site → Start Scan | Widget appears in Widgets tab |
| Scan page without AI | Navigate to example.com → Start Scan | "No endpoints" message |
| Run probes | After scanning → Run Probes | Probe results with SAFE/VULNERABLE/ERROR |
| Generate report | After probes → Report → Download | Valid .md/.html/.json file |
| Clear scan | Click clear button | All data reset |
| Service worker restart | Close popup, wait 30s, reopen | Scan state persists from storage |
| Multiple tabs | Scan in 2 tabs simultaneously | Each tab has independent scan state |
| CORS handling | Scan cross-origin endpoint | Shows CORS_BLOCKED, not crash |

## 5. Chrome Web Store Submission Checklist

- [ ] Remove all `console.log` statements (keep `console.warn`/`console.error`)
- [ ] Replace `"<all_urls>"` in content_scripts with specific patterns if possible
- [ ] Add a privacy policy URL
- [ ] Create promotional screenshots (1280x800 or 640x400)
- [ ] Write a detailed description for the store listing
- [ ] Test on Chrome Stable, Beta, and Canary
- [ ] Verify no permissions warnings on install
- [ ] Run `npm run lint` with zero errors
- [ ] Test with Chrome's "Enhanced Safe Browsing" enabled
