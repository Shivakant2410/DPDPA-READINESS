/**
 * AI Endpoint Scanner — Content Script (DOM Scanner)
 *
 * Scans the current page's DOM for AI chatbot widgets, embedded
 * configurations, leaked API keys, and metadata related to AI services.
 * Runs at document_idle in all frames (including iframes).
 */

// ──────────────────────────────────────────────
//  Configuration (mirrored from utils.js for content script context)
// ──────────────────────────────────────────────

const IFRAME_SRC_KEYWORDS = [
  'chat', 'intercom', 'zendesk', 'crisp', 'drift',
  'hubspot', 'freshdesk', 'freshchat', 'landbot',
  'tawk', 'livechat', 'chatwoot', 'purechat',
  'bot', 'assistant', 'widget',
];

const DIV_CLASS_ID_KEYWORDS = [
  'chat-widget', 'chatbot', 'ai-assistant', 'virtual-agent',
  'chat-container', 'chat-window', 'chat-bubble', 'chat-btn',
  'bot-container', 'bot-widget', 'ai-chat',
  'intercom', 'zendesk', 'crisp', 'drift',
];

const BUTTON_CLASS_ID_KEYWORDS = [
  'chat', 'bot', 'message', 'support', 'help',
];

const META_NAMES = [
  'ai-provider', 'chatbot', 'ai-model', 'openai-model',
  'gpt-model', 'llm-endpoint',
];

const SCRIPT_KEY_PATTERNS = [
  { regex: /sk-[a-zA-Z0-9]{20,}/g, label: 'OpenAI API Key' },
  { regex: /sk-ant-[a-zA-Z0-9-]{20,}/g, label: 'Anthropic API Key' },
  { regex: /AIza[a-zA-Z0-9_-]{35}/g, label: 'Google AI API Key' },
  { regex: /api[_-]?key\s*[:=]\s*["'][^"']{10,}/gi, label: 'Generic API Key' },
  { regex: /OPENAI_API_KEY\s*[:=]/gi, label: 'OpenAI Key Reference' },
  { regex: /ANTHROPIC_API_KEY\s*[:=]/gi, label: 'Anthropic Key Reference' },
];

const WIDGET_DOMAIN_MAP = {
  'intercom': 'Intercom',
  'intercomcdn': 'Intercom',
  'zendesk': 'Zendesk',
  'crisp': 'Crisp',
  'drift': 'Drift',
  'driftt': 'Drift',
  'hubspot': 'HubSpot',
  'freshdesk': 'Freshdesk',
  'freshchat': 'Freshchat',
  'landbot': 'Landbot',
  'tawk': 'Tawk.to',
  'livechat': 'LiveChat',
  'chatwoot': 'Chatwoot',
  'purechat': 'Pure Chat',
};

// ──────────────────────────────────────────────
//  Scan State
// ──────────────────────────────────────────────

let isScanning = false;
let foundWidgets = [];
let foundKeys = [];
let scanObserver = null;

// ──────────────────────────────────────────────
//  Message Handling
// ──────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case 'SCAN_DOM':
      performDOMScan().then(sendResponse);
      return true;

    case 'RUNTIME_AUDIT':
      sendResponse(collectRuntimeAudit());
      return false;

    case 'STOP_SCAN':
      stopDOMScan();
      sendResponse({ type: 'SCAN_STOPPED' });
      return false;

    default:
      break;
  }
});

function collectRuntimeAudit() {
  const resources = performance.getEntriesByType('resource').map((entry) => ({
    name: entry.name,
    initiatorType: entry.initiatorType,
    duration: Math.round(entry.duration),
    transferSize: entry.transferSize || 0,
  }));
  const cookies = document.cookie.split(';').map((cookie) => cookie.trim().split('=')[0]).filter(Boolean);
  const consentNodes = [...document.querySelectorAll('[id*="consent" i], [class*="consent" i], [id*="cookie" i], [class*="cookie" i]')];
  const trackerResources = resources.filter((resource) => /google|facebook|doubleclick|analytics|segment|hotjar|clarity|amplitude|mixpanel|hubspot|intercom|tiktok|linkedin/i.test(resource.name));
  return {
    url: window.location.href,
    capturedAt: new Date().toISOString(),
    cookies,
    cookieCount: cookies.length,
    resources,
    trackerResources,
    consentNodes: consentNodes.slice(0, 20).map((node) => ({
      tag: node.tagName,
      id: node.id,
      className: typeof node.className === 'string' ? node.className : '',
      text: (node.textContent || '').trim().slice(0, 240),
    })),
    forms: document.forms.length,
    secureContext: window.isSecureContext,
  };
}

// ──────────────────────────────────────────────
//  Main DOM Scanner
// ──────────────────────────────────────────────

async function performDOMScan() {
  isScanning = true;
  foundWidgets = [];
  foundKeys = [];

  const pageUrl = window.location.href;

  // 1. Scan iframes
  scanIframes();

  // 2. Scan divs for chat widget indicators
  scanDivs();

  // 3. Scan buttons
  scanButtons();

  // 4. Scan meta tags
  scanMetaTags();

  // 5. Scan inline scripts for AI configs and leaked keys
  await scanScripts();

  // 6. Start MutationObserver for dynamically loaded widgets
  startObserver();

  // Send results to background
  if (foundWidgets.length > 0) {
    try {
      await chrome.runtime.sendMessage({
        type: 'WIDGET_FOUND',
        tabId: null, // background will use sender.tab.id
        pageUrl,
        widgets: foundWidgets,
      });
    } catch (e) {
      // Extension context may be invalidated
    }
  }

  if (foundKeys.length > 0) {
    try {
      await chrome.runtime.sendMessage({
        type: 'LEAKED_KEYS_FOUND',
        tabId: null,
        pageUrl,
        keys: foundKeys,
      });
    } catch (e) {
      // Extension context may be invalidated
    }
  }

  isScanning = false;

  return {
    type: 'DOM_SCAN_COMPLETE',
    widgets: foundWidgets,
    keys: foundKeys,
  };
}

// ──────────────────────────────────────────────
//  Iframe Scanner
// ──────────────────────────────────────────────

function scanIframes() {
  const iframes = getAllElements('iframe');

  for (const iframe of iframes) {
    const src = (iframe.src || '').toLowerCase();
    const dataSrc = (iframe.dataset.src || '').toLowerCase();
    const allSrcs = [src, dataSrc].filter(Boolean);

    for (const srcUrl of allSrcs) {
      for (const keyword of IFRAME_SRC_KEYWORDS) {
        if (srcUrl.includes(keyword)) {
          const widgetType = identifyWidgetProvider(srcUrl);
          foundWidgets.push({
            type: 'iframe',
            provider: widgetType,
            src: iframe.src || iframe.dataset.src || '',
            selector: getSelector(iframe),
            keyword,
            visible: isVisible(iframe),
            dimensions: {
              width: iframe.offsetWidth,
              height: iframe.offsetHeight,
            },
          });
          break; // Don't double-count the same iframe
        }
      }
    }

    // Also check iframe attributes for AI-related identifiers
    const id = (iframe.id || '').toLowerCase();
    // SAFETY: className may be SVGAnimatedString for SVG elements
    const className = typeof iframe.className === 'string' ? iframe.className.toLowerCase() : '';
    const attrs = `${id} ${className}`;

    if (DIV_CLASS_ID_KEYWORDS.some(kw => attrs.includes(kw))) {
      foundWidgets.push({
        type: 'iframe',
        provider: 'Unknown',
        src: iframe.src || '',
        selector: getSelector(iframe),
        keyword: 'class/id match',
        visible: isVisible(iframe),
        dimensions: {
          width: iframe.offsetWidth,
          height: iframe.offsetHeight,
        },
      });
    }
  }
}

// ──────────────────────────────────────────────
//  Div Scanner
// ──────────────────────────────────────────────

function scanDivs() {
  // Scan both light DOM and shadow DOM
  const allElements = getAllElements('div, section, aside, article, main');

  for (const el of allElements) {
    const id = (el.id || '').toLowerCase();
    // SAFETY: className may be SVGAnimatedString for SVG elements
    const className = typeof el.className === 'string' ? el.className.toLowerCase() :
                      (el.getAttribute && el.getAttribute('class') || '').toLowerCase();
    const role = (el.getAttribute('role') || '').toLowerCase();
    const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
    const combined = `${id} ${className} ${role} ${ariaLabel}`;

    for (const keyword of DIV_CLASS_ID_KEYWORDS) {
      if (combined.includes(keyword)) {
        const widgetType = identifyWidgetProvider(combined);
        foundWidgets.push({
          type: 'container',
          provider: widgetType,
          selector: getSelector(el),
          keyword,
          visible: isVisible(el),
          tag: el.tagName.toLowerCase(),
          attributes: extractRelevantAttributes(el),
        });
        break; // One match per element is enough
      }
    }
  }
}

// ──────────────────────────────────────────────
//  Button Scanner
// ──────────────────────────────────────────────

function scanButtons() {
  const buttons = getAllElements('button, [role="button"], a[aria-label]');

  for (const btn of buttons) {
    const id = (btn.id || '').toLowerCase();
    // SAFETY: className may be SVGAnimatedString for SVG elements
    const className = typeof btn.className === 'string' ? btn.className.toLowerCase() :
                      (btn.getAttribute && btn.getAttribute('class') || '').toLowerCase();
    const ariaLabel = (btn.getAttribute('aria-label') || '').toLowerCase();
    const title = (btn.getAttribute('title') || '').toLowerCase();
    const text = btn.textContent.toLowerCase().substring(0, 100);
    const combined = `${id} ${className} ${ariaLabel} ${title} ${text}`;

    for (const keyword of BUTTON_CLASS_ID_KEYWORDS) {
      if (combined.includes(keyword)) {
        // Only add if it seems like a chat trigger (not just a "help" nav link)
        const isLikelyChatWidget = combined.includes('chat') ||
          combined.includes('bot') ||
          combined.includes('message') ||
          ariaLabel.includes('chat') ||
          title.includes('chat');

        if (isLikelyChatWidget) {
          foundWidgets.push({
            type: 'button',
            provider: identifyWidgetProvider(combined),
            selector: getSelector(btn),
            keyword,
            visible: isVisible(btn),
            text: btn.textContent.trim().substring(0, 50),
            tag: btn.tagName.toLowerCase(),
          });
        }
        break;
      }
    }
  }
}

// ──────────────────────────────────────────────
//  Meta Tag Scanner
// ──────────────────────────────────────────────

function scanMetaTags() {
  const metas = document.querySelectorAll('meta');

  for (const meta of metas) {
    const name = (meta.getAttribute('name') || '').toLowerCase();
    const property = (meta.getAttribute('property') || '').toLowerCase();
    const content = meta.getAttribute('content') || '';
    const combined = `${name} ${property}`;

    // Check for known AI-related meta tags
    for (const metaName of META_NAMES) {
      if (combined.includes(metaName)) {
        foundWidgets.push({
          type: 'meta',
          provider: 'Unknown',
          selector: `meta[name="${name}"]`,
          keyword: metaName,
          visible: true,
          content: content.substring(0, 200),
        });
      }
    }

    // Also detect generic AI indicators in meta content
    const aiContentIndicators = ['gpt', 'openai', 'claude', 'anthropic', 'gemini', 'llm', 'chatbot'];
    for (const indicator of aiContentIndicators) {
      if (content.toLowerCase().includes(indicator)) {
        foundWidgets.push({
          type: 'meta',
          provider: indicator.charAt(0).toUpperCase() + indicator.slice(1),
          selector: `meta[name="${name}"]`,
          keyword: indicator,
          visible: true,
          content: content.substring(0, 200),
        });
      }
    }
  }
}

// ──────────────────────────────────────────────
//  Script Scanner (Inline Scripts & Configs)
// ──────────────────────────────────────────────

async function scanScripts() {
  const scripts = document.querySelectorAll('script:not([src])');

  for (const script of scripts) {
    const text = script.textContent || '';

    // Skip tiny scripts
    if (text.length < 10) continue;

    // Secret candidate detection (Phase 5)
    // Keep legacy foundKeys shape in parallel, but base the output on secret-detection.js.
    try {
      if (typeof AIScannerSecrets !== 'undefined' && typeof AIScannerSecrets.extractSecretCandidates === 'function') {
        const candidates = AIScannerSecrets.extractSecretCandidates(text, { url: window.location.href });

        for (const c of candidates) {
          // Legacy parallel fields:
          // - redacted: redacted_value
          // - type: secret_type
          // - context: first evidence context
          // - url: window.location.href
          const legacyRedacted = c.redacted_value;
          if (!foundKeys.some(k => k.redacted === legacyRedacted && k.type === c.secret_type)) {
            const firstEvidence = Array.isArray(c.evidence) ? c.evidence[0] : null;
            foundKeys.push({
              redacted: legacyRedacted,
              type: c.secret_type,
              context: firstEvidence && firstEvidence.context ? firstEvidence.context.substring(0, 200) : null,
              url: window.location.href,
              // New optional fields (safe for forward migration)
              confidence: c.confidence,
              evidence: c.evidence,
              secret_type: c.secret_type,
            });
          }
        }
      }
    } catch (e) {
      // If new secret engine fails, keep old behavior (best-effort) rather than break scanning.
      for (const pattern of SCRIPT_KEY_PATTERNS) {
        const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
        let match;
        while ((match = regex.exec(text)) !== null) {
          const key = match[0];
          const redactedKey = redactKey(key);
          if (!foundKeys.some(k => k.redacted === redactedKey)) {
            foundKeys.push({
              redacted: redactedKey,
              type: pattern.label,
              context: text.substring(Math.max(0, match.index - 30), match.index + key.length + 30),
              url: window.location.href,
            });
          }
        }
      }
    }


    // Scan for AI configuration objects
    scanForAIConfig(text);
  }

  // Also scan external scripts that are loaded inline (data attributes)
  const externalScripts = document.querySelectorAll('script[src]');
  for (const script of externalScripts) {
    const src = (script.src || '').toLowerCase();

    // Detect AI service script inclusions
    const aiScriptPatterns = [
      { pattern: 'intercom', provider: 'Intercom' },
      { pattern: 'zendesk', provider: 'Zendesk' },
      { pattern: 'crisp', provider: 'Crisp' },
      { pattern: 'drift', provider: 'Drift' },
      { pattern: 'hubspot', provider: 'HubSpot' },
      { pattern: 'freshchat', provider: 'Freshchat' },
      { pattern: 'tawk', provider: 'Tawk.to' },
      { pattern: 'livechat', provider: 'LiveChat' },
      { pattern: 'chatwoot', provider: 'Chatwoot' },
      { pattern: 'openai', provider: 'OpenAI' },
      { pattern: 'ai-sdk', provider: 'AI SDK' },
    ];

    for (const { pattern, provider } of aiScriptPatterns) {
      if (src.includes(pattern)) {
        foundWidgets.push({
          type: 'script',
          provider,
          src: script.src,
          selector: getSelector(script),
          keyword: pattern,
          visible: false,
        });
      }
    }
  }
}

/**
 * Search script text for AI configuration objects.
 */
function scanForAIConfig(scriptText) {
  const configPatterns = [
    // Intercom config
    { regex: /intercomSettings\s*=\s*\{([^}]+)\}/gi, provider: 'Intercom', type: 'config' },
    // Zendesk config
    { regex: /zE\s*\(\s*['"]config['"]\s*,\s*\{([^}]+)\}/gi, provider: 'Zendesk', type: 'config' },
    // Crisp config
    { regex: /\$crisp\s*\.\s*push\s*\(\s*\[['"]set['"]\s*,/gi, provider: 'Crisp', type: 'config' },
    // Drift config
    { regex: /drift\.config\s*=\s*\{([^}]+)\}/gi, provider: 'Drift', type: 'config' },
    // HubSpot config
    { regex: /hsConversationsSettings\s*=\s*\{([^}]+)\}/gi, provider: 'HubSpot', type: 'config' },
    // Generic AI config
    { regex: /ai[_-]?config\s*[:=]\s*\{([^}]{5,})\}/gi, provider: 'Unknown', type: 'config' },
    { regex: /chatbot[_-]?config\s*[:=]\s*\{([^}]{5,})\}/gi, provider: 'Unknown', type: 'config' },
    // OpenAI init patterns
    { regex: /new\s+OpenAI\s*\(/gi, provider: 'OpenAI', type: 'sdk-init' },
    { regex: /openai\s*\.\s*chat\s*\.\s*completions/gi, provider: 'OpenAI', type: 'sdk-init' },
  ];

  for (const { regex, provider, type } of configPatterns) {
    let match;
    const r = new RegExp(regex.source, regex.flags);

    while ((match = r.exec(scriptText)) !== null) {
      const existing = foundWidgets.find(
        w => w.provider === provider && w.type === type && w.keyword === regex.source.substring(0, 30)
      );
      if (!existing) {
        foundWidgets.push({
          type: type,
          provider,
          selector: 'inline-script',
          keyword: regex.source.substring(0, 30),
          visible: false,
          configPreview: match[1] ? match[1].substring(0, 200) : match[0].substring(0, 100),
        });
      }
    }
  }
}

// ──────────────────────────────────────────────
//  MutationObserver (Dynamic Widget Detection)
// ──────────────────────────────────────────────

function startObserver() {
  if (scanObserver) return; // Already observing

  scanObserver = new MutationObserver((mutations) => {
    if (!isScanning && foundWidgets.length > 0) return;

    let hasNewWidgets = false;

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;

        const prevCount = foundWidgets.length;
        checkNewNode(node);

        // Also check child nodes
        if (node.querySelectorAll) {
          const iframes = node.querySelectorAll('iframe');
          for (const iframe of iframes) {
            checkIframeNode(iframe);
          }

          const divs = node.querySelectorAll('div, section, aside');
          for (const div of divs) {
            checkDivNode(div);
          }
        }

        if (foundWidgets.length > prevCount) hasNewWidgets = true;
      }
    }

    // Only notify if new widgets were actually found
    if (hasNewWidgets) {
      try {
        chrome.runtime.sendMessage({
          type: 'WIDGET_FOUND',
          tabId: null,
          pageUrl: window.location.href,
          widgets: foundWidgets,
        }).catch(() => {});
      } catch (e) {
        // Extension context invalidated
      }
    }
  });

  scanObserver.observe(document.body, {
    childList: true,
    subtree: true,
  });

  // Auto-disconnect after 60 seconds to save resources
  setTimeout(() => {
    if (scanObserver) {
      scanObserver.disconnect();
      scanObserver = null;
    }
  }, 60000);
}

function checkNewNode(node) {
  if (node.tagName === 'IFRAME') {
    checkIframeNode(node);
  } else if (node.tagName === 'DIV' || node.tagName === 'SECTION') {
    checkDivNode(node);
  } else if (node.tagName === 'BUTTON') {
    checkButtonNode(node);
  }
}

function checkIframeNode(iframe) {
  const src = (iframe.src || '').toLowerCase();
  for (const keyword of IFRAME_SRC_KEYWORDS) {
    if (src.includes(keyword)) {
      addWidgetIfNew({
        type: 'iframe',
        provider: identifyWidgetProvider(src),
        src: iframe.src || '',
        selector: getSelector(iframe),
        keyword,
        visible: isVisible(iframe),
        dimensions: { width: iframe.offsetWidth, height: iframe.offsetHeight },
      });
      break;
    }
  }
}

function checkDivNode(div) {
  const combined = `${(div.id || '').toLowerCase()} ${(div.className || '').toLowerCase()} ${(div.getAttribute('role') || '').toLowerCase()}`;
  for (const keyword of DIV_CLASS_ID_KEYWORDS) {
    if (combined.includes(keyword)) {
      addWidgetIfNew({
        type: 'container',
        provider: identifyWidgetProvider(combined),
        selector: getSelector(div),
        keyword,
        visible: isVisible(div),
        tag: div.tagName.toLowerCase(),
      });
      break;
    }
  }
}

function checkButtonNode(btn) {
  const combined = `${(btn.id || '').toLowerCase()} ${(btn.className || '').toLowerCase()} ${(btn.getAttribute('aria-label') || '').toLowerCase()}`;
  if (BUTTON_CLASS_ID_KEYWORDS.some(kw => combined.includes(kw)) && combined.includes('chat')) {
    addWidgetIfNew({
      type: 'button',
      provider: identifyWidgetProvider(combined),
      selector: getSelector(btn),
      keyword: 'chat',
      visible: isVisible(btn),
      text: btn.textContent.trim().substring(0, 50),
    });
  }
}

function addWidgetIfNew(widget) {
  const isDuplicate = foundWidgets.some(
    w => w.selector === widget.selector && w.type === widget.type && w.keyword === widget.keyword
  );
  if (!isDuplicate) {
    foundWidgets.push({ ...widget, discoveredAt: Date.now() });
  }
}

// ──────────────────────────────────────────────
//  Helper Functions
// ──────────────────────────────────────────────

function getSelector(element) {
  if (element.id) return `#${element.id}`;

  const path = [];
  let current = element;
  while (current && current !== document.body) {
    let selector = current.tagName.toLowerCase();
    if (current.id) {
      selector = `#${current.id}`;
      path.unshift(selector);
      break;
    }
    if (current.className && typeof current.className === 'string') {
      const firstClass = current.className.trim().split(/\s+/)[0];
      if (firstClass) {
        selector += `.${firstClass}`;
      }
    }
    const parent = current.parentElement;
    if (parent) {
      const siblings = Array.from(parent.children).filter(c => c.tagName === current.tagName);
      if (siblings.length > 1) {
        const index = siblings.indexOf(current) + 1;
        selector += `:nth-child(${index})`;
      }
    }
    path.unshift(selector);
    current = current.parentElement;
  }
  return path.join(' > ').substring(0, 200);
}

function isVisible(element) {
  if (!element) return false;
  const style = window.getComputedStyle(element);
  return style.display !== 'none' &&
    style.visibility !== 'hidden' &&
    style.opacity !== '0' &&
    element.offsetWidth > 0 &&
    element.offsetHeight > 0;
}

function extractRelevantAttributes(element) {
  const attrs = {};
  const relevantAttrs = ['role', 'aria-label', 'aria-live', 'data-testid', 'data-type', 'data-widget', 'data-bot'];
  for (const attr of relevantAttrs) {
    const value = element.getAttribute(attr);
    if (value) attrs[attr] = value;
  }
  return attrs;
}

function identifyWidgetProvider(text) {
  const lower = text.toLowerCase();
  for (const [domain, provider] of Object.entries(WIDGET_DOMAIN_MAP)) {
    if (lower.includes(domain)) return provider;
  }
  return 'Unknown';
}

function redactKey(key) {
  if (key.length <= 8) return '****';
  return key.substring(0, 6) + '****' + key.substring(key.length - 4);
}

/**
 * Get all elements matching a selector, including those inside shadow DOMs.
 * Many modern chat widgets (Intercom, Crisp, etc.) use shadow DOM.
 */
function getAllElements(selector, root = document) {
  const elements = [...root.querySelectorAll(selector)];

  // Traverse shadow DOMs
  for (const el of root.querySelectorAll('*')) {
    if (el.shadowRoot) {
      elements.push(...getAllElements(selector, el.shadowRoot));
    }
  }

  return elements;
}

// ──────────────────────────────────────────────
//  Stop / Cleanup
// ──────────────────────────────────────────────

function stopDOMScan() {
  isScanning = false;
  if (scanObserver) {
    scanObserver.disconnect();
    scanObserver = null;
  }
}

// ──────────────────────────────────────────────
//  Auto-scan removed: scanning only triggers on user action
//  (background sends SCAN_DOM message when user clicks Start Scan)
// ──────────────────────────────────────────────
