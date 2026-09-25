/**
 * URL Normalization & Endpoint Deduplication
 *
 * Canonicalizes URLs by removing volatile query parameters and noise.
 */

const QUERY_PARAM_BLACKLIST = new Set([
  // Analytics
  'utm_source',
  'utm_medium',
  'utm_campaign',
  'utm_term',
  'utm_content',
  'fbclid',
  'gclid',

  // Common cachebusters
  'cachebust',
  'cache_bust',
  'cb',
  'v',

  // Timestamps / nonces
  'timestamp',
  'time',
  'ts',
  't',
  'nonce',
  'random',
  'rand',
  'r',

  // Misc anti-caching / signatures commonly present in query params
  'nocache',
  'no_cache',
]);

const PARAM_VALUE_NONCE_REGEXES = [
  // Long-ish hex strings / base62-ish chunks
  /^[a-f0-9]{16,}$/i,
  /^[A-Za-z0-9_-]{20,}$/,
  // Epoch-ish
  /^\d{10,}$/,
  // Millis-ish
  /^\d{13,}$/,
];

function stripHash(u) {
  // Always drop fragment
  return new URL(u.origin + u.pathname + u.search);
}

function shouldRemoveQueryParam(nameLower, value) {
  if (QUERY_PARAM_BLACKLIST.has(nameLower)) return true;

  if (nameLower.includes('utm_')) return true;
  if (nameLower.includes('fbclid')) return true;
  if (nameLower.includes('gclid')) return true;

  // Heuristic: remove params that look like random nonces
  if (typeof value === 'string' && value.length > 0) {
    const v = value.trim();
    if (PARAM_VALUE_NONCE_REGEXES.some(re => re.test(v))) return true;
  }

  // Remove common cache-busting timestamp-like names
  if (nameLower.includes('ts') || nameLower.includes('time') || nameLower.includes('nonce')) {
    if (typeof value === 'string' && value.trim().match(/^\d{6,}$/)) return true;
  }

  return false;
}

/**
 * Normalize a URL into a canonical path+query form for dedup.
 *
 * Requirements handled:
 * - remove timestamps, cachebusters, utm params, fbclid, gclid, random nonces
 */
function normalizeUrl(url) {
  if (typeof url !== 'string' || url.length === 0) return { endpoint: 'unknown', normalizedUrl: null };

  try {
    const u = new URL(url);
    const withoutHash = stripHash(u);

    const params = new URLSearchParams(withoutHash.search);

    const kept = [];
    for (const [k, v] of params.entries()) {
      const kLower = k.toLowerCase();
      if (shouldRemoveQueryParam(kLower, v)) continue;
      kept.push([kLower, v]);
    }

    // Sort parameters for deterministic output
    kept.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

    const normalizedParams = new URLSearchParams();
    for (const [k, v] of kept) normalizedParams.append(k, v);

    const qs = normalizedParams.toString();
    const normalizedPath = withoutHash.pathname;

    const endpoint = qs ? `${normalizedPath}?${qs}` : normalizedPath;

    return { endpoint, normalizedUrl: endpoint };
  } catch {
    // Fallback: try to normalize a path-only string
    const s = url.trim();
    if (!s.startsWith('/')) {
      return { endpoint: 'unknown', normalizedUrl: null };
    }

    // Drop fragment
    const noHash = s.split('#')[0];
    const [path, query = ''] = noHash.split('?');
    if (!query) return { endpoint: path, normalizedUrl: path };

    const params = new URLSearchParams(query);
    const kept = [];
    for (const [k, v] of params.entries()) {
      const kLower = k.toLowerCase();
      if (shouldRemoveQueryParam(kLower, v)) continue;
      kept.push([kLower, v]);
    }
    kept.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    const normalizedParams = new URLSearchParams();
    for (const [k, v] of kept) normalizedParams.append(k, v);
    const qs = normalizedParams.toString();
    const endpoint = qs ? `${path}?${qs}` : path;

    return { endpoint, normalizedUrl: endpoint };
  }
}

/**
 * Endpoint key for dedup/aggregation.
 *
 * Use method + normalized endpoint so the same path across methods is distinct.
 */
function endpointKey(method, normalizedEndpoint) {
  const m = (method || 'GET').toUpperCase();
  const ep = normalizedEndpoint || 'unknown';
  return `${m} ${ep}`;
}

if (typeof globalThis !== 'undefined') {
  globalThis.AIScannerNormalization = { normalizeUrl, endpointKey };
}

if (typeof exports !== 'undefined') {
  module.exports = { normalizeUrl, endpointKey };
}

