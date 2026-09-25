/**
 * Data models (lightweight JS documentation + helpers)
 *
 * This repo uses plain JS objects; these functions define/validate the shape
 * expected by the redesigned pipeline.
 */

function clamp01(n) {
  // (Keeping repo in plain JS; this file is JS-only and is not type-checked for runtime.)

  const x = Number(n);
  if (Number.isNaN(x)) return 0;
  return Math.min(1, Math.max(0, x));
}

function confidenceOfEvidence(evidence) {
  // evidence: array of {confidence, kind, ...}
  if (!Array.isArray(evidence) || evidence.length === 0) return 0;
  const avg = evidence.reduce((s, e) => s + (typeof e.confidence === 'number' ? e.confidence : 0.5), 0) / evidence.length;
  return clamp01(avg);
}

/**
 * Asset inventory item
 * { id?, category, subtype, confidence, evidence: [Evidence] }
 */
function makeAsset({ category, subtype, confidence = 0.1, evidence = [] }) {
  return {
    category,
    subtype,
    confidence: clamp01(confidence),
    evidence: Array.isArray(evidence) ? evidence : [evidence].filter(Boolean),
  };
}

/**
 * Endpoint intelligence result
 */
function makeEndpointIntel({
  framework = null,
  endpoint_type = null,
  auth_required = null,
  auth_mechanism = null,
  streaming = null,
  ai_provider = null,
  confidence = 0,
} = {}) {
  return {
    framework,
    endpoint_type,
    auth_required,
    auth_mechanism,
    streaming,
    ai_provider,
    confidence: clamp01(confidence),
  };
}

/**
 * Secret candidate
 */
function makeSecretCandidate({ secret_type, confidence = 0.1, evidence = [], redacted_value = '[REDACTED]' } = {}) {
  return {
    secret_type,
    confidence: clamp01(confidence),
    evidence: Array.isArray(evidence) ? evidence : [evidence].filter(Boolean),
    redacted_value,
  };
}

/**
 * Finding (verified only)
 */
function makeFinding({ title, severity, confidence = 0.1, evidence = [], impact = [], remediation = [], affected = {} } = {}) {
  return {
    title,
    severity,
    confidence: clamp01(confidence),
    evidence: Array.isArray(evidence) ? evidence : [evidence].filter(Boolean),
    impact: Array.isArray(impact) ? impact : [impact].filter(Boolean),
    remediation: Array.isArray(remediation) ? remediation : [remediation].filter(Boolean),
    affected,
  };
}

if (typeof globalThis !== 'undefined') {
  globalThis.AIScannerModels = {
    clamp01,
    confidenceOfEvidence,
    makeAsset,
    makeEndpointIntel,
    makeSecretCandidate,
    makeFinding,
  };
}

if (typeof exports !== 'undefined') {
  module.exports = {
    clamp01,
    confidenceOfEvidence,
    makeAsset,
    makeEndpointIntel,
    makeSecretCandidate,
    makeFinding,
  };
}

