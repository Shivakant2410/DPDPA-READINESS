/**
 * Validation Workflow (Phase 6)
 * Evidence-gated conversion of discoveries into Verified Findings.
 */

function clamp01(n) {
  const x = Number(n);
  if (Number.isNaN(x)) return 0;
  return Math.min(1, Math.max(0, x));
}

function severityFromImpact(impact) {
  // impact: array of strings
  const set = new Set((impact || []).map(String));

  if (set.has('admin')) return 'Critical';
  if (set.has('auth_bypass')) return 'High';
  if (set.has('exposed_secret')) return 'High';
  if (set.has('prompt_leakage')) return 'Medium';
  if (set.has('info_disclosure')) return 'Low';
  return 'Informational';
}

function confidenceAggregate(parts) {
  const valid = (parts || []).filter(p => p && typeof p.confidence === 'number');
  if (valid.length === 0) return 0.15;
  const avg = valid.reduce((s, p) => s + p.confidence, 0) / valid.length;
  return clamp01(avg);
}

function validateSecretCandidate(secretCandidate) {
  const sc = secretCandidate || {};
  const confidence = clamp01(sc.confidence);

  // Red-team gating: never verify solely on regex.
  // Require either high confidence OR contextual evidence.
  const evidence = Array.isArray(sc.evidence) ? sc.evidence : [];
  const evidenceKinds = new Set(evidence.map(e => e.kind));
  const contextHit = evidence.some(e => typeof e.context === 'string' && /authorization|api key|apikey|bearer|token|secret|client_secret/i.test(e.context));

  const isHighFormat = confidence >= 0.75;
  const hasContext = contextHit || evidenceKinds.has('secret_regex_match');

  const verified = isHighFormat && hasContext;

  const impact = [];
  if (verified) impact.push('exposed_secret');

  return {
    verified,
    confidence: verified ? clamp01(confidence * 0.95) : clamp01(confidence * 0.55),
    impact: verified ? impact : [],
    evidence: evidence,
  };
}

function validateAuthBehavior(probeAuth) {
  const a = probeAuth || {};
  const status = a.httpStatus;
  if (status !== 401 && status !== 403 && status !== 200) {
    return { verified: false, confidence: 0.1, impact: [], evidence: [] };
  }

  // Red-team gating:
  // - 401/403 implies access control; not a vulnerability by itself.
  // - 200 can imply anonymous access only if paired with response evidence later.
  // In this repo we only have status-based auth; therefore we only verify
  // a finding when we can also see endpointIntelHint or response evidence.

  const evidence = Array.isArray(a.evidence) ? a.evidence : [];
  const baseConf = typeof a.confidence === 'number' ? clamp01(a.confidence) : 0.4;

  // Without response evidence we mark only Potential Issues.
  return {
    verified: false,
    confidence: baseConf,
    impact: [],
    evidence,
  };
}

function createVerifiedFindingFromSecret(secretCandidate) {
  const validation = validateSecretCandidate(secretCandidate);
  if (!validation.verified) return null;

  const secretType = secretCandidate.secret_type || 'secret';
  const title = `Verified exposed credential: ${secretType}`;

  const severity = severityFromImpact(validation.impact);
  const remediation = [
    'Revoke/rotate the exposed credential immediately.',
    'Remove the secret from client-delivered bundles and static assets.',
    'Move credential usage behind an authenticated backend proxy.',
  ];

  return {
    title,
    severity,
    confidence: validation.confidence,
    evidence: validation.evidence,
    impact: validation.impact,
    remediation,
    affected: {
      secrets: [secretCandidate.redacted_value || '[REDACTED]'],
    },
  };
}

function runValidationWorkflow({ secretCandidates = [], probeResults = [], endpointAgg = [] } = {}) {
  // Potential Issues: low/medium confidence issues that failed verification.
  const potentialIssues = [];
  const verifiedFindings = [];

  for (const sc of secretCandidates) {
    const vf = createVerifiedFindingFromSecret(sc);
    if (vf) {
      verifiedFindings.push(vf);
      continue;
    }

    // Potential Issue: keep it evidence-backed, but not verified.
    const conf = clamp01(sc.confidence);
    if (conf >= 0.45) {
      potentialIssues.push({
        title: `Potential exposed credential: ${sc.secret_type || 'secret'}`,
        confidence: clamp01(conf),
        evidence: Array.isArray(sc.evidence) ? sc.evidence : [],
        affected: { secrets: [sc.redacted_value || '[REDACTED]'] },
        note: 'Not verified: evidence/context insufficient to confirm exploitability.',
      });
    }
  }

  // Auth validation placeholder (Phase 6 gating scaffolding)
  // We do not create verified findings from auth status alone.
  for (const pr of probeResults || []) {
    if (!pr || !pr.authProbe) continue;
    const authVal = validateAuthBehavior(pr.authProbe);
    if (authVal.verified) {
      // future
    }
  }

  return {
    potentialIssues,
    verifiedFindings,
  };
}

if (typeof globalThis !== 'undefined') {
  globalThis.AIScannerValidation = {
    runValidationWorkflow,
    validateSecretCandidate,
    validateAuthBehavior,
  };
}

if (typeof exports !== 'undefined') {
  module.exports = {
    runValidationWorkflow,
    validateSecretCandidate,
    validateAuthBehavior,
  };
}


