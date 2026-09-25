/**
 * Secret Detection Engine (Phase 5)
 *
 * Expands beyond OpenAI/Anthropic/Google and returns evidence-backed candidates.
 *
 * Output shape:
 *   {
 *     secret_type,
 *     confidence,
 *     evidence: [{kind, value?, match?, context?, confidence}],
 *     redacted_value
 *   }
 */

const entropyCache = new Map();

function clamp01(n) {
  const x = Number(n);
  if (Number.isNaN(x)) return 0;
  return Math.min(1, Math.max(0, x));
}

function shannonEntropy(str) {
  if (typeof str !== 'string' || str.length === 0) return 0;
  if (entropyCache.has(str)) return entropyCache.get(str);

  const s = str;
  const freq = new Map();
  for (let i = 0; i < s.length; i++) {
    freq.set(s[i], (freq.get(s[i]) || 0) + 1);
  }

  let ent = 0;
  const len = s.length;
  for (const [, c] of freq) {
    const p = c / len;
    ent -= p * Math.log2(p);
  }

  entropyCache.set(str, ent);
  return ent;
}

function redactValue(value) {
  if (typeof value !== 'string') return '[REDACTED]';
  if (value.length <= 8) return '****';
  return value.slice(0, 6) + '****' + value.slice(-4);
}

function scoreFromEntropy(entropy, len) {
  // Normalize to [0..1]. Typical high-entropy secrets land roughly ~3.5-6.5 bits/char.
  const x = entropy / 6.5;
  const lengthBonus = Math.min(1, len / 40);
  return clamp01(0.2 + x * 0.7) * (0.7 + 0.3 * lengthBonus);
}

function contextProximityBoost(contextLower) {
  const keywords = [
    'api key', 'apikey', 'x-api-key', 'authorization', 'bearer', 'token',
    'secret', 'sk-', 'passwd', 'password', 'client secret', 'client_secret',
  ];
  for (const kw of keywords) {
    if (contextLower.includes(kw)) return 0.15;
  }
  return 0;
}

function makeEvidence({ kind, value, match, context, confidence }) {
  return {
    kind,
    value: value || undefined,
    match: match || undefined,
    context: context || undefined,
    confidence: typeof confidence === 'number' ? confidence : 0.5,
  };
}

// Secret families: regex + how to score.
// NOTE: regexes are heuristic; validation gating should later suppress obvious false positives.
const SECRET_FAMILIES = [
  // AWS
  {
    secret_type: 'aws_access_key_id',
    weight: 0.85,
    regex: /AKIA[0-9A-Z]{16}/g,
  },
  {
    secret_type: 'aws_secret_access_key',
    weight: 0.9,
    regex: /(?<![A-Za-z0-9/+])[A-Za-z0-9\/+=]{40}(?![A-Za-z0-9\/+=])/g,
    // This is broad; later entropy+context is critical.
  },
  // Azure (very rough)
  {
    secret_type: 'azure_client_secret',
    weight: 0.8,
    regex: /[a-f0-9]{32}/gi,
  },

  // GitHub
  {
    secret_type: 'github_token',
    weight: 0.95,
    regex: /gh[pousr]_[A-Za-z0-9]{36,}/g,
  },
  // GitLab
  {
    secret_type: 'gitlab_token',
    weight: 0.9,
    regex: /glpat-[A-Za-z0-9_-]{20,}/g,
  },

  // Stripe
  {
    secret_type: 'stripe_secret_key',
    weight: 0.95,
    regex: /sk_live_[a-zA-Z0-9]{20,}|sk_test_[a-zA-Z0-9]{20,}/g,
  },

  // Slack
  {
    secret_type: 'slack_token',
    weight: 0.9,
    regex: /(xox[baprs]-[0-9a-zA-Z-]{10,})/g,
  },

  // Twilio
  {
    secret_type: 'twilio_auth_token',
    weight: 0.85,
    regex: /SK[0-9a-fA-F]{32}/g,
  },

  // SendGrid
  {
    secret_type: 'sendgrid_api_key',
    weight: 0.9,
    regex: /SG\.[A-Za-z0-9_-]{20,}/g,
  },

  // Firebase
  {
    secret_type: 'firebase_api_key',
    weight: 0.8,
    // Firebase API key often looks like AIzaSy...
    regex: /AIza[0-9A-Za-z_-]{35,}/g,
  },

  // Supabase (heuristic)
  {
    secret_type: 'supabase_anon_key',
    weight: 0.7,
    regex: /[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}/g,
  },

  // Cloudflare
  {
    secret_type: 'cloudflare_api_token',
    weight: 0.85,
    regex: /\b(A[0-9a-zA-Z]{32}\.[0-9a-zA-Z]{15}\.[0-9a-zA-Z]{20})\b/g,
  },

  // Resend
  {
    secret_type: 'resend_api_key',
    weight: 0.8,
    regex: /re_[A-Za-z0-9]{20,}/g,
  },

  // Postmark
  {
    secret_type: 'postmark_api_token',
    weight: 0.8,
    regex: /[A-Z0-9]{25,}/g,
  },

  // OpenAI
  {
    secret_type: 'openai_api_key',
    weight: 0.95,
    regex: /sk-[a-zA-Z0-9]{20,}/g,
  },
  // Anthropic
  {
    secret_type: 'anthropic_api_key',
    weight: 0.95,
    regex: /sk-ant-[a-zA-Z0-9-]{20,}/g,
  },
  // Google (Generic AIza)
  {
    secret_type: 'google_api_key',
    weight: 0.85,
    regex: /AIza[a-zA-Z0-9_-]{30,}/g,
  },
];

function findEntropyForCandidate(candidate, contextLower) {
  const ent = shannonEntropy(candidate);
  const entropyScore = scoreFromEntropy(ent, candidate.length);
  const proximity = contextProximityBoost(contextLower);
  return clamp01(entropyScore + proximity);
}

function extractSecretCandidates(text, { url = null } = {}) {
  if (typeof text !== 'string' || text.length === 0) return [];

  const candidates = [];
  const lower = text.toLowerCase();

  for (const fam of SECRET_FAMILIES) {
    if (!fam.regex) continue;
    const globalRegex = new RegExp(fam.regex.source, fam.regex.flags.includes('g') ? fam.regex.flags : fam.regex.flags + 'g');

    let match;
    while ((match = globalRegex.exec(text)) !== null) {
      const value = match[0];
      if (!value) continue;

      const idx = match.index;
      const start = Math.max(0, idx - 60);
      const end = Math.min(text.length, idx + value.length + 60);
      const context = text.slice(start, end);
      const contextLower = context.toLowerCase();

      const entropyConf = findEntropyForCandidate(value, contextLower);

      // Baseline confidence from regex family weight + entropy.
      // Then penalize very short matches.
      const lenPenalty = value.length < 20 ? 0.2 : 0;
      let confidence = clamp01(0.25 + fam.weight * 0.55 + entropyConf * 0.4 - lenPenalty);

      // Suppress extremely common false-positives (all same char)
      if (/^(.)\1+$/.test(value)) confidence *= 0.2;

      candidates.push({
        secret_type: fam.secret_type,
        confidence,
        evidence: [
          makeEvidence({
            kind: 'secret_regex_match',
            value,
            match: fam.regex.source,
            context: context,
            confidence,
          }),
          ...(url
            ? [makeEvidence({ kind: 'source_url', value: url, confidence: 0.3 })]
            : []),
        ],
        redacted_value: redactValue(value),
      });
    }
  }

  // Dedup by secret_type + redacted_value
  const seen = new Set();
  const deduped = [];
  for (const c of candidates) {
    const key = `${c.secret_type}::${c.redacted_value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(c);
  }

  return deduped;
}

if (typeof globalThis !== 'undefined') {
  globalThis.AIScannerSecrets = { extractSecretCandidates };
}

if (typeof exports !== 'undefined') {
  module.exports = { extractSecretCandidates, shannonEntropy };
}

