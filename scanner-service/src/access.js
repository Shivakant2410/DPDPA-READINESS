// Access control for the public service: access keys, rate limits and the scan audit log.
//
// ACCESS_KEYS="alice:long-random-secret,bob:another-secret"  (label:secret pairs; labels go in the log)
// Keys are compared by SHA-256 digest with timingSafeEqual, so response time does not leak them.

import crypto from 'node:crypto';
import { appendFile, mkdir } from 'node:fs/promises';
import path from 'node:path';

const digest = (value) => crypto.createHash('sha256').update(String(value)).digest();

export function parseAccessKeys(raw = '') {
  return raw.split(',').map((entry) => entry.trim()).filter(Boolean).map((entry, index) => {
    const at = entry.indexOf(':');
    const label = at > 0 ? entry.slice(0, at).trim() : `key${index + 1}`;
    const secret = at > 0 ? entry.slice(at + 1).trim() : entry;
    if (secret.length < 16) throw new Error(`Access key "${label}" is shorter than 16 characters.`);
    return { label, digest: digest(secret) };
  });
}

/** Returns the key's label, or null. Checks every key so timing does not reveal which matched. */
export function matchAccessKey(keys, presented) {
  if (!presented) return null;
  const given = digest(presented);
  let label = null;
  for (const key of keys) {
    if (crypto.timingSafeEqual(key.digest, given)) label = key.label;
  }
  return label;
}

/** Sliding-window limiter: at most `limit` events per `windowMs` for each id. In memory. */
export function createRateLimiter({ limit, windowMs }) {
  const events = new Map();
  return {
    take(id, now = Date.now()) {
      const recent = (events.get(id) || []).filter((t) => now - t < windowMs);
      if (recent.length >= limit) {
        events.set(id, recent);
        return { ok: false, retryAfterSeconds: Math.ceil((windowMs - (now - recent[0])) / 1000) };
      }
      recent.push(now);
      events.set(id, recent);
      return { ok: true, remaining: limit - recent.length };
    },
  };
}

/** Appends one JSON line per event. The Rules expect processing logs to be kept for a year. */
export function createAuditLog(file) {
  let ready = null;
  return async (entry) => {
    if (!file) return;
    ready ||= mkdir(path.dirname(file), { recursive: true });
    await ready;
    await appendFile(file, `${JSON.stringify({ time: new Date().toISOString(), ...entry })}\n`).catch((error) => {
      console.error(`Audit log write failed: ${error.message}`);
    });
  };
}

export function clientIp(req, trustProxy) {
  if (trustProxy) {
    const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (forwarded) return forwarded;
  }
  return req.socket.remoteAddress || 'unknown';
}
