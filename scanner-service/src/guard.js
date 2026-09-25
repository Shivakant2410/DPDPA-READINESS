// SSRF guard: this service drives a real browser to arbitrary URLs, so it must refuse
// targets that resolve to loopback, private, link-local or metadata addresses.
// Set ALLOW_PRIVATE_TARGETS=1 only for local development against your own staging sites.

import dns from 'node:dns/promises';
import net from 'node:net';

export class ScanError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, part) => (acc << 8) + Number(part), 0) >>> 0;
}

const PRIVATE_V4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 3],
].map(([base, bits]) => [ipv4ToInt(base), bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0]);

export function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    const value = ipv4ToInt(ip);
    return PRIVATE_V4.some(([base, mask]) => ((value & mask) >>> 0) === base);
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateAddress(mapped[1]);
    return lower === '::' || lower === '::1' || /^f[cd]/.test(lower) || /^fe[89ab]/.test(lower) || /^ff/.test(lower);
  }
  return true;
}

export async function assertPublicUrl(url) {
  let parsed;
  try { parsed = new URL(url); } catch { throw new ScanError('That is not a valid URL.'); }
  if (!/^https?:$/.test(parsed.protocol)) throw new ScanError('Only http and https URLs can be scanned.');
  if (process.env.ALLOW_PRIVATE_TARGETS === '1') return;
  const host = parsed.hostname.replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal')) {
    throw new ScanError('Internal hostnames cannot be scanned.');
  }
  let addresses;
  try {
    addresses = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  } catch {
    throw new ScanError(`Could not resolve ${host}.`);
  }
  if (addresses.some(({ address }) => isPrivateAddress(address))) {
    throw new ScanError('The target resolves to a private or internal address.');
  }
}
