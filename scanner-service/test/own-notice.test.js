// Our own privacy notice must pass our own DPDP notice checks.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { analyzeNotice } from '../src/notice.js';

test('HypenSec Astra privacy notice passes its own notice checks', () => {
  const html = readFileSync(new URL('../../privacy.html', import.meta.url), 'utf8')
    .replace(/\{\{LEGAL_ENTITY\}\}/g, 'HypenSec Technologies Pvt Ltd')
    .replace(/\{\{GRIEVANCE_OFFICER\}\}/g, 'A. Sharma, Grievance Officer')
    .replace(/\{\{PRIVACY_EMAIL\}\}/g, 'privacy@hypensec.com')
    .replace(/\{\{POSTAL_ADDRESS\}\}/g, 'New Delhi, India')
    .replace(/\{\{AUDIT_RETENTION\}\}/g, 'one year')
    .replace(/\{\{HOSTING_LOCATION\}\}/g, 'India')
    .replace(/\{\{LAST_UPDATED\}\}/g, '26 September 2026');
  const main = html.slice(html.indexOf('<main'), html.indexOf('</main>'));
  const text = main.replace(/<\/(p|li|h1|h2|div)>/g, '\n').replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;/g, ' ');
  const results = analyzeNotice({ url: '/privacy.html', words: text.split(/\s+/).length }, text, []);
  const notPassing = results.filter((c) => c.status !== 'pass').map((c) => `${c.id}: ${c.status} (${c.detail})`);
  assert.deepEqual(notPassing, []);
});
