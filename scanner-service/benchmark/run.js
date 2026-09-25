// False-positive benchmark.
//
//   npm run benchmark                       # sites from benchmark/sites.txt
//   npm run benchmark -- a.com b.in         # or pass sites directly
//
// For every site: scans twice (stability), keeps the notice text and the pre-consent screenshot,
// then writes audit.md listing every failed check next to independent evidence a reviewer can
// use to confirm or reject it. Label each failure in labels.json and run `npm run benchmark:score`.

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { closeBrowser, scanSite } from '../src/scan.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RUNS = Number(process.env.BENCH_RUNS || 2);
const CONCURRENCY = Number(process.env.BENCH_CONCURRENCY || 3);

// Broad "could this actually be there?" searches for each notice check that claims something is
// missing. A hit does not mean the scanner was wrong, only that a human should read the passage.
const RECALL = {
  'notice-data-purpose': /personal\s+(data|information)/i,
  'notice-withdrawal': /withdraw|revok|opt[\s-]?out/i,
  'notice-board': /\bboard\b/i,
  'rights-access': /\baccess\b|copy\s+of|summary/i,
  'rights-correction-erasure': /correct|rectif|eras|delet/i,
  'rights-grievance': /grievance|complain/i,
  'rights-nomination': /nomin/i,
  'contact-officer': /officer|@|contact/i,
  'sharing-processors': /third[\s-]part|processor|service\s+provider|shar|disclos/i,
  'sharing-retention': /retain|retention|as\s+long\s+as|delet|eras/i,
  'children-consent': /child|minor|under\s+(the\s+age\s+of\s+)?\d{2}|below\s+\d{2}/i,
};

function snippets(text, regex, max = 4) {
  const out = [];
  const re = new RegExp(regex.source, 'gi');
  let match;
  while ((match = re.exec(text)) && out.length < max) {
    const start = Math.max(0, match.index - 140);
    out.push(text.slice(start, match.index + 160).replace(/\s+/g, ' ').trim());
    re.lastIndex = match.index + 300;
  }
  return out;
}

async function independentPrivacyLinks(browser, url) {
  const page = await browser.newPage();
  try {
    await page.goto(url, { waitUntil: 'load', timeout: 45_000 });
    await page.waitForTimeout(2000);
    return await page.evaluate(() => [...document.querySelectorAll('a[href]')]
      .map((a) => `${(a.innerText || '').trim().slice(0, 50)} -> ${a.href}`)
      .filter((line) => /privac|data\s*protection|gopniyata|गोपनीयता/i.test(line)).slice(0, 8));
  } catch (error) {
    return [`(could not load: ${error.message.split('\n')[0]})`];
  } finally {
    await page.close();
  }
}

async function scanTwice(site, outDir) {
  const runs = [];
  for (let i = 0; i < RUNS; i += 1) {
    try {
      runs.push(await scanSite(site, { screenshots: i === 0, includeNoticeText: i === 0 }));
    } catch (error) {
      runs.push({ error: error.message });
    }
  }
  const [first] = runs;
  if (first.screenshots?.preConsent) {
    const file = `${first.siteDomain}-preconsent.jpg`;
    await writeFile(path.join(outDir, file), Buffer.from(first.screenshots.preConsent.split(',')[1], 'base64'));
    first.screenshotFile = file;
  }
  if (first.screenshots) delete first.screenshots;
  await writeFile(path.join(outDir, `${(first.siteDomain || site).replace(/[^\w.-]/g, '_')}.json`), JSON.stringify(runs, null, 2));
  return { site, runs };
}

async function pool(items, size, fn) {
  const results = [];
  let next = 0;
  await Promise.all(Array.from({ length: size }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index]);
      console.log(`[${results.filter(Boolean).length}/${items.length}] ${items[index]}`);
    }
  }));
  return results;
}

const args = process.argv.slice(2);
const sites = args.length ? args : (await readFile(path.join(HERE, 'sites.txt'), 'utf8'))
  .split(/\r?\n/).map((line) => line.replace(/#.*/, '').trim()).filter(Boolean);
const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const outDir = path.join(HERE, 'results', stamp);
await mkdir(outDir, { recursive: true });
console.log(`Benchmarking ${sites.length} site(s), ${RUNS} run(s) each -> ${outDir}`);

const results = await pool(sites, CONCURRENCY, (site) => scanTwice(site, outDir));

// ---- aggregate ----
const perCheck = {};
const failures = [];
const blocked = [];
const helperBrowser = await chromium.launch();

for (const { site, runs } of results) {
  const [first, ...rest] = runs;
  if (first.error) { blocked.push(`${site}: ${first.error}`); continue; }
  for (const check of first.checks) {
    const row = perCheck[check.id] ||= { title: check.title, pass: 0, fail: 0, review: 0, 'not-evaluated': 0, unstable: 0, unstableSites: [] };
    row[check.status] += 1;
    const other = rest.find((run) => !run.error)?.checks.find((c) => c.id === check.id);
    if (other && other.status !== check.status) {
      row.unstable += 1;
      row.unstableSites.push(`${site} (${check.status} → ${other.status})`);
    }
    if (check.status !== 'fail') continue;
    const hints = [];
    if (RECALL[check.id] && first.noticeText) {
      const found = snippets(first.noticeText, RECALL[check.id]);
      hints.push(found.length ? `Broad search /${RECALL[check.id].source}/ found ${found.length} passage(s) — read them:` : `Broad search /${RECALL[check.id].source}/ found nothing in ${first.notice?.words} words → very likely a true failure.`);
      hints.push(...found.map((s) => `> …${s}…`));
    }
    if (['consent-banner', 'reject-parity', 'affirmative-consent'].includes(check.id) && first.screenshotFile) {
      hints.push(`Screenshot before consent: ${first.screenshotFile}`);
    }
    if (check.id === 'privacy-link') {
      const links = await independentPrivacyLinks(helperBrowser, first.finalUrl);
      hints.push(links.length ? 'Independent link search found:' : 'Independent link search found no privacy links → very likely a true failure.', ...links.map((l) => `- ${l}`));
    }
    failures.push({ key: `${first.siteDomain}:${check.id}`, site: first.siteDomain, check, hints });
  }
}
await helperBrowser.close();
await closeBrowser();

const lines = [
  `# False-positive audit — ${stamp}`,
  '',
  `${results.length - blocked.length} site(s) scanned, ${blocked.length} blocked, ${RUNS} run(s) each.`,
  '',
  '## Per check',
  '',
  '| Check | Fail | Review | Pass | Not tested | Unstable between runs |',
  '|---|---|---|---|---|---|',
  ...Object.entries(perCheck).map(([id, r]) => `| ${r.title} (\`${id}\`) | ${r.fail} | ${r.review} | ${r.pass} | ${r['not-evaluated']} | ${r.unstable}${r.unstable ? `: ${r.unstableSites.join(', ')}` : ''} |`),
  '',
  blocked.length ? `## Blocked\n\n${blocked.map((b) => `- ${b}`).join('\n')}\n` : '',
  '## Failures to verify',
  '',
  'For each one decide: **TP** (the site really has this problem) or **FP** (scanner wrong). Record it in `labels.json` as `{ "site:check-id": "TP" | "FP" }`.',
  '',
  ...failures.flatMap(({ key, check, hints }) => [
    `### ${key} — ${check.title} (${check.severity})`,
    '',
    check.detail,
    '',
    ...(check.evidence.length ? ['Scanner evidence:', ...check.evidence.slice(0, 6).map((e) => `- ${e.slice(0, 220)}`), ''] : []),
    ...(hints.length ? ['Independent check:', ...hints, ''] : []),
  ]),
];
await writeFile(path.join(outDir, 'audit.md'), lines.join('\n'));
await writeFile(path.join(outDir, 'failures.json'), JSON.stringify(failures.map(({ key, site, check }) => ({ key, site, id: check.id, severity: check.severity })), null, 2));
console.log(`\nWrote ${path.join(outDir, 'audit.md')} (${failures.length} failures to verify)`);
