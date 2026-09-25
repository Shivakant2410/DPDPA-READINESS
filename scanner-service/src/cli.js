// Scan from the terminal: npm run scan -- example.com
// Prints a readable summary and writes the full JSON (with screenshots) next to the working directory.

import { writeFile } from 'node:fs/promises';
import { closeBrowser, scanSite } from './scan.js';

const input = process.argv[2];
if (!input) {
  console.error('Usage: npm run scan -- <url>');
  process.exit(1);
}

try {
  const result = await scanSite(input);
  const file = `scan-${result.siteDomain}-${Date.now()}.json`;
  await writeFile(file, JSON.stringify(result, null, 2));

  console.log(`\n${result.finalUrl}  (${(result.durationMs / 1000).toFixed(1)}s)`);
  console.log(`Banner: ${result.banner ? `${result.banner.cmp} ${JSON.stringify(result.banner.buttons)}` : 'none'}`);
  console.log(`Score: ${result.score ?? 'n/a'}  ${JSON.stringify(result.summary)}\n`);
  for (const check of result.checks) {
    console.log(`[${check.status.toUpperCase().padEnd(13)}] ${check.severity.padEnd(6)} ${check.title}`);
    console.log(`    ${check.detail}`);
    for (const line of check.evidence.slice(0, 6)) console.log(`      - ${line}`);
  }
  console.log(`\nFull result: ${file}`);
} catch (error) {
  console.error(`Scan failed: ${error.message}`);
  process.exitCode = 1;
} finally {
  await closeBrowser();
}
