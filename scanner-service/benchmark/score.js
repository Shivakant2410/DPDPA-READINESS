// Computes false-positive rates from a labelled benchmark run.
//
//   npm run benchmark:score -- benchmark/results/<run>
//
// Reads failures.json (written by run.js) and labels.json ({ "site:check-id": "TP" | "FP" }).
// False-positive rate = FP / (TP + FP) among failed checks, overall and per check.

import { readFile } from 'node:fs/promises';
import path from 'node:path';

const dir = process.argv[2];
if (!dir) { console.error('Usage: npm run benchmark:score -- <results dir>'); process.exit(1); }
const failures = JSON.parse(await readFile(path.join(dir, 'failures.json'), 'utf8'));
const labels = JSON.parse(await readFile(path.join(dir, 'labels.json'), 'utf8'));

const byCheck = {};
let tp = 0;
let fp = 0;
const unlabelled = [];
for (const failure of failures) {
  const label = labels[failure.key];
  if (label !== 'TP' && label !== 'FP') { unlabelled.push(failure.key); continue; }
  const row = byCheck[failure.id] ||= { TP: 0, FP: 0 };
  row[label] += 1;
  if (label === 'TP') tp += 1; else fp += 1;
}

const pct = (a, b) => (b ? `${((a / b) * 100).toFixed(1)}%` : '—');
console.log(`Overall: ${fp} false positive(s) of ${tp + fp} failures = ${pct(fp, tp + fp)} false-positive rate\n`);
for (const [id, row] of Object.entries(byCheck).sort((a, b) => b[1].FP - a[1].FP)) {
  console.log(`${id.padEnd(30)} ${String(row.FP).padStart(3)} FP / ${String(row.TP + row.FP).padStart(3)} = ${pct(row.FP, row.TP + row.FP)}`);
}
if (unlabelled.length) console.log(`\n${unlabelled.length} failure(s) not labelled yet: ${unlabelled.join(', ')}`);
