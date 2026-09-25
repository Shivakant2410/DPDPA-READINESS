import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeCoverage } from '../src/findings.js';

const check = (status, area = 'Privacy notice', detail = '') => ({ status, area, severity: 'High', detail });

test('coverage counts only passed and failed checks as tested', () => {
  const c = computeCoverage([check('pass'), check('fail'), check('review'), check('not-evaluated', 'Privacy notice', 'Not tested: No privacy notice link was found on the homepage.')]);
  assert.equal(c.tested, 2);
  assert.equal(c.total, 4);
  assert.equal(c.level, 'partial');
  assert.deepEqual(c.reasons, [{ reason: 'No privacy notice link was found on the homepage.', count: 1 }]);
});

test('levels: 80% or more is full, under 50% is limited', () => {
  assert.equal(computeCoverage([check('pass'), check('pass'), check('pass'), check('pass'), check('review')]).level, 'full');
  assert.equal(computeCoverage([check('pass'), check('not-evaluated'), check('not-evaluated')]).level, 'limited');
});

test('reasons are grouped and areas summarised', () => {
  const why = 'Not tested: No privacy notice link was found on the homepage.';
  const c = computeCoverage([check('fail', 'Consent & cookies'), check('not-evaluated', 'Privacy notice', why), check('not-evaluated', 'Data principal rights', why)]);
  assert.equal(c.reasons[0].count, 2);
  assert.deepEqual(c.byArea.map((a) => [a.area, a.tested, a.total]), [['Consent & cookies', 1, 1], ['Privacy notice', 0, 1], ['Data principal rights', 0, 1]]);
});
