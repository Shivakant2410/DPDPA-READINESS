import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeNotice, detectLanguage } from '../src/notice.js';

const GDPR_ERA = `Privacy Policy
Last updated: 12 March 2020
We collect your name, email address, phone number and IP address when you contact us.
We use this information to respond to your enquiries and to improve our services.
We may share your information with trusted service providers who process data on our behalf.
We retain personal data for as long as necessary to fulfil the purposes described.
Your rights
Under the GDPR you have the right to access, rectify or erase your personal data.
You can opt out of marketing emails at any time.
Our services are not directed to children under 13.
Contact us at privacy@example.com with any questions.`;

const DPDP = `Privacy Notice
Last updated: 10 January 2026
This notice is issued under the Digital Personal Data Protection Act, 2023.
We process your name, email, mobile number and device information for the purposes of account creation and order delivery.
You may withdraw your consent at any time from Settings, as easily as you gave it.
You have the right to obtain a summary of your personal data and the processing activities.
You may request correction, completion, updating or erasure of your personal data.
You may nominate any other individual to exercise your rights in the event of death or incapacity.
Grievance Officer: Asha Rao, grievance@shop.in, +91 9876543210. We respond within 30 days.
If you are not satisfied, you may complain to the Data Protection Board of India.
Our Data Protection Officer can be reached at dpo@shop.in.
We share data with payment processors and delivery partners under contract.
We retain data until the purpose is served, then erase it unless required by law.
We do not knowingly process data of children below 18 without verifiable consent of a parent or lawful guardian.
We use Google Analytics to measure traffic.`;

const VENDORS = [{ vendor: 'Google Analytics', category: 'analytics' }, { vendor: 'Hotjar', category: 'session-replay' }];
const NOTICE = { url: 'https://example.com/privacy', words: 120 };

function statuses(text) {
  return Object.fromEntries(analyzeNotice(NOTICE, text, VENDORS).map((check) => [check.id, check.status]));
}

test('GDPR-era notice fails the DPDP-specific requirements', () => {
  assert.deepEqual(statuses(GDPR_ERA), {
    'notice-data-purpose': 'pass',
    'notice-withdrawal': 'review', // only "opt out of marketing"
    'notice-board': 'fail',
    'notice-dpdp-current': 'review', // dated 2020, cites GDPR
    'rights-access': 'pass',
    'rights-correction-erasure': 'pass', // "right to access, rectify or erase"
    'rights-grievance': 'fail',
    'rights-nomination': 'fail',
    'contact-officer': 'review', // general contact, no named officer
    'sharing-processors': 'pass',
    'sharing-retention': 'pass',
    'sharing-undisclosed-vendors': 'review',
    'children-consent': 'fail', // age 13, DPDP child = under 18
  });
});

test('DPDP-aligned notice passes', () => {
  const result = statuses(DPDP);
  for (const [id, status] of Object.entries(result)) {
    if (id === 'sharing-undisclosed-vendors') continue;
    assert.equal(status, 'pass', `${id} should pass`);
  }
  assert.equal(result['sharing-undisclosed-vendors'], 'review'); // Hotjar is not named
});

// Each line below was wrongly treated as a pass on a real site (OneTrust, BBC).
test('look-alike wording from GDPR and CCPA notices does not pass DPDP checks', () => {
  const text = `Privacy Notice
You may lodge a complaint with the European Data Protection Board or your local supervisory authority.
Our use of cookies in our marketing operations is based on the choices you make, and you may want to know more.
You may nominate an authorised agent to make a request on your behalf.
We reserve the right to access, read, preserve, and disclose any personal information as necessary to comply with law.`;
  const result = statuses(text);
  assert.equal(result['notice-board'], 'fail');
  assert.equal(result['rights-access'], 'fail');
  assert.equal(result['rights-nomination'], 'review');
});

test('contact a few lines below the officer sentence is found', () => {
  const text = `Complaints and Grievance Redressal
Any complaints or concerns regarding your Personal Information shall be addressed to the Grievance Officer.
Name: A. Kumar
Designation: Grievance Officer
Address: Bengaluru
Working hours: 10am to 6pm
E-mail: dpo@example.in`;
  const result = statuses(text);
  assert.equal(result['rights-grievance'], 'pass');
  assert.equal(result['contact-officer'], 'pass');
});

// Benchmark false positives: phonepe.com (portal link) and zerodha.com (officer named, no contact).
test('a support link counts as a contact; a named officer alone is partial', () => {
  const portal = statuses('Contact Us\nIn case you have any questions you may write to our Privacy Officer using this link https://support.example.com We answer within a reasonable time.');
  assert.equal(portal['contact-officer'], 'pass');
  const nameOnly = statuses('The designated Data Protection Officer shall be Mr A. Kumar.\nWe may update this policy.');
  assert.equal(nameOnly['contact-officer'], 'review');
});

// Benchmark false passes on groww.in and cred.club.
test('rights and Board checks need the real thing, not look-alike wording', () => {
  const text = `Terms
Groww is registered with the Securities and Exchange Board of India as a stock broker.
You can also choose to enable Our access to one or more of Your email accounts by connecting such accounts.
You retain the right to revoke the aforementioned access by amending access permissions within your device settings.`;
  const result = statuses(text);
  assert.equal(result['notice-board'], 'fail');
  assert.equal(result['rights-access'], 'fail');
  assert.equal(result['rights-correction-erasure'], 'fail');
});

// Benchmark false positives on zerodha.com, freshworks.com and swiggy.com.
test('obfuscated email, complaint route and "your data to be deleted" are recognised', () => {
  const zerodha = statuses('The designated Data Protection Officer shall be Mr S. Mukherjee.\nUsers are required to write to legal[@]zerodha[.]com.');
  assert.equal(zerodha['contact-officer'], 'pass');
  const freshworks = statuses('If you have a concern about any aspect of our privacy practices, please contact us using the details in section 18.');
  assert.equal(freshworks['rights-grievance'], 'review');
  const swiggy = statuses('If you do not want us to use your personal information in the manner provided in this Policy or you want your data to be deleted, please write to us at support@swiggy.in.');
  assert.notEqual(swiggy['rights-correction-erasure'], 'fail');
  // A complaint to a regulator is not a route to the company.
  const regulator = statuses('You also have the right to complain to a data protection authority in your Member State.');
  assert.equal(regulator['rights-grievance'], 'fail');
});

// Benchmark false positives in the after run: hdfc.bank.in, phonepe.com, byjus.com.
test('correction and erasure phrased as "shall be able to", "wish to" and "a way for you to" are found', () => {
  const hdfc = statuses('You shall be able to review the Data that you had provided and correct or amend as feasible any such Data which you find to be inaccurate. Personal data requests are handled by us.');
  assert.notEqual(hdfc['rights-correction-erasure'], 'fail');
  const phonepe = statuses('In case you wish to delete your account or Personal Information, please use the Help section.');
  assert.notEqual(phonepe['rights-correction-erasure'], 'fail');
  const byjus = statuses('We will provide you with the means to ensure that your Personal Information is correct. We will provide an obvious way for you to access and change your personal information.');
  assert.notEqual(byjus['rights-correction-erasure'], 'fail');
});

test('account deletion counts as erasure, but logging into your account is not an access right', () => {
  const groww = statuses('Account Deletion: You may choose to delete your account on the Platform (i.e. the website https://groww.in and/or the mobile application) and data associated with it.');
  assert.notEqual(groww['rights-correction-erasure'], 'fail');
  const login = statuses('You can access your account using your password.');
  assert.equal(login['rights-access'], 'fail');
});

// Found by comparing with Netras.GRC reports (comolho.com, openai.com policy for chatgpt.com).
test('retention needs a period, rights bullets need data, and "Date :" / "Updated:" are dates', () => {
  const comolho = statuses('Date : 03rd July 2024\nCom Olho Privacy Policy\nAgreements cover:\nSubprocessor management\nData retention and deletion requirements\nThe Digital Personal Data Protection Act, 2023 applies.');
  assert.equal(comolho['sharing-retention'], 'fail');
  const dated = analyzeNotice(NOTICE, 'Date : 03rd July 2024\nThis notice is issued under the Digital Personal Data Protection Act, 2023.', []).find((c) => c.id === 'notice-dpdp-current');
  assert.equal(dated.status, 'pass');
  assert.match(dated.evidence.join(' '), /03rd July 2024/);
  const openai = statuses('[中文 (香港)] Updated: 30 July 2026\nYour rights\nAccess your Personal Data and information relating to how it is processed.\nLodge a complaint with your local data protection authority.');
  assert.equal(openai['rights-access'], 'pass');
  assert.equal(openai['rights-correction-erasure'], 'fail'); // "Updated: 30 July" is not the right to update
  assert.equal(openai['rights-grievance'], 'fail'); // a regulator is not a route to the company
  // A copy of a contract is not the right to access your data (comolho.com).
  const dpa = statuses('Customers may request a copy of the applicable Data Processing Agreement by contacting Com Olho.');
  assert.equal(dpa['rights-access'], 'fail');
});

test('evidence quotes the sentence that was relied on', () => {
  const check = analyzeNotice(NOTICE, GDPR_ERA, []).find((c) => c.id === 'children-consent');
  assert.match(check.evidence[0], /^"Our services are not directed to children under 13\."$/);
});

test('unreadable notice is not evaluated rather than failed', () => {
  const checks = analyzeNotice({ url: 'https://example.com/privacy.pdf', error: 'PDF' }, '', VENDORS);
  assert.ok(checks.length > 0);
  assert.ok(checks.every((check) => check.status === 'not-evaluated'));
});

test('language detection', () => {
  assert.equal(detectLanguage(DPDP), 'en');
  assert.equal(detectLanguage('यह गोपनीयता नीति डिजिटल व्यक्तिगत डेटा संरक्षण अधिनियम के अंतर्गत जारी की गई है।'), 'hi');
});

test('a confirmed missing notice fails the notice checks; an unreadable one stays not tested', () => {
  const missing = analyzeNotice({ missing: true, checked: ['homepage links', 'https://x.in/privacy-policy'], error: 'No privacy notice was found on this site.' }, '', []);
  assert.ok(missing.length > 0);
  assert.ok(missing.every((c) => c.status === 'fail'));
  assert.match(missing[0].evidence[0], /privacy-policy/);
  const unreadable = analyzeNotice({ url: 'https://x.in/privacy.pdf', error: 'The privacy notice is a PDF, which is not analysed yet.' }, '', []);
  assert.ok(unreadable.every((c) => c.status === 'not-evaluated'));
});

test('retention periods written in words count ("for one year", "three years")', () => {
  assert.equal(statuses('We retain scan records in our audit log for one year, then erase them.')['sharing-retention'], 'pass');
  assert.equal(statuses('Personal data is kept for three years after your last transaction.')['sharing-retention'], 'pass');
});
