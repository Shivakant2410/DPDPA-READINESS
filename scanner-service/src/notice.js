// Privacy notice analysis: checks the text of the site's privacy notice against what the
// DPDP Act 2023 requires it to say, sentence by sentence, and quotes the sentence it relied on.
//
// Pure functions only (no browser), so this file can be tested with plain text.
// English notices only; anything else is reported as not evaluated rather than guessed.

const LEGAL = {
  notice: 'DPDP Act 2023, s.5(1): the notice must describe the personal data and the purpose of processing, how to exercise the rights under s.6(4) and s.13, and how to complain to the Board.',
  withdraw: 'DPDP Act 2023, s.5(1)(ii) and s.6(4): the notice must explain how to withdraw consent, and withdrawing must be as easy as giving consent.',
  board: 'DPDP Act 2023, s.5(1)(iii): the notice must explain how to make a complaint to the Data Protection Board of India.',
  access: 'DPDP Act 2023, s.11: right to obtain a summary of personal data processed and the processing activities, and the identities of those it was shared with.',
  correction: 'DPDP Act 2023, s.12: right to correction, completion, updating and erasure of personal data.',
  grievance: 'DPDP Act 2023, s.13 and s.8(10): right to grievance redressal; the Data Fiduciary must run an effective grievance mechanism.',
  nomination: 'DPDP Act 2023, s.14: right to nominate another person to exercise rights in the event of death or incapacity.',
  contact: 'DPDP Act 2023, s.8(9): publish the business contact of a Data Protection Officer, or of a person who can answer questions about processing.',
  sharing: 'DPDP Act 2023, s.8(2) and s.11(1)(b): processors may only be engaged under a valid contract, and Data Principals are entitled to know who their data was shared with.',
  retention: 'DPDP Act 2023, s.8(7): personal data must be erased once the purpose is no longer served or consent is withdrawn, unless retention is required by law.',
  children: 'DPDP Act 2023, s.2(f) and s.9: a child is anyone under 18; processing needs verifiable parental consent, and tracking, behavioural monitoring and targeted advertising directed at children are prohibited.',
};

// ---------- text utilities ----------

export function splitSentences(text) {
  const out = [];
  for (const rawLine of text.split(/\n+/)) {
    const line = rawLine.replace(/\s+/g, ' ').trim();
    if (line.length < 3) continue;
    for (const part of line.split(/(?<=[.!?;])\s+(?=["'(“]?[A-Z0-9])/)) {
      const sentence = part.trim();
      if (sentence.length >= 3) out.push(sentence);
    }
  }
  return out;
}

const isHeading = (s) => s.length < 90 && !/[.!?]$/.test(s);

function quote(sentences, index) {
  const sentence = sentences[index].slice(0, 260) + (sentences[index].length > 260 ? '…' : '');
  // Give short bullet lines their heading, e.g. "[Your rights] Erasure of your data".
  if (sentence.length < 80) {
    // Walk up through the bullet list only; stop at the first full sentence.
    for (let i = index - 1; i >= Math.max(0, index - 4); i -= 1) {
      if (isHeading(sentences[i])) return `[${sentences[i].slice(0, 60)}] ${sentence}`;
      if (sentences[i].length >= 80 || /[.!?]$/.test(sentences[i])) break;
    }
  }
  return sentence;
}

/**
 * Find the first sentence matching `primary`. If `near` is given it must match the sentence
 * itself or one of the `window` lines before it (a heading such as "Your rights").
 */
function find(sentences, primary, { near = null, window = 3, reject = null, where = null } = {}) {
  for (let i = 0; i < sentences.length; i += 1) {
    if (!primary.test(sentences[i])) continue;
    if (reject && reject.test(sentences[i])) continue;
    if (near) {
      const context = sentences.slice(Math.max(0, i - window), i + 1).join(' ');
      if (!near.test(context)) continue;
    }
    if (where && !where(i)) continue;
    return { index: i, quote: quote(sentences, i) };
  }
  return null;
}

const EMAIL = /[\w.+-]+@[\w-]+(\.[\w-]+)+/;
// A support or grievance portal is a valid channel ("write to our Privacy Officer using https://support.phonepe.com").
const CONTACT_URL = /https?:\/\/[^\s)"']*(support|contact|grievance|complain|help|privacy|dpo|feedback)[^\s)"']*/i;
// Spam-proofed addresses: "legal[@]zerodha[.]com", "privacy (at) example (dot) in" (zerodha.com).
const OBFUSCATED_EMAIL = /[\w.+-]+\s*(\[@\]|\(@\)|\[at\]|\(at\)|\s+at\s+)\s*[\w-]+(\s*(\[\.\]|\(\.\)|\[dot\]|\(dot\)|\s+dot\s+|\.)\s*[\w-]+)+/i;
const PHONE =/(\+91[\s-]?)?\b[6-9]\d{9}\b|\b0\d{2,4}[\s-]?\d{6,8}\b|\b1800[\s-]?\d{3}[\s-]?\d{4}\b/;

// Contact blocks often sit a few lines under the sentence naming the officer
// ("…addressed to the Grievance Officer below." / Name / Designation / E-mail: …).
function contactNear(sentences, index, span = 8) {
  const context = sentences.slice(Math.max(0, index - 1), index + span + 1).join(' ');
  return context.match(EMAIL)?.[0] || context.match(OBFUSCATED_EMAIL)?.[0] || context.match(PHONE)?.[0] || context.match(CONTACT_URL)?.[0] || null;
}

// The company's own rights ("We reserve the right to access… or delete…") are not Data Principal rights.
const OWN_RIGHT = /\b(we|us|our\s+company)\s+(\w+\s+){0,2}(reserve|retain|have)\s+(all\s+)?(the\s+)?rights?\b|\bour\s+rights?\b/i;

// A right expressed as something the reader can do, not just the verb appearing somewhere.
function rightPattern(verbs, extraObjects = '') {
  // The verb must act on the person's data: "access your personal data", not "enable Our access to
  // your email accounts" (groww.in) or "revoke the aforementioned access by amending permissions" (cred.club).
  const onData = String.raw`(${verbs})\w*\b[^.;]{0,70}\b(personal\s+)?(data|information|details|records${extraObjects})\b`;
  return new RegExp([
    // Words between the cue and the verb may carry commas and slashes: "right to access, rectify or erase".
    String.raw`\bright\w*\s+(to|of)\s+([\w,/'-]+\s+){0,8}${onData}`,
    // "you shall be able to review … and correct" (hdfc.bank.in), "you wish to delete your account or Personal Information" (phonepe.com)
    String.raw`\b(you|data principals?|users?|individuals?)\s+(may|can|could|have\s+the\s+right\s+to|are\s+entitled\s+to|shall\s+have\s+the\s+right\s+to|(shall|will|would)\s+be\s+able\s+to|are\s+able\s+to|wish\s+to|want\s+to|would\s+like\s+to)\s+([\w,/'-]+\s+){0,8}${onData}`,
    // "we will provide an obvious way for you to access and change" (byjus.com)
    String.raw`\b(way|means|option|ability)\s+for\s+you\s+to\s+([\w,/'-]+\s+){0,8}${onData}`,
    String.raw`\b(request|ask|write\s+to)\s+(us\s+)?(to\s+)?([\w,/'-]+\s+){0,8}${onData}`,
    // Data before the verb: "if you want your data to be deleted, write to support@…" (swiggy.com).
    String.raw`\b(want|wish|would\s+like|request|ask)\b[^.;]{0,40}\b(data|information|account|details)\b[^.;]{0,20}\b(${verbs})`,
    // Bullet in a rights list that starts with the verb and acts on data: "Access your Personal Data and
    // information relating to how it is processed." (openai.com). A bare verb no longer counts, so
    // "Updated: 30 July 2026" is not the right to update.
    String.raw`^\W*(right\s+to\s+)?(${verbs})\w*\b[^.;:]{0,40}\b(your|the|their|such|any)?\s*(personal\s+)?(data|information|details|records${extraObjects})\b.{0,160}$`,
  ].join('|'), 'i');
}

// ---------- individual checks ----------

const DATA_CATEGORIES = [
  ['name', /\b(full\s+)?name\b/i], ['email', /\be-?mail\b/i], ['phone', /\b(phone|mobile|telephone)\b/i],
  ['postal address', /(?<!(e-?mail|ip|web|url|internet|mac)\s)\baddress\b(?!\s+(this|these|the|any|your\s+(concerns|queries)))/i],
  ['date of birth', /\b(date\s+of\s+birth|\bdob\b|\bage\b)/i], ['IP address', /\bip\s+address/i],
  ['device information', /\bdevice\s+(id|identifier|information|data|type)/i], ['location', /\blocation\b/i],
  ['payment details', /\b(payment|card|bank\s+account|upi)\b/i], ['government ID', /\b(aadhaar|pan\s+card|passport|voter\s+id|driving\s+licen[cs]e)\b/i],
  ['cookies and usage data', /\b(cookies?|usage\s+data|browsing)\b/i],
];
const PURPOSE = /\b(we|may|will)\s+(\w+\s+){0,3}(use|process|collect)\w*\b.{0,120}\b(to|for)\b|\bpurposes?\s+(of|for)\b|\bused\s+(to|for)\b|\bprocess\w*\s+.{0,60}\bfor\s+the\s+following\b/i;

function checkDataAndPurpose(sentences) {
  const text = sentences.join('\n');
  const categories = DATA_CATEGORIES.filter(([, re]) => re.test(text)).map(([label]) => label);
  const purpose = find(sentences, PURPOSE, { near: /personal\s+(data|information)|information|data/i });
  const itemised = categories.length >= 3;
  const status = itemised && purpose ? 'pass' : itemised || purpose ? 'review' : 'fail';
  return {
    id: 'notice-data-purpose', controlId: 'DPDP-NOTICE-002', area: 'Privacy notice', severity: 'High', status,
    title: 'Notice lists the personal data and why it is used',
    detail: status === 'pass'
      ? `The notice names ${categories.length} categories of personal data and explains what they are used for.`
      : status === 'review'
        ? `${itemised ? 'Data categories are listed' : `Only ${categories.length} data categor${categories.length === 1 ? 'y is' : 'ies are'} named`}${purpose ? ' and a purpose is described' : ', but no sentence explains the purpose of processing'}. Confirm each item of data is linked to its purpose.`
        : 'The notice neither itemises the personal data collected nor explains the purposes.',
    evidence: [`Data categories named: ${categories.join(', ') || 'none found'}`, ...(purpose ? [`Purpose: "${purpose.quote}"`] : [])],
    legal: LEGAL.notice,
    fix: 'List each item of personal data you collect (for example name, email, phone, IP address) next to the specific purpose it is used for.',
    verify: 'Read the notice as a visitor: can you tell what data is collected and why, item by item?',
  };
}

function checkWithdrawal(sentences) {
  const withdraw = find(sentences, /\b(withdraw\w*|revok\w*)\b/i, { near: /consent/i, window: 2 });
  const optOut = withdraw ? null : find(sentences, /\bopt[\s-]?out\b|\bunsubscribe\b/i);
  return {
    id: 'notice-withdrawal', controlId: 'DPDP-NOTICE-003', area: 'Privacy notice', severity: 'High',
    status: withdraw ? 'pass' : optOut ? 'review' : 'fail',
    title: 'Notice explains how to withdraw consent',
    detail: withdraw
      ? 'The notice explains that consent can be withdrawn.'
      : optOut
        ? 'The notice mentions opting out or unsubscribing, but not withdrawing consent to processing in general.'
        : 'The notice does not explain how to withdraw consent.',
    evidence: [withdraw || optOut].filter(Boolean).map((m) => `"${m.quote}"`),
    legal: LEGAL.withdraw,
    fix: 'State that consent can be withdrawn at any time, and give the exact way to do it (for example a link, settings page, or email address).',
    verify: 'Follow the withdrawal steps in the notice and confirm they work in one or two actions.',
  };
}

function checkBoard(sentences) {
  // Not the European Data Protection Board (EDPB), which GDPR notices mention.
  // Only the Data Protection Board itself. "Board of India" alone matched SEBI on groww.in.
  const board = find(sentences, /(?<!european\s)data\s+protection\s+board(?!\s*\(EDPB\))|\bDPBI\b/i, { reject: /european\s+data\s+protection\s+board|\bEDPB\b/i });
  return {
    id: 'notice-board', controlId: 'DPDP-NOTICE-004', area: 'Privacy notice', severity: 'Medium',
    status: board ? 'pass' : 'fail',
    title: 'Notice explains how to complain to the Data Protection Board',
    detail: board
      ? 'The notice tells readers they can complain to the Data Protection Board of India.'
      : 'The notice does not mention the Data Protection Board of India. This is common in notices written for GDPR or older Indian rules.',
    evidence: board ? [`"${board.quote}"`] : [],
    legal: LEGAL.board,
    fix: 'Add a sentence explaining that, after using your grievance process, the reader may complain to the Data Protection Board of India, with a link to the Board.',
    verify: 'Search the notice for "Data Protection Board".',
  };
}

function checkDpdpCurrency(sentences) {
  const text = sentences.join('\n');
  const dpdp = find(sentences, /digital\s+personal\s+data\s+protection|\bDPDP(A)?\b/i);
  // Also "Updated: 30 July 2026" (openai.com) and "Date : 03rd July 2024" (comolho.com).
  const updated = text.match(/(last\s+(updated|revised|modified|amended)|effective\s+(date|from)|updated\s+on|date\s+of\s+last\s+revision|\bupdated(?=\s*:)|^\s*date(?=\s*:))\s*(on|:|-|–)?\s*([^\n]{0,40}\b(19|20)\d{2}\b)/im);
  const updatedYear = updated?.[5]?.match(/\b(19|20)\d{2}\b/)?.[0];
  const legacy = [
    /\bgdpr\b|general\s+data\s+protection\s+regulation/i.test(text) && 'GDPR',
    /sensitive\s+personal\s+data\s+or\s+information|\bSPDI\b|reasonable\s+security\s+practices\s+and\s+procedures/i.test(text) && 'IT (SPDI) Rules 2011',
    /\bccpa\b|california\s+consumer/i.test(text) && 'CCPA',
  ].filter(Boolean);
  const stale = updatedYear && Number(updatedYear) < 2023;
  const status = dpdp && !stale ? 'pass' : 'review';
  return {
    id: 'notice-dpdp-current', controlId: 'DPDP-NOTICE-005', area: 'Privacy notice', severity: 'Low', status,
    confidence: 'medium',
    title: 'Notice has been updated for the DPDP Act',
    detail: dpdp
      ? stale ? `The notice mentions the DPDP Act but says it was last updated in ${updatedYear}. Check it reflects the Act and the 2025 Rules.` : 'The notice refers to the DPDP Act.'
      : `The notice does not mention the DPDP Act${legacy.length ? ` and refers to ${legacy.join(' and ')}` : ''}${updatedYear ? `; it was last updated in ${updatedYear}` : ''}. It may predate the Act.`,
    evidence: [
      ...(dpdp ? [`"${dpdp.quote}"`] : []),
      ...(updatedYear ? [`Last updated: "${updated[0].trim().slice(0, 80)}"`] : ['No "last updated" date found.']),
      ...(legacy.length ? [`Refers to: ${legacy.join(', ')}`] : []),
    ],
    legal: LEGAL.notice,
    fix: 'Review the notice against the DPDP Act 2023 and DPDP Rules 2025, and show the date it was last updated.',
    verify: 'Check the notice\'s "last updated" date and whether it mentions the DPDP Act.',
  };
}

function checkAccess(sentences) {
  // "know" and bare "confirm" matched unrelated sentences ("based on the choices you make…"), so only
  // accept verbs that describe getting information about one's own data.
  const access = find(sentences, rightPattern(String.raw`access|obtain|a\s+copy|summary|confirm\w*\s+(whether|what|if)`), { near: /\brights?\b|request|personal\s+(data|information)/i, window: 4, reject: new RegExp(`\\bcookies?\\b|\\bagreements?\\b|\\bcontracts?\\b|${OWN_RIGHT.source}`, 'i') });
  return {
    id: 'rights-access', controlId: 'DPDP-RIGHTS-001', area: 'Data principal rights', severity: 'Medium',
    status: access ? 'pass' : 'fail',
    title: 'Right to access information is explained',
    detail: access ? 'The notice explains how to obtain information about the personal data being processed.' : 'The notice does not explain the right to obtain a summary of personal data and how it is processed.',
    evidence: access ? [`"${access.quote}"`] : [],
    legal: LEGAL.access,
    fix: 'Explain that Data Principals can request a summary of their personal data, the processing done, and who it was shared with, and how to make that request.',
    verify: 'Submit an access request through the channel in the notice and time the response.',
  };
}

function checkCorrectionErasure(sentences) {
  // No "near rights/request" guard: rightPattern already requires the verb to act on the person's
  // data, and the guard missed hdfc.bank.in's "you shall be able to review … and correct … Data".
  const correction = find(sentences, rightPattern(String.raw`correct|rectif|updat|complet|amend|change|edit|modif`), { reject: OWN_RIGHT });
  // Deleting your account counts as erasure ("You may choose to delete your account…", groww.in).
  const erasure = find(sentences, rightPattern(String.raw`eras|delet|remov`, '|account'), { reject:new RegExp(`\\bcookies?\\b.{0,40}\\b(browser|settings)\\b|${OWN_RIGHT.source}`, 'i') });
  const status = correction && erasure ? 'pass' : correction || erasure ? 'review' : 'fail';
  return {
    id: 'rights-correction-erasure', controlId: 'DPDP-RIGHTS-002', area: 'Data principal rights', severity: 'High', status,
    title: 'Rights to correction and erasure are explained',
    detail: status === 'pass' ? 'The notice explains both correction and erasure rights.'
      : status === 'review' ? `The notice explains ${correction ? 'correction' : 'erasure'} but not ${correction ? 'erasure' : 'correction'}.`
        : 'The notice does not explain how to correct or erase personal data.',
    evidence: [correction && `Correction: "${correction.quote}"`, erasure && `Erasure: "${erasure.quote}"`].filter(Boolean),
    legal: LEGAL.correction,
    fix: 'Explain how Data Principals can correct, complete, update and erase their personal data, and how to request it.',
    verify: 'Submit a correction and an erasure request and confirm they are completed.',
  };
}

function checkGrievance(sentences) {
  const grievance = find(sentences, /\bgrievances?\b/i);
  const contact = grievance ? contactNear(sentences, grievance.index) : null;
  // No "grievance" wording, but a route for complaints to the company itself: partial, not absent.
  // (freshworks.com: "If you have a concern about any aspect of our privacy practices… contact us".)
  const complaintRoute = grievance ? null : find(sentences, /\b(complaints?|concerns?)\b[^.;]{0,120}\b(contact\s+us|write\s+to|e-?mail|reach\s+(out|us)|let\s+us\s+know)\b/i,
    { reject: /supervisory\s+authority|data\s+protection\s+authority|commissioner/i });
  const status = grievance && contact ? 'pass' : grievance || complaintRoute ? 'review' : 'fail';
  return {
    id: 'rights-grievance', controlId: 'DPDP-RIGHTS-003', area: 'Data principal rights', severity: 'High', status,
    title: 'Grievance redressal channel is published',
    detail: status === 'pass' ? `The notice describes a grievance process with a contact (${contact}).`
      : grievance ? 'The notice mentions grievances but no email, phone number or contact link was found next to it.'
        : complaintRoute ? 'The notice says how to raise privacy concerns with you, but does not describe a grievance officer or redressal process.'
          : 'The notice does not describe how to raise a grievance.',
    evidence: grievance ? [`"${grievance.quote}"`, ...(contact ? [`Contact found: ${contact}`] : [])] : complaintRoute ? [`"${complaintRoute.quote}"`] : [],
    legal: LEGAL.grievance,
    fix: 'Name a grievance officer or team, give an email address and phone number, and state how quickly grievances are answered.',
    verify: 'Send a test grievance to the published contact and record the response time.',
  };
}

function checkNomination(sentences) {
  // DPDP nomination is for death or incapacity. "Nominate an authorised agent" is a CCPA right.
  const nominate = find(sentences, /\bnominat\w*/i, { near: /death|deceased|incapacit|unsound\s+mind|infirmity/i, window: 2 });
  const otherNomination = nominate ? null : find(sentences, /\bnominat\w*/i);
  const status = nominate ? 'pass' : otherNomination ? 'review' : 'fail';
  return {
    id: 'rights-nomination', controlId: 'DPDP-RIGHTS-004', area: 'Data principal rights', severity: 'Medium',
    status,
    title: 'Right to nominate is explained',
    detail: status === 'pass' ? 'The notice explains the right to nominate someone in the event of death or incapacity.'
      : status === 'review' ? 'The notice mentions nominating someone, but not for death or incapacity as the DPDP Act provides (for example a CCPA "authorised agent").'
        : 'The notice does not mention the right to nominate someone to exercise rights on the Data Principal\'s behalf. This right is specific to the DPDP Act and is usually missing from older notices.',
    evidence: [nominate || otherNomination].filter(Boolean).map((m) => `"${m.quote}"`),
    legal: LEGAL.nomination,
    fix: 'Explain that Data Principals may nominate another person to exercise their rights in the event of death or incapacity, and how to do so.',
    verify: 'Search the notice for "nominate".',
  };
}

function checkContact(sentences) {
  const officer = find(sentences, /data\s+protection\s+officer|\bDPO\b|privacy\s+officer|grievance\s+officer|nodal\s+officer/i);
  // Prefer a "contact us" line that actually has an email or phone next to it.
  const general = /\b(contact\s+us|questions?|queries|concerns?)\b/i;
  const contactLine = officer
    || find(sentences, general, { where: (i) => Boolean(contactNear(sentences, i, 1)) })
    || find(sentences, general, { near: /privacy|personal\s+(data|information)/i });
  const contact = contactLine ? contactNear(sentences, contactLine.index) : null;
  // A named officer without contact details is partial, not absent (zerodha.com names its DPO only).
  const status = officer && contact ? 'pass' : contact || officer ? 'review' : 'fail';
  return {
    id: 'contact-officer', controlId: 'DPDP-SECURITY-003', area: 'Governance & security', severity: 'Medium', status,
    title: 'Privacy contact person is published',
    detail: status === 'pass' ? `The notice names a responsible officer with a contact (${contact}).`
      : status === 'review' ? (contact
        ? `A general contact (${contact}) is given, but no Data Protection Officer or named person responsible for privacy questions.`
        : 'A privacy or grievance officer is named, but no email, phone number or contact link was found next to the name.')
        : 'No contact for privacy questions was found in the notice.',
    evidence: contactLine ? [`"${contactLine.quote}"`, ...(contact ? [`Contact found: ${contact}`] : [])] : [],
    legal: LEGAL.contact,
    fix: 'Publish the name or designation, email and phone of your Data Protection Officer or the person who answers privacy questions.',
    verify: 'Email the published contact with a privacy question and record the reply.',
  };
}

const PARTIES = String.raw`third[\s-]part\w*|processors?|service\s+providers?|vendors?|partners?|affiliates?|group\s+compan\w*|contractors?`;
function checkSharing(sentences) {
  const sharing = find(sentences, new RegExp(String.raw`\b(shar\w*|disclos\w*|transfer\w*|provid\w*|mak\w+\s+available)\b.{0,120}\b(${PARTIES})\b|\b(${PARTIES})\b.{0,120}\b(shar\w*|disclos\w*|access\w*|process\w*\s+(on\s+our\s+behalf|your))`, 'i'));
  return {
    id: 'sharing-processors', controlId: 'DPDP-SHARING-001', area: 'Data handling & sharing', severity: 'Medium',
    status: sharing ? 'pass' : 'fail',
    title: 'Sharing with processors and third parties is disclosed',
    detail: sharing ? 'The notice explains that personal data is shared with third parties or processors.' : 'The notice does not say whether personal data is shared with third parties or processors.',
    evidence: sharing ? [`"${sharing.quote}"`] : [],
    legal: LEGAL.sharing,
    fix: 'List the categories of processors and third parties you share data with, what for, and that they act under contract.',
    verify: 'Compare the notice against your vendor list and data processing agreements.',
  };
}

function checkRetention(sentences) {
  // A period or criterion must be stated. "Data retention and deletion requirements" in a list of
  // contract terms (comolho.com) is not a retention statement.
  const retention = find(sentences, /\b(retain\w*|retention|stor(e|ed|ing)|keep|kept|hold)\b.{0,160}\b(as\s+long\s+as|no\s+longer\s+than|for\s+(a|the)\s+period|period\s+of|until|(\d+|one|two|three|four|five|six|seven|eight|nine|ten|twelve|eighteen|twenty[\s-]?four|thirty[\s-]?six)\s+(days?|weeks?|months?|years?)|(is|are|remains?)\s+necessary|required\s+(by|under)\s+(law|applicable))\b/i,
    { near: /data|information|records?|details|ip\s+address|accounts?/i, reject: /\brequirements\b|\bobligations\b/i });
  return {
    id: 'sharing-retention', controlId: 'DPDP-SHARING-002', area: 'Data handling & sharing', severity: 'Medium',
    status: retention ? 'pass' : 'fail',
    title: 'Retention period or criteria are explained',
    detail: retention ? 'The notice explains how long personal data is kept.' : 'The notice does not explain how long personal data is kept or when it is erased.',
    evidence: retention ? [`"${retention.quote}"`] : [],
    legal: LEGAL.retention,
    fix: 'State how long each category of data is kept (or the criteria used), and that it is erased when no longer needed or when consent is withdrawn.',
    verify: 'Check your systems actually delete data on the schedule the notice states.',
  };
}

const VENDOR_ALIASES = {
  'Meta Pixel': ['meta', 'facebook'], Meta: ['meta', 'facebook'], 'Facebook social plugin': ['facebook', 'meta'],
  'Microsoft Advertising (UET)': ['microsoft', 'bing'], 'Microsoft Clarity': ['clarity', 'microsoft'],
  'X (Twitter) Pixel': ['twitter', ' x '], 'LinkedIn Insight Tag': ['linkedin'], 'TikTok Pixel': ['tiktok'],
  'Google Ads (DoubleClick)': ['google', 'doubleclick'], 'Xandr (AppNexus)': ['xandr', 'appnexus', 'microsoft'],
  'Piano (Cxense)': ['piano', 'cxense'],
};
function vendorTerms(vendor) {
  const base = vendor.replace(/\s*\(.*?\)\s*/g, ' ').trim().toLowerCase();
  return [...new Set([base, base.split(' ')[0], ...(VENDOR_ALIASES[vendor] || [])])].filter((t) => t.length >= 3);
}

function checkUndisclosedVendors(sentences, vendors) {
  if (!vendors.length) return null;
  const text = ` ${sentences.join(' ').toLowerCase()} `;
  const named = [];
  const missing = [];
  for (const { vendor, category } of vendors) {
    (vendorTerms(vendor).some((term) => text.includes(term)) ? named : missing).push(`${vendor} (${category})`);
  }
  return {
    id: 'sharing-undisclosed-vendors', controlId: 'DPDP-SHARING-003', area: 'Data handling & sharing', severity: 'Medium',
    status: missing.length ? 'review' : 'pass', confidence: 'medium',
    title: 'Trackers observed on the site are named in the notice',
    detail: missing.length
      ? `${missing.length} of ${vendors.length} tracking vendor(s) seen running on the site are not mentioned anywhere in the notice.`
      : `All ${vendors.length} tracking vendor(s) seen running on the site are mentioned in the notice.`,
    evidence: [...missing.map((v) => `Not mentioned: ${v}`), ...named.map((v) => `Mentioned: ${v}`)],
    legal: LEGAL.sharing,
    fix: 'Name each analytics, advertising and session-recording vendor in the notice (or cookie policy linked from it) with its purpose.',
    verify: 'Compare the vendors in this report with the notice text.',
  };
}

const CHILD = /\b(child(ren)?|minors?|kids|(under|below|younger\s+than|less\s+than)\s+(the\s+age\s+of\s+)?\d{1,2}(\s+years)?)\b/i;
function checkChildren(sentences) {
  const childLines = sentences.map((s, i) => [s, i]).filter(([s]) => CHILD.test(s));
  let lowAge = null;
  for (const [s, i] of childLines) {
    const age = s.match(/\b(under|below|younger\s+than|less\s+than)\s+(the\s+age\s+of\s+)?(\d{1,2})\b/i);
    if (age && Number(age[3]) < 18 && Number(age[3]) >= 10) { lowAge = { age: Number(age[3]), quote: quote(sentences, i) }; break; }
  }
  const parental = find(sentences, /\b(parent\w*|guardian\w*|verifiable)\b/i, { near: CHILD, window: 3 });
  let status;
  let severity = 'High';
  let detail;
  if (lowAge) {
    status = 'fail';
    detail = `The notice uses an age of ${lowAge.age} for children. Under the DPDP Act a child is anyone under 18, so users aged ${lowAge.age}–17 are treated as adults here. This usually means the notice was copied from a GDPR or US template.`;
  } else if (parental) {
    status = 'pass';
    detail = 'The notice addresses children\'s data and parental or guardian consent.';
  } else if (childLines.length) {
    status = 'review';
    detail = 'The notice mentions children but not verifiable consent from a parent or guardian.';
  } else {
    status = 'review';
    severity = 'Medium';
    detail = 'The notice does not address children. If anyone under 18 can use your service, you need verifiable parental consent and must not track or target them with ads.';
  }
  return {
    id: 'children-consent', controlId: 'DPDP-CHILDREN-001', area: "Children's data", severity, status,
    title: 'Children\'s data and parental consent are addressed',
    detail,
    evidence: [lowAge && `"${lowAge.quote}"`, parental && `"${parental.quote}"`, !lowAge && !parental && childLines[0] && `"${quote(sentences, childLines[0][1])}"`].filter(Boolean),
    legal: LEGAL.children,
    fix: 'Treat everyone under 18 as a child. Describe how you obtain verifiable parental consent, and state that you do not track, profile or target ads at children.',
    verify: 'Check the notice\'s age threshold and try signing up as a 16-year-old.',
  };
}

// ---------- entry point ----------

const NOTICE_CHECKS = [
  ['notice-data-purpose', 'Privacy notice', 'Notice lists the personal data and why it is used', 'High'],
  ['notice-withdrawal', 'Privacy notice', 'Notice explains how to withdraw consent', 'High'],
  ['notice-board', 'Privacy notice', 'Notice explains how to complain to the Data Protection Board', 'Medium'],
  ['rights-access', 'Data principal rights', 'Right to access information is explained', 'Medium'],
  ['rights-correction-erasure', 'Data principal rights', 'Rights to correction and erasure are explained', 'High'],
  ['rights-grievance', 'Data principal rights', 'Grievance redressal channel is published', 'High'],
  ['rights-nomination', 'Data principal rights', 'Right to nominate is explained', 'Medium'],
  ['contact-officer', 'Governance & security', 'Privacy contact person is published', 'Medium'],
  ['sharing-processors', 'Data handling & sharing', 'Sharing with processors and third parties is disclosed', 'Medium'],
  ['sharing-retention', 'Data handling & sharing', 'Retention period or criteria are explained', 'Medium'],
  ['children-consent', "Children's data", 'Children\'s data and parental consent are addressed', 'High'],
];

/**
 * @param notice  { url, error?, words, language }
 * @param text    the notice's visible text, or '' when unavailable
 * @param vendors non-essential tracking vendors observed on the site: [{ vendor, category }]
 */
export function analyzeNotice(notice, text, vendors = []) {
  // No notice exists at all (confirmed by the scanner): every notice requirement is unmet, so fail.
  // This differs from "exists but could not be read" (PDF, blocked, other language), which stays untested.
  if (notice?.missing) {
    return NOTICE_CHECKS.map(([id, area, title, severity]) => ({
      id, controlId: 'DPDP-NOTICE', area, title, severity, status: 'fail', confidence: 'high',
      detail: 'The site has no privacy notice, so this requirement is not met.',
      evidence: [`Looked for a privacy notice in: ${(notice.checked || []).join(', ')}. None was found.`],
      legal: LEGAL.notice,
      fix: 'Publish a DPDP privacy notice and link it from every page footer and next to every form. It must cover this requirement.',
      verify: 'Open the homepage footer and try /privacy-policy on the site; neither should lead nowhere.',
    }));
  }
  if (!notice || notice.error || !text) {
    const reason = notice?.error || 'The privacy notice could not be read.';
    return NOTICE_CHECKS.map(([id, area, title, severity]) => ({
      id, controlId: 'DPDP-NOTICE', area, title, severity, status: 'not-evaluated', confidence: 'low',
      detail: `Not tested: ${reason}`,
      evidence: notice?.url ? [`Notice URL: ${notice.url}`] : [],
      legal: LEGAL.notice,
      fix: 'Publish a privacy notice as an HTML page in English (you may add translations) and link it from the homepage footer, then re-scan.',
      verify: 'Open the notice link from the homepage and confirm it loads without login.',
    }));
  }
  const sentences = splitSentences(text);
  const source = `Read from ${notice.url} (${notice.words} words)${notice.hubUrl ? `, followed from the summary page ${notice.hubUrl}` : ''}`;
  const checks = [
    checkDataAndPurpose(sentences), checkWithdrawal(sentences), checkBoard(sentences), checkDpdpCurrency(sentences),
    checkAccess(sentences), checkCorrectionErasure(sentences), checkGrievance(sentences), checkNomination(sentences),
    checkContact(sentences), checkSharing(sentences), checkRetention(sentences),
    checkUndisclosedVendors(sentences, vendors), checkChildren(sentences),
  ].filter(Boolean);
  return checks.map((check) => ({ confidence: 'medium', ...check, evidence: [...check.evidence, source] }));
}

export function detectLanguage(text) {
  const letters = text.replace(/[^\p{L}]/gu, '');
  if (!letters.length) return 'unknown';
  const latin = (letters.match(/[A-Za-z]/g) || []).length / letters.length;
  const devanagari = (letters.match(/[ऀ-ॿ]/g) || []).length / letters.length;
  if (latin >= 0.7) return 'en';
  if (devanagari >= 0.3) return 'hi';
  return 'other';
}
