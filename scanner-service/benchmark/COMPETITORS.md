# Competitor comparison — 25 September 2026

## Who was compared

| Product | What it is | Could we test it? |
|---|---|---|
| **checkDPDP** (checkdpdp.in) | Free Indian DPDP scanner, 0–100 score, no signup | Yes, on the same 5 sites |
| **Dutro / BUA PrivacyAdvisor** (bua.dutro.ai) | "Automated privacy and cookie scans across DPDPA, GDPR, and CCPA"; enterprise privacy platform | No, login required. Public code shows a server-side scan with a consent journey ("Consent state — after Reject all (or equivalent)") and screenshot evidence |
| **ConsentX** (consentx.io) | Free cookie scanner, report by email | Not run. Its page says it records pre-consent trackers but does not click Reject or Accept |
| **"grc.netrus"** | — | Not found. netrus.in is a parked domain; the link is needed |

## Head-to-head on verified facts

Sites: freshworks.com, lenskart.com, esecforte.com, razorpay.com, groww.in. Each fact below was verified by hand during the false-positive audit (`REPORT.md`). Raw checkDPDP reports are in `competitors/`.

| Fact | Our scanner | checkDPDP |
|---|---|---|
| Consent banner present? | **5/5** | 3/5: says "no banner" on Freshworks (OneTrust) and esecforte (Cookie Notice) |
| Trackers firing before consent? | **5/5** | 3/5: **passes** Freshworks (14 trackers) and esecforte (Google Analytics) |
| Reject as easy as Accept? | **3/3** with the real reason | 3/3 verdicts, but every reason is "no banner region found" |
| Privacy notice linked? | **5/5** | 4/5: "no working privacy policy link" on Lenskart |
| Grievance or privacy contact published? | **4/4** (1 not tested: esecforte has no notice) | 2/5: "No Grievance Officer found anywhere" on Razorpay, Groww and Lenskart, which all publish one |
| Rights (access, correction, erasure) described? | 3/4 in the run, **4/4** with the fix made afterwards (1 not tested) | 2/5: "0 of 6 rights" on Freshworks, Lenskart and Razorpay, which describe them |
| **Total** | **25/26 correct as run (26/26 with the fix), 2 not tested** | **17/28 correct (61%)** |

Why checkDPDP got these wrong, in its own words:

- 3 of the 5 sites were marked "**WAF / bot-blocked** … The score reflects only what we could see", but it still scored them (38, 17, 31 out of 100). Its security-header results for those sites came from the challenge page (Freshworks "5 of 5", esecforte "4 of 5"; the real sites have 3 of 5 and 0 of 5).
- It reads HTML: "No consent banner detected in the rendered HTML", "No tracker domains in the home page HTML". Banners and trackers that load with JavaScript are missed.
- Groww: "0 of 7 Section 5 elements". It read the privacy hub page, not the linked full policy.
- Every report said "deterministic rules only — the LLM key pool was unavailable". **Its results may be better when its AI analyser is running**, so this should be re-run on another day.

## Detected only by our scanner

- Freshworks: scrolling closes the banner and stores consent for every category; optional categories are pre-ticked; tracking continues after a genuine reject.
- Lenskart: "Allow Selection" stores every category as granted, so there is no way to reject.
- esecforte: "If you continue to use this site we will assume that you are happy with it" (implied consent), and the ✕ records acceptance.
- Policies copied from GDPR or US templates: children's age of 13 or 16 instead of 18; European Data Protection Board instead of India's.

## Where checkDPDP is ahead

- **Report product**: prioritised fix list with severity, effort estimate ("5 minutes", "half day"), "what good looks like", suggested Indian consent tools, PDF download, share link, email, re-scan.
- **Checks we do not have yet**: footer "Cookie preferences" withdrawal link, Google Consent Mode v2 snippet, consent on forms that collect personal data, cross-border transfer disclosure, all six rights including withdrawal and grievance as one checklist.
- **Speed**: 7–17 seconds per site against our 30–100 seconds.
- **Around the scan**: certification badge, penalty calculator, notice and banner generators, a deadline countdown (13 May 2027), multilingual interface.
- **Honesty label**: it shows the site type (for example "WAF / bot-blocked") on the report, though it then scores the page anyway.

## Limits

- 5 sites. checkDPDP ran without its AI analyser. Dutro, the closest match to our approach, could not be tested without an account.
- Security-header counts were left out of the totals: the two tools may have fetched different URLs (apex or www).

## Netras.GRC (grc.netras.ai), added 25 September 2026

Not scanned: every scan requires a verified work email and a statement that the user owns or is authorised for the site, which is not true for the benchmark sites. The false-positive rate is therefore **not measured**. The comparison below comes from Netras's own "How the scan works" text and its public app code.

| | Netras.GRC | Our scanner |
|---|---|---|
| Headless Chrome, first-time visitor | Yes | Yes |
| Pre-consent trackers and cookies, named vendors | Yes | Yes |
| Clicks Reject / Accept | No ("clicks nothing and doesn't scroll") | Yes: reject, accept, stored consent state, tracking after reject |
| Pre-ticked categories, scroll-as-consent, "save" buttons that grant everything | Not detectable without interaction | Detected |
| Full policy text incl. collapsed sections | Yes | Yes, plus following summary/hub pages to the full policy |
| Policy checks (data, purposes, withdrawal, Board, rights, nomination, retention, sharing, children, contact) | Yes | Yes |
| Forms show a privacy notice, HSTS, mixed content, breach statement | Yes | Not yet |
| Bot-protection pages | General caveat only | Reported as blocked, not scored |
| Checks that could not run | Count against the score | Excluded from the score |

Netras check IDs (from its app code): pre-consent-tracking, pre-consent-cookies, consent-banner, reject-option, policy-link, policy-reachable, itemised-data, purposes, withdraw-consent, board-complaint, notice-at-collection, last-updated, right-access, right-correction-erasure, right-grievance, right-nomination, retention, sharing, undisclosed-vendors, children, contact-officer, https, hsts, mixed-content, breach.

To measure its false-positive rate: scan 10–20 sites you are authorised for with both tools, keep Netras's reports, and label every failure against the live site as in `REPORT.md`.

### Head-to-head on Netras reports (esecforte.com, comolho.com, chatgpt.com)

Netras reports supplied by the user (scanned 25 Sept 2026, 12:59–1:46 am). Our scans ran the same day. Every disagreement was settled on the live site or the policy text.

| Site | Check | Netras | Ours | Truth (how verified) |
|---|---|---|---|---|
| comolho.com | "Last updated" date | Fail | Missed in evidence (not a fail) | **Present**: policy opens "Date : 03rd July 2024" (visible in Netras's own screenshot) |
| comolho.com | Retention described | Fail | Pass (wrong) | **Missing**: our quote was "Data retention and deletion requirements", a list of contract terms |
| comolho.com | Tracking stops after "Decline All" | Not tested (no clicks) | Fail | **Still tracks**: after Decline All and reload, LinkedIn Insight loads and px.ads.linkedin.com/collect fires |
| chatgpt.com | Privacy policy found | Yes (openai.com) | No (same-site links only) | **Linked** from the footer to openai.com |
| chatgpt.com | Right to access | Fail | Not tested | **Present**: "Access your Personal Data and information relating to how it is processed." |
| chatgpt.com | Children's data | Pass | Fail (after fix) | **Age 13**: "not directed to… children under 13"; DPDP child = under 18 |
| esecforte.com | Implied consent ("If you continue… we will assume…") | Not flagged | Fail | **Implied consent** in banner text |

**Wrong fails (false positives), all three reports:**
- Netras: 2 of 21 failed checks wrong (comolho last-updated date, chatgpt right to access) = **9.5%**. Plus 1 wrong pass (chatgpt children, age 13) and 2 violations not detectable by its method (tracking after decline, implied-consent wording).
- Ours, as scanned before this comparison: 0 wrong fails, but 1 wrong pass (comolho retention), 1 wrong evidence quote (comolho access quoted a contract sentence), and chatgpt's policy not analysed (off-site link).
- Ours after the fixes made from this comparison: 0 of 18 failed checks wrong, and the wrong pass and missing policy fixed. These fixes were made after seeing these reports, so re-test on new sites before quoting this figure.

Fixes made from this comparison: retention needs a stated period; rights bullets must act on personal data (both "Access your Personal Data…" found and "Updated: 30 July" no longer taken as a right); "Date :" and "Updated:" dates recognised; off-site links labelled exactly "Privacy Policy" accepted; full-screen app layouts no longer mistaken for cookie banners; contract/agreement wording excluded from the access right; `bscookie` classified as LinkedIn. All covered by `npm test` (13 tests).

Netras is ahead on: breach-statement check, HSTS/mixed-content checks, forms notice check, and a polished report (services table with BEFORE CONSENT / NOT IN POLICY status, legal provision boxes, a remediation call to action).
