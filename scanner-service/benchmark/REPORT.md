# False-positive audit — DPDP consent scanner

Date: 25 September 2026. Sites: 29 Indian websites in `sites.txt` (fintech, banks, e-commerce, IT services, SaaS, edtech, health, media), each scanned twice.

## Result

| Run | Sites scanned | Failed checks | False positives | False-positive rate |
|---|---|---|---|---|
| Before fixes (`results/2026-09-25T05-44-23`) | 22 | 108 | 13 | **12.0%** |
| After fixes (`results/2026-09-25T06-34-19`) | 21 | 101 | 1 | **1.0%** |
| After the last fix, policy checks re-run on the saved texts | 21 | 100 | 0 | **0%** on this sample |

A false positive is a check reported as **Failed** when the site does not actually have that problem. Every failed check in both runs was verified by hand. The labels are in `labels.json` and the reasons in `label-notes.json` in each results folder. `npm run benchmark:score -- <folder>` recomputes the rates.

Stability: in the final run, every check gave the same result on both runs of every site, except BookMyShow's privacy notice. It was read on one run and reported as "not tested" on the other, not failed. A retry for slow policy pages has since been added.

## How each failure was verified

- **Security headers:** read directly from the response, so factual.
- **Tracking before consent:** every flagged request and cookie was listed across all sites and checked to be a real advertising, analytics, session-replay or marketing vendor.
- **No consent banner / reject options:** pre-consent screenshots were inspected; banners were opened in a real browser, and consent settings and stored consent state were read.
- **Privacy notice checks** ("X is missing"): the full policy was searched with a much broader pattern, and every passage found was read to decide whether the requirement is really there.

## False positives found and fixed

| Check | Site | What the site actually does | Fix |
|---|---|---|---|
| Several notice checks | groww.in, cred.club | "Privacy" page is a hub or summary; the full policy is one link deeper | Follow the full-policy link from short hub pages |
| Several notice checks | groww.in, cred.club | Policy text inside collapsed sections was not read | Read all text, including collapsed sections |
| Privacy contact | zerodha.com | `legal[@]zerodha[.]com` next to the named DPO | Recognise obfuscated emails |
| Privacy contact | phonepe.com | "write to PhonePe's Privacy Officer using https://support.phonepe.com" | Accept support and grievance links |
| Grievance | freshworks.com | "If you have a concern … contact us" | Complaint route without the word "grievance" → Needs review |
| Correction/erasure | swiggy.com, hdfc.bank.in, phonepe.com, byjus.com, groww.in | "want your data to be deleted", "shall be able to … correct", "wish to delete your account", "way for you to access and change", "choose to delete your account" | Wider phrasing, still tied to the person's own data |
| Privacy link | 1mg.com | Footer loads only on scroll | Separate browsing visit scrolls with the mouse wheel until the page stops growing |
| Reject options | freshworks.com | "Confirm My Choices" saved **pre-ticked** categories | Switch optional categories off before saving; report pre-ticked boxes as their own failure |

## Wrong passes found and fixed

These are just as serious for a compliance tool: the scanner said a site was fine when it was not.

| Check | Site | Problem |
|---|---|---|
| Data Protection Board | groww.in, zerodha.com | "Securities and Exchange Board of India" (SEBI) was counted as the Board |
| Access / correction rights | cred.club, groww.in | "enable Our access to your email", "revoke the aforementioned access by amending permissions" were counted as the user's rights |
| Several | practo.com | An Akamai "Processing your request" page (HTTP 200) was graded as the site. Now reported as blocked |
| Several | hdfc.bank.in, icici.bank.in | Every `*.bank.in` bank was treated as one site. Now `bank.in` and `fin.in` are handled as public suffixes |
| Accept journey / reject | lenskart.com | "Allow Selection" was taken as Accept, then as a reject. It actually stores every GoTrust category as granted. It is now reported as "no working way to reject" |
| Implied consent | freshworks.com | Scrolling alone closed the OneTrust banner and stored consent for all categories. Now detected by a separate browsing visit |

## Limits of this measurement

- One reviewer labelled the results. Borderline cases are explained in `label-notes.json`.
- 21 sites is a small sample. Rates on other sites, especially non-English policies or unusual consent tools, may differ.
- The false-positive rate does not measure missed problems. The wrong passes above were found while checking evidence, not by a systematic search for them.
- 8 of 29 sites (Policybazaar, Infosys, TCS, Naukri, MakeMyTrip, Myntra, NDTV, Practo) blocked the automated browser and are reported as blocked, not scored.

## Re-running

```bash
npm run benchmark                         # scans benchmark/sites.txt twice each, writes results/<time>/audit.md
# review audit.md, write results/<time>/labels.json as { "site:check-id": "TP" | "FP" }
npm run benchmark:score -- benchmark/results/<time>
npm test                                  # the policy-reading regression tests, including every case above
```
